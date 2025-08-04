# --- Standard Library Imports ---
import os
import re
import json
import socket
import base64
from io import BytesIO
from datetime import datetime, timedelta
from functools import wraps

# --- Flask Core Imports ---
from flask import Flask, render_template, redirect, url_for, flash, request, current_app, abort, jsonify, session
from flask_wtf import CSRFProtect, FlaskForm
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from apscheduler.schedulers.background import BackgroundScheduler

# antonio: forms
from forms import SignupForm,LoginForm,ReportForm,UpdateUserStatusForm,FriendRequestForm,UpdateReportStatusForm,Enable2FAForm,Disable2FAForm,RemovePassKeyForm, EventForm

# No clue but seems important
from sqlalchemy.dialects.mysql import ENUM
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

# --- Forms & Validation Imports ---
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, ValidationError

# --- Security & Authentication Imports ---
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from base64 import b64encode

# --- WebAuthn/Passkey Imports ---
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject

# --- Custom Module Imports ---
# Models
from models import (
    db, User, Role, Permission, Event, Post, PostImage, 
    Notification, Report, Chat, ChatParticipant, Message, 
    Friendship, AdminAction, UserLog, ModSecLog, ErrorLog, 
    WebAuthnCredential, user_role_assignments,Event
)

# Filters
from filters import (
    apply_user_filters, apply_user_sorting, 
    apply_report_filters, apply_user_log_filters
)

# Forms
from forms import (
    SignupForm, LoginForm, ReportForm, UpdateUserStatusForm,
    FriendRequestForm, UpdateReportStatusForm, Enable2FAForm,
    Disable2FAForm, RemovePassKeyForm
)

# Custom logging utilities
from user_actions import (
    log_user_login_attempt, log_user_login_success, 
    log_user_login_failure, log_user_logout
)

# Log parsing utilities
from parse_test import parse_modsec_audit_log, parse_error_log

# --- Configuration ---
# Flask app configuration
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdQNVsrAAAAAMp8AX4H_J4CwZ5OXVixltEf4RaC'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdQNVsrAAAAAMOmgh-7Tp-KAwQUQ6iIbi8_pRvM'

# Database configuration
DB_USER = os.getenv('MYSQL_USER', 'flaskuser')
DB_PASSWORD = os.getenv('MYSQL_PASSWORD', 'password')
DB_NAME = os.getenv('MYSQL_DATABASE', 'flaskdb')
DB_HOST = os.getenv('MYSQL_HOST', 'mysql')  # 'mysql' is the service name in docker-compose
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secret_key_for_dev')  # Change in production!

# Initialize database
db.init_app(app)

# Socket.IO configuration (MAKE DYNAMIC)
socketio = SocketIO(app, cors_allowed_origins=[
    "http://localhost",
    "http://127.0.0.1",
    "https://502a1f10a795.ngrok-free.app"
])

# --- Initialize Extensions ---
# CSRF protection
csrf = CSRFProtect(app)

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login if user not authenticated

# --- Context Processors ---
@app.context_processor
def inject_container_id():
    return {"container_id": socket.gethostname()}


# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database given their ID."""
    return db.session.get(User, int(user_id))


# --- User Required Decorator ---

# @login_required is already imported
def user_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        # Count the number of roles for the current user
        user_roles = [role.role_name for role in current_user.roles]
        if user_roles == ['user']:
            return f(*args, **kwargs)
        else:
            abort(403)
    return decorated_function

# --- Admin Required Decorator ---
def admin_required(f):
    @wraps(f)
    @login_required # Ensure user is logged in first
    def decorated_function(*args, **kwargs):
        if not current_user.has_role('admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function



# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- RBAC Decorators ---
#def role_required(role_name):
    #def decorator(f):
        #@wraps(f)
        #@login_required
        #def decorated_function(*args, **kwargs):
            #if not current_user.has_role(role_name):
                #return redirect(url_for('dashboard'))
            #return f(*args, **kwargs)
        #return decorated_function
    #return decorator

#def permission_required(permission_name):
    #ef decorator(f):
        #@wraps(f)
        #@login_required
        #def decorated_function(*args, **kwargs):
            #if not current_user.has_permission(permission_name):
                #flash(f'You do not have the required permission: {permission_name}.', 'danger')
                #return redirect(url_for('dashboard'))
            #return f(*args, **kwargs)
        #return decorated_function
    #return decorator


# -- Fido2 WebAuthn Server Setup --
# -- For passkey

def get_fido2_server():
    from flask import request
    rp_id = request.host.split(':')[0]
    rp_name = "SimpleBook"
    rp = PublicKeyCredentialRpEntity(rp_id, rp_name)
    return Fido2Server(rp)

def b64encode_all(obj):
    if isinstance(obj, dict):
        return {k: b64encode_all(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [b64encode_all(i) for i in obj]
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    else:
        return obj


# --- login,signup,home ---
@app.route('/')
@login_required
def home():
    return render_template('UserHome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()

            # --- Lockout check ---
            if user and user.lockout_until and user.lockout_until > datetime.utcnow():
                # Log the lockout attempt
                log_user_login_failure(user.user_id, details="Attempted login while locked out.")
                return render_template('UserLockedOut.html', lockout_until=user.lockout_until.strftime("%Y-%m-%d %H:%M:%S"))
            
            
            # Log every login attempt (regardless of outcome)
            if user:
                log_user_login_attempt(user.user_id, details="User attempted login.")

            if user and user.check_password(password):
                if user.totp_secret:
                    # Store user ID in session and redirect to 2FA page
                    session['pending_2fa_user_id'] = user.user_id
                    return redirect(url_for('verify_2fa'))
                else:

                    # --- Reset failed login attempts on successful login ---
                    user.failed_login_attempts = 0
                    user.lockout_until = None
                    db.session.commit()

                    login_user(user)
                    user.current_status = 'online'
                    user.last_active_at = datetime.utcnow()
                    db.session.commit()

                    # --- Log user login success ---
                    log_user_login_success(user.user_id, details="User logged in successfully.")
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('home'))
            
            else:
                if user:
                    user.failed_login_attempts += 1
                    if user.failed_login_attempts >= 3:
                        user.lockout_until = datetime.utcnow() + timedelta(minutes=10)
                        # Log lockout event
                        log_user_login_failure(user.user_id, details="User locked out after 3 failed attempts.")
                    else:
                        # Log failed login
                        log_user_login_failure(user.user_id, details="User failed login attempt.")
                    db.session.commit()
                else:
                    pass
    return render_template('UserLogin.html', form=form)

@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        current_user.current_status = 'offline'
        db.session.commit()
    log_user_logout(current_user.user_id, details="User logged out.")
    logout_user()
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        phone_no = form.phone_no.data
        password = form.password.data

        existing_user = User.query.filter(
            (User.username == username) |
            (User.phone_number == phone_no)
        ).first()

        if existing_user:
            return redirect(url_for('signup'))
                
        new_user = User(
            username=username,
            phone_number=phone_no,
            password_hash=generate_password_hash(password),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            current_status='online'
        )
        db.session.add(new_user)
        db.session.commit()

        # Assign 'user' role
        default_role = Role.query.filter_by(role_name='user').first()
        new_user.roles.append(default_role)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('home'))

    return render_template('UserSignup.html', form=form)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    
    if 'pending_2fa_user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['pending_2fa_user_id'])
    if not user or not user.totp_secret:
        return redirect(url_for('login'))

    form = Enable2FAForm()
    if form.validate_on_submit():
        code = form.totp_code.data
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code):
            login_user(user)
            session.pop('pending_2fa_user_id', None)
            return redirect(url_for('home'))
    return render_template('UserVerify2FA.html', form=form)


# -- User security management --


@app.route('/account_security', methods=['GET', 'POST'])
@user_required
def account_security():
    has_2fa = bool(current_user.totp_secret)
    form = Disable2FAForm()
    form1 = RemovePassKeyForm()
    return render_template('UserAccountSecurity.html', has_2fa=has_2fa, form=form, form1=form1)

@app.route('/enable_2fa', methods=['GET', 'POST'])
@user_required
def enable_2fa():
    form = Enable2FAForm()

    # -- Already enabled --
    if current_user.totp_secret:
        return redirect(url_for('account_security'))

    if 'pending_totp_secret' not in session:
        session['pending_totp_secret'] = pyotp.random_base32()
    totp_secret = session['pending_totp_secret']

    otp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
        name=current_user.username, issuer_name="SimpleBook"
    )
    img = qrcode.make(otp_uri)
    buf = BytesIO()
    img.save(buf)
    qr_b64 = b64encode(buf.getvalue()).decode('utf-8')

    if request.method == 'POST':
        code = request.form.get('totp_code')
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(code):
            current_user.totp_secret = totp_secret
            db.session.commit()
            session.pop('pending_totp_secret', None)  # Remove from session
            return redirect(url_for('account_security'))
    return render_template('UserEnable2FA.html', qr_b64=qr_b64, secret=totp_secret, form=form)

@app.route('/disable_2fa', methods=['POST'])
@user_required
def disable_2fa():
    form = Disable2FAForm()
    if form.validate_on_submit():
        current_user.totp_secret = None
        db.session.commit()
        return redirect(url_for('account_security'))
    return render_template('UserDisable2FA.html', form=form)

# -- User passkey management --
@app.route('/passkey/begin_register', methods=['POST'])
@csrf.exempt
@login_required
def passkey_begin_register(): #stable!
    try:
        fido2_server = get_fido2_server()
        user = {
            "id": str(current_user.user_id).encode(),
            "name": current_user.username,
            "displayName": current_user.username,
        }
        exclude_credentials = [
            {"id": bytes.fromhex(cred.credential_id), "type": "public-key"}
            for cred in current_user.webauthn_credentials
        ]
        registration_data, state = fido2_server.register_begin(
            user,
            credentials=exclude_credentials,
            user_verification="preferred"
        )
        session['fido2_state'] = state
        encoded = b64encode_all(registration_data)
        # --- FIX: Wrap in 'publicKey' ---
        return jsonify({"publicKey": encoded})
    except:
        return redirect(url_for('account_security'))

@app.route('/passkey/finish_register', methods=['POST'])
@csrf.exempt
@user_required
def passkey_finish_register():
    fido2_server = get_fido2_server()
    data = request.get_json()
    state = session.pop('fido2_state')
    clientDataJSON_bytes = base64.b64decode(data['response']['clientDataJSON'])
    attestationObject_bytes = base64.b64decode(data['response']['attestationObject'])

    client_data = ClientData(clientDataJSON_bytes)
    attestation_object = AttestationObject(attestationObject_bytes)

    # register_complete returns auth_data (AuthenticatorData)
    auth_data = fido2_server.register_complete(
        state,
        client_data,
        attestation_object
    )

    # Extract credential_id and public_key from attestation_object.auth_data.credential_data
    credential_id = attestation_object.auth_data.credential_data.credential_id
    public_key = attestation_object.auth_data.credential_data.public_key
    sign_count = 0 #debug
    new_cred = WebAuthnCredential(
        user_id=current_user.user_id,
        credential_id=credential_id.hex(),
        public_key=public_key,
        sign_count=sign_count,
        nickname=data.get('nickname', 'My Passkey')
    )
    db.session.add(new_cred)
    db.session.commit()
    return jsonify({"success": True})

@app.route('/remove_passkey/<int:cred_id>', methods=['POST'])
@user_required
def remove_passkey(cred_id):
    cred = WebAuthnCredential.query.filter_by(id=cred_id, user_id=current_user.user_id).first()
    if cred:
        db.session.delete(cred)
        db.session.commit()

    else:
        pass
    return redirect(url_for('account_security'))

# --- User Reporting ---
@app.route('/report_user', methods=['GET', 'POST'])
@user_required # Ensure only logged-in users can access this page
def report_user():
    form = ReportForm()

    if form.validate_on_submit():
        # The custom validator `validate_reported_username` in forms.py
        # has already found the user and stored it in `form.user_to_report_obj`
        reported_user = form.user_to_report_obj

        # At this point, reported_user is guaranteed to exist and not be the current user
        # due to the form's custom validator.

        new_report = Report(
            reporter_id=current_user.user_id, # The current logged-in user is the reporter
            reported_user_id=reported_user.user_id, # Get ID from the found user object
            report_type=form.report_type.data,
            description=form.description.data,
            submitted_at=datetime.utcnow(),
            status='open' # Default status
        )

        try:
            db.session.add(new_report)
            db.session.commit()
            # Redirect to the profile of the user who was reported, or a confirmation page
            return redirect(url_for('report_confirmation', reported_username=reported_user.username))
        except:
            #error or smth
            db.session.rollback()

    return render_template('UserReport.html', form=form)

@app.route('/report_confirmation')
@user_required
def report_confirmation():
    reported_username = request.args.get('reported_username', 'the user')
    return render_template('UserReportConfirmed.html', reported_username=reported_username)


# -- User friends management --
@app.route('/UserFriends', methods=['GET'])
@user_required
def user_friends():
    # Get all accepted friendships involving the current user
    friendships = Friendship.query.filter(
        ((Friendship.user_id1 == current_user.user_id) | (Friendship.user_id2 == current_user.user_id)),
        Friendship.status == 'accepted'
    ).all()

    # Get friend user IDs
    friend_ids = [
        f.user_id2 if f.user_id1 == current_user.user_id else f.user_id1
        for f in friendships
    ]
    friends = User.query.filter(User.user_id.in_(friend_ids)).all()

    accepted_friends = {}
    for f in friendships:
        friend_id = f.user_id2 if f.user_id1 == current_user.user_id else f.user_id1
        accepted_friends[friend_id] = f.friendship_id

    
    friends = User.query.filter(User.user_id.in_(accepted_friends.keys())).all()

    friends_info = []
    for user in friends:
        friends_info.append({
            'user_id': user.user_id,
            'username': user.username,
            'profile_pic_url': user.profile_pic_url,
            'is_online': user.current_status == 'online',
            'bio': user.bio,
            'friendship_id': accepted_friends[user.user_id]
        })

    form = FriendRequestForm()
    return render_template('userfriends.html', friends=friends_info, accepted_friends=accepted_friends, form=form)

@app.route('/DiscoverFriends', methods=['GET'])
@user_required
def discover_friends():
    user = current_user

    # Subquery for users who have admin/editor/guest roles
    subq = (
        db.session.query(user_role_assignments.c.user_id)
        .join(Role, user_role_assignments.c.role_id == Role.role_id)
        .filter(Role.role_name.in_(['admin', 'editor', 'guest']))
    )

    # Main query: users with 'user' role, not in subquery, and not current user
    all_users = (
        db.session.query(User)
        .join(user_role_assignments, User.user_id == user_role_assignments.c.user_id)
        .join(Role, user_role_assignments.c.role_id == Role.role_id)
        .filter(
            Role.role_name == 'user',
            ~User.user_id.in_(subq),
            User.user_id != user.user_id
        )
        .all()
    )
    pending_friendships = Friendship.query.filter(
    ((Friendship.user_id1 == current_user.user_id) | (Friendship.user_id2 == current_user.user_id)),
    Friendship.status == 'pending'
    ).all()

    pending_requests = {}
    for f in pending_friendships:
        other_id = f.user_id2 if f.user_id1 == current_user.user_id else f.user_id1
        if f.action_user_id == current_user.user_id:
            pending_requests[other_id] = 'sent'
        else:
            pending_requests[other_id] = 'received'

    accepted_friendships = Friendship.query.filter(
    ((Friendship.user_id1 == current_user.user_id) | (Friendship.user_id2 == current_user.user_id)),
    Friendship.status == 'accepted'
    ).all()

    accepted_friends = {}
    for f in accepted_friendships:
        other_id = f.user_id2 if f.user_id1 == current_user.user_id else f.user_id1
        accepted_friends[other_id] = f.friendship_id

    form = FriendRequestForm()

    return render_template('DiscoverFriends.html',all_users=all_users,current_user=user,form=form,pending_requests=pending_requests,accepted_friends=accepted_friends)

@app.route('/search_users')
@user_required
def search_users():
    query = request.args.get('q', '').strip()
    user = current_user

    subq = (
    db.session.query(user_role_assignments.c.user_id)
    .join(Role, user_role_assignments.c.role_id == Role.role_id)
    .filter(Role.role_name.in_(['admin', 'editor', 'guest']))
    )
    users = (
        db.session.query(User)
        .join(user_role_assignments, User.user_id == user_role_assignments.c.user_id)
        .join(Role, user_role_assignments.c.role_id == Role.role_id)
        .filter(
            User.user_id.in_(subq),
            User.user_id != user.user_id,
            User.username.ilike(f'%{query}%')
        )
        .all()
    )
    pending_friendships = [
        f.user_id2 if f.user_id1 == user.user_id else f.user_id1
        for f in Friendship.query.filter(
            ((Friendship.user_id1 == user.user_id) | (Friendship.user_id2 == user.user_id)),
            Friendship.status == 'pending'
        ).all()
    ]
    # Return minimal user info as JSON
    return jsonify([
        {
            'user_id': u.user_id,
            'username': u.username,
            'profile_pic_url': u.profile_pic_url or url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp'),
            'pending': u.user_id in pending_friendships  # Add this if you want to show "Pending"
        }
        for u in users
    ])


# --- Notifications ---
@app.route('/Notifications')
@user_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.user_id).order_by(Notification.created_at.desc()).all()
    # Group notifications by type
    grouped = {
        'like': [],
        'comment': [],
        'friend_request': [],
        'event_reminder': [],
        'message': [],
        'report_status': [],
        'admin_override': []
    }
    for n in notifications:
        grouped[n.type].append(n)

    friend_request_notifs = (
        db.session.query(Notification, User)
        .join(Friendship, Notification.source_id == Friendship.friendship_id)
        .join(User, User.user_id == Friendship.action_user_id)
        .filter(
            Notification.user_id == current_user.user_id,
            Notification.type == 'friend_request'
        )
        .order_by(Notification.created_at.desc())
        .all()
    )
    form = FriendRequestForm()
    return render_template('notifications.html',
            form=form,
            grouped=grouped,
            friend_request_notifs=friend_request_notifs,
            message_notifs=grouped['message'],
            like_notifs=grouped['like'],
            comment_notifs=grouped['comment'],
            event_reminder_notifs=grouped['event_reminder'],
            report_status_notifs=grouped['report_status'],
            admin_override_notifs=grouped['admin_override']
        )


# -- Friends Management --
@app.route('/send_friend_request/<int:target_user_id>', methods=['POST'])
@user_required
def send_friend_request(target_user_id):
    form = FriendRequestForm()
    if form.validate_on_submit():
        # Always store user_id1 < user_id2 to avoid duplicates
        user1, user2 = sorted([current_user.user_id, target_user_id])
        # Check if a friendship already exists
        existing = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
        if not existing:
            new_friendship = Friendship(
                user_id1=user1,
                user_id2=user2,
                status='pending',
                action_user_id=current_user.user_id
            )
            db.session.add(new_friendship)
            db.session.commit()

            notification = Notification(
                user_id=target_user_id,
                type='friend_request',
                source_id=new_friendship.friendship_id,
                message=f"{current_user.username} sent you a friend request."

            )
            db.session.add(notification)
            db.session.commit()
            flash('Friend request sent!', 'success')
        else:
            flash('Friend request already exists.', 'info')
    else:
        return redirect(url_for('discover_friends'))
    return redirect(url_for('discover_friends'))
                
@app.route('/respond_friend_request/<int:friendship_id>/<action>', methods=['POST'])
@user_required
def respond_friend_request(friendship_id, action):
    friendship = Friendship.query.get_or_404(friendship_id)
    # Only the receiver can accept/declineMore actions
    if current_user.user_id == friendship.action_user_id:
        abort(403)
    if current_user.user_id not in [friendship.user_id1, friendship.user_id2]:
        abort(403)
    if action == 'accept':
        friendship.status = 'accepted'
    elif action == 'decline':
        friendship.status = 'blocked'
    friendship.action_user_id = current_user.user_id
    db.session.commit()
    # Optionally, mark notification as read or delete it
    notif = Notification.query.filter_by(user_id=current_user.user_id, source_id=friendship_id, type='friend_request').first()
    if notif:
        notif.is_read = True
        db.session.delete(notif)  # Remove the notification after responding
        db.session.commit()

    return redirect(url_for('notifications'))

@app.route('/cancel_friend_request/<int:target_user_id>', methods=['POST'])
@user_required
def cancel_friend_request(target_user_id):
    user1, user2 = sorted([current_user.user_id, target_user_id])
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2, status='pending').first()
    if friendship and friendship.action_user_id == current_user.user_id:
        db.session.delete(friendship)
        # Optionally, delete the notification as well:
        Notification.query.filter_by(user_id=target_user_id, source_id=friendship.friendship_id, type='friend_request').delete()
        db.session.commit()
        flash('Friend request cancelled.', 'info')
    else:
        flash('No pending friend request to cancel.', 'warning')
    return redirect(url_for('discover_friends'))

@app.route('/unfriend/<int:friendship_id>', methods=['POST'])
@user_required
def unfriend(friendship_id):
    friendship = Friendship.query.get_or_404(friendship_id)
    # Only allow if current user is part of the friendship and status is accepted
    if current_user.user_id not in [friendship.user_id1, friendship.user_id2] or friendship.status != 'accepted':
        abort(403)
    db.session.delete(friendship)
    db.session.commit()
    flash('You have unfriended this user.', 'info')

    
    return redirect(request.referrer or url_for('friends'))


# --- Messaging ---
@app.route('/messages', methods=['GET'])
@user_required
def messages():
    # Get all accepted friendships involving the current user
    friendships = Friendship.query.filter(
        ((Friendship.user_id1 == current_user.user_id) | (Friendship.user_id2 == current_user.user_id)),
        Friendship.status == 'accepted'
    ).all()

    # Get friend user IDs
    friend_ids = []
    for f in friendships:
        if f.user_id1 == current_user.user_id:
            friend_ids.append(f.user_id2)
        else:
            friend_ids.append(f.user_id1)

    # Get friend user objects
    friends = User.query.filter(User.user_id.in_(friend_ids)).all()

    my_chat_ids = [c.chat_id for c in ChatParticipant.query.filter_by(user_id=current_user.user_id).all()]
    # Build a mapping of friend_id -> chat_id
    friend_chat_ids = {}

    for friend in friends:
        chat = (db.session.query(Chat)
            .join(ChatParticipant, Chat.chat_id == ChatParticipant.chat_id)
            .filter(ChatParticipant.user_id.in_([current_user.user_id, friend.user_id]))
            .group_by(Chat.chat_id)
            .having(db.func.count(Chat.chat_id) == 2)
            .first())
        if not chat:
            #create it once if does not exist
            chat = Chat()
            db.session.add(chat)
            db.session.commit()
            db.session.add_all([
                ChatParticipant(chat_id=chat.chat_id, user_id=current_user.user_id),
                ChatParticipant(chat_id=chat.chat_id, user_id=friend.user_id)
            ])
            db.session.commit()

        friend_chat_ids[friend.user_id] = chat.chat_id

    my_chat_ids = list(friend_chat_ids.values())

    return render_template('messages.html', friends=friends, my_chat_ids=my_chat_ids, friend_chat_ids=friend_chat_ids)

@socketio.on('join_chat')
def handle_join_chat(data):
    if not current_user.is_authenticated:
        print("Anonymous user tried to join chat.")
        return  # Optionally emit an error event here
    print(f"User {current_user.user_id} joined chat {data['chat_id']}")
    chat_id = data['chat_id']
    join_room(str(chat_id))

@socketio.on('send_message')
def handle_send_message(data):
    print('[SERVER] send_message got data:', data)
    if not current_user.is_authenticated:
       print("Anonymous user tried to send a message.")
       return  # Optionally emit an error event here
    print(f"User {current_user.user_id} sent message to chat {data['chat_id']}")
    chat_id = data['chat_id']
    encrypted_message = data['message']
    sender_id = current_user.user_id

    msg = Message(chat_id=chat_id, sender_id=sender_id, message_text=encrypted_message)
    db.session.add(msg)
    db.session.commit()

    emit('receive_message', {
        'message_id': msg.message_id,
        'chat_id': chat_id,
        'sender_id': sender_id,
        'message_text': encrypted_message,
        'sent_at': msg.sent_at.strftime('%H:%M')
    }, to=str(chat_id))

@app.route('/get_chat_id/<int:friend_id>')
@user_required
def get_chat_id(friend_id):
    # Try to find existing chat
    chat = (db.session.query(Chat)
        .join(ChatParticipant, Chat.chat_id == ChatParticipant.chat_id)
        .filter(ChatParticipant.user_id.in_([current_user.user_id, friend_id]))
        .group_by(Chat.chat_id)
        .having(db.func.count(Chat.chat_id) == 2)
        .first())
    if not chat:
        # Create new chat
        chat = Chat()
        db.session.add(chat)
        db.session.commit()
        db.session.add_all([
            ChatParticipant(chat_id=chat.chat_id, user_id=current_user.user_id),
            ChatParticipant(chat_id=chat.chat_id, user_id=friend_id)
        ])
        db.session.commit()
    return jsonify({'chat_id': chat.chat_id})

@app.route('/chat_history/<int:friend_id>')
@user_required
def chat_history(friend_id):
    # Find the chat_id for these two users
    chat = Chat.query.join(ChatParticipant).filter(
        ChatParticipant.user_id.in_([current_user.user_id, friend_id])
    ).group_by(Chat.chat_id).having(db.func.count(Chat.chat_id) == 2).first()
    if not chat:
        return jsonify([])
    messages = Message.query.filter_by(chat_id=chat.chat_id).order_by(Message.sent_at).all()
    return jsonify([{
        'sender_id': m.sender_id,
        'message_text': m.message_text,
        'sent_at': m.sent_at.strftime('%H:%M')
    } for m in messages])


# --- Admin Routes ---
@app.route('/users_dashboard')
@admin_required
def manage_users():
    # Get query parameters
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id')  # Default sort by ID
    order = request.args.get('order', 'asc')  # Default order is ascending

    # Base query
    query = User.query

    # Apply filters using the separate function
    query = apply_user_filters(query, search_query)
    
    # Apply sorting using the separate function
    query = apply_user_sorting(query, sort_by, order)

    users = query.all()

    total_users = User.query.count()
    online_users = User.query.filter_by(current_status='online').count()
    offline_users = User.query.filter_by(current_status='offline').count()

    return render_template(
        'AdminManageUsers.html',
        total_users=total_users,
        online_users=online_users,
        offline_users=offline_users,
        users=users,
        sort_by=sort_by,
        order=order,
        search_query=search_query,
        form=UpdateUserStatusForm()
    )
@app.route('/manage_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def manage_user(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('manage_users'))

    form = UpdateUserStatusForm()
    if form.validate_on_submit():  # Validate the form, including the CAPTCHA
        new_status = form.status.data
        if new_status in ['offline', 'online', 'suspended', 'terminated']:
            user.current_status = new_status
            db.session.commit()
            flash(f"User {user.username}'s status updated to {new_status}.", "success")
        else:
            flash("Invalid status.", "danger")
        return redirect(url_for('manage_users'))

    return render_template('AdminChangeUserStatus.html', user=user, form=form)

@app.route('/reports_dashboard', methods=['GET'])
@admin_required
def manage_reports():
    # Get query parameters for filtering and sorting
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'submitted_at')
    order = request.args.get('order', 'desc')

    # Base query
    query = Report.query

    # Apply filters using the separate function
    query = apply_report_filters(query, search_query)

    # Apply sorting (you could move this to filters.py too)
    if sort_by == 'submitted_at':
        query = query.order_by(Report.submitted_at.asc() if order == 'asc' else Report.submitted_at.desc())
    elif sort_by == 'resolved_at':
        query = query.order_by(Report.resolved_at.asc() if order == 'asc' else Report.resolved_at.desc())
    else:  # Default sort by report ID
        query = query.order_by(Report.report_id.asc() if order == 'asc' else Report.report_id.desc())

    reports = query.all()

    # Calculate counts for each status
    open_reports = Report.query.filter_by(status='open').count()
    in_review_reports = Report.query.filter_by(status='in_review').count()
    action_taken_reports = Report.query.filter_by(status='action_taken').count()
    rejected_reports = Report.query.filter_by(status='rejected').count()

    return render_template(
        'AdminManageReports.html',
        reports=reports,
        sort_by=sort_by,
        order=order,
        search_query=search_query,
        open_reports=open_reports,
        in_review_reports=in_review_reports,
        action_taken_reports=action_taken_reports,
        rejected_reports=rejected_reports
    )


@app.route('/manage_report/<int:report_id>', methods=['GET', 'POST'])
@admin_required
def manage_report(report_id):
    report = Report.query.get(report_id)
    form = UpdateReportStatusForm()
    if not report:
        flash("Report not found.", "danger")
        return redirect(url_for('manage_reports'))

    # Fetch usernames for reporter and reported user
    reporter_username = None
    if report.reporter_id:
        reporter = User.query.get(report.reporter_id)
        reporter_username = reporter.username if reporter else "Deleted User"

    reported_user = User.query.get(report.reported_user_id)
    reported_username = reported_user.username if reported_user else "Deleted User"

    if request.method == 'POST':
        new_status = request.form.get('status')
        admin_notes = request.form.get('admin_notes')
        if new_status in ['open', 'in_review', 'action_taken', 'rejected']:
            report.status = new_status
            report.admin_notes = admin_notes
            report.resolved_at = datetime.utcnow() if new_status in ['action_taken', 'rejected'] else None
            db.session.commit()
            flash(f"Report {report.report_id} updated successfully.", "success")
        else:
            flash("Invalid status.", "danger")
        return redirect(url_for('manage_reports'))

    return render_template(
        'AdminChangeReportStatus.html',
        report=report,
        reporter_username=reporter_username,
        reported_username=reported_username,
        form=form
    )

@app.route('/manage_ModSecLogs', methods=['GET'])
@admin_required
def admin_modsec_logs():
    # Automatically refresh logs during a GET request
    log_file_path = os.path.join(os.path.dirname(__file__), "shared_logs", "modsec_audit.log")
    parsed_logs = parse_modsec_audit_log(log_file_path)

    for log in parsed_logs:
        # Check if the log already exists to avoid duplicates
        existing_log = ModSecLog.query.filter_by(
            date=log['date'],
            time=log['time'],
            source=log['source'],
            request=log['request'],
            response=log['response'],
            attack_detected=log['attack_detected']
        ).first()
        if not existing_log:
            new_log = ModSecLog(
                date=log['date'],
                time=log['time'],
                source=log['source'],
                request=log['request'],
                response=log['response'],
                attack_detected=log['attack_detected']
            )
            db.session.add(new_log)
    db.session.commit()

    # Get query parameters for filtering and sorting
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id')  # Default sort by ID
    order = request.args.get('order', 'asc')  # Default order is ascending

    # Base query
    query = ModSecLog.query

    # Apply search filters
    if search_query:
        filters = search_query.split(',')
        for filter_item in filters:
            filter_item = filter_item.strip()
            if 'id=' in filter_item:
                try:
                    log_id = int(filter_item.split('id=')[1])
                    query = query.filter(ModSecLog.id == log_id)
                except ValueError:
                    flash("Invalid ID format. ID must be a number.", "danger")
            elif 'date=' in filter_item:
                date = filter_item.split('date=')[1].strip()
                query = query.filter(ModSecLog.date.ilike(f"%{date}%"))
            elif 'time=' in filter_item:
                time = filter_item.split('time=')[1].strip()
                query = query.filter(ModSecLog.time.ilike(f"%{time}%"))
            else:
                flash("Invalid query format. Please use id=, date=, or time=.", "danger")

    # Apply sorting
    if sort_by == 'date':
        query = query.order_by(ModSecLog.date.asc() if order == 'asc' else ModSecLog.date.desc())
    elif sort_by == 'time':
        query = query.order_by(ModSecLog.time.asc() if order == 'asc' else ModSecLog.time.desc())
    else:  # Default sort by ID
        query = query.order_by(ModSecLog.id.asc() if order == 'asc' else ModSecLog.id.desc())

    # Fetch logs
    logs = query.all()

    # Fetch statistics
    total_logs = ModSecLog.query.count()
    critical_attacks = ModSecLog.query.filter(ModSecLog.attack_detected.like('%Critical%')).count()
    recent_logs = ModSecLog.query.filter(ModSecLog.date >= '2025-06-01').count()

    return render_template(
        'AdminManageModSecLogs.html',
        logs=logs,
        total_logs=total_logs,
        critical_attacks=critical_attacks,
        recent_logs=recent_logs,
        sort_by=sort_by,
        order=order,
        search_query=search_query
    )

@app.route('/manage_ErrorLogs', methods=['GET'])
@admin_required
def admin_error_logs():
    # Automatically refresh logs during a GET request
    log_file_path = os.path.join(os.path.dirname(__file__), "shared_logs", "error.log")
    parsed_logs = parse_error_log(log_file_path)

    for log in parsed_logs:
        # Check if the log already exists to avoid duplicates
        existing_log = ErrorLog.query.filter_by(
            date=log['date'],
            time=log['time'],
            level=log['level'],
            message=log['message'],
            client_ip=log['client_ip']
        ).first()
        if not existing_log:
            new_log = ErrorLog(
                date=log['date'],
                time=log['time'],
                level=log['level'],
                message=log['message'],
                client_ip=log['client_ip']
            )
            db.session.add(new_log)
    db.session.commit()

    # Get query parameters for filtering and sorting
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id')  # Default sort by ID
    order = request.args.get('order', 'asc')  # Default order is ascending

    # Base query
    query = ErrorLog.query

    # Apply search filters
    if search_query:
        filters = search_query.split(',')
        for filter_item in filters:
            filter_item = filter_item.strip()
            if 'id=' in filter_item:
                try:
                    log_id = int(filter_item.split('id=')[1])
                    query = query.filter(ErrorLog.id == log_id)
                except ValueError:
                    flash("Invalid ID format. ID must be a number.", "danger")
            elif 'date=' in filter_item:
                date = filter_item.split('date=')[1].strip()
                query = query.filter(ErrorLog.date.ilike(f"%{date}%"))
            elif 'time=' in filter_item:
                time = filter_item.split('time=')[1].strip()
                query = query.filter(ErrorLog.time.ilike(f"%{time}%"))
            else:
                flash("Invalid query format. Please use id=, date=, or time=.", "danger")

    # Apply sorting
    if sort_by == 'date':
        query = query.order_by(ErrorLog.date.asc() if order == 'asc' else ErrorLog.date.desc())
    elif sort_by == 'time':
        query = query.order_by(ErrorLog.time.asc() if order == 'asc' else ErrorLog.time.desc())
    else:  # Default sort by ID
        query = query.order_by(ErrorLog.id.asc() if order == 'asc' else ErrorLog.id.desc())

    # Fetch logs
    logs = query.all()

    # Fetch statistics
    total_logs = ErrorLog.query.count()
    error_logs = ErrorLog.query.filter(ErrorLog.level == 'error').count()
    warning_logs = ErrorLog.query.filter(ErrorLog.level == 'warning').count()

    return render_template(
        'AdminManageErrorLogs.html',
        logs=logs,
        total_logs=total_logs,
        error_logs=error_logs,
        warning_logs=warning_logs,
        sort_by=sort_by,
        order=order,
        search_query=search_query
    )

@app.route('/manage_UserActions', methods=['GET'])
@admin_required
def admin_user_actions():
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id')
    order = request.args.get('order', 'asc')

    query = UserLog.query

    # Apply filters using the separate function
    query = apply_user_log_filters(query, search_query)

    # Apply sorting
    if sort_by == 'log_timestamp':
        query = query.order_by(UserLog.log_timestamp.asc() if order == 'asc' else UserLog.log_timestamp.desc())
    else:  # Default sort by ID
        query = query.order_by(UserLog.log_id.asc() if order == 'asc' else UserLog.log_id.desc())

    logs = query.all()
    total_logs = UserLog.query.count()
    login_attempts = UserLog.query.filter(UserLog.log_type == 'login_attempt').count()
    login_successes = UserLog.query.filter(UserLog.log_type == 'login_success').count()
    login_failures = UserLog.query.filter(UserLog.log_type == 'login_failure').count()

    return render_template(
        'AdminManageUserActions.html',
        logs=logs,
        total_logs=total_logs,
        login_attempts=login_attempts,
        login_successes=login_successes,
        login_failures=login_failures,
        sort_by=sort_by,
        order=order,
        search_query=search_query
    )

# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404_error.html'), 404

@app.errorhandler(403)
def forbidden_error(error): 
    return render_template('403_error.html'), 403


@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500_error.html'), 500

def send_event_reminders():
    tomorrow = datetime.utcnow().date() + timedelta(days=1)
    start = datetime.combine(tomorrow, datetime.min.time())
    end = datetime.combine(tomorrow, datetime.max.time())
    events = Event.query.filter(Event.event_datetime >= start, Event.event_datetime <= end).all()
    for event in events:
        # Check if notification already sent
        notif_exists = Notification.query.filter_by(
            user_id=event.user_id,
            type='event_reminder',
            source_id=event.event_id,
            message=f"Reminder: '{event.title}' is happening tomorrow!"
        ).first()
        if not notif_exists:
            notif = Notification(
                user_id=event.user_id,
                type='event_reminder',
                source_id=event.event_id,
                message=f"Reminder: '{event.title}' is happening tomorrow!"
            )
            db.session.add(notif)
    db.session.commit()

# Start the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=send_event_reminders, trigger="interval", hours=24)
scheduler.start()

@app.route('/events_dashboard', methods=['GET', 'POST'])
@user_required
def events_dashboard():
    # TO CHANGE:
    #  - currently it is retrieving Events created by the user ( first query ) however the second query will practically do the same thing.
    #  - add new table called 'event_participants' to store user_id and event_id
    #  - add way to access 'create_event.html' 
    #  - remove flash() 
    # Events created by the user #Changed EventSignup to Event
    created_events = Event.query.filter_by(user_id=current_user.user_id).order_by(Event.event_datetime.desc()).all()
    # Events the user signed up for #Changed EventSignup to Event
    signedup_event_ids = [signup.event_id for signup in Event.query.filter_by(user_id=current_user.user_id).all()]
    signedup_events = Event.query.filter(Event.event_id.in_(signedup_event_ids)).order_by(Event.event_datetime.desc()).all()
    return render_template('events_dashboard.html', created_events=created_events, signedup_events=signedup_events)

@app.route('/delete_event/<int:event_id>', methods=['POST'])
@user_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id) #Changed EventSignup to Event
    if event.user_id != current_user.user_id:
        abort(403)
    # Notify all users who signed up for this event
    signups = Event.query.filter_by(event_id=event_id).all()
    for signup in signups:
        notif = Notification(
            user_id=signup.user_id,
            type='event_cancelled',
            source_id=event_id,
            message=f"The event '{event.title}' you signed up for has been cancelled."
        )
        db.session.add(notif)
        db.session.delete(signup)  # Optionally remove their signup record
    db.session.delete(event)
    db.session.commit()
    flash('Event deleted and attendees notified.', 'success')
    return redirect(url_for('events_dashboard'))

@app.route('/leave_event/<int:event_id>', methods=['POST'])
@user_required
def leave_event(event_id):
    signup = Event.query.filter_by(event_id=event_id, user_id=current_user.user_id).first() #Changed EventSignup to Event
    if not signup:
        abort(404)
    db.session.delete(signup)
    db.session.commit()
    flash('You have left the event.', 'success')
    return redirect(url_for('events_dashboard'))

@app.route('/event_signup/<int:event_id>', methods=['GET', 'POST'])
@user_required
def event_signup(event_id):
    form = EventForm()  # Changed this to EventForm
    event = Event.query.get_or_404(event_id) #Changed EventSignup to Event
    if form.validate_on_submit(): 
        signup = Event(user_id=current_user.user_id, event_id=event_id) #Changed EventSignup to Event
        db.session.add(signup)
        db.session.commit()
        flash('Signed up for event!', 'success')
        return redirect(url_for('events_dashboard'))
    return render_template('event_signup.html', event=event, form=form)

# --- Run the App ---
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
    # When running directly, ensure context is set up for db operations
    #with app.app_context():
        # IMPORTANT: DO NOT run initdb_command() here automatically in production!
        # This command should be run manually once via `flask initdb`
        # after your .sql schema has been applied.
        #pass

    #app.run(debug=True, host='0.0.0.0')

