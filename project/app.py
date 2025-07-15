from flask import Flask, render_template, redirect, url_for, flash, request, current_app, abort, jsonify,session
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, ValidationError
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import datetime, timedelta # Keep datetime for datetime.utcnow()
import re
import flask_socketio 
from flask_socketio import SocketIO, emit, join_room, leave_room, send

# antonio: forms
from forms import SignupForm,LoginForm,ReportForm,UpdateUserStatusForm,FriendRequestForm,UpdateReportStatusForm,Enable2FAForm,Disable2FAForm,RemovePassKeyForm

# No clue but seems important
from sqlalchemy.dialects.mysql import ENUM
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

#parsing stufff for logs
from parse_test import parse_modsec_audit_log,parse_error_log
import socket

# custom logs
from user_actions import log_user_login_attempt, log_user_login_success, log_user_login_failure, log_user_logout

#security stuff
import pyotp
import qrcode
from io import BytesIO
import base64
from base64 import b64encode

#web auth stuff
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
import json
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject

# --- Configuration ---
# -- Flask app configuration --
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdQNVsrAAAAAMp8AX4H_J4CwZ5OXVixltEf4RaC'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdQNVsrAAAAAMOmgh-7Tp-KAwQUQ6iIbi8_pRvM'
socketio = SocketIO(app, cors_allowed_origins="https://localhost", message_queue='redis://redis:6379', logger=True, engineio_logger=True)   

# -- Database configuration
DB_USER = os.getenv('MYSQL_USER', 'flaskuser')
DB_PASSWORD = os.getenv('MYSQL_PASSWORD', 'password')
DB_NAME = os.getenv('MYSQL_DATABASE', 'flaskdb')
DB_HOST = os.getenv('MYSQL_HOST', 'mysql')  # 'mysql' is the service name in docker-compose
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secret_key_for_dev') # Change in production!
db = SQLAlchemy(app)

# --- Initialize Extensions ---
# -- CSRF --
app.config['SECRET_KEY'] = "your-very-secret-key"  # Set a secret key for CSRF protection
csrf = CSRFProtect(app)  # Initialize CSRF protection


# -- Flask-Login --
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login if user not authenticated

# -- Return container ID to templates --
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
    """
    Decorator to restrict access to users who have ONLY the 'user' role.
    Admins and editors (or anyone with more than just 'user' role) are denied.
    """
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
    """
    Decorator to restrict access to views to users with the 'admin' role.
    Ensures user is logged in and has the 'admin' role.
    """
    @wraps(f)
    @login_required # Ensure user is logged in first
    def decorated_function(*args, **kwargs):
        if not current_user.has_role('admin'):
            flash('Access denied. You do not have administrator privileges.', 'danger')
            # Abort with 403 Forbidden status code
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# --- Models ---

# **************************************
# Association Tables (Many-to-Many Relationships)
# **************************************

user_role_assignments = db.Table('user_role_assignments',
    db.Column('user_id', db.Integer, db.ForeignKey('users.user_id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.role_id'), primary_key=True),
    db.Column('assigned_at', db.DateTime, nullable=False, default=datetime.utcnow)
)

role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.role_id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.permission_id'), primary_key=True)
)


# **************************************
# 1. Users Table
# **************************************
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    phone_number = db.Column(db.String(8), unique=True, nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_pic_url = db.Column(db.String(255), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    current_status = db.Column(db.String(50), nullable=False, default='offline')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_active_at = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.String(32), nullable=True)
    # Relationships
    roles = db.relationship('Role', secondary=user_role_assignments,
                            backref=db.backref('users', lazy='dynamic'), lazy='dynamic')
    events = db.relationship('Event', backref='user', lazy=True)
    posts = db.relationship('Post', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    submitted_reports = db.relationship(
        'Report',
        primaryjoin="User.user_id == Report.reporter_id", # Explicitly join User.user_id to Report.reporter_id
        backref=db.backref('reporter_obj', lazy=True), # Use a unique backref name if needed, or let backref handle it
        lazy=True
    )

    # A User can be reported in many reports
    received_reports = db.relationship(
        'Report',
        primaryjoin="User.user_id == Report.reported_user_id", # Explicitly join User.user_id to Report.reported_user_id
        backref=db.backref('reported_user_obj', lazy=True), # Use a unique backref name if needed
        lazy=True
    )
    chat_participants = db.relationship('ChatParticipant', backref='user', lazy=True)
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    admin_actions_performed = db.relationship('AdminAction', foreign_keys='AdminAction.admin_user_id', backref='admin_user', lazy=True)
    admin_actions_targeted = db.relationship('AdminAction', foreign_keys='AdminAction.target_user_id', backref='target_user', lazy=True)
    user_logs = db.relationship('UserLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.user_id)

    def has_role(self, role_name):
        return any(role.role_name == role_name for role in self.roles)

    def has_permission(self, permission_name):
        for role in self.roles:
            if any(perm.permission_name == permission_name for perm in role.permissions):
                return True
        return False

    def __repr__(self):
        return f"<User {self.username}>"


# **************************************
# 2. Roles and Permissions
# **************************************
class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)

    permissions = db.relationship('Permission', secondary=role_permissions,
                                  backref=db.backref('roles', lazy='dynamic'), lazy='dynamic')

    def __repr__(self):
        return f"<Role {self.role_name}>"

class Permission(db.Model):
    __tablename__ = 'permissions'
    permission_id = db.Column(db.Integer, primary_key=True)
    permission_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<Permission {self.permission_name}>"


# **************************************
# 3. Events/Reminders
# **************************************
class Event(db.Model):
    __tablename__ = 'events'
    event_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    event_datetime = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(255), nullable=True)
    is_reminder = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Event {self.title}>"

# **************************************
# 4. Posts
# **************************************
class Post(db.Model):
    __tablename__ = 'posts'
    post_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    post_content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    images = db.relationship('PostImage', backref='post', lazy=True)

    def __repr__(self):
        return f"<Post {self.post_id} by User {self.user_id}>"

class PostImage(db.Model):
    __tablename__ = 'post_images'
    image_id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.post_id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    order_index = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<PostImage {self.image_url[:20]}...>"


# **************************************
# 5. Notifications
# **************************************
class Notification(db.Model):
    __tablename__ = 'notifications'
    notification_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    type = db.Column(ENUM('like', 'comment', 'friend_request', 'event_reminder', 'message', 'report_status', 'admin_override', name='notification_type'), nullable=False)
    source_id = db.Column(db.Integer, nullable=True)
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<Notification {self.notification_id} for User:{self.user_id}>"


# **************************************
# 6. Customer Service
# **************************************
class Report(db.Model):
    __tablename__ = 'reports'

    report_id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    reporter_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='SET NULL'), nullable=True)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)

    report_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='open')
    submitted_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    admin_notes = db.Column(db.Text, nullable=True)

    # Relationships:
    # Add the overlaps parameter for the 'reporter' relationship
    reporter = db.relationship('User', foreign_keys=[reporter_id],
                               overlaps="reporter_obj,submitted_reports")

    # This one already has the overlaps parameter from the previous fix
    reported_user = db.relationship('User', foreign_keys=[reported_user_id],
                                    overlaps="received_reports,reported_user_obj")

    def __repr__(self):
        return f"<Report {self.report_id} - Type: {self.report_type} - Status: {self.status}>"

    def __repr__(self):
        return f"<Report {self.report_id} - Type: {self.report_type} - Status: {self.status}>"


# **************************************
# 7. Messaging
# **************************************
class Chat(db.Model):
    __tablename__ = 'chats'
    chat_id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    participants = db.relationship('ChatParticipant', backref='chat', lazy=True)
    messages = db.relationship('Message', backref='chat', lazy=True)

    def __repr__(self):
        return f"<Chat {self.chat_id}>"

class ChatParticipant(db.Model):
    __tablename__ = 'chat_participants'
    chat_participant_id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.chat_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)

    __table_args__ = (db.UniqueConstraint('chat_id', 'user_id', name='_chat_user_uc'),)

    def __repr__(self):
        return f"<ChatParticipant Chat:{self.chat_id} User:{self.user_id}>"

class Message(db.Model):
    __tablename__ = 'messages'
    message_id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.chat_id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    message_text = db.Column(db.Text, nullable=False)
    sent_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_deleted_by_sender = db.Column(db.Boolean, nullable=False, default=False)
    is_deleted_by_receiver = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"<Message {self.message_id} in Chat:{self.chat_id} from User:{self.sender_id}>"


# **************************************
# 8. Friend System
# **************************************
class Friendship(db.Model):
    __tablename__ = 'friendships'
    friendship_id = db.Column(db.Integer, primary_key=True)
    user_id1 = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user_id2 = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    status = db.Column(ENUM('pending', 'accepted', 'blocked', name='friendship_status'), nullable=False, default='pending')
    action_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint('user_id1', 'user_id2', name='_user1_user2_uc'),)

    user1 = db.relationship('User', foreign_keys=[user_id1], backref=db.backref('friendships_as_user1', lazy='dynamic'))
    user2 = db.relationship('User', foreign_keys=[user_id2], backref=db.backref('friendships_as_user2', lazy='dynamic'))
    action_user = db.relationship('User', foreign_keys=[action_user_id], backref=db.backref('friendship_actions', lazy='dynamic'))

    def __repr__(self):
        return f"<Friendship {self.user_id1} - {self.user_id2} ({self.status})>"


# **************************************
# 9. Admin Panel
# **************************************
class AdminAction(db.Model):
    __tablename__ = 'admin_actions'
    action_id = db.Column(db.Integer, primary_key=True)
    admin_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    action_type = db.Column(db.String(100), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='SET NULL'), nullable=True)
    target_entity_type = db.Column(db.String(50), nullable=True)
    target_entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    action_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<AdminAction {self.action_type} by Admin:{self.admin_user_id}>"

class UserLog(db.Model):
    __tablename__ = 'user_logs'
    log_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    log_type = db.Column(db.String(100), nullable=False)
    log_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

class ModSecLog(db.Model): #actually in use
    __tablename__ = 'ModSecLog'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(50), nullable=False)
    request = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    attack_detected = db.Column(db.Text, nullable=False)

class ErrorLog(db.Model):
    __tablename__ = 'ErrorLog'

    id = db.Column(db.Integer, primary_key=True)  # Unique identifier for each log entry
    date = db.Column(db.String(20), nullable=False)  # Date of the log (e.g., 2025/06/01)
    time = db.Column(db.String(20), nullable=False)  # Time of the log (e.g., 12:40:46)
    level = db.Column(db.Enum('notice', 'error', 'warning', 'critical'), nullable=False)  # Log level (e.g., notice, error)
    message = db.Column(db.Text, nullable=False)  # Log message (e.g., limiting requests, excess: 3.295 by zone "api_limit")
    client_ip = db.Column(db.String(50), nullable=False)  # Client IP address (e.g., 172.18.0.1)

    def __repr__(self):
        return f"<ErrorLog id={self.id} date={self.date} time={self.time} level={self.level} client_ip={self.client_ip}>"
    

# -- Webauth credentials -- 
class WebAuthnCredential(db.Model):
    __tablename__ = 'webauthn_credentials'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    credential_id = db.Column(db.String(255), nullable=False, unique=True)
    public_key = db.Column(db.Text, nullable=False)
    sign_count = db.Column(db.Integer, nullable=False)
    nickname = db.Column(db.String(100))
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='webauthn_credentials')

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- RBAC Decorators ---
def role_required(role_name):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.has_role(role_name):
                flash(f'You do not have the required role: {role_name}.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(permission_name):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            if not current_user.has_permission(permission_name):
                flash(f'You do not have the required permission: {permission_name}.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# -- Fido2 WebAuthn Server Setup --
def get_fido2_server():
    from flask import request
    rp_id = request.host.split(':')[0]
    rp_name = "SimpleBook"
    rp = PublicKeyCredentialRpEntity(rp_id, rp_name)
    return Fido2Server(rp)
def b64encode_all(obj):
    import base64
    if isinstance(obj, dict):
        return {k: b64encode_all(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [b64encode_all(i) for i in obj]
    elif isinstance(obj, bytes):
        return base64.b64encode(obj).decode('utf-8')
    else:
        return obj
# --- Routes ---
# index = home


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
                    # Optionally, log attempts for non-existent users (not recommended for privacy)
                    flash('Invalid username or password.', 'danger')
    return render_template('UserLogin.html', form=form)

@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        # --- NEW: Update user status on logout ---
        current_user.current_status = 'offline'
        db.session.commit()
    # --- NEW: Log user logout action ---
    log_user_logout(current_user.user_id, details="User logged out.")
    # --- END NEW ---
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
            
        )
        db.session.add(new_user)
        db.session.commit()

        default_role = Role.query.filter_by(role_name='user').first()
        if default_role:
            new_user.roles.append(default_role)
            new_user.current_status = 'online'
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        else:
            return redirect(url_for('login'))

    return render_template('UserSignup.html', form=form)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pending_2fa_user_id' not in session:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['pending_2fa_user_id'])
    if not user or not user.totp_secret:
        flash('Invalid session or 2FA not enabled.', 'danger')
        return redirect(url_for('login'))

    form = Enable2FAForm()  # Reuse your 2FA form
    if form.validate_on_submit():
        code = form.totp_code.data
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code):
            login_user(user)
            session.pop('pending_2fa_user_id', None)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid 2FA code.', 'danger')
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
    if current_user.totp_secret:
        flash('2FA is already enabled.', 'info')
        return redirect(url_for('account_security'))

    # Only generate a new secret if not already in session
    if 'pending_totp_secret' not in session:
        session['pending_totp_secret'] = pyotp.random_base32()
    totp_secret = session['pending_totp_secret']

    otp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
        name=current_user.username, issuer_name="YourApp"
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
            flash('2FA enabled successfully!', 'success')
            return redirect(url_for('account_security'))
        else:
            flash('Invalid code. Please try again.', 'danger')

    return render_template('UserEnable2FA.html', qr_b64=qr_b64, secret=totp_secret, form=form)

@app.route('/disable_2fa', methods=['POST'])
@user_required
def disable_2fa():
    form = Disable2FAForm()
    if form.validate_on_submit():
        current_user.totp_secret = None
        db.session.commit()
        flash('2FA has been disabled.', 'info')
        return redirect(url_for('account_security'))
    # If not valid or GET (shouldn't happen for POST-only), re-render the page
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
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 400

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
            flash('Your report has been submitted successfully. Thank you for helping us keep the community safe!', 'success')
            # Redirect to the profile of the user who was reported, or a confirmation page
            return redirect(url_for('report_confirmation', reported_username=reported_user.username))
        except IntegrityError as e:
            db.session.rollback()
            current_app.logger.error(f"IntegrityError submitting report: {e}", exc_info=True)
            flash('Could not submit report due to a data conflict.', 'danger')
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Database error submitting report: {e}", exc_info=True)
            flash('An unexpected database error occurred. Please try again later.', 'danger')
        except Exception as e:
            db.session.rollback() # Rollback in case of any unhandled exception during DB ops
            current_app.logger.error(f"Unhandled exception submitting report: {e}", exc_info=True)
            flash('An unknown error occurred while submitting your report. Please try again.', 'danger')

    # For GET request or if validation fails, render the form
    return render_template('UserReport.html', form=form)

@app.route('/report_confirmation')
@user_required
def report_confirmation():
    # You can get the reported_username from the query parameters if passed
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
@admin_required # Protect this route with the admin_required decorator
def manage_users():
    # Get query parameters
    
    search_query = request.args.get('search', '').strip()
    sort_by = request.args.get('sort_by', 'id')  # Default sort by ID
    order = request.args.get('order', 'asc')  # Default order is ascending

    # Base query
    query = User.query

    # Apply search filters with enhanced validation
    if search_query:
        filters = search_query.split(',')
        for filter_item in filters:
            filter_item = filter_item.strip()  # Remove extra spaces
            filter_item = re.sub(r'[^\w=]', '', filter_item)  # Remove special characters except '='

            if 'id=' in filter_item:
                try:
                    user_id = int(filter_item.split('id=')[1])
                    query = query.filter(User.user_id == user_id)
                except ValueError:
                    flash("Invalid ID format. ID must be a number.", "danger")
            elif 'username=' in filter_item:
                username = filter_item.split('username=')[1].strip()
                if re.match(r'^[a-zA-Z0-9_]+$', username):  # Allow alphanumeric and underscores
                    query = query.filter(User.username.ilike(f"%{username}%"))
                else:
                    flash("Invalid username format. Username must be alphanumeric.", "danger")
            elif 'phone=' in filter_item:
                phone = filter_item.split('phone=')[1].strip()
                if re.match(r'^\d+$', phone):  # Ensure phone contains only digits
                    query = query.filter(User.phone_number.ilike(f"%{phone}%"))
                else:
                    flash("Invalid phone format. Phone must contain only digits.", "danger")
            elif 'status=' in filter_item:
                status = filter_item.split('status=')[1].strip().lower()
                if status in ['online', 'offline']:  # Ensure status is valid
                    query = query.filter(User.current_status.ilike(f"%{status}%"))
                else:
                    flash("Invalid status format. Status must be 'online' or 'offline'.", "danger")
            else:
                flash("Invalid query format. Please use id=, username=, phone=, or status=.", "danger")

    # Apply sorting
    if sort_by == 'username':
        query = query.order_by(User.username.asc() if order == 'asc' else User.username.desc())
    elif sort_by == 'registration_date':
        query = query.order_by(User.created_at.asc() if order == 'asc' else User.created_at.desc())
    else:  # Default sort by ID
        query = query.order_by(User.user_id.asc() if order == 'asc' else User.user_id.desc())

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
    sort_by = request.args.get('sort_by', 'submitted_at')  # Default sort by submission date
    order = request.args.get('order', 'desc')  # Default order is descending

    # Base query
    query = Report.query

    # Apply search filters
    if search_query:
        filters = search_query.split(',')
        for filter_item in filters:
            filter_item = filter_item.strip()
            if 'report_id=' in filter_item:
                try:
                    report_id = int(filter_item.split('report_id=')[1])
                    query = query.filter(Report.report_id == report_id)
                except ValueError:
                    flash("Invalid report ID format. ID must be a number.", "danger")
            elif 'status=' in filter_item:
                status = filter_item.split('status=')[1].strip().lower()
                if status in ['open', 'in_review', 'action_taken', 'rejected']:
                    query = query.filter(Report.status.ilike(f"%{status}%"))
                else:
                    flash("Invalid status format. Status must be 'open', 'in_review', 'action_taken', or 'rejected'.", "danger")
            elif 'report_type=' in filter_item:
                report_type = filter_item.split('report_type=')[1].strip().lower()
                if report_type in ['spam', 'harassment', 'impersonation', 'inappropriate_content', 'fraud', 'other']:
                    query = query.filter(Report.report_type.ilike(f"%{report_type}%"))
                else:
                    flash("Invalid report type format.", "danger")
            else:
                flash("Invalid query format. Please use report_id=, status=, or report_type=.", "danger")

    # Apply sorting
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

    # Filtering
    if search_query:
        filters = search_query.split(',')
        for filter_item in filters:
            filter_item = filter_item.strip()
            if 'id=' in filter_item:
                try:
                    log_id = int(filter_item.split('id=')[1])
                    query = query.filter(UserLog.log_id == log_id)
                except ValueError:
                    flash("Invalid ID format. ID must be a number.", "danger")
            elif 'user_id=' in filter_item:
                try:
                    user_id = int(filter_item.split('user_id=')[1])
                    query = query.filter(UserLog.user_id == user_id)
                except ValueError:
                    flash("Invalid user ID format.", "danger")
            elif 'log_type=' in filter_item:
                log_type = filter_item.split('log_type=')[1].strip()
                query = query.filter(UserLog.log_type.ilike(f"%{log_type}%"))
            elif 'date=' in filter_item:
                date = filter_item.split('date=')[1].strip()
                query = query.filter(UserLog.log_timestamp.ilike(f"%{date}%"))
            else:
                flash("Invalid query format. Please use id=, user_id=, log_type=, or date=.", "danger")

    # Only allow sorting by id or log_timestamp
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

    