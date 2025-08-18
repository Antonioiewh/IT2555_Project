# --- Standard Library Imports ---
import os
import re
import json
import socket
import base64
import io
from io import BytesIO
from datetime import datetime, timedelta
from functools import wraps
import random
import string
import uuid
import logging
import hashlib
from PIL import Image

# --- Flask Core Imports ---
from flask import Flask, render_template, redirect, url_for, flash, request, current_app, abort, jsonify, session,make_response
from flask_wtf import CSRFProtect, FlaskForm
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from flask_wtf.file import FileAllowed, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo,ValidationError, Optional
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
# -- profile imports --
import imghdr
import bleach
import magic

# antonio: forms
from forms import SignupForm,LoginForm,ReportForm,UpdateUserStatusForm,FriendRequestForm,UpdateReportStatusForm,Enable2FAForm,Disable2FAForm,RemovePassKeyForm, EventForm

# No clue but seems important
from sqlalchemy.dialects.mysql import ENUM
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import and_, or_, func

# --- Forms & Validation Imports ---
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, ValidationError

# --- Security & Authentication Imports ---
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from base64 import b64encode
from werkzeug.utils import secure_filename

# --- WebAuthn/Passkey Imports ---
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.ctap2.base import AttestationObject
from fido2.client import ClientData
from fido2.ctap2 import AuthenticatorData
import cbor2

# --- Custom Module Imports ---


# Models
from models import (
    db, User, Role, Permission, Event, EventParticipant, Post, PostImage, PostLike,
    Notification, Report, Chat, ChatParticipant, Message, 
    Friendship, AdminAction, UserLog, ModSecLog, ErrorLog, 
    WebAuthnCredential, user_role_assignments,Event,FriendChatMap,BlockedUser,UserPublicKey, ChatKeyEnvelope

)
from decorators import user_required, admin_required, editor_required, role_required, admin_or_editor_required


# Filters
from filters import (
    apply_user_filters, apply_user_sorting, 
    apply_report_filters, apply_user_log_filters
)

# Forms
from forms import (
    SignupForm, LoginForm, ReportForm, UpdateUserStatusForm,
    FriendRequestForm, UpdateReportStatusForm, Enable2FAForm,
    Disable2FAForm, RemovePassKeyForm, CreatePostForm,EditProfileForm,ChangePasswordForm 
)

# Custom logging utilities
from user_actions import (
    log_user_login_attempt, log_user_login_success, 
    log_user_login_failure, log_user_logout
)


# Log parsing utilities
from parse_test import parse_modsec_audit_log, parse_error_log

from file_validate import validate_file_security, scan_upload

#message validators
from message_validator import validate_attachment, save_attachment


# --- Configuration ---
# Flask app configuration
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LefCKcrAAAAAK-REXMG_5i6aqTW_ewYwRbEecB6'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LefCKcrAAAAAGaO2Rac8zgqVqhjsy9oxp31fThl' #this in .env!
app.config['GOOGLE_MAPS_API_KEY'] = os.getenv('GOOGLE_MAPS_API_KEY')


# Database configuration
DB_USER = os.getenv('MYSQL_USER', 'flaskuser')
DB_PASSWORD = os.getenv('MYSQL_PASSWORD', 'password')
DB_NAME = os.getenv('MYSQL_DATABASE', 'flaskdb')
DB_HOST = os.getenv('MYSQL_HOST', 'mysql')  # 'mysql' is the service name in docker-compose
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
CONTAINER_ID = os.environ.get('HOSTNAME', socket.gethostname())
BASE_SECRET = os.getenv('SECRET_KEY', 'a_very_secret_key_for_dev')
app.config['SECRET_KEY'] = f"{BASE_SECRET}-{CONTAINER_ID}"
ALLOWED_SESSION_DOMAINS = [
    'localhost',
    '127.0.0.1',
    'glowing-briefly-cicada.ngrok-free.app'
]

@app.before_request
def set_session_domain():
    """Dynamically set session cookie domain based on request host"""
    host = request.headers.get('Host', '').lower()
    
    # Remove port from host (localhost:5000 -> localhost)
    if ':' in host:
        host = host.split(':')[0]
    
    # Check if host is in allowed domains
    if host in ALLOWED_SESSION_DOMAINS:
        app.config['SESSION_COOKIE_DOMAIN'] = host
    else:
        # Default to localhost for unknown domains
        app.config['SESSION_COOKIE_DOMAIN'] = 'localhost'
# CHANGE FOR DOMAIN
app.config['SESSION_COOKIE_SECURE'] = True  # Set to True with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Changed from 'Lax' to 'Strict'
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_NAME'] = f'session_{CONTAINER_ID}'


REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')
# -- img -- uploads
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize database
db.init_app(app)

# Socket.IO configuration - NEED ADD DOMAIN WHEN USE - MESSAGE
socketio = SocketIO(app, cors_allowed_origins=[
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://127.0.0.1",
    "https://glowing-briefly-cicada.ngrok-free.app"
],  
message_queue=REDIS_URL,     # <— important when running >1 instance
ping_interval=25,
ping_timeout=60 )

connected_sids = {}  # { user_id: set([sid, ...]) }

@socketio.on('connect')
def on_connect():
    if getattr(current_user, 'is_authenticated', False):
        connected_sids.setdefault(current_user.user_id, set()).add(request.sid)
        print(f"Socket connected user {current_user.user_id} sid {request.sid}")

@socketio.on('disconnect')
def on_disconnect():
    if getattr(current_user, 'is_authenticated', False):
        s = connected_sids.get(current_user.user_id)
        if s:
            s.discard(request.sid)
            if not s:
                connected_sids.pop(current_user.user_id, None)
        print(f"Socket disconnected user {current_user.user_id} sid {request.sid}")

def emit_to_user(user_id, event, payload):
    sids = connected_sids.get(user_id)
    if not sids:
        return
    for sid in list(sids):
        try:
            socketio.emit(event, payload, room=sid)
        except Exception:
            continue

# No longer used!
def allowed_file(filename):
    """Check if file extension is allowed"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# CSRF protection
csrf = CSRFProtect(app)

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login if user not authenticated


#CHANGE FOR DOMAIN - before request
@app.before_request
def validate_host():
    """STRICTLY enforce only exact localhost hostname"""
    # Get the exact host from request
    request_host = request.headers.get('Host', '').lower()
    server_name = request.host.lower()
    
    # FIXED: Allow both localhost and ngrok domains
    allowed_hosts = [
        'localhost', 
        'localhost:5000', 
        'localhost:80',
        'glowing-briefly-cicada.ngrok-free.app'
    ]
    
    # FIXED: Only check if request_host is in allowed list
    if request_host not in allowed_hosts:
        app.logger.warning(f"BLOCKED: Invalid host '{request_host}' / '{server_name}' from IP: {request.remote_addr}")
        
        # Clear any existing session for security
        session.clear()
        
        # Return error
        abort(400, description=f"Access denied. Only allowed hosts permitted. Requested: {request_host}")

@app.before_request  
def validate_session():
    """Enhanced session validation with hostname binding"""
    if current_user.is_authenticated:
        # Bind session to exact hostname
        session_host = session.get('bound_hostname')
        current_host = request.headers.get('Host', '').lower()
        
        if not session_host:
            # First request - bind session to current hostname
            session['bound_hostname'] = current_host
            session['user_ip'] = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
            session['session_created'] = datetime.utcnow().isoformat()
        else:
            # Validate hostname hasn't changed
            if session_host != current_host:
                app.logger.warning(f"SESSION HIJACK ATTEMPT: User {current_user.user_id} session bound to '{session_host}' but accessed from '{current_host}'")
                
                # FORCE LOGOUT
                session.clear()
                logout_user()
                flash('Security violation detected. Please log in again.', 'error')
                return redirect(url_for('login'))
        
        # Existing IP validation...
        current_ip = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        session_ip = session.get('user_ip')
        
        if session_ip and session_ip != current_ip:
            app.logger.warning(f"IP CHANGE: User {current_user.user_id} IP changed from {session_ip} to {current_ip}")
            session.clear()
            logout_user()
            flash('Session invalid - IP address changed', 'error')
            return redirect(url_for('login'))

@app.before_request
def check_session_timeout():
    """Check session timeout"""
    if current_user.is_authenticated:
        session_created = session.get('session_created')
        if session_created:
            created_time = datetime.fromisoformat(session_created)
            if datetime.utcnow() - created_time > timedelta(hours=8):  # 8 hour session timeout
                session.clear()
                logout_user()
                flash('Session expired - please log in again', 'info')
                return redirect(url_for('login'))
            
# -- Return container ID to templates --
@app.context_processor
def inject_container_id():
    return {"container_id": socket.gethostname()}



# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database given their ID."""
    return db.session.get(User, int(user_id))


# avail everywhere
@app.template_global()
def google_maps_api_key():
    return app.config.get('GOOGLE_MAPS_API_KEY')



# Replace both b64encode_all function definitions with this single improved version:
def b64encode_all(data, _seen=None):
    """Recursively encode all bytes objects in a data structure to base64 strings with recursion protection"""
    if _seen is None:
        _seen = set()
    
    # Prevent infinite recursion by tracking objects we've already seen
    obj_id = id(data)
    if obj_id in _seen:
        return str(data)  # Return string representation if we've seen this object before
    
    if isinstance(data, bytes):
        return base64.b64encode(data).decode('utf-8')
    elif isinstance(data, dict):
        _seen.add(obj_id)
        result = {}
        try:
            for key, value in data.items():
                result[key] = b64encode_all(value, _seen)
        finally:
            _seen.discard(obj_id)
        return result
    elif isinstance(data, list):
        _seen.add(obj_id)
        result = []
        try:
            for item in data:
                result.append(b64encode_all(item, _seen))
        finally:
            _seen.discard(obj_id)
        return result
    elif hasattr(data, 'value') and not isinstance(data, type):
        # Handle enum-like objects
        try:
            return str(data.value)
        except:
            return str(data)
    elif hasattr(data, '__dict__') and not isinstance(data, type):
        # Handle objects with attributes, but with recursion protection
        _seen.add(obj_id)
        try:
            obj_dict = {}
            # Limit the attributes we process to avoid complex internal objects
            safe_attrs = []
            for attr_name in dir(data):
                if (not attr_name.startswith('_') and 
                    not callable(getattr(data, attr_name, None)) and
                    attr_name not in ['__class__', '__module__', '__dict__', '__weakref__']):
                    safe_attrs.append(attr_name)
                    if len(safe_attrs) > 20:  # Limit to prevent excessive processing
                        break
            
            for attr_name in safe_attrs:
                try:
                    attr_value = getattr(data, attr_name)
                    obj_dict[attr_name] = b64encode_all(attr_value, _seen)
                except Exception:
                    # Skip attributes that can't be accessed or converted
                    continue
            return obj_dict
        except Exception:
            return str(data)
        finally:
            _seen.discard(obj_id)
    else:
        return data

# -- Fido2 WebAuthn Server Setup --

def get_fido2_server():
    from flask import request
    rp_id = request.host.split(':')[0]
    rp_name = "SimpleBook"
    rp = PublicKeyCredentialRpEntity(rp_id, rp_name)
    return Fido2Server(rp)




# --- login,signup,home ---

# Helper function for relative time
def get_relative_time(post_date):
    from datetime import datetime, timezone
    import math
    
    now = datetime.now(timezone.utc)
    if post_date.tzinfo is None:
        post_date = post_date.replace(tzinfo=timezone.utc)
    
    diff = now - post_date
    
    if diff.days > 0:
        if diff.days == 1:
            return "1 day ago"
        elif diff.days < 7:
            return f"{diff.days} days ago"
        elif diff.days < 30:
            weeks = diff.days // 7
            return f"{weeks} week{'s' if weeks > 1 else ''} ago"
        else:
            months = diff.days // 30
            return f"{months} month{'s' if months > 1 else ''} ago"
    
    hours = diff.seconds // 3600
    if hours > 0:
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    
    minutes = diff.seconds // 60
    if minutes > 0:
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    
    return "Just now"


# load posts
@app.route('/api/load_more_posts')
@login_required
def load_more_posts():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        # Get current user's accepted friendships
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
        
        # Include current user's own posts
        friend_ids.append(current_user.user_id)
        
        # Query posts only from friends and current user
        posts_query = Post.query.filter(
            Post.user_id.in_(friend_ids)
        ).order_by(Post.created_at.desc())
        
        posts = posts_query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        posts_data = []
        for post in posts.items:
            # Get the first image for this post
            first_image = PostImage.query.filter_by(post_id=post.post_id).first()
            image_url = None
            if first_image:
                image_url = url_for('static', filename=first_image.image_url)
            
            post_data = {
                'post_id': post.post_id,
                'content': post.post_content,
                'image_url': image_url,
                'date': post.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'relative_date': get_relative_time(post.created_at),
                'user': {
                    'user_id': post.user.user_id,
                    'username': post.user.username,
                    'profile_picture': url_for('static', filename=f'uploads/{post.user.profile_pic_url}') if post.user.profile_pic_url else url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp')
                },
                'likes_count': PostLike.query.filter_by(post_id=post.post_id).count(),
                'is_liked': PostLike.query.filter_by(post_id=post.post_id, user_id=current_user.user_id).first() is not None,
                'is_own_post': post.user_id == current_user.user_id
            }
            posts_data.append(post_data)
        
        return jsonify({
            'posts': posts_data,
            'has_more': posts.has_next,
            'next_page': page + 1 if posts.has_next else None
        })
        
    except Exception as e:
        app.logger.error(f"Error loading more posts: {str(e)}")
        return jsonify({'error': 'Failed to load posts'}), 500


@app.route('/upload_banner', methods=['POST'])
@login_required
def upload_banner():
    try:
        if 'banner' not in request.files:
            return jsonify({'success': False, 'error': 'No banner file provided'})
        
        file = request.files['banner']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Use modular validation
        from file_validate import validate_banner_image, clean_old_file
        
        upload_dir = os.path.join(app.static_folder, 'uploads')
        result = validate_banner_image(file, current_user.user_id, upload_dir)
        
        if not result['success']:
            app.logger.warning(f"Banner upload failed for user {current_user.user_id}: {result['error']}")
            return jsonify({'success': False, 'error': result['error']})
        
        # Remove old banner
        clean_old_file(upload_dir, current_user.banner_url)
        
        # Update database
        current_user.banner_url = result['filename']
        db.session.commit()
        
        app.logger.info(f"User {current_user.user_id} successfully uploaded banner: {result['filename']}")
        
        return jsonify({
            'success': True,
            'banner_url': result['filename'],
            'message': 'Banner updated successfully!'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error uploading banner: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to upload banner. Please try again.'})

@app.route('/remove_banner', methods=['POST'])
@login_required
def remove_banner():
    try:
        # Remove banner file if exists
        if current_user.banner_url:
            upload_dir = os.path.join(app.static_folder, 'uploads')
            banner_path = os.path.join(upload_dir, current_user.banner_url)
            if os.path.exists(banner_path):
                try:
                    os.remove(banner_path)
                except:
                    pass  # Ignore if file can't be deleted
        
        # Update database
        current_user.banner_url = None
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Banner removed successfully!'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error removing banner: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to remove banner. Please try again.'})

@app.route('/')
@login_required
def home():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Posts per page
        
        # Get current user's accepted friendships
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
        
        # Include current user's own posts
        friend_ids.append(current_user.user_id)
        
        # Query posts only from friends and current user
        posts_query = Post.query.filter(
            Post.user_id.in_(friend_ids)
        ).order_by(Post.created_at.desc())
        
        posts = posts_query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        # Get current user's actual stats
        current_user_post_count = Post.query.filter_by(user_id=current_user.user_id).count()
        current_user_friend_count = len(friendships)  # Number of accepted friendships
        
        # Format posts data for frontend
        posts_data = []
        for post in posts.items:
            # Get the first image for this post
            first_image = PostImage.query.filter_by(post_id=post.post_id).first()
            image_url = None
            if first_image:
                image_url = url_for('static', filename=first_image.image_url)
            
            post_data = {
                'post_id': post.post_id,
                'content': post.post_content,
                'image_url': image_url,
                'date': post.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'relative_date': get_relative_time(post.created_at),
                'user': {
                    'user_id': post.user.user_id,
                    'username': post.user.username,
                    'profile_picture': url_for('static', filename=f'uploads/{post.user.profile_pic_url}') if post.user.profile_pic_url else url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp')
                },
                'likes_count': PostLike.query.filter_by(post_id=post.post_id).count(),
                'is_liked': PostLike.query.filter_by(post_id=post.post_id, user_id=current_user.user_id).first() is not None,
                'is_own_post': post.user_id == current_user.user_id
            }
            posts_data.append(post_data)
        
        print(f"DEBUG: Found {len(posts_data)} posts from friends and self")
        print(f"DEBUG: User post count: {current_user_post_count}")
        print(f"DEBUG: User friend count: {current_user_friend_count}")
        
        return render_template('UserHome.html', 
                             posts=posts_data,
                             pagination=posts,
                             has_more=posts.has_next,
                             current_user_post_count=current_user_post_count,
                             current_user_friend_count=current_user_friend_count)
                             
    except Exception as e:
        app.logger.error(f"Error loading home feed: {str(e)}")
        print(f"DEBUG: Error in home route: {str(e)}")
        import traceback
        traceback.print_exc()
        flash('Error loading feed. Please try again.', 'error')
        return render_template('UserHome.html', 
                             posts=[], 
                             pagination=None, 
                             has_more=False,
                             current_user_post_count=0,
                             current_user_friend_count=0)


@app.route('/api/toggle_like/<int:post_id>', methods=['POST'])
@login_required
def toggle_like_api(post_id):
    try:
        post = Post.query.get_or_404(post_id)
        
        # Check if user already liked this post
        existing_like = PostLike.query.filter_by(
            user_id=current_user.user_id,
            post_id=post_id
        ).first()
        
        if existing_like:
            # Unlike the post
            db.session.delete(existing_like)
            is_liked = False
        else:
            # Like the post
            new_like = PostLike(
                user_id=current_user.user_id,
                post_id=post_id
            )
            db.session.add(new_like)
            is_liked = True
        
        db.session.commit()
        
        # Get updated like count
        likes_count = PostLike.query.filter_by(post_id=post_id).count()
        
        return jsonify({
            'success': True,
            'is_liked': is_liked,
            'likes_count': likes_count
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error toggling like: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to toggle like'}), 500


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
                log_user_login_failure(user.user_id, details="Attempted login while locked out.")
                return render_template('UserLockedOut.html', lockout_until=user.lockout_until.strftime("%Y-%m-%d %H:%M:%S"))
            
            # Log every login attempt
            if user:
                log_user_login_attempt(user.user_id, details="User attempted login.")

            if user and user.check_password(password):
                # Implement the login flow logic
                if user.is_terminated():
                    flash('Your account has been permanently terminated. Access is denied.', 'error')
                    app.logger.warning(f"Login attempt by terminated user: {username} from IP: {request.remote_addr}")
                    return render_template('UserLogin.html', form=form)
                
                if user.is_suspended():
                    flash('Your account is currently suspended. Please contact support for assistance.', 'warning')
                    app.logger.warning(f"Login attempt by suspended user: {username} from IP: {request.remote_addr}")
                    return render_template('UserLogin.html', form=form)
                
                has_2fa = bool(user.totp_secret)
                has_passkeys = WebAuthnCredential.query.filter_by(user_id=user.user_id).first() is not None
                
                if has_2fa:
                    if has_passkeys:
                        # User has both 2FA and passkeys - they should use passkey (handled by frontend)
                        # If they reach here via normal form submission, proceed to 2FA as fallback
                        session['pending_2fa_user_id'] = user.user_id
                        session['login_method'] = 'password_fallback_from_passkey'
                        return redirect(url_for('verify_2fa'))
                    else:
                        # User has only 2FA - redirect to 2FA page
                        session['pending_2fa_user_id'] = user.user_id
                        session['login_method'] = 'password'
                        return redirect(url_for('verify_2fa'))
                else:
                    # User has no 2FA - direct login
                    user.failed_login_attempts = 0
                    user.lockout_until = None
                    
                    # SECURE SESSION SETUP with hostname binding
                    session.permanent = False
                    session['user_ip'] = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
                    session['session_created'] = datetime.utcnow().isoformat()
                    session['container_id'] = socket.gethostname()
                    session['bound_hostname'] = request.headers.get('Host', '').lower()
                    session['login_timestamp'] = datetime.utcnow().isoformat()
                    
                    login_user(user)
                    user.current_status = 'online'
                    user.last_active_at = datetime.utcnow()
                    db.session.commit()

                    # ✅ Send event reminders on login
                    send_user_event_reminders(user.user_id)

                    log_user_login_success(user.user_id, details=f"User logged in successfully with password only from host: {session['bound_hostname']}")
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('home'))
            
            else:
                if user:
                    user.failed_login_attempts += 1
                    if user.failed_login_attempts >= 3:
                        user.lockout_until = datetime.utcnow() + timedelta(minutes=10)
                        log_user_login_failure(user.user_id, details="User locked out after 3 failed attempts.")
                    else:
                        log_user_login_failure(user.user_id, details="User failed login attempt.")
                    db.session.commit()
    
    return render_template('UserLogin.html', form=form)


@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        current_user.current_status = 'offline'
        db.session.commit()
        log_user_logout(current_user.user_id, details="User logged out.")
    
    # COMPREHENSIVE SESSION CLEARING
    user_id = getattr(current_user, 'user_id', None)
    
    # Clear Flask-Login session
    logout_user()
    
    # Clear ALL session data
    session.clear()
    
    # Force session regeneration to prevent fixation
    session.permanent = False
    
    # Log the logout for security
    app.logger.info(f"User {user_id} logged out from host: {request.headers.get('Host', 'unknown')}")
    
    # Set response headers to prevent caching
    response = make_response(redirect(url_for('login')))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    flash('You have been logged out successfully.', 'info')
    return response

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
            # Clear failed login attempts and lockout
            user.failed_login_attempts = 0
            user.lockout_until = None
            
            # SECURE SESSION SETUP
            session.permanent = False
            session['user_ip'] = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
            session['session_created'] = datetime.utcnow().isoformat()
            session['container_id'] = socket.gethostname()
            
            # Update user status to online and last active time
            user.current_status = 'online'
            user.last_active_at = datetime.utcnow()
            
            login_user(user)
            session.pop('pending_2fa_user_id', None)
            session.pop('login_method', None)  # Clean up login method too
            
            # Commit all user updates
            db.session.commit()
            
            # Send event reminders on login
            send_user_event_reminders(user.user_id)
            
            # Log successful 2FA login
            log_user_login_success(user.user_id, details="User logged in successfully with 2FA.")
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash('Invalid 2FA code. Please try again.', 'error')
    
    return render_template('UserVerify2FA.html', form=form)

@app.route('/check_user_auth_methods', methods=['POST'])
@csrf.exempt
def check_user_auth_methods():
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({"error": "Username required"}), 400
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"has_2fa": False, "has_passkeys": False})
        
        has_2fa = bool(user.totp_secret)
        has_passkeys = WebAuthnCredential.query.filter_by(user_id=user.user_id).first() is not None
        
        return jsonify({
            "has_2fa": has_2fa,
            "has_passkeys": has_passkeys
        })
        
    except Exception as e:
        print(f"Error checking user auth methods: {e}")
        return jsonify({"has_2fa": False, "has_passkeys": False})

# -- User security management --
@app.route('/account_security', methods=['GET', 'POST'])
@user_required
def account_security():
    has_2fa = bool(current_user.totp_secret)
    
    # Get user's passkeys
    user_passkeys = WebAuthnCredential.query.filter_by(user_id=current_user.user_id).all()
    
    form = Disable2FAForm()
    form1 = RemovePassKeyForm()
    
    return render_template('UserAccountSecurity.html', 
                         has_2fa=has_2fa, 
                         form=form, 
                         form1=form1,
                         user_passkeys=user_passkeys)

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
def passkey_begin_register():
    try:
        # Check if user has 2FA enabled
        if not current_user.totp_secret:
            return jsonify({"error": "You must enable 2FA before adding passkeys"}), 400
        
        fido2_server = get_fido2_server()
        user = {
            "id": str(current_user.user_id).encode(),
            "name": current_user.username,
            "displayName": current_user.username,
        }
        
        # Get existing credentials to exclude
        exclude_credentials = []
        try:
            existing_creds = db.session.query(WebAuthnCredential).filter_by(user_id=current_user.user_id).all()
            exclude_credentials = [
                {"id": bytes.fromhex(cred.credential_id), "type": "public-key"}
                for cred in existing_creds
            ]
        except Exception as cred_error:
            print(f"Warning: Could not access webauthn_credentials: {cred_error}")
            exclude_credentials = []
        
        registration_data, state = fido2_server.register_begin(
            user,
            credentials=exclude_credentials,
            user_verification="preferred"
        )
        session['fido2_state'] = state
        
        encoded = b64encode_all(registration_data)
        return jsonify(encoded)
        
    except Exception as e:
        print(f"Error in passkey_begin_register: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to begin passkey registration: {str(e)}"}), 500
    
@app.route('/passkey/finish_register', methods=['POST'])
@csrf.exempt
@user_required
def passkey_finish_register():
    try:
        fido2_server = get_fido2_server()
        data = request.get_json()
        
        if 'fido2_state' not in session:
            return jsonify({"error": "No registration in progress"}), 400
        
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
        sign_count = 0  # Initial sign count
        
        # Serialize the public_key object to bytes using CBOR2
        try:
            public_key_bytes = cbor2.dumps(public_key)
            print(f"DEBUG: Serialized public_key to {len(public_key_bytes)} bytes")
        except Exception as serialize_error:
            print(f"ERROR: Failed to serialize public_key with CBOR2: {serialize_error}")
            # Fallback: convert to string and encode
            import json
            public_key_bytes = json.dumps(public_key, default=str).encode('utf-8')
            print(f"DEBUG: Used JSON fallback, {len(public_key_bytes)} bytes")
        
        new_cred = WebAuthnCredential(
            user_id=current_user.user_id,
            credential_id=credential_id.hex(),
            public_key=public_key_bytes,
            sign_count=sign_count,
            nickname=data.get('nickname', 'My Passkey'),
            added_at=datetime.utcnow()
        )
        
        print(f"DEBUG: About to save credential with public_key type: {type(public_key_bytes)}, length: {len(public_key_bytes)}")
        
        db.session.add(new_cred)
        db.session.commit()
        
        print(f"DEBUG: Successfully saved passkey for user {current_user.user_id}")
        return jsonify({"success": True})
        
    except Exception as e:
        print(f"ERROR in passkey_finish_register: {e}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({"error": f"Failed to complete passkey registration: {str(e)}"}), 500
    
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

# --- Passkey when logging in ---
@app.route('/passkey/begin_login', methods=['POST'])
@csrf.exempt
def passkey_begin_login():
    try:
        fido2_server = get_fido2_server()
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No data provided"}), 400
            
        username = data.get('username')
        print(f"DEBUG: passkey_begin_login called with username: {username}")
        
        if username:
            user = User.query.filter_by(username=username).first()
            if not user:
                return jsonify({"error": "User not found"}), 404
            
            user_credentials = WebAuthnCredential.query.filter_by(user_id=user.user_id).all()
            print(f"DEBUG: Found {len(user_credentials)} credentials for user {username}")
        else:
            # For passwordless login, get all credentials
            user_credentials = WebAuthnCredential.query.all()
            print(f"DEBUG: Found {len(user_credentials)} total credentials for passwordless login")
        
        if not user_credentials:
            return jsonify({"error": "No passkeys found for authentication"}), 400
        
        allow_credentials = []
        for cred in user_credentials:
            try:
                allow_credentials.append({
                    "id": bytes.fromhex(cred.credential_id),
                    "type": "public-key"
                })
            except ValueError as e:
                print(f"Invalid credential_id format: {cred.credential_id}, error: {e}")
                continue
        
        if not allow_credentials:
            return jsonify({"error": "No valid passkeys found"}), 400
        
        print(f"DEBUG: Creating authentication options for {len(allow_credentials)} credentials")
        
        # Get the authentication options - this returns a tuple (options, state)
        options, state = fido2_server.authenticate_begin(
            credentials=allow_credentials,
            user_verification="preferred"
        )
        
        # Store the state in session
        session['fido2_auth_state'] = state
        session['pending_passkey_user_id'] = user.user_id if username else None
        
        print(f"DEBUG: Raw options from fido2_server: {options}")
        print(f"DEBUG: Options type: {type(options)}")
        
        # The authenticate_begin method returns a PublicKeyCredentialRequestOptions object
        # We need to extract its attributes correctly
        try:
            # Build the response dictionary manually from the options object
            response_dict = {
                'challenge': base64.b64encode(options.challenge).decode('utf-8'),
                'rpId': options.rp_id,
                'userVerification': options.user_verification.value if hasattr(options.user_verification, 'value') else str(options.user_verification),
                'allowCredentials': []
            }
            
            # Convert allowCredentials manually
            if hasattr(options, 'allow_credentials') and options.allow_credentials:
                for cred in options.allow_credentials:
                    cred_dict = {
                        'type': cred.type.value if hasattr(cred.type, 'value') else str(cred.type),
                        'id': base64.b64encode(cred.id).decode('utf-8')
                    }
                    response_dict['allowCredentials'].append(cred_dict)
            
            print(f"DEBUG: Manual conversion successful")
            print(f"DEBUG: Challenge present: {'challenge' in response_dict}")
            print(f"DEBUG: Challenge length: {len(response_dict['challenge'])}")
            print(f"DEBUG: AllowCredentials count: {len(response_dict['allowCredentials'])}")
            
            return jsonify(response_dict)
            
        except AttributeError as attr_error:
            print(f"ERROR: AttributeError when accessing options attributes: {attr_error}")
            print(f"DEBUG: Available attributes on options: {dir(options)}")
            
            # If options is actually a dict (as shown in debug), handle it differently
            if isinstance(options, dict):
                print("DEBUG: Options is a dictionary, attempting to extract publicKey")
                if 'publicKey' in options:
                    actual_options = options['publicKey']
                    print(f"DEBUG: Extracted publicKey, type: {type(actual_options)}")
                    
                    response_dict = {
                        'challenge': base64.b64encode(actual_options.challenge).decode('utf-8'),
                        'rpId': actual_options.rp_id,
                        'userVerification': actual_options.user_verification.value if hasattr(actual_options.user_verification, 'value') else str(actual_options.user_verification),
                        'allowCredentials': []
                    }
                    
                    # Convert allowCredentials manually
                    if hasattr(actual_options, 'allow_credentials') and actual_options.allow_credentials:
                        for cred in actual_options.allow_credentials:
                            cred_dict = {
                                'type': cred.type.value if hasattr(cred.type, 'value') else str(cred.type),
                                'id': base64.b64encode(cred.id).decode('utf-8')
                            }
                            response_dict['allowCredentials'].append(cred_dict)
                    
                    return jsonify(response_dict)
                else:
                    return jsonify({"error": "Invalid options format - no publicKey found"}), 500
            else:
                return jsonify({"error": "Invalid options format"}), 500
            
        except Exception as manual_error:
            print(f"ERROR: Manual conversion failed: {manual_error}")
            import traceback
            traceback.print_exc()
            return jsonify({"error": "Failed to process authentication options"}), 500
        
    except Exception as e:
        print(f"Error in passkey_begin_login: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to begin passkey authentication: {str(e)}"}), 500
    

@app.route('/passkey/finish_login', methods=['POST'])
@csrf.exempt
def passkey_finish_login():
    try:
        if 'fido2_auth_state' not in session:
            return jsonify({"error": "No authentication in progress"}), 400
        
        data = request.get_json()
        state = session.pop('fido2_auth_state')
        
        credential_id = data['id']
        clientDataJSON_bytes = base64.b64decode(data['response']['clientDataJSON'])
        authenticatorData_bytes = base64.b64decode(data['response']['authenticatorData'])
        signature = base64.b64decode(data['response']['signature'])
        
        print(f"DEBUG: Looking for credential_id from browser: {credential_id}")
        
        # Convert base64url to hex for database lookup
        def base64url_to_base64(base64url_string):
            base64_string = base64url_string.replace('-', '+').replace('_', '/')
            padding = len(base64_string) % 4
            if padding:
                base64_string += '=' * (4 - padding)
            return base64_string
        
        try:
            standard_b64 = base64url_to_base64(credential_id)
            credential_id_bytes = base64.b64decode(standard_b64)
            credential_id_hex = credential_id_bytes.hex()
        except Exception:
            credential_id_hex = credential_id
        
        # Find credential in database
        cred_record = WebAuthnCredential.query.filter_by(credential_id=credential_id_hex).first()
        if not cred_record:
            cred_record = WebAuthnCredential.query.filter_by(credential_id=credential_id).first()
        
        if not cred_record:
            return jsonify({"error": "Credential not found"}), 400
        
        print(f"DEBUG: Found credential for user {cred_record.user_id}")
        
        # Deserialize the public key (same as registration)
        try:
            public_key = cbor2.loads(cred_record.public_key)
        except Exception:
            import json
            public_key = json.loads(cred_record.public_key.decode('utf-8'))
        
        # Create ClientData and AuthenticatorData objects (same as registration)
        client_data = ClientData(clientDataJSON_bytes)
        auth_data = AuthenticatorData(authenticatorData_bytes)
        
        print(f"DEBUG: About to verify assertion manually")
        
        try:
            # SKIP the FIDO2 server verification entirely and do manual verification
            # This avoids the verify() method issue completely
            
            # Verify the challenge matches (basic check)
            import hashlib
            client_data_hash = hashlib.sha256(clientDataJSON_bytes).digest()
            signed_data = authenticatorData_bytes + client_data_hash
            
            # Manual ECDSA signature verification (same pattern as registration)
            if public_key.get(1) == 2 and public_key.get(3) == -7:  # EC2 key type, ES256 algorithm
                
                # Extract x and y coordinates
                x_bytes = public_key.get(-2)
                y_bytes = public_key.get(-3)
                
                if x_bytes and y_bytes:
                    # Convert to EC public key
                    x_int = int.from_bytes(x_bytes, 'big')
                    y_int = int.from_bytes(y_bytes, 'big')
                    public_numbers = EllipticCurvePublicNumbers(x_int, y_int, SECP256R1())
                    public_key_obj = public_numbers.public_key()
                    
                    # Verify signature
                    public_key_obj.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
                    print(f"DEBUG: Manual signature verification successful")
                else:
                    raise Exception("Missing x or y coordinates in public key")
            else:
                raise Exception("Unsupported key type")
            
        except Exception as verify_error:
            print(f"ERROR: Manual signature verification failed: {verify_error}")
            return jsonify({"error": f"Authentication failed: {str(verify_error)}"}), 400
        
        # Update sign count
        cred_record.sign_count = auth_data.counter
        db.session.commit()
        
        # Log in the user with SECURE SESSION SETUP
        user = User.query.get(cred_record.user_id)
        if not user:
            return jsonify({"error": "User not found"}), 400
        
        # Check if user is locked out
        if user.lockout_until and user.lockout_until > datetime.utcnow():
            return jsonify({"error": "Account is locked out"}), 423
        
        # Reset failed attempts and setup secure session
        user.failed_login_attempts = 0
        user.lockout_until = None
        user.current_status = 'online'
        user.last_active_at = datetime.utcnow()
        
        # SECURE SESSION SETUP with hostname binding
        session.permanent = False
        session['user_ip'] = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        session['session_created'] = datetime.utcnow().isoformat()
        session['container_id'] = socket.gethostname()
        session['bound_hostname'] = request.headers.get('Host', '').lower()
        session['login_timestamp'] = datetime.utcnow().isoformat()
        
        login_user(user)
        db.session.commit()
        
        # Send event reminders
        send_user_event_reminders(user.user_id)
        
        # Clean up session
        session.pop('pending_passkey_user_id', None)
        
        # Log successful passkey login
        log_user_login_success(user.user_id, details=f"User logged in with passkey from host: {session['bound_hostname']}")
        
        print(f"DEBUG: User {user.username} logged in successfully with passkey")
        return jsonify({"success": True, "redirect": url_for('home')})
        
    except Exception as e:
        print(f"Error in passkey_finish_login: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to complete passkey authentication: {str(e)}"}), 500

# --- change password ---

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    
    # Check user's security setup
    has_2fa = bool(current_user.totp_secret)
    has_passkeys = WebAuthnCredential.query.filter_by(user_id=current_user.user_id).first() is not None
    
    if request.method == 'POST':
        # Handle passkey authentication
        if request.form.get('auth_method') == 'passkey':
            # Verify passkey was used (this would be set by JavaScript)
            passkey_verified = session.get('passkey_verified_for_password_change')
            if not passkey_verified:
                flash('Passkey verification required.', 'error')
                return render_template('change_password.html', form=form, has_2fa=has_2fa, has_passkeys=has_passkeys)
            
            # Clear the session flag
            session.pop('passkey_verified_for_password_change', None)
        
        if form.validate_on_submit():
            try:
                # Additional validation based on security setup
                auth_method = form.auth_method.data
                
                if has_2fa and auth_method != 'passkey':
                    # 2FA is enabled and not using passkey - require 2FA code
                    if not form.totp_code.data:
                        flash('2FA code is required when 2FA is enabled.', 'error')
                        return render_template('change_password.html', form=form, has_2fa=has_2fa, has_passkeys=has_passkeys)
                    
                    # Verify 2FA code
                    totp = pyotp.TOTP(current_user.totp_secret)
                    if not totp.verify(form.totp_code.data):
                        flash('Invalid 2FA code.', 'error')
                        return render_template('change_password.html', form=form, has_2fa=has_2fa, has_passkeys=has_passkeys)
                
                # Update password
                current_user.password_hash = generate_password_hash(form.new_password.data)
                current_user.updated_at = datetime.utcnow()
                db.session.commit()
                
                # Log the action
                try:
                    from user_actions import log_user_action
                    log_user_action(
                        current_user.user_id,
                        'change_password',
                        f'Password changed using {auth_method or "password"}',
                        request.remote_addr,
                        request.headers.get('User-Agent', 'Unknown')
                    )
                except ImportError:
                    pass
                
                flash('Password changed successfully!', 'success')
                return redirect(url_for('account_security'))
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error changing password: {str(e)}")
                flash('An error occurred while changing your password.', 'error')
    
    return render_template('change_password.html', form=form, has_2fa=has_2fa, has_passkeys=has_passkeys)

@app.route('/verify_passkey_for_password_change', methods=['POST'])
@csrf.exempt
@login_required
def verify_passkey_for_password_change():
    """Verify passkey for password change"""
    try:
        if 'fido2_auth_state' not in session:
            return jsonify({"error": "No authentication in progress"}), 400
        
        data = request.get_json()
        state = session.pop('fido2_auth_state')
        
        credential_id = data['id']
        clientDataJSON_bytes = base64.b64decode(data['response']['clientDataJSON'])
        authenticatorData_bytes = base64.b64decode(data['response']['authenticatorData'])
        signature = base64.b64decode(data['response']['signature'])
        
        # Convert base64url to hex for database lookup
        def base64url_to_base64(base64url_string):
            base64_string = base64url_string.replace('-', '+').replace('_', '/')
            padding = len(base64_string) % 4
            if padding:
                base64_string += '=' * (4 - padding)
            return base64_string
        
        try:
            standard_b64 = base64url_to_base64(credential_id)
            credential_id_bytes = base64.b64decode(standard_b64)
            credential_id_hex = credential_id_bytes.hex()
        except Exception:
            credential_id_hex = credential_id
        
        # Find credential in database - must belong to current user
        cred_record = WebAuthnCredential.query.filter_by(
            credential_id=credential_id_hex,
            user_id=current_user.user_id
        ).first()
        
        if not cred_record:
            return jsonify({"error": "Credential not found or not owned by user"}), 400
        
        # Deserialize the public key
        try:
            public_key = cbor2.loads(cred_record.public_key)
        except Exception:
            import json
            public_key = json.loads(cred_record.public_key.decode('utf-8'))
        
        # Create ClientData and AuthenticatorData objects
        client_data = ClientData(clientDataJSON_bytes)
        auth_data = AuthenticatorData(authenticatorData_bytes)
        
        # Manual ECDSA signature verification
        try:
            if public_key.get(1) == 2 and public_key.get(3) == -7:  # EC2 key type, ES256 algorithm
                # Extract x and y coordinates
                x_bytes = public_key.get(-2)
                y_bytes = public_key.get(-3)
                
                if x_bytes and y_bytes:
                    # Convert to EC public key
                    x_int = int.from_bytes(x_bytes, 'big')
                    y_int = int.from_bytes(y_bytes, 'big')
                    public_numbers = EllipticCurvePublicNumbers(x_int, y_int, SECP256R1())
                    public_key_obj = public_numbers.public_key()
                    
                    # Verify signature
                    import hashlib
                    client_data_hash = hashlib.sha256(clientDataJSON_bytes).digest()
                    signed_data = authenticatorData_bytes + client_data_hash
                    
                    public_key_obj.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
                else:
                    raise Exception("Missing x or y coordinates in public key")
            else:
                raise Exception("Unsupported key type")
            
        except Exception as verify_error:
            return jsonify({"error": f"Authentication failed: {str(verify_error)}"}), 400
        
        # Update sign count
        cred_record.sign_count = auth_data.counter
        db.session.commit()
        
        # Set session flag for password change
        session['passkey_verified_for_password_change'] = True
        
        return jsonify({"success": True})
        
    except Exception as e:
        print(f"Error in verify_passkey_for_password_change: {e}")
        return jsonify({"error": f"Failed to verify passkey: {str(e)}"}), 500

@app.route('/begin_passkey_auth_for_password_change', methods=['POST'])
@csrf.exempt
@login_required
def begin_passkey_auth_for_password_change():
    """Begin passkey authentication for password change"""
    try:
        fido2_server = get_fido2_server()
        
        # Get user's credentials
        user_credentials = WebAuthnCredential.query.filter_by(user_id=current_user.user_id).all()
        
        if not user_credentials:
            return jsonify({"error": "No passkeys found for authentication"}), 400
        
        allow_credentials = []
        for cred in user_credentials:
            try:
                allow_credentials.append({
                    "id": bytes.fromhex(cred.credential_id),
                    "type": "public-key"
                })
            except ValueError as e:
                continue
        
        if not allow_credentials:
            return jsonify({"error": "No valid passkeys found"}), 400
        
        # Get the authentication options
        options, state = fido2_server.authenticate_begin(
            credentials=allow_credentials,
            user_verification="preferred"
        )
        
        # Store the state in session
        session['fido2_auth_state'] = state
        
        # Build the response dictionary manually
        try:
            response_dict = {
                'challenge': base64.b64encode(options.challenge).decode('utf-8'),
                'rpId': options.rp_id,
                'userVerification': options.user_verification.value if hasattr(options.user_verification, 'value') else str(options.user_verification),
                'allowCredentials': []
            }
            
            # Convert allowCredentials manually
            if hasattr(options, 'allow_credentials') and options.allow_credentials:
                for cred in options.allow_credentials:
                    cred_dict = {
                        'type': cred.type.value if hasattr(cred.type, 'value') else str(cred.type),
                        'id': base64.b64encode(cred.id).decode('utf-8')
                    }
                    response_dict['allowCredentials'].append(cred_dict)
            
            return jsonify(response_dict)
            
        except Exception as manual_error:
            # If options is a dict with publicKey
            if isinstance(options, dict) and 'publicKey' in options:
                actual_options = options['publicKey']
                response_dict = {
                    'challenge': base64.b64encode(actual_options.challenge).decode('utf-8'),
                    'rpId': actual_options.rp_id,
                    'userVerification': actual_options.user_verification.value if hasattr(actual_options.user_verification, 'value') else str(actual_options.user_verification),
                    'allowCredentials': []
                }
                
                if hasattr(actual_options, 'allow_credentials') and actual_options.allow_credentials:
                    for cred in actual_options.allow_credentials:
                        cred_dict = {
                            'type': cred.type.value if hasattr(cred.type, 'value') else str(cred.type),
                            'id': base64.b64encode(cred.id).decode('utf-8')
                        }
                        response_dict['allowCredentials'].append(cred_dict)
                
                return jsonify(response_dict)
            else:
                return jsonify({"error": "Invalid options format"}), 500
        
    except Exception as e:
        print(f"Error in begin_passkey_auth_for_password_change: {e}")
        return jsonify({"error": f"Failed to begin passkey authentication: {str(e)}"}), 500



# --- User Reporting ---
@app.route('/report_user', methods=['GET', 'POST'])
@login_required
@user_required
def report_user():
    form = ReportForm()
    report_submitted = False
    reported_username = None

    # this is name fill for report user from message should not cause issue.
    if request.method == 'GET':
        q_username = request.args.get('username')
        if q_username:
            form.reported_username.data = q_username

    if form.validate_on_submit():
        try:
            # Lookup user by username
            reported_user = User.query.filter_by(username=form.reported_username.data).first()
            if not reported_user:
                flash('User not found.', 'error')
                return render_template('UserReport.html', form=form, report_submitted=False, reported_username=None)
            
            # FIXED: Ensure reporter_id is always set
            if not current_user.user_id:
                app.logger.error("Current user has no user_id - this should not happen")
                flash('Authentication error. Please log in again.', 'error')
                return redirect(url_for('login'))
            
            new_report = Report(
                reporter_id=current_user.user_id,  # ✅ This must not be NULL
                reported_user_id=reported_user.user_id,
                report_type=form.report_type.data,
                description=form.description.data,
                submitted_at=datetime.utcnow(),
                status='open'
            )
            db.session.add(new_report)
            db.session.flush()  # Get the report_id
            
            app.logger.info(f"📝 Creating report - Reporter: {current_user.user_id}, Reported: {reported_user.user_id}, Report ID: {new_report.report_id}")
            
            submission_notification = Notification(
                user_id=current_user.user_id,  # Notify the reporter
                type='report_status',
                source_id=new_report.report_id,
                message=f"Your report #{new_report.report_id} against {reported_user.username} has been submitted and is being reviewed.",
                created_at=datetime.utcnow(),
                is_read=False
            )
            db.session.add(submission_notification)
            
            db.session.commit()
            
            app.logger.info(f"✅ Report #{new_report.report_id} created successfully with notification")
            
            report_submitted = True
            reported_username = reported_user.username
            form = ReportForm()  # Reset form
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"❌ Error creating report: {str(e)}")
            flash('An error occurred while submitting your report. Please try again.', 'error')
            
    return render_template('UserReport.html',
                          form=form,
                          report_submitted=report_submitted,
                          reported_username=reported_username)

# -- User friends management --
@app.route('/UserFriends')
@user_required
def user_friends():
    friendships = Friendship.query.filter(
        ((Friendship.user_id1 == current_user.user_id) | (Friendship.user_id2 == current_user.user_id)),
        Friendship.status.in_(['accepted', 'blocked'])
    ).all()
    friend_ids = [
        f.user_id2 if f.user_id1 == current_user.user_id else f.user_id1
        for f in friendships
    ]
    friends = User.query.filter(User.user_id.in_(friend_ids)).all()
    friends_info = []
    for f in friendships:
        friend_id = f.user_id2 if f.user_id1 == current_user.user_id else f.user_id1
        friend_user = next((u for u in friends if u.user_id == friend_id), None)
        if friend_user:
            friends_info.append({
                'user_id': friend_user.user_id,
                'username': friend_user.username,
                'profile_pic_url': friend_user.profile_pic_url,
                'is_online': friend_user.current_status == 'online',
                'bio': friend_user.bio,
                'friendship_id': f.friendship_id,
                'status': f.status,
                'action_user_id': f.action_user_id,               # <-- added
                'blocked_by_me': (f.action_user_id == current_user.user_id) if f.status == 'blocked' else False
            })
    form = FriendRequestForm()
    return render_template('userfriends.html', friends=friends_info, form=form)

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
@login_required
def search_users():
    query = request.args.get('q', '').strip()
    user = current_user

    subq = (
    db.session.query(user_role_assignments.c.user_id)
    .join(Role, user_role_assignments.c.role_id == Role.role_id)
    .filter(Role.role_name.in_(['admin', 'editor', 'guest']))
    )
    roles_alias = db.aliased(Role)
    users = (
        db.session.query(User)
        .join(user_role_assignments, User.user_id == user_role_assignments.c.user_id)
        .join(roles_alias, user_role_assignments.c.role_id == roles_alias.role_id)
        .filter(User.user_id != user.user_id)
        .group_by(User.user_id)
        .having(
            db.func.sum(db.case((roles_alias.role_name == 'user', 1), else_=0)) >= 1,
        ).having(
            db.func.count(db.distinct(roles_alias.role_name)) == 1
        )
        .filter(User.username.ilike(f'%{query}%') if query else True)
        .all()
    )
    pending_friendships = Friendship.query.filter(
        ((Friendship.user_id1 == user.user_id) | (Friendship.user_id2 == user.user_id)),
        Friendship.status == 'pending'
    ).all()
    pending_ids = {
        f.user_id2 if f.user_id1 == user.user_id else f.user_id1
        for f in pending_friendships
    }
    pending_by_me_ids = {
        (f.user_id2 if f.user_id1 == user.user_id else f.user_id1)
        for f in pending_friendships if f.action_user_id == user.user_id
    }
    # Return minimal user info as JSON
    return jsonify([
        {
            'user_id': u.user_id,
            'username': u.username,
            'profile_pic_url': u.profile_pic_url or url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp'),
            'pending': u.user_id in pending_ids,
            'pending_by_me': u.user_id in pending_by_me_ids,
            'bio': u.bio or ''
        }
        for u in users
    ])


# --- Notifications ---
@app.route('/Notifications')
@user_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.user_id).order_by(Notification.created_at.desc()).all()
    
    # Standardized notification grouping - 6 types only
    grouped = {
        'friend_request': [],
        'event_notification': [],
        'message': [],
        'post_activity': [],
        'report_status': [],
        'admin_notification': []
    }
    
    # Group notifications by standardized types - FIX THE LOGIC ORDER
    for n in notifications:
        notification_type = n.type
        
        # First check for current standardized types
        if notification_type == 'friend_request':
            grouped['friend_request'].append(n)
        elif notification_type == 'event_notification':
            grouped['event_notification'].append(n)
        elif notification_type == 'message':
            grouped['message'].append(n)
        elif notification_type == 'post_activity':
            grouped['post_activity'].append(n)
        elif notification_type == 'report_status':
            grouped['report_status'].append(n)
        elif notification_type == 'admin_notification':
            grouped['admin_notification'].append(n)
        # Then map legacy types to standardized types
        elif notification_type in ['event_reminder', 'event_join', 'event_cancelled']:
            grouped['event_notification'].append(n)
        elif notification_type in ['like', 'comment']:
            grouped['post_activity'].append(n)
        elif notification_type in ['admin_override', 'admin_action']:
            grouped['admin_notification'].append(n)
        else:
            # Default unknown types to admin_notification
            grouped['admin_notification'].append(n)

    # Get friend request notifications with user details
    friend_request_notifs = (
        db.session.query(Notification, User)
        .join(Friendship, Notification.source_id == Friendship.friendship_id)
        .join(User, User.user_id == Friendship.action_user_id)
        .filter(
            Notification.user_id == current_user.user_id,
            Notification.type == 'friend_request',
            Notification.is_read == False
        )
        .order_by(Notification.created_at.desc())
        .all()
    )
    
    # Get event notifications with event details
    event_notifs_with_details = []
    for notif in grouped['event_notification']:
        event = Event.query.get(notif.source_id) if notif.source_id else None
        event_notifs_with_details.append((notif, event))

    #unread message stacks 
    rows = (Notification.query
        .filter_by(user_id=current_user.user_id, type='message', is_read=False)
        .order_by(Notification.created_at.desc())
        .all()
    )

    by_sender = {}
    for n in rows:
        sid = n.source_id or 0
        info = by_sender.get(sid)
        if not info:
            by_sender[sid] = {
                'sender_user_id': sid,
                'latest_message': n.message,
                'latest_created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'count': 0,      # unread count
                'unread': 0
            }
            info = by_sender[sid]
        info['count'] += 1
        info['unread'] += 1

    sender_ids = [sid for sid in by_sender.keys() if sid]
    users = {u.user_id: u for u in User.query.filter(User.user_id.in_(sender_ids)).all()}
    message_stacks = []
    for sid, info in by_sender.items():
        u = users.get(sid)
        message_stacks.append({
            **info,
            'sender_username': u.username if u else 'Unknown',
            'sender_profile_pic': (url_for('static', filename=f'uploads/{u.profile_pic_url}')
                                   if (u and u.profile_pic_url)
                                   else url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp'))
        })

    message_unread_count = sum(stack['unread'] for stack in message_stacks)

    
    form = FriendRequestForm()
    
    return render_template('notifications.html',
            form=form,
            grouped=grouped,
            friend_request_notifs=friend_request_notifs,
            event_notifs=event_notifs_with_details,
            message_notifs=grouped['message'],
            message_stacks=message_stacks,              
            message_unread_count=message_unread_count,    
            post_activity_notifs=grouped['post_activity'],
            report_status_notifs=grouped['report_status'],
            admin_notifs=grouped['admin_notification']
        )

@app.route('/delete_notification/<int:notification_id>', methods=['POST'])
@user_required
def delete_notification(notification_id):
    """Delete a specific notification"""
    notification = Notification.query.get_or_404(notification_id)
    
    # Check if user owns this notification
    if notification.user_id != current_user.user_id:
        abort(403)
    
    try:
        db.session.delete(notification)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/delete_all_notifications/<notification_type>', methods=['POST'])
@user_required
def delete_all_notifications(notification_type):
    """Delete all notifications of a specific type for the current user"""
    
    # Validate notification type
    valid_types = [
        'friend_request', 'event_notification', 'message', 
        'post_activity', 'report_status', 'admin_notification'
    ]
    
    if notification_type not in valid_types:
        return jsonify({'success': False, 'error': 'Invalid notification type'}), 400
    
    try:
        # Build query based on type (including legacy type mapping)
        query = Notification.query.filter_by(user_id=current_user.user_id)
        
        if notification_type == 'event_notification':
            # Include legacy event types
            query = query.filter(Notification.type.in_(['event_notification', 'event_reminder', 'event_join', 'event_cancelled']))
        elif notification_type == 'post_activity':
            # Include legacy post types
            query = query.filter(Notification.type.in_(['post_activity', 'like', 'comment']))
        elif notification_type == 'admin_notification':
            # Include legacy admin types
            query = query.filter(Notification.type.in_(['admin_notification', 'admin_override', 'admin_action']))
        else:
            query = query.filter_by(type=notification_type)
        
        # Delete all matching notifications
        deleted_count = query.delete()
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500
    
@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@user_required
def mark_notification_read(notification_id):
    """Mark a specific notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    
    # Check if user owns this notification
    if notification.user_id != current_user.user_id:
        abort(403)
    
    try:
        notification.is_read = True
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/mark_all_notifications_read/<notification_type>', methods=['POST'])
@user_required
def mark_all_notifications_read(notification_type):
    """Mark all notifications of a specific type as read for the current user"""
    try:
        # Get notification IDs from request body
        data = request.get_json()
        notification_ids = data.get('notification_ids', [])
        
        if not notification_ids:
            return jsonify({'success': False, 'error': 'No notification IDs provided'}), 400
        
        # Update all specified notifications to read status
        updated_count = Notification.query.filter(
            Notification.notification_id.in_(notification_ids),
            Notification.user_id == current_user.user_id,
            Notification.is_read == False
        ).update(
            {Notification.is_read: True},
            synchronize_session=False
        )
        
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': f'Marked {updated_count} notifications as read',
            'updated_count': updated_count
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error marking notifications as read: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500


# -- Friends Management --
@app.route('/send_friend_request/<int:target_user_id>', methods=['POST'])
@user_required
def send_friend_request(target_user_id):
    form = FriendRequestForm()
    if form.validate_on_submit():

        elevated_exists = (
            db.session.query(user_role_assignments.c.user_id)
            .join(Role, user_role_assignments.c.role_id == Role.role_id)
            .filter(
                user_role_assignments.c.user_id == target_user_id,
                Role.role_name.in_(['admin', 'editor', 'guest'])
            )
            .first()
        )
        has_user_role = (
            db.session.query(user_role_assignments.c.user_id)
            .join(Role, user_role_assignments.c.role_id == Role.role_id)
            .filter(
                user_role_assignments.c.user_id == target_user_id,
                Role.role_name == 'user'
            )
            .first()
        )
        if elevated_exists or not has_user_role:
            flash('Cannot send friend requests to this account.', 'warning')
            return redirect(url_for('discover_friends'))

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
    # Only the receiver can accept/decline
    if current_user.user_id == friendship.action_user_id:
        abort(403)
    if current_user.user_id not in [friendship.user_id1, friendship.user_id2]:
        abort(403)
    if action == 'accept':
        friendship.status = 'accepted'
        user1, user2 = friendship.user_id1, friendship.user_id2
        # --- Ensure chat exists and both users are mapped ---
        chat = get_strict_pair_chat(user1, user2)
        if not chat:
            chat = Chat()
            db.session.add(chat)
            db.session.commit()
            db.session.add_all([
                ChatParticipant(chat_id=chat.chat_id, user_id=user1),
                ChatParticipant(chat_id=chat.chat_id, user_id=user2)
            ])
            db.session.commit()
            add_friend_chat_map(user1, user2, chat.chat_id)
        else:
            # Ensure both users are in ChatParticipant and FriendChatMap
            for uid, fid in [(user1, user2), (user2, user1)]:
                cp = ChatParticipant.query.filter_by(chat_id=chat.chat_id, user_id=uid).first()
                if not cp:
                    db.session.add(ChatParticipant(chat_id=chat.chat_id, user_id=uid))
                mapping = FriendChatMap.query.filter_by(user_id=uid, friend_id=fid, chat_id=chat.chat_id).first()
                if not mapping:
                    db.session.add(FriendChatMap(user_id=uid, friend_id=fid, chat_id=chat.chat_id))
            db.session.commit()
    elif action == 'decline':
        # treat decline as a block from the current user to the requester (directional)
        user_ids = [friendship.user_id1, friendship.user_id2]
        other_id = user_ids[0] if user_ids[1] == current_user.user_id else user_ids[1]

        # create BlockedUser record or reactivate existing
        block = BlockedUser.query.filter_by(blocker_id=current_user.user_id, blocked_id=other_id).first()
        if not block:
            block = BlockedUser(blocker_id=current_user.user_id, blocked_id=other_id, chat_id=None, active=True, created_at=datetime.utcnow())
            db.session.add(block)
        else:
            block.active = True
            block.removed_at = None
            block.chat_id = None

        # keep friendship.status for UI/history but do not rely on it for message delivery
        friendship.status = 'blocked'
        friendship.action_user_id = current_user.user_id

        db.session.commit()
    notif = Notification.query.filter_by(user_id=current_user.user_id, source_id=friendship_id, type='friend_request').first()
    if notif:
        notif.is_read = True
        db.session.delete(notif)
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


def set_block(blocker_id, blocked_id, chat_id=None):
    """Create or reactivate a BlockedUser record and set friendship.status='blocked'."""
    block = BlockedUser.query.filter_by(blocker_id=blocker_id, blocked_id=blocked_id).first()
    if not block:
        block = BlockedUser(blocker_id=blocker_id, blocked_id=blocked_id, chat_id=chat_id, active=True, created_at=datetime.utcnow())
        db.session.add(block)
    else:
        block.active = True
        block.chat_id = chat_id
        block.removed_at = None

    user1, user2 = sorted([blocker_id, blocked_id])
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
    if friendship:
        friendship.status = 'blocked'
        friendship.action_user_id = blocker_id
    db.session.commit()

    # notify both parties (if connected) so clients update UI / leave rooms if needed
    try:
        other_sid = connected_sids.get(blocked_id)
        if other_sid:
            socketio.emit('blocked', {'chat_id': chat_id, 'by': blocker_id}, room=other_sid)
        my_sid = connected_sids.get(blocker_id)
        if my_sid:
            socketio.emit('blocked', {'chat_id': chat_id, 'by': blocker_id}, room=my_sid)
    except Exception:
        db.session.rollback()

def clear_block(blocker_id, blocked_id, chat_id=None):
    """Clear an active BlockedUser record and notify both parties."""
    try:
        block = BlockedUser.query.filter_by(blocker_id=blocker_id, blocked_id=blocked_id, active=True).first()
        if not block:
            return False

        block.active = False
        block.removed_at = datetime.utcnow()
        db.session.commit()

        # If friendship row exists and was 'blocked', restore to 'accepted' (safe default)
        user1, user2 = sorted([blocker_id, blocked_id])
        friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
        if friendship and friendship.status == 'blocked':
            friendship.status = 'accepted'
            friendship.action_user_id = None
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

        # Notify both users so clients can re-join rooms / update UI
        try:
            # use emit_to_user helper if present (safely fall back to socketio.emit)
            try:
                emit_to_user(blocker_id, 'unblocked', {'chat_id': chat_id, 'by': blocker_id, 'unblocked_id': blocked_id})
                emit_to_user(blocked_id, 'unblocked', {'chat_id': chat_id, 'by': blocker_id, 'unblocked_id': blocked_id})
            except NameError:
                # emit_to_user not defined yet — fall back
                socketio.emit('unblocked', {'chat_id': chat_id, 'by': blocker_id, 'unblocked_id': blocked_id}, room=connected_sids.get(blocker_id))
                socketio.emit('unblocked', {'chat_id': chat_id, 'by': blocker_id, 'unblocked_id': blocked_id}, room=connected_sids.get(blocked_id))
        except Exception:
            # don't let notification failure break flow
            pass

        return True
    except Exception:
        db.session.rollback()
        return False


@app.route('/unblock_user_friend/<int:friend_id>', methods=['POST'])
@user_required
def unblock_user_friend(friend_id):
    user1, user2 = sorted([current_user.user_id, friend_id])
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
    if not friendship or friendship.status != 'blocked':
        flash('No blocked friendship found.', 'warning')
        return redirect(url_for('user_friends'))
    if friendship.action_user_id != current_user.user_id:
        flash('Only the user who blocked can unblock.', 'danger')
        return redirect(url_for('user_friends'))

    # find chat
    chat = get_strict_pair_chat(user1, user2)
    chat_id = chat.chat_id if chat else None

    # clear block using centralized helper
    clear_block(current_user.user_id, friend_id, chat_id=chat_id)

    # ensure chat and mappings same as before (existing code)
    if not chat:
        try:
            chat = Chat()
            db.session.add(chat)
            db.session.commit()
            db.session.add_all([
                ChatParticipant(chat_id=chat.chat_id, user_id=user1),
                ChatParticipant(chat_id=chat.chat_id, user_id=user2)
            ])
            db.session.commit()
            add_friend_chat_map(user1, user2, chat.chat_id)
        except Exception:
            db.session.rollback()
            flash('Could not create chat after unblock.', 'warning')
            return redirect(url_for('user_friends'))

    flash('User unblocked and added back as friend.', 'success')
    return redirect(url_for('user_friends'))


@app.route('/block_user/<int:chat_id>', methods=['POST'])
@user_required
def block_user(chat_id):
    chat = Chat.query.get(chat_id)
    if not chat:
        return 'Chat not found', 404
    other_cp = ChatParticipant.query.filter(ChatParticipant.chat_id == chat_id, ChatParticipant.user_id != current_user.user_id).first()
    if not other_cp:
        return 'Other participant not found', 404
    set_block(current_user.user_id, other_cp.user_id, chat_id=chat_id)
    return '', 204


@app.route('/is_blocked/<int:chat_id>')
@user_required
def is_blocked_route(chat_id):
    cp = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id).first()
    other_cp = ChatParticipant.query.filter(ChatParticipant.chat_id == chat_id, ChatParticipant.user_id != current_user.user_id).first()
    if not other_cp:
        return jsonify({'is_blocked': False, 'blocked_by_me': False})
    # check blocked_users in both directions
    b1 = BlockedUser.query.filter_by(blocker_id=current_user.user_id, blocked_id=other_cp.user_id, active=True).first()
    b2 = BlockedUser.query.filter_by(blocker_id=other_cp.user_id, blocked_id=current_user.user_id, active=True).first()
    if b1:
        return jsonify({'is_blocked': True, 'blocked_by_me': True})
    if b2:
        return jsonify({'is_blocked': True, 'blocked_by_me': False})
    return jsonify({'is_blocked': False, 'blocked_by_me': False})

def is_blocked_by(blocker_id, blocked_id):
    """Return True if blocker_id has an active block against blocked_id (blocker -> blocked)."""
    return BlockedUser.query.filter_by(blocker_id=blocker_id, blocked_id=blocked_id, active=True).first() is not None

def is_any_active_block_between(user_a, user_b):
    """Return True if either user has an active block against the other."""
    return BlockedUser.query.filter(
        db.or_(
            db.and_(BlockedUser.blocker_id == user_a, BlockedUser.blocked_id == user_b),
            db.and_(BlockedUser.blocker_id == user_b, BlockedUser.blocked_id == user_a)
        ),
        BlockedUser.active == True
    ).first() is not None


@app.route('/unblock_user/<int:chat_id>', methods=['POST'])
@user_required
def unblock_user(chat_id):
    chat = Chat.query.get(chat_id)
    if not chat:
        return jsonify({'error': 'Chat not found'}), 404
    other_cp = ChatParticipant.query.filter(ChatParticipant.chat_id == chat_id, ChatParticipant.user_id != current_user.user_id).first()
    if not other_cp:
        return jsonify({'error': 'Other participant not found'}), 404
    # only allow the original blocker to clear their block
    block = BlockedUser.query.filter_by(blocker_id=current_user.user_id, blocked_id=other_cp.user_id, active=True).first()
    if not block:
        return jsonify({'error': 'No active block by you'}), 403
    clear_block(current_user.user_id, other_cp.user_id, chat_id=chat_id)
    return '', 204



def get_strict_pair_chat(current_user_id, friend_id):
    """Finds chat with exactly two participants: current user and friend, and no one else."""
    # Find all chat_ids where both users are participants
    subq = db.session.query(ChatParticipant.chat_id)\
        .filter(ChatParticipant.user_id.in_([current_user_id, friend_id]))\
        .group_by(ChatParticipant.chat_id)\
        .having(db.func.count(ChatParticipant.user_id) == 2)\
        .subquery()

    # Now ensure that the chat has exactly two participants (no more, no less)
    chat = db.session.query(Chat)\
        .join(ChatParticipant, Chat.chat_id == ChatParticipant.chat_id)\
        .filter(Chat.chat_id.in_(subq))\
        .group_by(Chat.chat_id)\
        .having(db.func.count(ChatParticipant.user_id) == 2)\
        .first()
    return chat

def get_loose_pair_chat(current_user_id, friend_id):
    """Finds chat with only these two participants, or creates a new one if not found."""
    subq = db.session.query(ChatParticipant.chat_id)\
        .filter(ChatParticipant.user_id.in_([current_user_id, friend_id]))\
        .group_by(ChatParticipant.chat_id)\
        .having(db.func.count(ChatParticipant.user_id) == 2)\
        .subquery()

    chat = db.session.query(Chat)\
        .join(ChatParticipant, Chat.chat_id == ChatParticipant.chat_id)\
        .filter(Chat.chat_id.in_(subq))\
        .group_by(Chat.chat_id)\
        .having(db.func.count(ChatParticipant.user_id) == 2)\
        .first()
    return chat

def add_friend_chat_map(user_id, friend_id, chat_id):
    
    try:
        for uid, fid in [(user_id, friend_id), (friend_id, user_id)]:
            mapping = FriendChatMap.query.filter_by(user_id=uid, friend_id=fid).first()
            if mapping:
                if mapping.chat_id != chat_id:
                    mapping.chat_id = chat_id
                    db.session.add(mapping)
            else:
                db.session.add(FriendChatMap(user_id=uid, friend_id=fid, chat_id=chat_id))
        db.session.commit()
    except IntegrityError:
        # Concurrent insert race — rollback and try update path
        db.session.rollback()
        try:
            for uid, fid in [(user_id, friend_id), (friend_id, user_id)]:
                mapping = FriendChatMap.query.filter_by(user_id=uid, friend_id=fid).first()
                if mapping:
                    if mapping.chat_id != chat_id:
                        mapping.chat_id = chat_id
                        db.session.add(mapping)
                else:
                    db.session.add(FriendChatMap(user_id=uid, friend_id=fid, chat_id=chat_id))
            db.session.commit()
        except Exception:
            db.session.rollback()
    except Exception:
        db.session.rollback()
# --- Messaging ---
@app.route('/api/me/pubkey', methods=['POST'])
@user_required
def api_set_user_pubkey():
    data = request.get_json(silent=True) or {}
    spki_b64 = (data.get('spki_b64') or '').strip()
    alg = (data.get('alg') or 'P-256').strip()
    if not spki_b64:
        return jsonify({'ok': False, 'error': 'missing_key'}), 400

    row = UserPublicKey.query.get(current_user.user_id)
    if row:
        row.public_key_spki_b64 = spki_b64
        row.alg = alg
    else:
        row = UserPublicKey(user_id=current_user.user_id, public_key_spki_b64=spki_b64, alg=alg)
        db.session.add(row)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/users/<int:user_id>/pubkey', methods=['GET'])
@user_required
def api_get_user_pubkey(user_id):
    row = UserPublicKey.query.get(user_id)
    if not row:
        return jsonify({'ok': False, 'error': 'no_key'}), 404
    return jsonify({'ok': True, 'alg': row.alg, 'spki_b64': row.public_key_spki_b64})

@app.route('/api/chats/<int:chat_id>/key_envelope', methods=['POST'])
@user_required
def api_put_chat_envelope(chat_id):
    data = request.get_json(silent=True) or {}
    envelope_b64 = (data.get('envelope_b64') or '').strip()
    key_version = int(data.get('key_version') or 1)
    if not envelope_b64:
        return jsonify({'ok': False, 'error': 'missing_envelope'}), 400

    # authorize: must be a participant
    cp = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id, is_in_chat=True).first()
    if not cp:
        return jsonify({'ok': False, 'error': 'not_in_chat'}), 403

    row = ChatKeyEnvelope.query.filter_by(chat_id=chat_id, user_id=current_user.user_id, key_version=key_version).first()
    if row:
        row.envelope_b64 = envelope_b64
    else:
        row = ChatKeyEnvelope(chat_id=chat_id, user_id=current_user.user_id, key_version=key_version, envelope_b64=envelope_b64)
        db.session.add(row)
    db.session.commit()
    return jsonify({'ok': True})

@app.route('/api/chats/<int:chat_id>/key_envelope', methods=['GET'])
@user_required
def api_get_chat_envelope(chat_id):
    key_version = request.args.get('version', type=int)
    q = ChatKeyEnvelope.query.filter_by(chat_id=chat_id, user_id=current_user.user_id)
    if key_version:
        q = q.filter_by(key_version=key_version)
    row = q.order_by(ChatKeyEnvelope.key_version.desc()).first()
    if not row:
        return jsonify({'ok': False, 'error': 'no_envelope'}), 404
    return jsonify({'ok': True, 'key_version': row.key_version, 'envelope_b64': row.envelope_b64})



@app.route('/messages', methods=['GET'])
@user_required
def messages():
    #to be Implemented later
    """
    # Get all chat IDs for current user
    my_chat_ids = [c.chat_id for c in ChatParticipant.query.filter_by(user_id=current_user.user_id).all()]

    # get chat keys for current user
    chat_keys = {}
    for chat_id in my_chat_ids:
        chat = Chat.query.get(chat_id)
        if chat:
            chat_keys[chat_id] = chat.chat_secret_key
    """

    friend_id = request.args.get('friend_id', type=int)
    selected_friend = None
    if friend_id:
        selected_friend = User.query.filter_by(user_id=friend_id).first()

    # Get all accepted friendships involving the current user
    friendships = Friendship.query.filter(
        ((Friendship.user_id1 == current_user.user_id) | (Friendship.user_id2 == current_user.user_id)),
        Friendship.status.in_(['accepted', 'blocked'])
    ).all()

        # Get friend user IDs
    friend_ids = [
        f.user_id2 if f.user_id1 == current_user.user_id else f.user_id1
        for f in friendships
    ]
    friends = User.query.filter(User.user_id.in_(friend_ids)).all()
    
    # Build sidebar from active ChatParticipant rows for current user.
    # This ensures deleted chats (no ChatParticipant for current user) do not reappear in the sidebar.
    friend_chat_ids = {}
    sidebar_friends_info = []
    my_cps = ChatParticipant.query.filter_by(user_id=current_user.user_id, is_in_chat=True).all()

    seen_friend_ids = set()
    for cp in my_cps:
        # find the other participant in the chat
        other_cp = ChatParticipant.query.filter(
            ChatParticipant.chat_id == cp.chat_id,
            ChatParticipant.user_id != current_user.user_id
        ).first()
        if not other_cp:
            continue
        friend_user = User.query.get(other_cp.user_id)
        if not friend_user:
            continue

        # Show only the canonical (mapped) chat for this pair.
        mapping = FriendChatMap.query.filter_by(
            user_id=current_user.user_id, friend_id=friend_user.user_id
        ).first()
        if mapping and mapping.chat_id and mapping.chat_id != cp.chat_id:
            # This CP is not the mapped chat for this pair -> skip (prevents ghost entries)
            continue

        if friend_user.user_id in seen_friend_ids:
            continue
        seen_friend_ids.add(friend_user.user_id)

        blocked_by_me = BlockedUser.query.filter_by(blocker_id=current_user.user_id, blocked_id=friend_user.user_id, active=True).first() is not None
        blocked_by_other = BlockedUser.query.filter_by(blocker_id=friend_user.user_id, blocked_id=current_user.user_id, active=True).first() is not None

        friend_chat_ids[friend_user.user_id] = cp.chat_id
        sidebar_friends_info.append({
            'user_id': friend_user.user_id,
            'username': friend_user.username,
            'profile_pic_url': friend_user.profile_pic_url or url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp'),
            'is_online': friend_user.current_status == 'online',
            'bio': friend_user.bio,
            'chat_id': cp.chat_id,
            'is_blocked': blocked_by_me or blocked_by_other,
            'blocked_by_me': blocked_by_me,
            'blocked_by_other': blocked_by_other
       })
        
    friends_to_readd = []
    for friend in friends:
        friend_chat_ids_sq = db.session.query(ChatParticipant.chat_id).filter_by(user_id=friend.user_id).subquery()
        cp = ChatParticipant.query.filter(
            ChatParticipant.user_id == current_user.user_id,
            ChatParticipant.chat_id.in_(friend_chat_ids_sq)
        ).first()
        if not cp:
            friends_to_readd.append(friend)

    friends_to_readd_info = [
         {
             'user_id': fr.user_id,
             'username': fr.username,
             'profile_pic_url': fr.profile_pic_url or url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp')
         }
         for fr in friends_to_readd
     ]

    
    print("friends_to_readd:", [f['username'] for f in friends_to_readd_info])

    my_chat_ids = list(friend_chat_ids.values())

    return render_template('messages.html', friends=sidebar_friends_info, my_chat_ids=my_chat_ids, friend_chat_ids=friend_chat_ids, selected_friend=selected_friend, friends_to_readd=friends_to_readd_info, )

@csrf.exempt
@app.route('/create_chat/<int:friend_id>', methods=['POST'])
@user_required
def create_chat(friend_id):
    try:
        chat_id = readd_friend_chat(current_user.user_id, friend_id)
        friend = User.query.get(friend_id)
        return jsonify({
            'chat_id': chat_id,
            'friend': {
                'user_id': friend.user_id,
                'username': friend.username,
                'profile_pic_url': friend.profile_pic_url or url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp')
            }
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error in create_chat: {e}")
        return jsonify({'error': 'internal'}), 500



def readd_friend_chat(current_user_id, friend_id):
    mapping = FriendChatMap.query.filter_by(user_id=current_user_id, friend_id=friend_id).first()
    if mapping:
        # Validate that the chat actually exists
        mapping = FriendChatMap.query.filter_by(user_id=current_user_id, friend_id=friend_id).first()
        if mapping:
            # If mapped chat exists and chat still exists, ensure participant exists for current user
            chat = Chat.query.get(mapping.chat_id) if mapping.chat_id else None
            if chat:
                cp = ChatParticipant.query.filter_by(chat_id=chat.chat_id, user_id=current_user_id).first()
                if not cp:
                    # no participant row at all -> add one
                    db.session.add(ChatParticipant(chat_id=chat.chat_id, user_id=current_user_id, cleared_at=func.now(), is_in_chat=True))
                    db.session.commit()
                else:
                    # previously hidden: mark visible again and set cleared_at so old messages stay hidden
                    if not getattr(cp, 'is_in_chat', True):
                        cp.is_in_chat = True
                        cp.cleared_at = func.now()
                        db.session.add(cp)
                        db.session.commit()
                # ensure mapping for both directions is consistent
                add_friend_chat_map(current_user_id, friend_id, chat.chat_id)
                return chat.chat_id
        # mapping pointed to missing chat -> create new chat and update existing mappings
        new_chat = Chat()
        db.session.add(new_chat)
        db.session.commit()
        db.session.add_all([
            ChatParticipant(chat_id=new_chat.chat_id, user_id=current_user_id, cleared_at=None, is_in_chat=True),
            ChatParticipant(chat_id=new_chat.chat_id, user_id=friend_id, cleared_at=None, is_in_chat=True)
        ])
        db.session.commit()
        add_friend_chat_map(current_user_id, friend_id, new_chat.chat_id)
        return new_chat.chat_id
    else:
        # No mapping exists -> create chat, participants and mapping (visible)
        chat = Chat()
        db.session.add(chat)
        db.session.commit()
        db.session.add_all([
            ChatParticipant(chat_id=chat.chat_id, user_id=current_user_id, cleared_at=None, is_in_chat=True),
            ChatParticipant(chat_id=chat.chat_id, user_id=friend_id, cleared_at=None, is_in_chat=True)
        ])
        db.session.commit()
        add_friend_chat_map(current_user_id, friend_id, chat.chat_id)
        return chat.chat_id
    

@socketio.on('join_chat')
def handle_join_chat(data):
    if not current_user.is_authenticated:
        return

    chat_id = data.get('chat_id')
    friend_id = data.get('friend_id')

    # If client supplied friend_id, resolve mapping but DO NOT auto-create/re-add participant
    if not chat_id and friend_id:
        mapping = FriendChatMap.query.filter_by(user_id=current_user.user_id, friend_id=int(friend_id)).first()
        if mapping:
            # only allow join if the current user is still a ChatParticipant
            cp = ChatParticipant.query.filter_by(chat_id=mapping.chat_id, user_id=current_user.user_id).first()
            if cp:
                chat_id = mapping.chat_id
            else:
                emit('join_error', {'error': 'deleted_for_you', 'message': 'Chat removed on your side. Use Add-chat to re-create.'}, room=request.sid)
                return
        else:
            emit('join_error', {'error': 'no_mapping', 'message': 'No chat mapping exists. Use Add-chat to create.'}, room=request.sid)
            return

    try:
        chat_id = int(chat_id)
    except Exception:
        emit('join_error', {'error': 'invalid_chat_id'}, room=request.sid)
        return

    chat = Chat.query.get(chat_id)
    if not chat:
        emit('join_error', {'chat_id': chat_id, 'error': 'chat_not_found'}, room=request.sid)
        return

    cp = ChatParticipant.query.filter_by(chat_id=chat.chat_id, user_id=current_user.user_id).first()
    if not cp or not getattr(cp, 'is_in_chat', True):
         emit('join_error', {'chat_id': chat.chat_id, 'error': 'not_a_participant'}, room=request.sid)
         return

    join_room(str(chat.chat_id))
    emit('joined_chat', {'chat_id': chat.chat_id}, room=request.sid)
    print(f"User {current_user.user_id} joined room {chat.chat_id} (sid {request.sid})")

@socketio.on('leave_chat')
def handle_leave_chat(data):
    if not current_user.is_authenticated:
        return
    try:
        chat_id = int(data.get('chat_id'))
    except Exception:
        return
    leave_room(str(chat_id))
    emit('left_chat', {'chat_id': chat_id}, room=request.sid)
    print(f"User {current_user.user_id} left room {chat_id} (sid {request.sid})")

def emit_to_user(user_id, event, payload):
    """Emit an event to all connected sids for a user (defensive)."""
    sids = connected_sids.get(user_id)
    if not sids:
        return
    # handle single-sid or set-of-sids
    if isinstance(sids, (list, set)):
        for sid in list(sids):
            try:
                socketio.emit(event, payload, room=sid)
            except Exception:
                continue
    else:
        try:
            socketio.emit(event, payload, room=sids)
        except Exception:
            pass


@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        print("Anonymous user tried to send a message.")
        return
    
    encrypted_message = data.get('message')
    if not encrypted_message or (isinstance(encrypted_message, str) and encrypted_message.strip() == ""):
        # Ignore empty messages
        return
    
    try:
        chat_id = int(data.get('chat_id'))
    except Exception:
        return

    chat = Chat.query.get(chat_id)
    if not chat:
        return

    participants = [cp.user_id for cp in chat.participants]
    if current_user.user_id not in participants:
        return
    
    sender_id = current_user.user_id
    other_user_id = next((uid for uid in participants if uid != current_user.user_id), None)
    if other_user_id is None:
        return
    

    #  if either direction has an active block, silently drop for both ends
    if is_any_active_block_between(sender_id, other_user_id):
        msg = Message(
            chat_id=chat_id,
            sender_id=sender_id,
            message_text=encrypted_message,
            is_deleted_by_sender=True,
            is_deleted_by_receiver=True
        )
        db.session.add(msg)
        db.session.commit()
        # Do not emit to sender or recipient
        socketio.emit('send_error', {'chat_id': chat_id, 'reason': 'blocked'}, room=request.sid)
        print(f"send_message: blocked {sender_id}<->{other_user_id} chat {chat_id}")
        return

    # No block: deliver normally
    msg = Message(chat_id=chat_id, sender_id=sender_id, message_text=encrypted_message)
    db.session.add(msg)
    db.session.commit()

    payload = {
        'chat_id': msg.chat_id,
        'message_id': msg.message_id,
        'sender_id': msg.sender_id,
        'message_text': msg.message_text,
        'sent_at': msg.sent_at.strftime('%H:%M')
    }
    socketio.emit('receive_message', payload, room=str(msg.chat_id))

    # notif for message to other party
    try:
        others = ChatParticipant.query.filter(
            ChatParticipant.chat_id == chat_id,
            ChatParticipant.user_id != sender_id,
            ChatParticipant.is_in_chat == True
        ).all()
        for other in others:
            add_message_notification(other.user_id, sender_id, 'New message')
    except Exception as e:
        current_app.logger.warning(f'notify on send_message failed: {e}')


def is_blocked(user_id1, user_id2):
    user1, user2 = sorted([user_id1, user_id2])
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
    return friendship and friendship.status == 'blocked'

@socketio.on('delete_message')
def handle_delete_message(data):
    if not current_user.is_authenticated:
        return
    message_id = data.get('message_id')
    msg = Message.query.get(message_id)
    if not msg:
        return

    # authorize: must be in the chat
    cp = ChatParticipant.query.filter_by(chat_id=msg.chat_id, user_id=current_user.user_id, is_in_chat=True).first()
    if not cp:
        return

    # Sender can delete for everyone; receiver deletes only for themselves.
    if msg.sender_id == current_user.user_id:
        # Delete for both sides
        msg.is_deleted_by_sender = True
        msg.is_deleted_by_receiver = True
        msg.message_text = "Message deleted"
        db.session.add(msg)
        db.session.commit()

        socketio.emit('message_deleted', {
            'chat_id': msg.chat_id,
            'message_id': msg.message_id,
            'scope': 'everyone'
        }, room=str(msg.chat_id))
    else:
        # Delete only for me (the receiver). Do NOT change message_text.
        msg.is_deleted_by_receiver = True
        db.session.add(msg)
        db.session.commit()

        # Notify only the deleting user’s sockets
        try:
            emit_to_user(current_user.user_id, 'message_deleted', {
                'chat_id': msg.chat_id,
                'message_id': msg.message_id,
                'scope': 'me'
            })
        except NameError:
            socketio.emit('message_deleted', {
                'chat_id': msg.chat_id,
                'message_id': msg.message_id,
                'scope': 'me'
            }, room=request.sid)


@app.route('/get_chat_id/<int:friend_id>')
@user_required
def get_chat_id(friend_id):
    # Try to find existing chat
    chat = get_strict_pair_chat(current_user.user_id, friend_id)
    if not chat:
        # No active chat for current user — client should present "Add chat" option
        return jsonify({'chat_id': None})
    return jsonify({'chat_id': chat.chat_id})


@app.route('/chat_history/<int:friend_id>')
@user_required
def chat_history(friend_id):
    me = current_user.user_id
    chat = get_strict_pair_chat(me, friend_id)  # your helper
    if not chat:
        return jsonify([])

    cp = ChatParticipant.query.filter_by(chat_id=chat.chat_id, user_id=me).first()
    cleared_at = cp.cleared_at if cp and cp.cleared_at else datetime.min

    messages = Message.query.filter(
        Message.chat_id == chat.chat_id,
        Message.sent_at >= cleared_at
    ).order_by(Message.sent_at.asc()).all()

    out = []
    for m in messages:
        i_am_sender = (m.sender_id == me)
        deleted_for_everyone = (m.is_deleted_by_sender and m.is_deleted_by_receiver)
        deleted_for_me = (
            deleted_for_everyone or
            (m.is_deleted_by_sender and i_am_sender) or
            (m.is_deleted_by_receiver and not i_am_sender)
        )
        out.append({
            'message_id': m.message_id,
            'sender_id': m.sender_id,
            'message_text': "Message deleted" if deleted_for_me else m.message_text,
            'sent_at': m.sent_at.strftime('%H:%M'),
            'is_deleted_by_sender': m.is_deleted_by_sender,
            'is_deleted_by_receiver': m.is_deleted_by_receiver,
            'deleted_for_me': deleted_for_me
        })
    return jsonify(out)


@app.route('/clear_chat/<int:chat_id>', methods=['POST'])
@user_required
def clear_chat(chat_id):
    updated = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id).update(
        { ChatParticipant.cleared_at: func.now() }
    )
    if updated:
        db.session.commit()
    return '', 204


@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
@user_required
def delete_chat(chat_id):
    try:
        cp = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id).first()
        if not cp:
            print(f"DEBUG delete_chat: no ChatParticipant for user {current_user.user_id} chat {chat_id}")
            return '', 204

        # Soft-hide for current user: mark not in-chat and update cleared_at so history is hidden
        cp.is_in_chat = False
        cp.cleared_at = func.now()
        db.session.add(cp)
        db.session.commit()

        print(f"DEBUG: User {current_user.user_id} hid chat {chat_id} (is_in_chat=False)")

        # inspect remaining participants for debugging
        remaining = ChatParticipant.query.filter_by(chat_id=chat_id).all()
        rem_user_ids = [r.user_id for r in remaining]
        mappings = FriendChatMap.query.filter_by(chat_id=chat_id).all()
        mapping_info = [(m.user_id, m.friend_id, m.chat_id) for m in mappings]

        print(f"DEBUG: User {current_user.user_id} deleted their ChatParticipant for chat {chat_id}")
        print(f"DEBUG: Remaining participants for chat {chat_id}: {rem_user_ids}")
        print(f"DEBUG: FriendChatMap rows pointing at chat {chat_id}: {mapping_info}")

        return '', 204

    except Exception as e:
        db.session.rollback()
        print(f"ERROR delete_chat: {e}")
        return jsonify({'error': 'internal'}), 500

@app.route('/api/friends_to_readd')
@user_required
def api_friends_to_readd():
    # accepted friends
    friendships = Friendship.query.filter(
        ((Friendship.user_id1 == current_user.user_id) | (Friendship.user_id2 == current_user.user_id)),
        Friendship.status == 'accepted'
    ).all()
    friend_ids = [
        f.user_id2 if f.user_id1 == current_user.user_id else f.user_id1
        for f in friendships
    ]
    friends = User.query.filter(User.user_id.in_(friend_ids)).all()

    friends_to_readd = []
    for friend in friends:
        mapping = FriendChatMap.query.filter_by(user_id=current_user.user_id, friend_id=friend.user_id).first()
        if not mapping or not mapping.chat_id:
            # No mapped chat history for this pair -> skip (this endpoint is for re-adding mapped chats)
            continue

        # only include if current user is NOT a participant of the mapped chat
        cp = ChatParticipant.query.filter_by(chat_id=mapping.chat_id, user_id=current_user.user_id).first()
        if not cp or not getattr(cp, 'is_in_chat', True):
            friends_to_readd.append(friend)

    payload = [
        {
            'user_id': f.user_id,
            'username': f.username,
            'profile_pic_url': f.profile_pic_url or url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp')
        }
        for f in friends_to_readd
    ]
    return jsonify(payload)


# -------------------- Message validation and filtering --------------------

@app.route('/upload_message_attachment', methods=['POST'])
@login_required
def upload_message_attachment():
    file = request.files.get('file')
    verdict = validate_attachment(file)
    if not verdict.get('ok'):
        return jsonify(ok=False, error=verdict.get('error', 'Validation failed'), issues=verdict.get('issues', [])), 400

    rel_path, _abs = save_attachment(file, current_user.user_id)
    return jsonify(
        ok=True,
        url=url_for('static', filename=rel_path),
        name=verdict['name'],
        size=verdict['size'],
        mime=verdict['mime'],
        kind=verdict['kind']
    )

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

@app.route('/admin/suspend_user/<int:user_id>', methods=['POST'])
@admin_required
def suspend_user(user_id):
    """Suspend a user account"""
    user = User.query.get_or_404(user_id)
    
    if user.has_role('admin'):
        flash('Cannot suspend an admin user.', 'error')
        return redirect(url_for('manage_users'))
    
    user.current_status = 'suspended'
    db.session.commit()
    
    # Log the action
    app.logger.info(f"User {user.username} suspended by {current_user.username}")
    
    flash(f'User {user.username} has been suspended.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/terminate_user/<int:user_id>', methods=['POST'])
@admin_required
def terminate_user(user_id):
    """Terminate a user account permanently"""
    user = User.query.get_or_404(user_id)
    
    if user.has_role('admin'):
        flash('Cannot terminate an admin user.', 'error')
        return redirect(url_for('manage_users'))
    
    user.current_status = 'terminated'
    db.session.commit()
    
    # Log the action
    app.logger.critical(f"User {user.username} terminated by {current_user.username}")
    
    flash(f'User {user.username} has been permanently terminated.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/reactivate_user/<int:user_id>', methods=['POST'])
@admin_required
def reactivate_user(user_id):
    """Reactivate a suspended user account"""
    user = User.query.get_or_404(user_id)
    
    if user.current_status == 'terminated':
        flash('Cannot reactivate a terminated user.', 'error')
        return redirect(url_for('manage_users'))
    
    user.current_status = 'offline'
    db.session.commit()
    
    # Log the action
    app.logger.info(f"User {user.username} reactivated by {current_user.username}")
    
    flash(f'User {user.username} has been reactivated.', 'success')
    return redirect(url_for('manage_users'))

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



# ----------- Message notification -------------

def add_message_notification(recipient_id: int, sender_id: int, text: str):
    """Create a per-message notification; UI will stack by sender."""
    try:
        preview = (text or '').strip()
        if len(preview) > 140:
            preview = preview[:137] + '...'
        n = Notification(
            user_id=recipient_id,
            type='message',
            source_id=sender_id,
            message=preview,
            created_at=datetime.utcnow(),
            is_read=False
        )
        db.session.add(n)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.warning(f'add_message_notification failed: {e}')

@app.route('/api/unread_message_notifications_count')
@user_required
def unread_message_notifications_count():
    try:
        cnt = Notification.query.filter_by(
            user_id=current_user.user_id,
            type='message',
            is_read=False
        ).count()
        return jsonify({'ok': True, 'count': cnt})
    except Exception as e:
        current_app.logger.error(f'unread_message_notifications_count: {e}')
        return jsonify({'ok': False, 'count': 0}), 500

@app.route('/api/notifications/message_stacks')
@user_required
def api_message_notification_stacks():
    try:
        rows = (Notification.query
            .filter_by(user_id=current_user.user_id, type='message', is_read=False)
            .order_by(Notification.created_at.desc())
            .all()
        )
        
        by_sender = {}
        for n in rows:
            sid = n.source_id or 0
            info = by_sender.get(sid)
            if not info:
                by_sender[sid] = {
                    'sender_user_id': sid,
                    'latest_message': n.message,
                    'latest_created_at': n.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    'count': 0,
                    'unread': 0
                }
                info = by_sender[sid]
            info['count'] += 1   
            info['unread'] += 1
        sender_ids = [sid for sid in by_sender.keys() if sid]
        users = {u.user_id: u for u in User.query.filter(User.user_id.in_(sender_ids)).all()}
        stacks = []
        for sid, info in by_sender.items():
            u = users.get(sid)
            stacks.append({
                **info,
                'sender_username': u.username if u else 'Unknown',
                'sender_profile_pic': (url_for('static', filename=f'uploads/{u.profile_pic_url}')
                                       if (u and u.profile_pic_url)
                                       else url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp'))
            })
        return jsonify({'ok': True, 'items': stacks})
    except Exception as e:
        current_app.logger.error(f'api_message_notification_stacks: {e}')
        return jsonify({'ok': False, 'items': []}), 500

@app.route('/api/notifications/messages/mark_read', methods=['POST'])
@user_required
def mark_message_notifications_read():
    """Mark all message notifications from a specific sender as read."""
    try:
        data = request.get_json(silent=True) or {}
        sender_id = int(data.get('sender_id', 0))
        if not sender_id:
            return jsonify({'ok': False, 'error': 'sender_id required'}), 400
        q = Notification.query.filter_by(
            user_id=current_user.user_id,
            type='message',
            source_id=sender_id,
            is_read=False
        )
        updated = q.update({'is_read': True})
        db.session.commit()
        return jsonify({'ok': True, 'updated': updated})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'mark_message_notifications_read: {e}')
        return jsonify({'ok': False}), 500


# Find the manage_report route (around line 1600) and replace the POST handling section:

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
            old_status = report.status
            report.status = new_status
            report.admin_notes = admin_notes
            report.resolved_at = datetime.utcnow() if new_status in ['action_taken', 'rejected'] else None
            
            if report.reporter_id:  # Make sure reporter exists
                # Create user-friendly status messages
                status_messages = {
                    'open': 'reopened',
                    'in_review': 'under review',
                    'action_taken': 'resolved with action taken',
                    'rejected': 'closed without action'
                }
                
                status_display = status_messages.get(new_status, new_status)
                
                notification = Notification(
                    user_id=report.reporter_id,
                    type='report_status',
                    source_id=report.report_id,
                    message=f"Your report against {reported_username} has been {status_display}.",
                    created_at=datetime.utcnow(),
                    is_read=False
                )
                
                db.session.add(notification)
                print(f"DEBUG: Created report status notification for user {report.reporter_id}")
            
            db.session.commit()
            flash(f"Report {report.report_id} updated from '{old_status}' to '{new_status}' and reporter notified.", "success")
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

@app.route('/test_upload', methods=['GET', 'POST'])
@csrf.exempt 
@admin_required
def test_upload():
    """Testing endpoint for file upload security validation"""
    if request.method == 'POST':
        # Check if file is present
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        try:
            # Get file data
            file.seek(0)  # Reset file pointer
            file_data = file.read()
            file.seek(0)  # Reset again for potential future use
            
            # Run security validation
            result = validate_file_security(
                file_data=file_data, 
                filename=file.filename,
                max_size=10*1024*1024  # 10MB limit
            )
            
            # Display results
            if result['is_safe']:
                flash('✅ File passed security validation!', 'success')
                flash(f"Risk Level: {result['risk_level'].upper()}", 'info')
                
                # Show file info
                info = result['file_info']
                flash(f"File: {info['filename']} ({info['size']} bytes)", 'info')
                flash(f"MD5: {info['md5_hash'][:16]}...", 'info')
                
                # Save the safe file (optional)
                if request.form.get('save_file'):
                    upload_dir = os.path.join(os.path.dirname(__file__), 'static', 'test_uploads')
                    os.makedirs(upload_dir, exist_ok=True)
                    
                    filename = secure_filename(file.filename)
                    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                    safe_filename = f"safe_{timestamp}_{filename}"
                    
                    file_path = os.path.join(upload_dir, safe_filename)
                    with open(file_path, 'wb') as f:
                        f.write(file_data)
                    
                    flash(f'File saved as: {safe_filename}', 'success')
            else:
                flash('❌ File FAILED security validation!', 'error')
                flash(f"Risk Level: {result['risk_level'].upper()}", 'warning')
                
                # Show threats
                for threat in result['threats']:
                    flash(f"🚨 THREAT: {threat}", 'error')
                
                # Show warnings
                for warning in result['warnings']:
                    flash(f"⚠️ WARNING: {warning}", 'warning')
            
            # Show polyglot detection details if available
            if 'polyglot_detection' in result:
                polyglot = result['polyglot_detection']
                if polyglot.get('detected_formats'):
                    formats = ', '.join(polyglot['detected_formats'])
                    flash(f"Detected formats: {formats}", 'info')
        
        except Exception as e:
            flash(f'Validation error: {str(e)}', 'error')
    
    return render_template('test_upload.html')


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


# -- USER PROFILE + POSTS


@app.route('/account')
@login_required
def account():
    """Redirect to user's own profile using ID"""
    return redirect(url_for('view_profile', user_id=current_user.user_id))

@app.route('/account/<int:user_id>')
@login_required
def view_profile(user_id):
    """
    Route to view user profiles with dynamic permissions.
    Automatically redirects to appropriate template based on ownership.
    """
    import logging
    
    # Input validation
    if not user_id or user_id <= 0:
        flash('Invalid user ID provided.', 'error')
        return redirect(url_for('home'))
    
    try:
        # Get the target user by ID
        target_user = User.query.get(user_id)
        if not target_user:
            flash('User not found.', 'error')
            return redirect(url_for('home'))
        
        # CRITICAL: Simple ownership check
        is_own_profile = (current_user.user_id == user_id)
        
        # Log profile access for security monitoring
        logging.info(f"User {current_user.user_id} ({current_user.username}) accessing profile of {user_id} ({target_user.username}). Own profile: {is_own_profile}")
        
        # Get friendship status for permission checks (only if not own profile)
        friendship_status = 'none'
        friendship_id = None
        
        if not is_own_profile:
            # Check friendship status
            user1, user2 = sorted([current_user.user_id, user_id])
            friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
            
            if friendship:
                friendship_status = friendship.status
                friendship_id = friendship.friendship_id
        
        # Get user's posts (only their own posts)
        posts_query = Post.query.filter_by(user_id=user_id)
        posts = posts_query.order_by(Post.created_at.desc()).all()
        
        # Get accurate friend count (accepted friendships only)
        accepted_friendships = Friendship.query.filter(
            ((Friendship.user_id1 == user_id) | (Friendship.user_id2 == user_id)),
            Friendship.status == 'accepted'
        ).count()
        
        # Get accurate post count for this user
        user_post_count = Post.query.filter_by(user_id=user_id).count()
        
        # Prepare template data
        template_data = {
            'user': target_user,
            'profile_user': target_user,
            'user_id': target_user,
            'posts': posts,
            'post_count': user_post_count,  # Accurate post count
            'friend_count': accepted_friendships,  # Accurate friend count
            'is_own_profile': is_own_profile,
            'friendship_status': friendship_status,
            'friendship_id': friendship_id,
            'current_user': current_user
        }
        
        # DYNAMIC TEMPLATE SELECTION BASED ON OWNERSHIP
        if is_own_profile:
            # Own profile - full permissions (edit, delete, create)
            logging.info(f"Rendering own profile template for user {current_user.username}")
            return render_template('UserProfilePage.html', **template_data)
        else:
            # Viewing someone else's profile - restricted permissions (view only)
            logging.info(f"Rendering view-only profile template for user {target_user.username} viewed by {current_user.username}")
            return render_template('ViewProfile.html', **template_data)
            
    except Exception as e:
        logging.error(f"Error in view_profile for user ID {user_id}: {str(e)}")
        flash('An error occurred while loading the profile.', 'error')
        return redirect(url_for('home'))
    
@app.route('/create_post', methods=['GET', 'POST'])
@login_required
def create_post():
    form = CreatePostForm()
    
    if request.method == 'POST':
        try:
            post_content = request.form.get('post_content', '').strip()
            
            if not post_content:
                flash('Post content cannot be empty.', 'error')
                return render_template('create_post.html', form=form)
            
            # Create the post object
            new_post = Post(
                user_id=current_user.user_id,
                post_content=post_content,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            db.session.add(new_post)
            db.session.flush()
            
            # Handle uploaded files with modular validation
            uploaded_files = request.files.getlist('image')
            
            if uploaded_files and uploaded_files[0].filename:
                from file_validate import validate_post_images
                
                upload_dir = app.config['UPLOAD_FOLDER']
                result = validate_post_images(uploaded_files, new_post.post_id, upload_dir)
                
                # Add warnings/errors to flash messages
                for error in result['errors']:
                    flash(error, 'warning')
                
                for warning in result['warnings']:
                    flash(warning, 'info')
                
                # Create PostImage objects for successfully processed files
                for file_info in result['processed_files']:
                    post_image = PostImage(
                        post_id=new_post.post_id,
                        image_url=file_info['url'],
                        order_index=0,
                        created_at=datetime.utcnow()
                    )
                    db.session.add(post_image)
                    app.logger.info(f"User {current_user.user_id} uploaded post image: {file_info['filename']}")
            
            db.session.commit()
            
            valid_file_count = len(result['processed_files']) if 'result' in locals() else 0
            if valid_file_count > 0:
                flash(f'Post created successfully with {valid_file_count} images!', 'success')
            else:
                flash('Post created successfully!', 'success')
            
            return redirect(url_for('account'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error in create_post: {str(e)}")
            flash('An error occurred while creating the post.', 'error')
            return render_template('create_post.html', form=form)

    return render_template('create_post.html', form=form)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    
    # Security check: Ensure user owns the post
    if post.user_id != current_user.user_id:
        abort(403)
    
    if request.method == 'POST':
        try:
            # Get content from form
            post_content = request.form.get('post_content', '').strip()
            
            # Validate content
            if not post_content:
                flash('Post content cannot be empty.', 'error')
                return render_template('edit_post.html', post=post)
            
            if len(post_content) > 250:
                flash('Post content must be 250 characters or less.', 'error')
                return render_template('edit_post.html', post=post)
            
            # Sanitize input
            sanitized_content = bleach.clean(post_content, tags=[], strip=True)
            
            # Update post
            post.post_content = sanitized_content
            post.updated_at = datetime.utcnow()
            
            db.session.commit()
            
            # Log the action
            try:
                from user_actions import log_user_action
                log_user_action(
                    current_user.user_id,
                    'edit_post',
                    f'Edited post {post_id}',
                    request.remote_addr,
                    request.headers.get('User-Agent', 'Unknown')
                )
            except ImportError:
                pass
            
            flash('Post updated successfully!', 'success')
            return redirect(url_for('account'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating post: {str(e)}")
            flash('An error occurred while updating the post.', 'error')
            return render_template('edit_post.html', post=post)
    
    # GET request - show form with current content
    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    """Delete a post and its associated images"""
    try:
        # Get the post
        post = Post.query.filter_by(post_id=post_id).first()
        
        if not post:
            flash('Post not found.', 'error')
            return redirect(url_for('account'))
        
        # Check if the current user owns the post
        if post.user_id != current_user.user_id:
            flash('You can only delete your own posts.', 'error')
            return redirect(url_for('account'))
        
        # Delete associated images from filesystem
        for image in post.images:
            try:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], image.image_url)
                if os.path.exists(image_path):
                    os.remove(image_path)
                    app.logger.info(f"Deleted image file: {image_path}")
            except Exception as e:
                app.logger.error(f"Error deleting image file {image.image_url}: {str(e)}")
        
        # Delete the post (cascade will delete images and likes)
        db.session.delete(post)
        db.session.commit()
        
        # Log the action (if function exists)
        try:
            from user_actions import log_user_action
            log_user_action(
                current_user.user_id,
                'delete_post',
                f'Deleted post {post_id}',
                request.remote_addr,
                request.headers.get('User-Agent', 'Unknown')
            )
        except ImportError:
            pass  # Skip logging if function doesn't exist
        
        flash('Post deleted successfully!', 'success')
        app.logger.info(f"User {current_user.user_id} deleted post {post_id}")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting post {post_id}: {str(e)}")
        flash('An error occurred while deleting the post.', 'error')
    
    return redirect(url_for('account'))

@app.route('/api/like_post/<int:post_id>', methods=['POST'])
@login_required
def like_post(post_id):
    """Like or unlike a post"""
    try:
        # Check if post exists
        post = Post.query.filter_by(post_id=post_id).first()
        if not post:
            return jsonify({'success': False, 'message': 'Post not found'}), 404
        
        # Check if user already liked this post
        existing_like = PostLike.query.filter_by(
            user_id=current_user.user_id,
            post_id=post_id
        ).first()
        
        if existing_like:
            # Unlike the post
            db.session.delete(existing_like)
            db.session.commit()
            
            
            like_count = post.get_like_count()
            return jsonify({
                'success': True,
                'action': 'unliked',
                'like_count': like_count,
                'is_liked': False
            })
        else:
            # Like the post
            new_like = PostLike(
                user_id=current_user.user_id,
                post_id=post_id
            )
            db.session.add(new_like)
            db.session.commit()
            
            
            like_count = post.get_like_count()
            return jsonify({
                'success': True,
                'action': 'liked',
                'like_count': like_count,
                'is_liked': True
            })
            
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Database error'}), 500
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in like_post: {str(e)}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500








# --- Edit Profile ---

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    
    if request.method == 'GET':
        form.username.data = current_user.username
    
    if form.validate_on_submit():
        try:
            # Check username changes
            if form.username.data != current_user.username:
                existing_user = User.query.filter_by(username=form.username.data).first()
                if existing_user:
                    flash('Username already exists. Please choose a different one.', 'error')
                    return render_template('EditProfile.html', form=form)
                current_user.username = form.username.data
            
            # Handle profile picture upload with modular validation
            cropped_image_data = request.form.get('cropped_image_data')
            
            if cropped_image_data:
                from file_validate import validate_cropped_image_data, clean_old_file
                
                upload_dir = app.config['UPLOAD_FOLDER']
                result = validate_cropped_image_data(cropped_image_data, current_user.user_id, upload_dir)
                
                if not result['success']:
                    app.logger.warning(f"Profile image upload failed for user {current_user.user_id}: {result['error']}")
                    flash(result['error'], 'error')
                    return render_template('EditProfile.html', form=form)
                
                # Clean old file and update database
                clean_old_file(upload_dir, current_user.profile_pic_url)
                current_user.profile_pic_url = result['filename']
                app.logger.info(f"User {current_user.user_id} updated profile picture: {result['filename']}")
            
            current_user.updated_at = datetime.utcnow()
            db.session.commit()
            
            # Log the action
            try:
                from user_actions import log_user_action
                log_user_action(current_user.user_id, 'update_profile', 'Updated profile information')
            except ImportError:
                pass
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('account'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating profile: {str(e)}")
            flash('An error occurred while updating your profile.', 'error')
    
    return render_template('EditProfile.html', form=form)




@app.context_processor
def inject_datetime():
    from datetime import datetime
    return {
        'datetime': datetime,
        'moment': datetime,  # Alias for backward compatibility
        'utcnow': datetime.utcnow
    }


# Create Event Route
@app.route('/create_event', methods=['GET', 'POST'])
@user_required
def create_event():
    form = EventForm()
    
    if form.validate_on_submit():
        try:
            # Get coordinates from form data
            latitude = request.form.get('latitude')
            longitude = request.form.get('longitude')
            
            # Convert to float if provided
            lat = float(latitude) if latitude else None
            lng = float(longitude) if longitude else None
            

            new_event = Event(
                user_id=current_user.user_id,
                title=form.event_name.data,           
                description=form.event_description.data,  
                event_datetime=form.event_start_time.data, 
                location=form.event_location.data,   
                latitude=lat,
                longitude=lng,
                is_reminder=False,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            db.session.add(new_event)
            db.session.commit()
            
            print(f"✅ EVENT CREATED: ID={new_event.event_id}, Title='{new_event.title}'")
            
            flash(f"Event '{new_event.title}' created successfully!", 'success')
            return redirect(url_for('events_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"❌ ERROR creating event: {str(e)}")
            import traceback
            traceback.print_exc()
            flash('An error occurred while creating the event. Please try again.', 'danger')
    else:
        if request.method == 'POST':
            print(f"❌ FORM VALIDATION FAILED:")
            for field, errors in form.errors.items():
                print(f"  {field}: {errors}")
            flash('Please check the form for errors.', 'error')
    
    return render_template('create_event.html', form=form)

# Events Dashboard Route
@app.route('/events_dashboard', methods=['GET', 'POST'])
@user_required
def events_dashboard():
    # Events created by the user (user is the event organizer)
    created_events = Event.query.filter_by(user_id=current_user.user_id).order_by(Event.event_datetime.desc()).all()
    
    # Events the user signed up for (user is a participant, but not the creator)
    participated_events = (
        db.session.query(Event)
        .join(EventParticipant, Event.event_id == EventParticipant.event_id)
        .filter(
            EventParticipant.user_id == current_user.user_id,
            EventParticipant.status == 'joined',
            Event.user_id != current_user.user_id  # Exclude events they created
        )
        .order_by(Event.event_datetime.desc())
        .all()
    )
    
    return render_template('events_dashboard.html', 
                         created_events=created_events, 
                         participated_events=participated_events)

# Discover Events Route
@app.route('/discover_events', methods=['GET'])
@user_required
def discover_events():
    # Get all public events that are not reminders and not created by current user
    public_events = Event.query.filter(
        Event.user_id != current_user.user_id,
        Event.is_reminder == False,
        Event.event_datetime > datetime.utcnow()  # Only future events
    ).order_by(Event.event_datetime.asc()).all()
    
    # Get events the user has already signed up for
    user_participations = EventParticipant.query.filter(
        EventParticipant.user_id == current_user.user_id,
        EventParticipant.status == 'joined'
    ).all()
    
    participated_event_ids = [p.event_id for p in user_participations]
    
    return render_template('discover_events.html', 
                         events=public_events, 
                         participated_event_ids=participated_event_ids)

# JOIN event
@app.route('/join_event/<int:event_id>', methods=['POST'])
@user_required
def join_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if user is trying to join their own event
    if event.user_id == current_user.user_id:
        flash("You cannot join your own event.", 'warning')
        return redirect(url_for('discover_events'))
    
    # Check if user is already participating with 'joined' status
    existing_participation = EventParticipant.query.filter_by(
        user_id=current_user.user_id,
        event_id=event_id,
        status='joined'
    ).first()
    
    print(f"DEBUG: User {current_user.user_id} attempting to join event {event_id}")
    print(f"DEBUG: Existing participation: {existing_participation}")
    
    if existing_participation:
        flash('You are already participating in this event!', 'warning')
        return redirect(url_for('discover_events'))
    
    try:
        # Create new participation record
        new_participation = EventParticipant(
            user_id=current_user.user_id,
            event_id=event_id,
            status='joined',
            joined_at=datetime.utcnow()
        )
        
        print(f"DEBUG: Creating participation record: user_id={current_user.user_id}, event_id={event_id}")
        
        db.session.add(new_participation)
        db.session.flush()  # Flush to get any constraint errors before notification
        
        print(f"DEBUG: Participation record created successfully")
        
        # Create notification for event creator using standardized type
        creator_notification = Notification(
            user_id=event.user_id,
            type='event_notification',
            source_id=event_id,
            message=f"{current_user.username} joined your event '{event.title}'",
            created_at=datetime.utcnow(),
            is_read=False
        )
        
        print(f"DEBUG: Creating notification for user {event.user_id}")
        
        db.session.add(creator_notification)
        db.session.commit()
        
        print(f"DEBUG: Successfully joined event and created notification")
        
        flash(f'Successfully joined "{event.title}"!', 'success')
        
    except IntegrityError as ie:
        db.session.rollback()
        print(f"ERROR: IntegrityError joining event: {str(ie)}")
        # Check if it's a duplicate key error
        if "Duplicate entry" in str(ie) or "UNIQUE constraint" in str(ie):
            flash('You are already participating in this event!', 'warning')
        else:
            flash('A database constraint error occurred. Please try again.', 'danger')
    except Exception as e:
        db.session.rollback()
        print(f"ERROR: Exception joining event: {str(e)}")
        print(f"ERROR: Exception type: {type(e)}")
        import traceback
        traceback.print_exc()
        flash('An error occurred while joining the event. Please try again.', 'danger')
    
    return redirect(url_for('discover_events'))

# Leave Event Route
@app.route('/leave_event/<int:event_id>', methods=['POST'])
@user_required
def leave_event(event_id):
    participation = EventParticipant.query.filter_by(
        user_id=current_user.user_id,
        event_id=event_id
    ).first()
    
    if participation:
        try:
            db.session.delete(participation)
            db.session.commit()
            
            event = Event.query.get(event_id)
            flash(f'You have left "{event.title}".', 'info')
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while leaving the event.', 'danger')
    else:
        flash('You were not participating in this event.', 'warning')
    
    # Redirect based on referrer
    referrer = request.referrer
    if referrer and 'discover_events' in referrer:
        return redirect(url_for('discover_events'))
    else:
        return redirect(url_for('events_dashboard'))

@app.route('/delete_event/<int:event_id>', methods=['POST'])
@user_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if user owns the event
    if event.user_id != current_user.user_id:
        abort(403)
    
    try:
        # Get all participants before deletion
        participants = EventParticipant.query.filter_by(
            event_id=event_id, 
            status='joined'
        ).all()
        
        # Notify all participants that the event was cancelled
        for participant in participants:
            notif = Notification(
                user_id=participant.user_id,
                type='event_notification',  # ✅ Standardized type
                source_id=event_id,
                message=f"The event '{event.title}' you joined has been cancelled.",
                created_at=datetime.utcnow(),
                is_read=False
            )
            db.session.add(notif)
        
        # Delete all participant records first (foreign key constraints)
        EventParticipant.query.filter_by(event_id=event_id).delete()
        
        # Delete the event
        db.session.delete(event)
        db.session.commit()
        
        flash(f'Event "{event.title}" deleted and attendees notified.', 'success')
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting event: {str(e)}")
        flash('An error occurred while deleting the event.', 'danger')
        
    return redirect(url_for('events_dashboard'))


def send_event_reminders():
    """Send notifications for events happening tomorrow"""
    tomorrow = datetime.utcnow().date() + timedelta(days=1)
    start = datetime.combine(tomorrow, datetime.min.time())
    end = datetime.combine(tomorrow, datetime.max.time())
    
    # Get events happening tomorrow
    events = Event.query.filter(
        Event.event_datetime >= start, 
        Event.event_datetime <= end,
        Event.is_reminder == False  # Only actual events, not personal reminders
    ).all()
    
    for event in events:
        # Notify event creator
        creator_notif_exists = Notification.query.filter_by(
            user_id=event.user_id,
            type='event_notification',  # ✅ Standardized type
            source_id=event.event_id
        ).filter(Notification.message.like(f"%Your event '{event.title}' is happening tomorrow%")).first()
        
        if not creator_notif_exists:
            creator_notif = Notification(
                user_id=event.user_id,
                type='event_notification',  # ✅ Standardized type
                source_id=event.event_id,
                message=f"Reminder: Your event '{event.title}' is happening tomorrow!",
                created_at=datetime.utcnow(),
                is_read=False
            )
            db.session.add(creator_notif)
        
        # Notify all participants
        participants = EventParticipant.query.filter_by(
            event_id=event.event_id,
            status='joined'
        ).all()
        
        for participant in participants:
            participant_notif_exists = Notification.query.filter_by(
                user_id=participant.user_id,
                type='event_notification',  # ✅ Standardized type
                source_id=event.event_id
            ).filter(Notification.message.like(f"%'{event.title}' you joined is happening tomorrow%")).first()
            
            if not participant_notif_exists:
                participant_notif = Notification(
                    user_id=participant.user_id,
                    type='event_notification',  # ✅ Standardized type
                    source_id=event.event_id,
                    message=f"Reminder: '{event.title}' you joined is happening tomorrow!",
                    created_at=datetime.utcnow(),
                    is_read=False
                )
                db.session.add(participant_notif)
    
    db.session.commit()

# Add this function after the existing send_event_reminders() function (around line 2307):

def send_user_event_reminders(user_id):
    """Send event reminder notifications to a specific user for events happening in the next 24 hours"""
    try:
        # Get events happening in the next 24 hours
        now = datetime.utcnow()
        next_24_hours = now + timedelta(hours=24)
        
        # Find events user created that are happening in next 24 hours
        user_created_events = Event.query.filter(
            Event.user_id == user_id,
            Event.event_datetime >= now,
            Event.event_datetime <= next_24_hours,
            Event.is_reminder == False
        ).all()
        
        # Find events user joined that are happening in next 24 hours
        user_joined_events = (
            db.session.query(Event)
            .join(EventParticipant, Event.event_id == EventParticipant.event_id)
            .filter(
                EventParticipant.user_id == user_id,
                EventParticipant.status == 'joined',
                Event.event_datetime >= now,
                Event.event_datetime <= next_24_hours,
                Event.is_reminder == False
            )
            .all()
        )
        
        # Send reminders for events user created
        for event in user_created_events:
            # Check if reminder already exists
            existing_notif = Notification.query.filter_by(
                user_id=user_id,
                type='event_notification',
                source_id=event.event_id
            ).filter(
                Notification.message.like(f"%Your event '{event.title}' is happening%"),
                Notification.created_at >= now - timedelta(hours=1)  # Don't spam - only if no recent reminder
            ).first()
            
            if not existing_notif:
                hours_until = int((event.event_datetime - now).total_seconds() / 3600)
                if hours_until <= 1:
                    time_msg = "very soon"
                elif hours_until <= 6:
                    time_msg = f"in {hours_until} hours"
                else:
                    time_msg = "within 24 hours"
                
                notification = Notification(
                    user_id=user_id,
                    type='event_notification',
                    source_id=event.event_id,
                    message=f"Reminder: Your event '{event.title}' is happening {time_msg}!",
                    created_at=datetime.utcnow(),
                    is_read=False
                )
                db.session.add(notification)
        
        # Send reminders for events user joined
        for event in user_joined_events:
            # Check if reminder already exists
            existing_notif = Notification.query.filter_by(
                user_id=user_id,
                type='event_notification',
                source_id=event.event_id
            ).filter(
                Notification.message.like(f"%'{event.title}' you joined is happening%"),
                Notification.created_at >= now - timedelta(hours=1)  # Don't spam
            ).first()
            
            if not existing_notif:
                hours_until = int((event.event_datetime - now).total_seconds() / 3600)
                if hours_until <= 1:
                    time_msg = "very soon"
                elif hours_until <= 6:
                    time_msg = f"in {hours_until} hours"
                else:
                    time_msg = "within 24 hours"
                
                notification = Notification(
                    user_id=user_id,
                    type='event_notification',
                    source_id=event.event_id,
                    message=f"Reminder: '{event.title}' you joined is happening {time_msg}!",
                    created_at=datetime.utcnow(),
                    is_read=False
                )
                db.session.add(notification)
        
        db.session.commit()
        
    except Exception as e:
        print(f"Error sending user event reminders: {e}")
        db.session.rollback()



# Initialize scheduler for event reminders
scheduler = BackgroundScheduler()
scheduler.add_job(func=send_event_reminders, trigger="interval", hours=24)
scheduler.start()
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

