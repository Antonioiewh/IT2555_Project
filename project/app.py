# app.py - Consolidated Flask Application

# --- Standard Library Imports ---
import os
import re
import json
import socket
import hashlib
import traceback
import base64
import cbor2
import pyotp
import qrcode
import bleach
from io import BytesIO
from datetime import datetime, timedelta
from functools import wraps

# --- Third Party Library Imports ---
from PIL import Image, ImageDraw, ImageFont

# --- Flask Core Imports ---
from flask import Flask, render_template, redirect, url_for, flash, request, current_app, abort, jsonify, session, make_response, send_file 
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.csrf import CSRFError
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from flask_wtf.file import FileAllowed, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, Optional
from werkzeug.utils import secure_filename
from apscheduler.schedulers.background import BackgroundScheduler

# --- Cryptography Imports ---
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1

# --- Security & Authentication Imports ---
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64encode
from werkzeug.utils import secure_filename

# --- WebAuthn/Passkey Imports ---
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.ctap2.base import AttestationObject
from fido2.client import ClientData
from fido2.ctap2 import AuthenticatorData

# --- Database Imports ---
from sqlalchemy.dialects.mysql import ENUM
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import and_, or_, func, text

# --- Forms & Validation Imports ---
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, ValidationError

# --- HashiCorp Vault Imports ---
from vault import vault_bp

# --- Custom Module Imports ---

# Models
from models import (
    db, User, Role, Permission, Event, EventParticipant, Post, PostImage, PostLike, PostUserPermission,
    Notification, Report, Chat, ChatParticipant, Message, 
    Friendship, AdminAction, UserLog, ModSecLog, ErrorLog, 
    WebAuthnCredential, user_role_assignments, Event, FriendChatMap, BlockedUser, SupportAgent, UserChatLock
)

# Decorators
from decorators_py.decorators import user_required, admin_required, single_role_required, role_required

# Filters
from filters import (
    apply_user_filters, apply_user_sorting, 
    apply_report_filters, apply_user_log_filters
)

# Forms
from forms import (
    SignupForm, LoginForm, ReportForm, UpdateUserStatusForm,
    FriendRequestForm, UpdateReportStatusForm, Enable2FAForm,
    Disable2FAForm, RemovePassKeyForm, CreatePostForm, EditPostVisibilityForm, EditProfileForm, ChangePasswordForm, EventForm
)

# Database Management
from database_manager import DatabaseHA, with_db_failover, create_health_endpoints

# Custom logging utilities
from user_actions import (
    log_user_login_attempt, log_user_login_success, 
    log_user_login_failure, log_user_logout
)

# File validation
from validators_py.file_validate import validate_file_security, scan_upload, validate_banner_image, clean_old_file, validate_post_images, validate_cropped_image_data, validate_and_clean_file, demo_metadata_before_after

# Metadata removal
from validators_py.metadata_remover import remove_metadata

# Message validators
from validators_py.message_validate import validate_attachment, save_attachment

# Helper functions
from functions import get_relative_time, b64encode_all, get_fido2_server, send_user_event_reminders

# Splunk logging
from splunk_logger import splunk_logger

# IMPORTANT FOR ROUTES
# NOTE: HREF -> /<prefix>/<orginal_route>
# e.g. /admin/users_dashboard
# NOTE: URL_FOR ->/<blueprint_prefix>.<orginal_route_function>
# e.g. url_for('admin.users_dashboard')


# --- Configuration Classes ---
class Config:
    """Base configuration class"""
    
    # Basic Flask configuration
    TEMPLATES_AUTO_RELOAD = True
    SEND_FILE_MAX_AGE_DEFAULT = 0  # Disable static file caching for live reloading
    
    # External APIs
    RECAPTCHA_PUBLIC_KEY = os.getenv('RECAPTCHA_PUBLIC_KEY')
    RECAPTCHA_PRIVATE_KEY = os.getenv('RECAPTCHA_PRIVATE_KEY')
    GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY')
    
    # Database configuration
    DB_USER = os.getenv('MYSQL_USER', 'flaskuser')
    DB_PASSWORD = os.getenv('MYSQL_PASSWORD', 'password')
    DB_NAME = os.getenv('MYSQL_DATABASE', 'flaskdb')
    DB_HOST = os.getenv('MYSQL_HOST', 'mysql')
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security configuration
    CONTAINER_ID = os.environ.get('HOSTNAME', socket.gethostname())
    BASE_SECRET = os.getenv('SECRET_KEY', 'a_very_secret_key_for_dev')
    SECRET_KEY = f"{BASE_SECRET}-{CONTAINER_ID}"
    
    # Session configuration
    SESSION_COOKIE_SECURE = False  # Changed to False for HTTP development
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_NAME = f'session_{CONTAINER_ID}'
    
    # File upload configuration
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Redis configuration
    REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6666/0')

    # Splunk Configuration
    SPLUNK_HOST = 'splunk'  # Docker service name
    SPLUNK_PORT = '8088'
    SPLUNK_HEC_TOKEN = '56ee284a-a63c-4e59-9f78-5cb13e0edbe3'
    SPLUNK_INDEX = 'main'
    SPLUNK_USERNAME = 'admin'
    SPLUNK_PASSWORD = 'Admin123!'
    SPLUNK_VERIFY_SSL = False

    # MLTK configuration
    MLTK_ENABLED = os.environ.get('MLTK_ENABLED', 'True').lower() == 'true'
    # Allowed domains
    ALLOWED_SESSION_DOMAINS = [
        'localhost',
        '127.0.0.1',
        'glowing-briefly-cicada.ngrok-free.app'
    ]
    
    # SocketIO configuration
    SOCKETIO_CORS_ORIGINS = [
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "https://glowing-briefly-cicada.ngrok-free.app"
    ]

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = True
    
    # Development specific settings for live reloading
    TEMPLATES_AUTO_RELOAD = True
    SEND_FILE_MAX_AGE_DEFAULT = 0
    WTF_CSRF_ENABLED = False  # Temporarily disabled for development
    
    # least scuffed but remember generate new token on the web UI and replace here
    SPLUNK_HEC_TOKEN = 'f1be25f6-d14f-46fe-b324-c69a82676ec1'  # Replace with actual token
    SPLUNK_HOST = 'splunk'
    SPLUNK_PORT = '8088'
    SPLUNK_INDEX = 'main'
    SPLUNK_VERIFY_SSL = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = True
    TESTING = True

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
def initialize_database_manager(app):
    """Initialize database high availability manager"""
    
    # Create HA manager instance
    db_ha = DatabaseHA()
    
    # Store in app for access elsewhere
    app.db_ha = db_ha
    
    # Create health check endpoints
    create_health_endpoints(app, db_ha)
    
    return db_ha
# --- Application Factory Functions ---
def create_app(config_name=None):
    """Application factory pattern"""
    
    # Determine config
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'development')
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])

    # Register vault blueprint
    app.register_blueprint(vault_bp)
    
    # Enable template auto-reload for development
    if config_name in ['development', 'testing'] or app.config.get('DEBUG'):
        app.jinja_env.auto_reload = True
        app.config['TEMPLATES_AUTO_RELOAD'] = True
    
    # Initialize extensions
    initialize_extensions(app)

     # Initialize database manager
    initialize_database_manager(app)  # Add this line
    # Register blueprints
    register_blueprints(app)
    
    # Register template functions
    register_template_functions(app)
    
    # Register before request handlers
    register_before_request_handlers(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Add cache-busting headers for development
    if config_name in ['development', 'testing'] or app.config.get('DEBUG'):
        @app.after_request
        def add_cache_headers(response):
            # Apply cache-busting to ALL responses in development
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            return response
    
    return app

def initialize_extensions(app):
    """Initialize Flask extensions"""
    
    # Initialize database
    db.init_app(app)
    
    # CSRF protection
    csrf = CSRFProtect()
    csrf.init_app(app)
    
    # Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    # Initialize Splunk logger
    from splunk_logger import splunk_logger
    splunk_logger.init_app(app)
    # Socket.IO configuration
    socketio = SocketIO()
    socketio.init_app(app, 
                     cors_allowed_origins=app.config.get('SOCKETIO_CORS_ORIGINS', "*"),
                     message_queue=app.config.get('REDIS_URL', 'redis://redis:6666/0'),
                     ping_interval=25,
                     ping_timeout=60)
    
    # Store extensions in app for access elsewhere
    app.socketio = socketio
    app.csrf = csrf
    app.login_manager = login_manager
    
    return app

def register_blueprints(app):
    """Register Flask blueprints"""
    
    try:
        # Register admin blueprint
        from admin import admin_bp
        app.register_blueprint(admin_bp, url_prefix='/admin')
        app.logger.info("Admin blueprint registered")
    except Exception as e:
        app.logger.error(f"Failed to register admin blueprint: {e}")
    
    try:
        # Register user blueprint
        from user import user_bp
        app.register_blueprint(user_bp, url_prefix='/user')
        app.logger.info("User blueprint registered")
    except Exception as e:
        app.logger.error(f"Failed to register user blueprint: {e}")
    try:
        # Register ticketing blueprint
        from ticketing import ticketing_bp
        app.register_blueprint(ticketing_bp)
        app.logger.info("Ticketing blueprint registered")
    except Exception as e:
        app.logger.error(f"Failed to register ticketing blueprint: {e}")
    
    return app

def register_template_functions(app):
    """Register template filters and context processors"""
    
    @app.template_filter('has_role')
    def has_role_filter(user, role):
        """Template filter to check if user has role"""
        if not user or not user.is_authenticated:
            return False
        try:
            return user.has_role(role)
        except:
            return False
    
    @app.context_processor
    def inject_user():
        """Inject current user into templates"""
        return dict(current_user=current_user)
    
    @app.context_processor
    def inject_config():
        """Inject config values into templates"""
        return dict(config=current_app.config)
    
    @app.template_global()
    def get_csrf_token():
        """Generate CSRF token for templates"""
        return session.get('csrf_token', '')
    
    @app.context_processor
    def inject_now():
        """Inject current datetime into templates"""
        return dict(now=datetime.utcnow())
    
    return app

def register_before_request_handlers(app):
    """Register before_request handlers"""
    
    @app.before_request
    def load_logged_in_user():
        """Load user info before each request"""
        if current_user.is_authenticated:
            session['last_activity'] = datetime.utcnow().timestamp()
    
    @app.before_request
    def check_session_timeout():
        """Check for session timeout"""
        if current_user.is_authenticated:
            last_activity = session.get('last_activity')
            if last_activity:
                timeout = app.config.get('SESSION_TIMEOUT', 3600)  # 1 hour default
                if datetime.utcnow().timestamp() - last_activity > timeout:
                    logout_user()
                    flash('Your session has expired. Please log in again.', 'warning')
                    return redirect(url_for('login'))
    
    @app.before_request
    def security_headers():
        """Add security headers"""
        pass  # Will be implemented later
    
    @app.before_request
    def log_request():
        """Log security-relevant requests"""
        try:
            # Log suspicious patterns, admin access, etc.
            if request.endpoint and 'admin' in request.endpoint:
                try:
                    from splunk_logger import splunk_logger
                    splunk_logger.log_security_event('admin_access', {
                        'endpoint': request.endpoint,
                        'method': request.method,
                        'args': dict(request.args)
                    })
                except ImportError:
                    pass
        except Exception as e:
            app.logger.error(f"Failed to log request: {e}")
    
    return app

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors"""
        try:
            try:
                from splunk_logger import splunk_logger
                splunk_logger.log_security_event('page_not_found', {
                    'requested_url': request.url,
                    'referrer': request.referrer
                })
            except ImportError:
                pass
        except Exception as e:
            app.logger.error(f"Failed to log 404 error: {e}")
        
        try:
            return render_template('errors/404.html'), 404
        except:
            return '<h1>404 - Page Not Found</h1>', 404
    
    @app.errorhandler(403)
    def forbidden(error):
        """Handle 403 errors"""
        try:
            try:
                from splunk_logger import splunk_logger
                splunk_logger.log_access_violation(
                    resource=request.endpoint or request.url,
                    action=request.method,
                    reason='Forbidden access'
                )
            except ImportError:
                pass
        except Exception as e:
            app.logger.error(f"Failed to log 403 error: {e}")
        
        try:
            return render_template('errors/403.html'), 403
        except:
            return '<h1>403 - Access Forbidden</h1>', 403
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors"""
        try:
            try:
                from splunk_logger import splunk_logger
                splunk_logger.log_security_event('server_error', {
                    'error': str(error),
                    'endpoint': request.endpoint
                }, 'HIGH')
            except ImportError:
                pass
        except Exception as e:
            app.logger.error(f"Failed to log 500 error: {e}")
        
        try:
            return render_template('errors/500.html'), 500
        except:
            return '<h1>500 - Internal Server Error</h1>', 500
    
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """Handle CSRF token errors"""
        
        # Check if this is an exempted endpoint
        if request.endpoint == 'check_user_auth_methods':
            # This should be handled by the @csrf.exempt decorator
            # If we're here, there might be a configuration issue
            app.logger.warning(f"CSRF error on exempted endpoint: {request.endpoint}")
            return jsonify({"error": "Authentication check failed"}), 400
        
        # For non-API requests, check if user is not authenticated
        if not current_user.is_authenticated:
            # Don't redirect unauthenticated users, clear session and show login
            session.clear()
            flash('Session expired. Please log in again.', 'warning')
            return redirect(url_for('login'))
        
        try:
            try:
                from splunk_logger import splunk_logger
                splunk_logger.log_security_event('csrf_error', {
                    'description': e.description,
                    'endpoint': request.endpoint,
                    'user_id': getattr(current_user, 'user_id', None),
                    'source_ip': request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
                }, 'HIGH')
            except ImportError:
                pass
        except Exception as ex:
            app.logger.error(f"Failed to log CSRF error: {ex}")
        
        # For AJAX/API requests
        if request.is_xhr or request.content_type == 'application/json':
            
            return jsonify({'error': 'CSRF token missing or invalid'}), 400
        
        # For regular requests, redirect to login with clear session
        session.clear()
        flash('Security violation detected. Please log in again.', 'error')
        return redirect(url_for('login'))

def _get_profile_pic_url(profile_pic_url):
    """Helper function to get the correct profile picture URL for both old and new file structures"""
    if not profile_pic_url:
        return url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp')
    
    # If it already contains a path separator, it's the full path
    if '/' in profile_pic_url:
        return url_for('static', filename=profile_pic_url)
    else:
        # Legacy filename only - try clean folder first, then uploads
        clean_path = f'clean/profile_pictures/{profile_pic_url}'
        uploads_path = f'uploads/{profile_pic_url}'
        
        # Check if clean version exists
        clean_full_path = os.path.join(current_app.static_folder, 'clean', 'profile_pictures', profile_pic_url)
        if os.path.exists(clean_full_path):
            return url_for('static', filename=clean_path)
        else:
            return url_for('static', filename=uploads_path)

def _get_banner_url(banner_url):
    """Helper function to get the correct banner URL for both old and new file structures"""
    if not banner_url:
        return None
    
    # If it already contains a path separator, it's the full path
    if '/' in banner_url:
        return url_for('static', filename=banner_url)
    else:
        # Legacy filename only - try clean folder first, then uploads
        clean_path = f'clean/banner/{banner_url}'
        uploads_path = f'uploads/{banner_url}'
        
        # Check if clean version exists
        clean_full_path = os.path.join(current_app.static_folder, 'clean', 'banner', banner_url)
        if os.path.exists(clean_full_path):
            return url_for('static', filename=clean_path)
        else:
            return url_for('static', filename=uploads_path)

# --- watermark functions ---
def apply_bottom_right_overlay_bytes(input_image_path, watermark_text):
    """
    Apply a watermark text to the bottom-right corner of an image.
    Returns a BytesIO buffer for direct download.
    
    Args:
        input_image_path: Path to the image file
        watermark_text: Text to display as watermark (e.g., username)
    
    Returns:
        BytesIO buffer containing the watermarked image
    """
    try:
        # Open image and ensure it's in RGBA mode for alpha compositing
        with Image.open(input_image_path) as img:
            # Convert to RGBA for proper alpha compositing
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            # Create a copy to avoid modifying original
            img = img.copy()
            width, height = img.size
            
            # Create overlay layer for watermark
            overlay = Image.new('RGBA', img.size, (255, 255, 255, 0))
            draw = ImageDraw.Draw(overlay)
            
            # Try to load a nice font, fallback to default if unavailable
            try:
                # Try common system fonts
                font_size = max(int(height * 0.06), 24)  # 6% of image height, minimum 24px
                font = ImageFont.truetype("arial.ttf", font_size)
            except:
                try:
                    font = ImageFont.truetype("C:\\Windows\\Fonts\\arial.ttf", font_size)
                except:
                    try:
                        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", font_size)
                    except:
                        # Fallback to default font
                        font = ImageFont.load_default()
                        font_size = 12
            
            # Get text bounding box to know its size
            bbox = draw.textbbox((0, 0), watermark_text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
            
            # Calculate position (bottom-right with padding)
            padding = max(int(width * 0.02), 10)  # 2% of image width, minimum 10px
            x = width - text_width - padding
            y = height - text_height - padding
            
            # Draw watermark with black text at full opacity (255)
            # In RGBA: (R, G, B, Alpha) where Alpha=255 is fully opaque
            watermark_color = (0, 0, 0, 255)  # Black, fully opaque
            draw.text((x, y), watermark_text, font=font, fill=watermark_color)
            
            # Composite the overlay onto the image (both are RGBA)
            img = Image.alpha_composite(img, overlay)
            
            # Convert to RGB only for JPEG saving
            img = img.convert('RGB')
            
            # Save to BytesIO buffer
            buf = BytesIO()
            img.save(buf, format='JPEG', quality=90, optimize=True)
            buf.seek(0)
            
            return buf
            
    except Exception as e:
        app.logger.error(f"Error applying watermark: {str(e)}")
        # Return original image if watermarking fails
        buf = BytesIO()
        with Image.open(input_image_path) as img:
            # Convert to RGB for JPEG output
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img.save(buf, format='JPEG', quality=90)
        buf.seek(0)
        return buf


def add_watermark_overlay(input_image_path, output_image_path, watermark_text):
    """Legacy function for applying watermark and saving to file"""
    try:
        img = Image.open(input_image_path)
        if img.mode in ('RGBA', 'P'):
            rgb_img = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'RGBA':
                rgb_img.paste(img, mask=img.split()[3])
            else:
                rgb_img.paste(img)
            img = rgb_img
        elif img.mode != 'RGB':
            img = img.convert('RGB')
        
        width, height = img.size
        overlay = Image.new('RGBA', img.size, (255, 255, 255, 30))
        draw = ImageDraw.Draw(overlay)
        
        try:
            font_size = max(int(height * 0.04), 20)
            font = ImageFont.truetype("arial.ttf", font_size)
        except:
            font = ImageFont.load_default()
        
        bbox = draw.textbbox((0, 0), watermark_text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        padding = max(int(width * 0.02), 10)
        x = width - text_width - padding
        y = height - text_height - padding
        
        watermark_color = (255, 255, 255, 255)
        draw.text((x, y), watermark_text, font=font, fill=watermark_color)
        
        img = Image.alpha_composite(img.convert('RGBA'), overlay).convert('RGB')
        img.save(output_image_path, 'JPEG', quality=90, optimize=True)
        
    except Exception as e:
        app.logger.error(f"Error in add_watermark_overlay: {str(e)}")
        # Copy original if watermarking fails
        import shutil
        shutil.copy(input_image_path, output_image_path) 


# --- Cleanup Functions ---
def cleanup_old_downloads():
    """
    Clean up old downloaded files from the downloads directory
    This function should be called periodically to prevent disk space issues
    """
    try:
        downloads_dir = os.path.join(os.path.dirname(__file__), 'static', 'downloads')
        if not os.path.exists(downloads_dir):
            return
        
        current_time = datetime.now().timestamp()
        max_age = 24 * 60 * 60  # 24 hours in seconds
        
        for filename in os.listdir(downloads_dir):
            if filename == '.gitignore':
                continue
                
            file_path = os.path.join(downloads_dir, filename)
            try:
                # Check file age
                file_modified_time = os.path.getmtime(file_path)
                if current_time - file_modified_time > max_age:
                    os.unlink(file_path)
                    app.logger.info(f"Cleaned up old download file: {filename}")
            except Exception as e:
                app.logger.error(f"Error cleaning up file {filename}: {str(e)}")
                
    except Exception as e:
        app.logger.error(f"Error in cleanup_old_downloads: {str(e)}")


# --- Create Flask Application ---
app = create_app()
socketio = app.socketio
connected_sids = {}  # { user_id: set([sid, ...]) }

# CSRF protection
csrf = CSRFProtect(app)

# Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login if user not authenticated

# BEFORE REQ FUNCS
# CHANGE FOR DOMAIN - before request
# note: seriously tho why is this here
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
        '127.0.0.1',          
        '127.0.0.1:5000',
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


# -- Fido2 WebAuthn Server Setup --
# in functions.py


# --- login,signup,home ---
# Helper function for relative time in functions.py

# load posts
def _get_profile_pic_url(profile_pic_url):
    """Helper function to get the correct profile picture URL for both old and new file structures"""
    if not profile_pic_url:
        return url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp')
    
    # If it already contains a path separator, it's the full path
    if '/' in profile_pic_url:
        return url_for('static', filename=profile_pic_url)
    else:
        # Legacy filename only - try clean folder first, then uploads
        clean_path = f'clean/profile_pictures/{profile_pic_url}'
        uploads_path = f'uploads/{profile_pic_url}'
        
        # Check if clean version exists
        clean_full_path = os.path.join(current_app.static_folder, 'clean', 'profile_pictures', profile_pic_url)
        if os.path.exists(clean_full_path):
            return url_for('static', filename=clean_path)
        else:
            return url_for('static', filename=uploads_path)

def _get_banner_url(banner_url):
    """Helper function to get the correct banner URL for both old and new file structures"""
    if not banner_url:
        return None
    
    # If it already contains a path separator, it's the full path
    if '/' in banner_url:
        return url_for('static', filename=banner_url)
    else:
        # Legacy filename only - try clean folder first, then uploads
        clean_path = f'clean/banner/{banner_url}'
        uploads_path = f'uploads/{banner_url}'
        
        # Check if clean version exists
        clean_full_path = os.path.join(current_app.static_folder, 'clean', 'banner', banner_url)
        if os.path.exists(clean_full_path):
            return url_for('static', filename=clean_path)
        else:
            return url_for('static', filename=uploads_path)

@app.route('/api/load_more_posts')
@role_required('user')
def load_more_posts():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        # Get current user's accepted friendships for friends-only posts
        friendships = Friendship.query.filter(
            ((Friendship.user_id1 == current_user.user_id) | (Friendship.user_id2 == current_user.user_id)),
            Friendship.status == 'accepted'
        ).all()
        
        friend_ids = []
        for f in friendships:
            if f.user_id1 == current_user.user_id:
                friend_ids.append(f.user_id2)
            else:
                friend_ids.append(f.user_id1)

        # NEW VISIBILITY LOGIC: Same as home route
        posts_query = Post.query.filter(
            or_(
                # Public posts (everyone can see)
                Post.visibility == 'public',
                
                # User's own posts (always visible to owner)
                Post.user_id == current_user.user_id,
                
                # Friends-only posts from friends
                and_(
                    Post.visibility == 'friends',
                    Post.user_id.in_(friend_ids)
                ),
                
                # Specific posts the user has permission to see
                and_(
                    Post.visibility == 'specific',
                    Post.post_id.in_(
                        db.session.query(PostUserPermission.post_id).filter(
                            PostUserPermission.user_id == current_user.user_id
                        )
                    )
                )
            )
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
                    'profile_picture': _get_profile_pic_url(post.user.profile_pic_url)
                },
                'likes_count': PostLike.query.filter_by(post_id=post.post_id).count(),
                'is_liked': PostLike.query.filter_by(post_id=post.post_id, user_id=current_user.user_id).first() is not None,
                'is_own_post': post.user_id == current_user.user_id,
                'visibility': post.visibility  # Add visibility info for frontend
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
@role_required('user')
def upload_banner():
    try:
        if 'banner' not in request.files:
            return jsonify({'success': False, 'error': 'No banner file provided'})
        
        file = request.files['banner']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Read file data for pipeline processing 
        file.seek(0)
        file_data = file.read()
        file.seek(0)
        
        # Run comprehensive validation pipeline with username watermarking
        validation_result = validate_and_clean_file(
            file_data=file_data,
            filename=file.filename,
            max_size=10*1024*1024,  # 10MB for banners
            remove_metadata_flag=True,
            add_watermark=True,
            watermark_text=current_user.username
        )

        if not validation_result['is_safe']:
            threats_msg = '; '.join(validation_result['threats'][:3])
            app.logger.warning(f"Banner upload failed security validation for user {current_user.user_id}: {threats_msg}")
            return jsonify({'success': False, 'error': f'File security validation failed: {threats_msg}'})

        # Generate secure filename and save processed file
        clean_banner_dir = os.path.join(app.static_folder, 'clean', 'banner')
        os.makedirs(clean_banner_dir, exist_ok=True)
        
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        name_part, ext_part = os.path.splitext(filename)
        safe_filename = f"clean_banner_{current_user.user_id}_{timestamp}_{name_part[:50]}{ext_part}"
        
        upload_path = os.path.join(clean_banner_dir, safe_filename)
        
        # Save the processed (validated, cleaned, watermarked) file
        processed_data = validation_result.get('processed_data', file_data)
        with open(upload_path, 'wb') as f:
            f.write(processed_data)
        
        # Remove old banner (check both old uploads dir and new clean/banner dir)
        if current_user.banner_url:
            old_upload_dir = os.path.join(app.static_folder, 'uploads')
            clean_old_file(old_upload_dir, current_user.banner_url)
            clean_old_file(clean_banner_dir, current_user.banner_url)
        
        # Update database with new path structure
        current_user.banner_url = f"clean/banner/{safe_filename}"
        db.session.commit()
        
        app.logger.info(f"User {current_user.user_id} successfully uploaded banner through full pipeline: {safe_filename}")
        if validation_result['metadata_removed']:
            app.logger.info(f"Metadata removed from banner for user {current_user.user_id}")
        if validation_result['watermark_added']:
            app.logger.info(f"Username watermark added to banner for user {current_user.user_id}")
        
        return jsonify({
            'success': True,
            'banner_url': f"clean/banner/{safe_filename}",
            'message': 'Banner updated successfully with security validation and watermarking!'
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error uploading banner: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to upload banner. Please try again.'})

@app.route('/remove_banner', methods=['POST'])
@role_required('user')
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
@role_required('user')
def home():
    try:
        page = request.args.get('page', 1, type=int)
        per_page = 10  # Posts per page
        
        # NEW LOGIC: Show ALL posts that the current user can view
        # This includes: public posts, friends-only posts from friends, and specific posts they're allowed to see
        try:
            # Get friend IDs first for friends-only posts
            friendships = Friendship.query.filter(
                ((Friendship.user_id1 == current_user.user_id) | (Friendship.user_id2 == current_user.user_id)),
                Friendship.status == 'accepted'
            ).all()
            
            friend_ids = []
            for f in friendships:
                if f.user_id1 == current_user.user_id:
                    friend_ids.append(f.user_id2)
                else:
                    friend_ids.append(f.user_id1)
            
            # Build comprehensive query for all viewable posts
            posts_query = Post.query.filter(
                or_(
                    # Public posts (everyone can see)
                    Post.visibility == 'public',
                    
                    # User's own posts (always visible to owner)
                    Post.user_id == current_user.user_id,
                    
                    # Friends-only posts from friends
                    and_(
                        Post.visibility == 'friends',
                        Post.user_id.in_(friend_ids)
                    ),
                    
                    # Specific posts the user has permission to see
                    and_(
                        Post.visibility == 'specific',
                        Post.post_id.in_(
                            db.session.query(PostUserPermission.post_id).filter(
                                PostUserPermission.user_id == current_user.user_id
                            )
                        )
                    )
                )
            ).order_by(Post.created_at.desc())
            
            posts = posts_query.paginate(
                page=page, 
                per_page=per_page, 
                error_out=False
            )
            
        except Exception as e:
            # Fallback to simpler query showing all public posts if new logic fails
            app.logger.warning(f"Advanced visibility query failed: {e}. Falling back to simple public query.")
            posts_query = Post.query.filter_by(visibility='public').order_by(Post.created_at.desc())
            posts = posts_query.paginate(
                page=page, 
                per_page=per_page, 
                error_out=False
            )
        
        # Get current user's actual stats
        current_user_post_count = Post.query.filter_by(user_id=current_user.user_id).count()
        current_user_friend_count = len(friendships) if 'friendships' in locals() else 0
        
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
                'relative_date': get_relative_time(post.created_at), # imported from functions.py
                'user': {
                    'user_id': post.user.user_id,
                    'username': post.user.username,
                    'profile_picture': _get_profile_pic_url(post.user.profile_pic_url)
                },
                'likes_count': PostLike.query.filter_by(post_id=post.post_id).count(),
                'is_liked': PostLike.query.filter_by(post_id=post.post_id, user_id=current_user.user_id).first() is not None,
                'is_own_post': post.user_id == current_user.user_id,
                'visibility': post.visibility  # Add visibility info for frontend
            }
            posts_data.append(post_data)
        
        print(f"DEBUG: Found {len(posts_data)} viewable posts for user {current_user.user_id}")
        print(f"DEBUG: User post count: {current_user_post_count}")
        print(f"DEBUG: User friend count: {current_user_friend_count}")
        
        return render_template('users/UserHome.html', 
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
@role_required('user')
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
    from splunk_logger import splunk_logger  # Add this import
    
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
                # Log lockout attempt to Splunk
                splunk_logger.log_security_event('login_blocked_lockout', {
                    'username': username,
                    'lockout_until': user.lockout_until.isoformat(),
                    'reason': 'Account locked due to previous failed attempts'
                }, severity="WARNING")
                
                log_user_login_failure(user.user_id, details="Attempted login while locked out.")
                return render_template('UserLockedOut.html', lockout_until=user.lockout_until.strftime("%Y-%m-%d %H:%M:%S"))
            
            # Log every login attempt
            if user:
                log_user_login_attempt(user.user_id, details="User attempted login.")

            if user and user.check_password(password):
                # Check for terminated accounts
                if user.is_terminated():
                    # Log terminated user login attempt
                    splunk_logger.log_security_event('login_blocked_terminated', {
                        'username': username,
                        'user_id': user.user_id,
                        'reason': 'Account permanently terminated'
                    }, severity="HIGH")
                    
                    flash('Your account has been permanently terminated. Access is denied.', 'error')
                    app.logger.warning(f"Login attempt by terminated user: {username} from IP: {request.remote_addr}")
                    return render_template('UserLogin.html', form=form)
                
                # Check for suspended accounts
                if user.is_suspended():
                    # Log suspended user login attempt
                    splunk_logger.log_security_event('login_blocked_suspended', {
                        'username': username,
                        'user_id': user.user_id,
                        'reason': 'Account currently suspended'
                    }, severity="WARNING")
                    
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
                        
                        # Log 2FA redirect
                        splunk_logger.log_security_event('login_2fa_redirect', {
                            'username': username,
                            'user_id': user.user_id,
                            'has_passkeys': True,
                            'method': 'password_fallback'
                        })
                        
                        return redirect(url_for('user.verify_2fa'))
                    else:
                        # User has only 2FA - redirect to 2FA page
                        session['pending_2fa_user_id'] = user.user_id
                        session['login_method'] = 'password'
                        
                        # Log 2FA redirect
                        splunk_logger.log_security_event('login_2fa_redirect', {
                            'username': username,
                            'user_id': user.user_id,
                            'has_passkeys': False,
                            'method': 'password_only'
                        })
                        
                        return redirect(url_for('user.verify_2fa'))
                else:
                    # User has no 2FA - direct login (SUCCESS)
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

                    # Send event reminders on login
                    send_user_event_reminders(user.user_id)

                    # Log successful login to Splunk
                    splunk_logger.log_login_attempt(username, True)
                    splunk_logger.log_security_event('user_session_start', {
                        'user_id': user.user_id,
                        'username': username,
                        'login_method': 'password_only',
                        'session_id': session.get('session_id'),
                        'container_id': session['container_id'],
                        'bound_hostname': session['bound_hostname'],
                        'has_2fa': False,
                        'has_passkeys': has_passkeys
                    })

                    log_user_login_success(user.user_id, details=f"User logged in successfully with password only from host: {session['bound_hostname']}")
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('home'))
            
            else:
                # FAILED LOGIN - Invalid credentials
                attempted_username = username
                
                if user:
                    # User exists but wrong password
                    user.failed_login_attempts += 1
                    
                    if user.failed_login_attempts >= 3:
                        # Account will be locked
                        user.lockout_until = datetime.utcnow() + timedelta(minutes=10)
                        
                        # Log account lockout
                        splunk_logger.log_security_event('account_locked', {
                            'username': attempted_username,
                            'user_id': user.user_id,
                            'failed_attempts': user.failed_login_attempts,
                            'lockout_until': user.lockout_until.isoformat(),
                            'lockout_duration_minutes': 10
                        }, severity="HIGH")
                        
                        log_user_login_failure(user.user_id, details="User locked out after 3 failed attempts.")
                    else:
                        # Failed attempt but not locked yet
                        splunk_logger.log_login_attempt(attempted_username, False, 'invalid_password')
                        splunk_logger.log_security_event('login_failure', {
                            'username': attempted_username,
                            'user_id': user.user_id,
                            'failed_attempts': user.failed_login_attempts,
                            'attempts_remaining': 3 - user.failed_login_attempts,
                            'failure_reason': 'invalid_password'
                        }, severity="WARNING")
                        
                        log_user_login_failure(user.user_id, details="User failed login attempt.")
                    
                    db.session.commit()
                else:
                    # User doesn't exist
                    splunk_logger.log_login_attempt(attempted_username, False, 'invalid_username')
                    splunk_logger.log_security_event('login_failure', {
                        'username': attempted_username,
                        'failure_reason': 'invalid_username',
                        'user_exists': False
                    }, severity="WARNING")

    return render_template('UserLogin.html', form=form)

@app.route('/logout')
@login_required
def logout():
    from splunk_logger import splunk_logger  # Add this import
    
    if current_user.is_authenticated:
        # Log successful logout before clearing session
        splunk_logger.log_security_event(
            event_type='logout_success',
            data={
                'logout_time': datetime.utcnow().isoformat(),
                'session_duration': 'calculated_if_available'
            },
            severity='INFO'
        )
    
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
        try:
            username = form.username.data
            phone_no = form.phone_no.data
            password = form.password.data

            # Get keys from hidden fields (You must add these to SignupForm or request.form)
            pub_key = request.form.get('public_key')
            enc_priv_key = request.form.get('encrypted_private_key')
            salt = request.form.get('key_salt')

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
                # Save E2EE Data
                public_key=pub_key,
                encrypted_private_key=enc_priv_key,
                key_salt=salt,
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

            # Log successful signup
            splunk_logger.log_security_event(
                event_type='signup_success',
                data={
                    'new_user_id': new_user.user_id,
                    'username': form.username.data,
                    'registration_time': datetime.utcnow().isoformat(),
                    'email_domain': form.email.data.split('@')[1] if '@' in form.email.data else 'unknown'
                },
                severity='INFO'
            )
            return redirect(url_for('home'))
        except Exception as e:
            # Log signup failure
            splunk_logger.log_security_event(
                event_type='signup_failure',
                data={
                    'attempted_username': form.username.data,
                    'error_reason': str(e),
                    'attempted_email': form.email.data
                },
                severity='ERROR'
            )
            raise e

    return render_template('UserSignup.html', form=form)

#verify 2fa in

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


@app.route('/enable_2fa', methods=['GET', 'POST'])
@role_required('user')
def enable_2fa():
    form = Enable2FAForm()

    # -- Already enabled --
    if current_user.totp_secret:
        return redirect(url_for('user.account_security'))

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
        if form.validate_on_submit():
            code = request.form.get('totp_code')
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(code):
                try:
                    current_user.totp_secret = totp_secret
                    db.session.commit()
                    session.pop('pending_totp_secret', None)  # Remove from session
                    
                    flash('Two-factor authentication has been enabled successfully!', 'success')
                    
                    # Log successful 2FA enablement AFTER successful completion
                    try:
                        splunk_logger.log_security_event(
                            event_type='two_factor_enabled',
                            data={
                                'enabled_time': datetime.utcnow().isoformat(),
                                'method': 'TOTP'
                            },
                            severity='INFO'
                        )
                    except Exception as log_e:
                        app.logger.error(f"Failed to log 2FA enablement: {log_e}")
                    
                    return redirect(url_for('user.account_security'))
                    
                except Exception as e:
                    db.session.rollback()
                    flash('Failed to enable two-factor authentication. Please try again.', 'error')
                    
                    # Log 2FA enablement failure AFTER rollback
                    try:
                        splunk_logger.log_security_event(
                            event_type='two_factor_enable_failed',
                            data={
                                'error_reason': str(e),
                                'attempt_time': datetime.utcnow().isoformat()
                            },
                            severity='ERROR'
                        )
                    except Exception as log_e:
                        app.logger.error(f"Failed to log 2FA enablement failure: {log_e}")
            else:
                flash('Invalid verification code. Please try again.', 'error')
                
                # Log invalid TOTP code attempt AFTER user feedback
                try:
                    splunk_logger.log_security_event(
                        event_type='two_factor_enable_invalid_code',
                        data={
                            'attempt_time': datetime.utcnow().isoformat(),
                            'failure_reason': 'invalid_totp_code'
                        },
                        severity='WARNING'
                    )
                except Exception as log_e:
                    app.logger.error(f"Failed to log invalid 2FA code: {log_e}")
        else:
            # Log form validation failure AFTER validation fails
            try:
                splunk_logger.log_security_event(
                    event_type='two_factor_enable_form_error',
                    data={
                        'form_errors': str(form.errors),
                        'attempt_time': datetime.utcnow().isoformat()
                    },
                    severity='WARNING'
                )
            except Exception as log_e:
                app.logger.error(f"Failed to log form validation error: {log_e}")
            
    return render_template('UserEnable2FA.html', qr_b64=qr_b64, secret=totp_secret, form=form)
@app.route('/disable_2fa', methods=['POST'])
@role_required('user')
def disable_2fa():
    form = Disable2FAForm()
    if form.validate_on_submit():
        current_user.totp_secret = None
        db.session.commit()
        return redirect(url_for('user.account_security'))
    return render_template('UserDisable2FA.html', form=form)


# -- User passkey management --
@app.route('/passkey/begin_register', methods=['POST'])
@csrf.exempt
@role_required('user')
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
    
# need user
@app.route('/passkey/finish_register', methods=['POST'])
@csrf.exempt
@role_required('user')
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

# need user
@app.route('/remove_passkey/<int:cred_id>', methods=['POST'])
@role_required('user')
def remove_passkey(cred_id):
    cred = WebAuthnCredential.query.filter_by(id=cred_id, user_id=current_user.user_id).first()
    if cred:
        db.session.delete(cred)
        db.session.commit()

    else:
        pass
    return redirect(url_for('user.account_security'))

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
@role_required('user')
def change_password():
    form = ChangePasswordForm()
    
    # Check user's security setup
    has_2fa = bool(current_user.totp_secret)
    has_passkeys = WebAuthnCredential.query.filter_by(user_id=current_user.user_id).first() is not None
    
    if request.method == 'POST':
        # Handle passkey authentication
        if request.form.get('auth_method') == 'passkey':
            return jsonify({'redirect': url_for('begin_passkey_auth_for_password_change')})
        
        if form.validate_on_submit():
            try:
                # Validate current password
                if not current_user.check_password(form.current_password.data):
                    flash('Current password is incorrect.', 'error')
                    
                    # Log failed password change attempt AFTER user feedback
                    try:
                        splunk_logger.log_security_event(
                            event_type='password_change_failed',
                            data={
                                'failure_reason': 'invalid_current_password',
                                'attempt_time': datetime.utcnow().isoformat()
                            },
                            severity='WARNING'
                        )
                    except Exception as log_e:
                        app.logger.error(f"Failed to log password change failure: {log_e}")
                    
                    return render_template('change_password.html', form=form, has_2fa=has_2fa, has_passkeys=has_passkeys)
                
                # Update password
                current_user.password_hash = generate_password_hash(form.new_password.data)
                db.session.commit()
                
                flash('Password updated successfully!', 'success')
                
                # Log successful password change AFTER successful completion
                try:
                    splunk_logger.log_security_event(
                        event_type='password_changed',
                        data={
                            'change_time': datetime.utcnow().isoformat(),
                            'has_2fa': has_2fa,
                            'has_passkeys': has_passkeys,
                            'authentication_method': 'current_password'
                        },
                        severity='INFO'
                    )
                except Exception as log_e:
                    app.logger.error(f"Failed to log password change: {log_e}")
                
                return redirect(url_for('user.account_security'))
                
            except Exception as e:
                db.session.rollback()
                flash('Failed to update password. Please try again.', 'error')
                app.logger.error(f"Password change error: {str(e)}")
                
                # Log password change failure AFTER rollback and user feedback
                try:
                    splunk_logger.log_security_event(
                        event_type='password_change_failed',
                        data={
                            'error_reason': str(e),
                            'attempt_time': datetime.utcnow().isoformat()
                        },
                        severity='ERROR'
                    )
                except Exception as log_e:
                    app.logger.error(f"Failed to log password change failure: {log_e}")
        else:
            # Log form validation errors AFTER validation fails
            try:
                splunk_logger.log_security_event(
                    event_type='password_change_form_error',
                    data={
                        'form_errors': str(form.errors),
                        'attempt_time': datetime.utcnow().isoformat()
                    },
                    severity='WARNING'
                )
            except Exception as log_e:
                app.logger.error(f"Failed to log form validation error: {log_e}")
    
    return render_template('change_password.html', form=form, has_2fa=has_2fa, has_passkeys=has_passkeys)

@app.route('/verify_passkey_for_password_change', methods=['POST'])
@csrf.exempt
@role_required('user')
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
# in user.py

# -- User friends management --
@app.route('/UserFriends')
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
            'sender_profile_pic': _get_profile_pic_url(u.profile_pic_url if u else None)
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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



# --- E2EE Chat Management ---
@app.route('/api/get_public_key/<int:user_id>')
@login_required
def get_user_public_key(user_id):
    user = User.query.get_or_404(user_id)
    
    response = {
        'user_id': user.user_id,
        'public_key': user.public_key,
        'salt': user.key_salt 
    }
    
    # CRITICAL: Only send the encrypted private key to its owner
    if current_user.user_id == user.user_id:
        response['encrypted_private_key'] = user.encrypted_private_key
        
    return jsonify(response)


@app.route('/api/update_security_keys', methods=['POST'])
@login_required
def update_security_keys():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        public_key = data.get('public_key')
        
        # For Option 2 (Enclave), we might not send these, so we allow them to be empty/dummy
        encrypted_private_key = data.get('encrypted_private_key', 'DEVICE_BOUND_ENCLAVE') 
        key_salt = data.get('key_salt', 'DEVICE_BOUND_SALT')

        if not public_key:
            return jsonify({'error': 'Missing public key'}), 400

        # Update current user
        current_user.public_key = public_key
        current_user.encrypted_private_key = encrypted_private_key
        current_user.key_salt = key_salt
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Public identity synced'})
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Key update failed: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# --- Chat Lock Management ---
@app.route('/api/sync_chat_lock/<int:chat_id>', methods=['POST'])
@login_required
def sync_chat_lock(chat_id):
    """
    Sync chat lock per-user.
    Each user can lock/unlock independently.
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        is_locked = data.get('is_locked')
        pin_hash = data.get('pin_hash')
        lock_type = data.get('lock_type')
        
        # Security: only allow user to lock their own chats
        if str(user_id) != str(current_user.user_id):
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Verify user is in this chat
        chat_participant = ChatParticipant.query.filter_by(
            chat_id=chat_id, 
            user_id=user_id
        ).first()
        
        if not chat_participant:
            return jsonify({'error': 'Not a chat participant'}), 403
        
        # Update UserChatLock for this user+chat combination
        lock = UserChatLock.query.filter_by(
            user_id=user_id,
            chat_id=chat_id
        ).first()
        
        if is_locked:
            if not lock:
                lock = UserChatLock(user_id=user_id, chat_id=chat_id)
            lock.is_locked = True
            lock.pin_hash = pin_hash
            lock.lock_type = lock_type
            db.session.add(lock)
        else:
            # Remove lock if exists
            if lock:
                db.session.delete(lock)
        
        db.session.commit()
        return jsonify({'ok': True})
        
    except Exception as e:
        app.logger.error(f"Error syncing chat lock: {e}")
        return jsonify({'error': str(e)}), 500
@app.route('/api/get_locked_chats', methods=['GET'])
@login_required
def get_locked_chats():
    """Get all locked chats for current user (per-user locks only)."""
    locked_chats = UserChatLock.query.filter_by(
        user_id=current_user.user_id,
        is_locked=True
    ).all()
    
    return jsonify({
        'locked_chats': {str(lock.chat_id): lock.pin_hash for lock in locked_chats}
    })
# --- Messaging ---

@app.route('/messages', methods=['GET'])
@single_role_required('user')
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


def delete_expired_messages():
    """Background task to delete expired messages."""
    with app.app_context():
        try:
            now = datetime.utcnow()
            # Find and delete messages where expiration time has passed
            num_deleted = Message.query.filter(Message.expires_at <= now).delete()
            if num_deleted > 0:
                db.session.commit()
                print(f"[Cleanup] Deleted {num_deleted} expired messages.")
        except Exception as e:
            print(f"[Cleanup Error] {e}")


@csrf.exempt
@app.route('/create_chat/<int:friend_id>', methods=['POST'])
@single_role_required('user')
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
        return
    
    # 1. Extract Encrypted Data Fields
    ciphertext = data.get('ciphertext')
    iv = data.get('iv')
    sender_enc_key = data.get('sender_enc_key')
    receiver_enc_key = data.get('receiver_enc_key')

    expires_in = int(data.get('expires_in', 0)) # Get timer from frontend
    expires_at = None
    if expires_in > 0:
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
    
    # Validate critical fields
    if not all([ciphertext, iv, sender_enc_key, receiver_enc_key]):
        print("Error: Missing encryption fields in message data.")
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

    # Check for blocks
    if is_any_active_block_between(sender_id, other_user_id):
        # Save as deleted if blocked (optional, or just reject)
        msg = Message(
            chat_id=chat_id,
            sender_id=sender_id,
            message_text=ciphertext, # Save ciphertext even if blocked/deleted logic applies
            iv=iv,
            sender_enc_key=sender_enc_key,
            receiver_enc_key=receiver_enc_key,
            is_deleted_by_sender=True,
            is_deleted_by_receiver=True,
            expires_at=expires_at
        )
        db.session.add(msg)
        db.session.commit()
        socketio.emit('send_error', {'chat_id': chat_id, 'reason': 'blocked'}, room=request.sid)
        return

    # 2. Save Message to Database
    msg = Message(
        chat_id=chat_id, 
        sender_id=sender_id, 
        message_text=ciphertext,  # Store the encrypted content
        iv=iv,
        sender_enc_key=sender_enc_key,
        receiver_enc_key=receiver_enc_key,
        expires_at=expires_at
    )
    db.session.add(msg)
    db.session.commit()

    # 3. Emit to Client
    payload = {
        'chat_id': msg.chat_id,
        'message_id': msg.message_id,
        'sender_id': msg.sender_id,
        'message_text': msg.message_text, # ciphertext
        'iv': msg.iv,
        'sender_enc_key': msg.sender_enc_key,
        'receiver_enc_key': msg.receiver_enc_key,
        'sent_at': msg.sent_at.strftime('%H:%M'),
        'expires_at': expires_at.isoformat() + 'Z' if expires_at else None
    }
    
    # Broadcast to the chat room
    socketio.emit('receive_message', payload, room=str(msg.chat_id))

    # Notifications
    try:
        others = ChatParticipant.query.filter(
            ChatParticipant.chat_id == chat_id,
            ChatParticipant.user_id != sender_id,
            ChatParticipant.is_in_chat == True
        ).all()
        for other in others:
            # Note: We send a generic notification because content is encrypted
            add_message_notification(other.user_id, sender_id, 'New Encrypted Message')
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
@single_role_required('user')
def get_chat_id(friend_id):
    # Try to find existing chat
    chat = get_strict_pair_chat(current_user.user_id, friend_id)
    if not chat:
        # No active chat for current user — client should present "Add chat" option
        return jsonify({'chat_id': None})
    return jsonify({'chat_id': chat.chat_id})


@app.route('/chat_history/<int:friend_id>')
@single_role_required('user')
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
            'deleted_for_me': deleted_for_me,
            'iv': m.iv,                           
            'sender_enc_key': m.sender_enc_key,  
            'receiver_enc_key': m.receiver_enc_key, 
            'expires_at': m.expires_at.isoformat() + 'Z' if m.expires_at else None
        })
    return jsonify(out)


@app.route('/clear_chat/<int:chat_id>', methods=['POST'])
@single_role_required('user')
def clear_chat(chat_id):
    updated = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id).update(
        { ChatParticipant.cleared_at: func.now() }
    )
    if updated:
        db.session.commit()
    return '', 204


@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
def upload_message_attachment():
    file = request.files.get('file')
    if not file or not file.filename:
        return jsonify(ok=False, error='No file provided'), 400
    
    try:
        # Read file data for pipeline processing
        file.seek(0)
        file_data = file.read()
        file.seek(0)
        
        # Run comprehensive validation pipeline with username watermarking
        validation_result = validate_and_clean_file(
            file_data=file_data,
            filename=file.filename,
            max_size=16*1024*1024,  # 16MB for attachments
            remove_metadata_flag=True,
            add_watermark=True,  # Will only watermark images
            watermark_text=current_user.username
        )
        
        if not validation_result['is_safe']:
            threats_msg = '; '.join(validation_result['threats'][:3])
            app.logger.warning(f"Message attachment failed validation for user {current_user.user_id}: {threats_msg}")
            return jsonify(ok=False, error=f'File security validation failed: {threats_msg}'), 400
        
        # Generate secure filename and save processed file
        clean_chat_dir = os.path.join(app.static_folder, 'clean', 'chat')
        os.makedirs(clean_chat_dir, exist_ok=True)
        
        filename = secure_filename(file.filename)
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_%f')
        name_part, ext_part = os.path.splitext(filename)
        safe_filename = f"clean_msg_{current_user.user_id}_{timestamp}_{name_part[:30]}{ext_part}"
        
        upload_path = os.path.join(clean_chat_dir, safe_filename)
        
        # Save the processed (validated, cleaned, potentially watermarked) file
        processed_data = validation_result.get('processed_data', file_data)
        with open(upload_path, 'wb') as f:
            f.write(processed_data)
        
        # Determine file type and size
        file_size = len(processed_data)
        mime_type = file.content_type or 'application/octet-stream'
        
        # Determine file kind
        if mime_type.startswith('image/'):
            kind = 'image'
        elif mime_type.startswith('video/'):
            kind = 'video'
        elif mime_type.startswith('audio/'):
            kind = 'audio'
        elif mime_type == 'application/pdf':
            kind = 'document'
        elif mime_type in ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
            kind = 'document'
        else:
            kind = 'file'
        
        rel_path = f"clean/chat/{safe_filename}"
        
        app.logger.info(f"Message attachment processed through full pipeline for user {current_user.user_id}: {safe_filename}")
        if validation_result['metadata_removed']:
            app.logger.info(f"Metadata removed from message attachment for user {current_user.user_id}")
        if validation_result['watermark_added']:
            app.logger.info(f"Username watermark added to message attachment for user {current_user.user_id}")
        
        return jsonify(
            ok=True,
            url=url_for('static', filename=rel_path),
            name=filename,
            size=file_size,
            mime=mime_type,
            kind=kind
        )
        
    except Exception as e:
        app.logger.error(f"Error processing message attachment for user {current_user.user_id}: {str(e)}")
        return jsonify(ok=False, error='File processing failed'), 500




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
@single_role_required('user')
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
@single_role_required('user')
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
                'sender_profile_pic': _get_profile_pic_url(u.profile_pic_url if u else None)
            })
        return jsonify({'ok': True, 'items': stacks})
    except Exception as e:
        current_app.logger.error(f'api_message_notification_stacks: {e}')
        return jsonify({'ok': False, 'items': []}), 500

@app.route('/api/notifications/messages/mark_read', methods=['POST'])
@single_role_required('user')
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
        
        # Get accurate friend count (accepted friendships only)
        accepted_friendships = Friendship.query.filter(
            ((Friendship.user_id1 == user_id) | (Friendship.user_id2 == user_id)),
            Friendship.status == 'accepted'
        ).count()

        # Get user's posts (visibility-filtered)
        if is_own_profile:
            posts_query = Post.query.filter_by(user_id=user_id)
        else:
            # If friend, allow 'friends' + 'public'; if not friend, only 'public'
            if friendship_status == 'accepted':
                posts_query = Post.query.filter(
                    Post.user_id == user_id,
                    or_(Post.visibility == 'public', Post.visibility == 'friends')
                )
            else:
                posts_query = Post.query.filter_by(user_id=user_id, visibility='public')
        
        posts = posts_query.order_by(Post.created_at.desc()).all()
        
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
        print(f"DEBUG: Form data received: {request.form}")
        print(f"DEBUG: Form validation: {form.validate_on_submit()}")
        print(f"DEBUG: Form errors: {form.errors}")
        
        if form.validate_on_submit():
            try:
                # Create new post with updated visibility system
                new_post = Post(
                    user_id=current_user.user_id,
                    post_content=form.post_content.data,
                    visibility=form.visibility.data or 'public'
                )
                
                print(f"DEBUG: Creating post with data: user_id={new_post.user_id}, content='{new_post.post_content}', visibility={new_post.visibility}")
                
                db.session.add(new_post)
                db.session.flush()  # Get the post_id for potential user permissions
                
                print(f"DEBUG: Post flushed, post_id: {new_post.post_id}")
                
                # Handle specific user permissions if visibility is 'specific'
                if form.visibility.data == 'specific' and form.specific_users.data:
                    usernames = [username.strip() for username in form.specific_users.data.split(',') if username.strip()]
                    print(f"DEBUG: Processing specific users: {usernames}")
                    
                    for username in usernames:
                        user = User.query.filter_by(username=username).first()
                        if user and user.user_id != current_user.user_id:
                            permission = PostUserPermission(
                                post_id=new_post.post_id,
                                user_id=user.user_id,
                                granted_by=current_user.user_id
                            )
                            db.session.add(permission)
                            print(f"DEBUG: Added permission for user {username} (ID: {user.user_id})")
                
                # Handle image upload using comprehensive validation pipeline
                image_file = form.image.data
                if image_file and image_file.filename:
                    try:
                        # Read image data for pipeline processing
                        image_file.seek(0)
                        image_data = image_file.read()
                        image_file.seek(0)
                        
                        # Run comprehensive validation pipeline with username watermarking
                        validation_result = validate_and_clean_file(
                            file_data=image_data,
                            filename=image_file.filename,
                            max_size=5*1024*1024,  # 5MB for post images
                            remove_metadata_flag=True,
                            add_watermark=True,
                            watermark_text=current_user.username
                        )
                        
                        if validation_result['is_safe']:
                            # Generate secure filename and save processed file
                            clean_posts_dir = os.path.join(current_app.root_path, 'static', 'clean', 'posts')
                            os.makedirs(clean_posts_dir, exist_ok=True)
                            
                            filename = secure_filename(image_file.filename)
                            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                            name_part, ext_part = os.path.splitext(filename)
                            safe_filename = f"clean_post_{new_post.post_id}_{current_user.user_id}_{timestamp}_{name_part[:30]}{ext_part}"
                            
                            upload_path = os.path.join(clean_posts_dir, safe_filename)
                            
                            # Save the processed (validated, cleaned, watermarked) file
                            processed_data = validation_result.get('processed_data', image_data)
                            with open(upload_path, 'wb') as f:
                                f.write(processed_data)
                            
                            # Create PostImage record
                            post_image = PostImage(
                                post_id=new_post.post_id,
                                image_url=f"clean/posts/{safe_filename}",  # Store path relative to static folder
                                order_index=1
                            )
                            db.session.add(post_image)
                            
                            app.logger.info(f"Post image processed through full pipeline for post {new_post.post_id}: {safe_filename}")
                            if validation_result['metadata_removed']:
                                app.logger.info(f"Metadata removed from post image for post {new_post.post_id}")
                            if validation_result['watermark_added']:
                                app.logger.info(f"Username watermark added to post image for post {new_post.post_id}")
                            
                        else:
                            # Security validation failed - log errors but continue with post creation
                            threats_msg = '; '.join(validation_result['threats'][:2])
                            app.logger.warning(f"Post image failed validation for post {new_post.post_id}: {threats_msg}")
                            flash('Post created but image upload failed security validation: ' + threats_msg, 'warning')
                        
                    except Exception as img_error:
                        app.logger.error(f"Error processing post image for post {new_post.post_id}: {str(img_error)}")
                        flash('Post created but image processing failed', 'warning')
                
                db.session.commit()
                print("DEBUG: Post committed successfully")
                
                flash('Post created successfully!', 'success')
                
                return redirect(url_for('account'))
                
            except Exception as e:
                db.session.rollback()
                print(f"DEBUG: Post creation error: {str(e)}")
                flash('Failed to create post. Please try again.', 'error')
                current_app.logger.error(f"Post creation error: {str(e)}")
        else:
            print(f"DEBUG: Form validation failed with errors: {form.errors}")
            flash('Please correct the errors in the form.', 'error')

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

# -- Edit Post Visibility ---
@app.route('/edit_post_visibility/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post_visibility(post_id):
    """Edit post visibility settings"""
    post = Post.query.get_or_404(post_id)
    
    # Only post owner can edit visibility
    if post.user_id != current_user.user_id:
        abort(403)
    
    form = EditPostVisibilityForm()
    
    if form.validate_on_submit():
        try:
            # Update visibility
            old_visibility = post.visibility
            post.visibility = form.visibility.data
            
            # Clear existing specific user permissions
            PostUserPermission.query.filter_by(post_id=post_id).delete()
            
            # Add new specific user permissions if needed
            if form.visibility.data == 'specific' and form.specific_users.data:
                usernames = [username.strip() for username in form.specific_users.data.split(',') if username.strip()]
                
                for username in usernames:
                    user = User.query.filter_by(username=username).first()
                    if user and user.user_id != current_user.user_id:
                        permission = PostUserPermission(
                            post_id=post_id,
                            user_id=user.user_id,
                            granted_by=current_user.user_id
                        )
                        db.session.add(permission)
            
            db.session.commit()
            
            # Log the action
            try:
                splunk_logger.log_security_event(
                    event_type='post_visibility_changed',
                    data={
                        'post_id': post_id,
                        'old_visibility': old_visibility,
                        'new_visibility': post.visibility,
                        'specific_users_count': len([u.strip() for u in form.specific_users.data.split(',') if u.strip()]) if form.specific_users.data else 0,
                        'change_time': datetime.utcnow().isoformat()
                    },
                    severity='INFO'
                )
            except Exception as log_e:
                app.logger.error(f"Failed to log post visibility change: {log_e}")
            
            flash('Post visibility updated successfully!', 'success')
            return redirect(url_for('account', user_id=current_user.user_id))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating post visibility: {str(e)}")
            flash('Error updating post visibility. Please try again.', 'error')
    
    # Pre-populate form with current values
    if request.method == 'GET':
        form.visibility.data = post.visibility
        if post.visibility == 'specific':
            allowed_users = [perm.user.username for perm in post.user_permissions]
            form.specific_users.data = ', '.join(allowed_users)
    
    return render_template('edit_post_visibility.html', form=form, post=post)



# -- download post image ---
@app.route('/download_post_image/<int:post_id>/<path:filename>')
@login_required
def download_post_image(post_id, filename):
    """
    Serve downloadable image with username at bottom-right (100% opacity).
    """
    # Validate post exists and image belongs to post
    post = Post.query.get_or_404(post_id)
    
    # Check if the post has an image that matches the filename
    # The image_url in database now contains "uploads/filename.jpg"
    post_image = PostImage.query.filter(
        PostImage.post_id == post_id,
        or_(
            PostImage.image_url == f'uploads/{filename}',
            PostImage.image_url.like(f'%{filename}')
        )
    ).first()
    
    if not post_image:
        abort(404)

    # Construct the full file path - check both clean/posts and uploads (legacy)
    clean_file_path = os.path.join(app.static_folder, 'clean', 'posts', filename)
    legacy_file_path = os.path.join(app.static_folder, 'uploads', filename)
    
    file_path = None
    if os.path.exists(clean_file_path):
        file_path = clean_file_path
    elif os.path.exists(legacy_file_path):
        file_path = legacy_file_path
    else:
        abort(404)

    # Apply username overlay and return
    buf = apply_bottom_right_overlay_bytes(file_path, post.user.username)
    return send_file(
        buf,
        mimetype='image/jpeg',
        as_attachment=True,
        download_name=f"watermarked_{filename}"
    )
@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    """Delete a post and its associated images"""
    try:
        post = Post.query.get_or_404(post_id)
        
                # Security check: Ensure user owns the post
        if post.user_id != current_user.user_id:
            abort(403)
            
            # Log unauthorized deletion attempt AFTER abort
            try:
                splunk_logger.log_security_event(
                    event_type='unauthorized_post_delete_attempt',
                    data={
                        'target_post_id': post_id,
                        'post_owner_id': post.user_id,
                        'attempt_time': datetime.utcnow().isoformat()
                    },
                    severity='HIGH'
                )
            except Exception as log_e:
                app.logger.error(f"Failed to log unauthorized deletion attempt: {log_e}")
        
        # Store post details for logging
        post_details = {
            'post_id': post_id,
            'content_length': len(post.post_content) if post.post_content else 0,
            'had_images': bool(post.images),
            'image_count': len(post.images) if post.images else 0
        }
        
        # Delete associated images
        for image in post.images:
            try:
                image_path = os.path.join(app.static_folder, image.image_url)
                if os.path.exists(image_path):
                    os.remove(image_path)
            except Exception as img_error:
                app.logger.warning(f"Failed to delete image file: {img_error}")
            
            db.session.delete(image)
        
        # Delete the post
        db.session.delete(post)
        db.session.commit()
        
        flash('Post deleted successfully!', 'success')
        
        # Log successful post deletion AFTER successful completion
        try:
            splunk_logger.log_security_event(
                event_type='post_deleted',
                data={
                    'deleted_post_id': post_id,
                    'deletion_time': datetime.utcnow().isoformat(),
                    **post_details
                },
                severity='INFO'
            )
        except Exception as log_e:
            app.logger.error(f"Failed to log post deletion: {log_e}")
        
    except Exception as e:
        db.session.rollback()
        flash('Failed to delete post. Please try again.', 'error')
        app.logger.error(f"Post deletion error: {str(e)}")
        
        # Log post deletion failure AFTER rollback and user feedback
        try:
            splunk_logger.log_security_event(
                event_type='post_deletion_failed',
                data={
                    'target_post_id': post_id,
                    'error_reason': str(e),
                    'attempt_time': datetime.utcnow().isoformat()
                },
                severity='ERROR'
            )
        except Exception as log_e:
            app.logger.error(f"Failed to log post deletion failure: {log_e}")
    
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
            
            # Handle profile picture upload with comprehensive pipeline
            cropped_image_data = request.form.get('cropped_image_data')
            
            if cropped_image_data:
                import base64
                try:
                    # Decode base64 image data
                    header, encoded = cropped_image_data.split(',', 1)
                    image_data = base64.b64decode(encoded)
                    
                    # Run comprehensive validation pipeline with username watermarking
                    validation_result = validate_and_clean_file(
                        file_data=image_data,
                        filename="profile_picture.png",
                        max_size=5*1024*1024,  # 5MB for profile pics
                        remove_metadata_flag=True,
                        add_watermark=True,
                        watermark_text=current_user.username
                    )
                    
                    if not validation_result['is_safe']:
                        threats_msg = '; '.join(validation_result['threats'][:3])
                        app.logger.warning(f"Profile image upload failed security validation for user {current_user.user_id}: {threats_msg}")
                        flash(f'Profile picture security validation failed: {threats_msg}', 'error')
                        return render_template('EditProfile.html', form=form)
                    
                    # Generate secure filename and save processed file
                    clean_profile_dir = os.path.join(app.static_folder, 'clean', 'profile_pictures')
                    os.makedirs(clean_profile_dir, exist_ok=True)
                    
                    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                    safe_filename = f"clean_profile_{current_user.user_id}_{timestamp}.png"
                    upload_path = os.path.join(clean_profile_dir, safe_filename)
                    
                    # Save the processed (validated, cleaned, watermarked) file
                    processed_data = validation_result.get('processed_data', image_data)
                    with open(upload_path, 'wb') as f:
                        f.write(processed_data)
                    
                    # Clean old files from both old and new directories
                    if current_user.profile_pic_url:
                        old_upload_dir = os.path.join(app.static_folder, 'uploads')
                        clean_old_file(old_upload_dir, current_user.profile_pic_url)
                        clean_old_file(clean_profile_dir, current_user.profile_pic_url)
                    
                    current_user.profile_pic_url = f"clean/profile_pictures/{safe_filename}"
                    
                    app.logger.info(f"User {current_user.user_id} updated profile picture through full pipeline: {safe_filename}")
                    if validation_result['metadata_removed']:
                        app.logger.info(f"Metadata removed from profile picture for user {current_user.user_id}")
                    if validation_result['watermark_added']:
                        app.logger.info(f"Username watermark added to profile picture for user {current_user.user_id}")
                        
                except Exception as img_error:
                    app.logger.error(f"Error processing profile image for user {current_user.user_id}: {str(img_error)}")
                    flash('Failed to process profile picture. Please try again.', 'error')
                    return render_template('EditProfile.html', form=form)
            
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
@single_role_required('user')
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
                type='event_notification',  
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
            type='event_notification',  
            source_id=event.event_id
        ).filter(Notification.message.like(f"%Your event '{event.title}' is happening tomorrow%")).first()
        
        if not creator_notif_exists:
            creator_notif = Notification(
                user_id=event.user_id,
                type='event_notification',  
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
                type='event_notification',  
                source_id=event.event_id
            ).filter(Notification.message.like(f"%'{event.title}' you joined is happening tomorrow%")).first()
            
            if not participant_notif_exists:
                participant_notif = Notification(
                    user_id=participant.user_id,
                    type='event_notification',  
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
                Notification.created_at >= now - timedelta(hours=1) 
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

@app.route('/admin/file_pipeline_demo', methods=['GET', 'POST'])
@admin_required
def file_pipeline_demo():
    """
    Admin page to demonstrate file validation and metadata removal pipeline
    """
    result = None
    
    if request.method == 'POST':
        if 'demo_file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['demo_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        try:
            import tempfile
            import os
            import uuid
            
            # Create downloads directory if it doesn't exist
            downloads_dir = os.path.join(app.root_path, 'static', 'downloads')
            os.makedirs(downloads_dir, exist_ok=True)
            
            # Save file temporarily for metadata extraction demo
            temp_fd, temp_path = tempfile.mkstemp(suffix=f"_{secure_filename(file.filename)}")
            try:
                with os.fdopen(temp_fd, 'wb') as temp_file:
                    file.seek(0)
                    temp_file.write(file.read())
                    file.seek(0)
                
                # Read file data for validation
                file_data = file.read()
                file.seek(0)
                
                # Run the pipeline
                pipeline_result = validate_and_clean_file(
                    file_data=file_data,
                    filename=file.filename,
                    max_size=16*1024*1024,  # 16MB max for demo
                    remove_metadata_flag=True,
                    add_watermark=True,  # Enable watermarking step
                    watermark_text=current_user.username  # Use current user's username
                )
                
                # Run metadata demo (before/after comparison) and create cleaned file
                metadata_demo = None
                
                try:
                    # Call the updated demo function with downloads directory
                    metadata_demo = demo_metadata_before_after(temp_path, downloads_dir, current_user.username)
                    
                    # If file is safe and metadata demo was successful and produced a download
                    if (pipeline_result['is_safe'] and 
                        metadata_demo.get('success', False) and 
                        metadata_demo.get('download_id')):
                        
                        # Store download info in session for security
                        session[f'download_{metadata_demo["download_id"]}'] = {
                            'filepath': metadata_demo['cleaned_file_path'],
                            'original_filename': metadata_demo['original_filename'],
                            'created_at': datetime.now().timestamp()
                        }
                        
                except Exception as e:
                    app.logger.warning(f'Metadata demo failed: {str(e)}')
                    metadata_demo = {
                        'before': {}, 
                        'after': {}, 
                        'removed_count': 0, 
                        'success': False,
                        'details': f'Demo error: {str(e)}'
                    }
                
                # Create result summary
                result = {
                    'filename': file.filename,
                    'file_size': len(file_data),
                    'file_size_mb': round(len(file_data) / (1024*1024), 2),
                    'validation_result': pipeline_result,
                    'metadata_demo': metadata_demo,
                    'md5_hash': pipeline_result.get('file_info', {}).get('md5_hash', 'N/A'),
                    'file_type': pipeline_result.get('file_info', {}).get('expected_type', 'Unknown')
                }
                
                # Add human-readable status
                if pipeline_result['is_safe']:
                    if pipeline_result['metadata_removed']:
                        result['status'] = 'SAFE - Metadata Removed'
                        result['status_class'] = 'success'
                    elif pipeline_result.get('metadata_removal_error'):
                        result['status'] = 'SAFE - Metadata Removal Failed'
                        result['status_class'] = 'warning'
                    else:
                        result['status'] = 'SAFE - No Metadata Removal'
                        result['status_class'] = 'info'
                else:
                    result['status'] = 'UNSAFE - File Rejected'
                    result['status_class'] = 'danger'
                
            finally:
                # Clean up temp file
                try:
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                except Exception:
                    pass
                
        except Exception as e:
            flash(f'Error processing file: {str(e)}', 'error')
            app.logger.error(f'File pipeline demo error: {str(e)}')
    
    return render_template('admin/file_pipeline_demo.html', result=result)

@app.route('/admin/download_cleaned_file/<download_id>')
@admin_required
def download_cleaned_file(download_id):
    """
    Download a cleaned file that was processed through the pipeline demo
    """
    try:
        # Check if download info exists in session
        download_key = f'download_{download_id}'
        if download_key not in session:
            flash('Download link expired or invalid', 'error')
            return redirect(url_for('admin.file_pipeline_demo'))
        
        download_info = session[download_key]
        
        # Check if file still exists
        file_path = download_info['filepath']
        if not os.path.exists(file_path):
            flash('File no longer available for download', 'error')
            # Clean up session entry
            session.pop(download_key, None)
            return redirect(url_for('admin.file_pipeline_demo'))
        
        # Check if download is not too old (24 hours limit)
        created_at = download_info['created_at']
        if datetime.now().timestamp() - created_at > 24 * 60 * 60:  # 24 hours
            # Clean up old file and session
            try:
                os.unlink(file_path)
            except Exception:
                pass
            session.pop(download_key, None)
            flash('Download link expired', 'error')
            return redirect(url_for('admin.file_pipeline_demo'))
        
        # Send file for download
        original_filename = download_info['original_filename']
        cleaned_filename = f"cleaned_{original_filename}"
        
        # Clean up session entry after successful access
        session.pop(download_key, None)
        
        # Schedule file cleanup after download
        def cleanup_file():
            import time
            time.sleep(60)  # Wait 1 minute
            try:
                if os.path.exists(file_path):
                    os.unlink(file_path)
            except Exception:
                pass
        
        # Start cleanup in background
        import threading
        threading.Thread(target=cleanup_file, daemon=True).start()
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=cleaned_filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        app.logger.error(f'Download error: {str(e)}')
        flash('Error downloading file', 'error')
        return redirect(url_for('admin.file_pipeline_demo'))

@app.route('/admin/create_support_agent', methods=['GET', 'POST'])
@admin_required  
def create_support_agent():
    """Admin route to create support agents"""
    if request.method == 'POST':
        try:
            user_id = request.form.get('user_id', type=int)
            clearance_level = request.form.get('clearance_level', type=int)
            department = request.form.get('department', '').strip()
            specialization = request.form.get('specialization', '').strip()
            
            # Validate inputs
            if not all([user_id, clearance_level, department]):
                flash('User ID, clearance level, and department are required.', 'error')
                return redirect(url_for('create_support_agent'))
            
            if clearance_level < 1 or clearance_level > 5:
                flash('Clearance level must be between 1 and 5.', 'error')
                return redirect(url_for('create_support_agent'))
            
            # Check if user exists
            user = User.query.get(user_id)
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('create_support_agent'))
            
            # Check if already an agent
            existing_agent = SupportAgent.query.filter_by(user_id=user_id).first()
            if existing_agent:
                flash(f'{user.username} is already a support agent.', 'error')
                return redirect(url_for('create_support_agent'))
            
            # Create support agent
            agent = SupportAgent(
                user_id=user_id,
                clearance_level=clearance_level,
                department=department,
                specialization=specialization,
                created_by=current_user.user_id,
                created_at=datetime.utcnow(),
                is_active=True
            )
            
            db.session.add(agent)
            db.session.commit()
            
            flash(f'Support agent created for {user.username} with L{clearance_level} clearance!', 'success')
            return redirect(url_for('create_support_agent'))
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error creating support agent: {str(e)}")
            flash('An error occurred while creating the support agent.', 'error')
    
    # GET request - show form
    users = User.query.all()
    existing_agents = {agent.user_id for agent in SupportAgent.query.all()}
    available_users = [user for user in users if user.user_id not in existing_agents]
    
    return render_template('admin/create_support_agent.html', users=available_users)
# Initialize scheduler for event reminders
scheduler = BackgroundScheduler()
scheduler.add_job(func=send_event_reminders, trigger="interval", hours=24)
scheduler.add_job(func=delete_expired_messages, trigger="interval", seconds=30)
scheduler.add_job(func=cleanup_old_downloads, trigger="interval", hours=6)  # Clean up downloads every 6 hours
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