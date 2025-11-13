# app_factory.py
import os
import socket
from flask import Flask, request, session, current_app, abort, flash, redirect, url_for
from flask_wtf import CSRFProtect
from flask_login import LoginManager, current_user, logout_user
from flask_socketio import SocketIO
from datetime import datetime, timedelta

# Import your models and other modules
from models import db
from config import config
from admin import admin_bp
from user import user_bp
def create_app(config_name=None):
    """Application factory pattern"""
    
    # Determine config
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'default')
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    initialize_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register template functions
    register_template_functions(app)
    
    # Register before request handlers
    register_before_request_handlers(app)
    
    # Register error handlers
    register_error_handlers(app)
    
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
    
    @login_manager.user_loader
    def load_user(user_id):
        """Loads a user from the database given their ID."""
        from models import User
        return db.session.get(User, int(user_id))
    
    # Socket.IO configuration
    socketio = SocketIO()
    socketio.init_app(app, 
                     cors_allowed_origins=app.config['SOCKETIO_CORS_ORIGINS'],
                     message_queue=app.config['REDIS_URL'],
                     ping_interval=25,
                     ping_timeout=60)
    
    # Store extensions in app for access elsewhere
    app.socketio = socketio
    app.csrf = csrf
    app.login_manager = login_manager
    
    return app

def register_blueprints(app):
    """Register Flask blueprints"""
    
    # Register admin blueprint
    app.register_blueprint(admin_bp)
    app.register_blueprint(user_bp)
    
    # Add other blueprints here as you create them
    # app.register_blueprint(users_bp)
    
    return app

def register_template_functions(app):
    """Register template filters and context processors"""
    
    @app.template_filter('has_role')
    def has_role_filter(user, role_name):
        """Custom filter to check if user has a role"""
        if not user or not hasattr(user, 'is_authenticated') or not user.is_authenticated:
            return False
        if not hasattr(user, 'roles'):
            return False
        return any(role.role_name == role_name for role in user.roles)

    @app.context_processor
    def inject_user_roles():
        """Make role checking available in all templates"""
        def has_role(role_name):
            if not current_user.is_authenticated:
                return False
            return any(role.role_name == role_name for role in current_user.roles)
        
        return dict(has_role=has_role)
    
    @app.context_processor
    def inject_container_id():
        return {"container_id": app.config['CONTAINER_ID']}
    
    @app.template_global()
    def google_maps_api_key():
        return app.config.get('GOOGLE_MAPS_API_KEY')
    
    @app.context_processor
    def inject_datetime():
        from datetime import datetime
        return {
            'datetime': datetime,
            'moment': datetime,
            'utcnow': datetime.utcnow
        }
    
    return app

def register_before_request_handlers(app):
    """Register before_request handlers"""
    
    @app.before_request
    def set_session_domain():
        """Dynamically set session cookie domain based on request host"""
        host = request.headers.get('Host', '').lower()
        
        if ':' in host:
            host = host.split(':')[0]
        
        if host in app.config['ALLOWED_SESSION_DOMAINS']:
            app.config['SESSION_COOKIE_DOMAIN'] = host
        else:
            app.config['SESSION_COOKIE_DOMAIN'] = 'localhost'

    @app.before_request
    def validate_host():
        """STRICTLY enforce only exact localhost hostname"""
        request_host = request.headers.get('Host', '').lower()
        
        allowed_hosts = app.config['ALLOWED_SESSION_DOMAINS'] + [
            'localhost:5000', 
            'localhost:80'
        ]
        
        if request_host not in allowed_hosts:
            app.logger.warning(f"BLOCKED: Invalid host '{request_host}' from IP: {request.remote_addr}")
            session.clear()
            abort(400, description=f"Access denied. Only allowed hosts permitted. Requested: {request_host}")

    @app.before_request  
    def validate_session():
        """Enhanced session validation with hostname binding"""
        if current_user.is_authenticated:
            session_host = session.get('bound_hostname')
            current_host = request.headers.get('Host', '').lower()
            
            if not session_host:
                session['bound_hostname'] = current_host
                session['user_ip'] = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
                session['session_created'] = datetime.utcnow().isoformat()
            else:
                if session_host != current_host:
                    app.logger.warning(f"SESSION HIJACK ATTEMPT: User {current_user.user_id} session bound to '{session_host}' but accessed from '{current_host}'")
                    session.clear()
                    logout_user()
                    flash('Security violation detected. Please log in again.', 'error')
                    return redirect(url_for('login'))
            
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
                if datetime.utcnow() - created_time > timedelta(hours=8):
                    session.clear()
                    logout_user()
                    flash('Session expired - please log in again', 'info')
                    return redirect(url_for('login'))
    
    return app

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('404_error.html'), 404

    @app.errorhandler(403)
    def forbidden_error(error): 
        return render_template('403_error.html'), 403

    @app.errorhandler(500)
    def internal_server_error(error):
        return render_template('500_error.html'), 500
    
    return app