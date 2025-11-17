from flask import Flask, request, session, current_app, abort, flash, redirect, url_for, render_template
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_login import LoginManager, current_user, logout_user
from flask_socketio import SocketIO
from datetime import datetime, timedelta
import os

# Import your models and other modules
from models import db, User
from config import config
from admin import admin_bp
from user import user_bp
from splunk_logger import splunk_logger

def create_app(config_name=None):
    """Application factory pattern"""
    
    # Determine config
    if config_name is None:
        config_name = os.getenv('FLASK_CONFIG', 'development')
    
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
    login_manager.login_view = 'user.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Socket.IO configuration
    socketio = SocketIO()
    socketio.init_app(app, 
                     cors_allowed_origins=app.config.get('SOCKETIO_CORS_ORIGINS', "*"),
                     message_queue=app.config.get('REDIS_URL', 'redis://redis:6379/0'),
                     ping_interval=25,
                     ping_timeout=60)
    
    # Initialize Splunk logger
    try:
        splunk_logger.init_app(app)
    except Exception as e:
        app.logger.warning(f"Splunk logger initialization failed: {e}")
    
    # Store extensions in app for access elsewhere
    app.socketio = socketio
    app.csrf = csrf
    app.login_manager = login_manager
    app.splunk_logger = splunk_logger
    
    return app

def register_blueprints(app):
    """Register Flask blueprints"""
    
    try:
        # Register admin blueprint
        app.register_blueprint(admin_bp, url_prefix='/admin')
        app.logger.info("Admin blueprint registered")
    except Exception as e:
        app.logger.error(f"Failed to register admin blueprint: {e}")
    
    try:
        # Register user blueprint
        app.register_blueprint(user_bp, url_prefix='/user')
        app.logger.info("User blueprint registered")
    except Exception as e:
        app.logger.error(f"Failed to register user blueprint: {e}")
    
    # Add a simple root route if no other routes handle it
    @app.route('/')
    def index():
        return redirect(url_for('login'))
    
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
                    return redirect(url_for('user.login'))
    
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
                splunk_logger.log_security_event('admin_access', {
                    'endpoint': request.endpoint,
                    'method': request.method,
                    'args': dict(request.args)
                })
        except Exception as e:
            app.logger.error(f"Failed to log request: {e}")
    
    return app

def register_error_handlers(app):
    """Register error handlers"""
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors"""
        try:
            splunk_logger.log_security_event('page_not_found', {
                'requested_url': request.url,
                'referrer': request.referrer
            })
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
            splunk_logger.log_access_violation(
                resource=request.endpoint or request.url,
                action=request.method,
                reason='Forbidden access'
            )
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
            splunk_logger.log_security_event('server_error', {
                'error': str(error),
                'endpoint': request.endpoint
            }, 'HIGH')
        except Exception as e:
            app.logger.error(f"Failed to log 500 error: {e}")
        
        try:
            return render_template('errors/500.html'), 500
        except:
            return '<h1>500 - Internal Server Error</h1>', 500
    
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        """Handle CSRF token errors"""
        try:
            splunk_logger.log_security_event('csrf_error', {
                'description': e.description,
                'endpoint': request.endpoint
            }, 'HIGH')
        except Exception as ex:
            app.logger.error(f"Failed to log CSRF error: {ex}")
        
        try:
            return render_template('errors/csrf.html'), 400
        except:
            return '<h1>400 - CSRF Token Error</h1>', 400
    
    return app