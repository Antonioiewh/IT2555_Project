from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import login_required, current_user

# ONLY USER
def user_required(f):
    """Decorator to ensure user has only 'user' role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        user_roles = [role.role_name for role in current_user.roles]
        if user_roles == ['user']:
            return f(*args, **kwargs)
        else:
            abort(403)
    return decorated_function

# ONLY ADMIN
def admin_required(f):
    """Decorator to ensure user has 'admin' role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.has_role('admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ONE OF
def role_required(*roles):
    """Decorator to ensure user has one of the specified roles"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user_roles = [role.role_name for role in current_user.roles]
            if any(role in user_roles for role in roles):
                return f(*args, **kwargs)
            else:
                abort(403)
        return decorated_function
    return decorator

# ONLY THAT  ROLE
def single_role_required(required_role):
    """Decorator to ensure user has ONLY the specified role and no others"""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated_function(*args, **kwargs):
            user_roles = [role.role_name for role in current_user.roles]
            if user_roles == [required_role]:
                return f(*args, **kwargs)
            else:
                abort(403)
        return decorated_function
    return decorator

def admin_or_editor_required(f):
    """Decorator to ensure user has either 'admin' or 'editor' role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if current_user.has_role('admin') or current_user.has_role('editor'):
            return f(*args, **kwargs)
        else:
            abort(403)
    return decorated_function

def agent_required(f):
    """Decorator to require agent role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        if not current_user.has_role('support_agent'):
            flash('Access denied. Support agent role required.', 'error')
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

def agent_or_admin_required(f):
    """Decorator to require agent or admin role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        if not (current_user.has_role('agent') or current_user.has_role('admin')):
            flash('Access denied. Support agent or admin role required.', 'error')
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function