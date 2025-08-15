from functools import wraps
from flask import abort
from flask_login import login_required, current_user

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

def admin_required(f):
    """Decorator to ensure user has 'admin' role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.has_role('admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def editor_required(f):
    """Decorator to ensure user has 'editor' role"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.has_role('editor'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

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