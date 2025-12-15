from flask_sqlalchemy import SQLAlchemy
from flask import current_app
from datetime import datetime

def log_user_login_attempt(user_id, details=None):
    """Log a user login attempt (success or failure)."""
    from app import db, UserLog  # Import inside the function to avoid circular import
    log = UserLog(
        user_id=user_id,
        log_type='login_attempt',
        log_timestamp=datetime.utcnow(),
        details=details
    )
    db.session.add(log)
    db.session.commit()

def log_user_login_success(user_id, details=None):
    """Log a successful user login."""
    from app import db, UserLog  # Import inside the function to avoid circular import
    log = UserLog(
        user_id=user_id,
        log_type='login_success',
        log_timestamp=datetime.utcnow(),
        details=details
    )
    db.session.add(log)
    db.session.commit()



def log_user_logout(user_id, details=None):
    """Log a successful user logout."""
    from app import db, UserLog  # Import inside the function to avoid circular import
    log = UserLog(
        user_id=user_id,
        log_type='logout_success',
        log_timestamp=datetime.utcnow(),
        details=details
    )
    db.session.add(log)
    db.session.commit()


def log_user_login_failure(user_id, details=None):
    """Log a failed user login."""
    from app import db, UserLog  # Import inside the function to avoid circular import
    log = UserLog(
        user_id=user_id,
        log_type='login_failure',
        log_timestamp=datetime.utcnow(),
        details=details
    )
    db.session.add(log)
    db.session.commit()

def log_user_request(user_id, details=None):
    """Log when a user creates a request (e.g., submits a form, makes an action)."""
    from app import db, UserLog  # Import inside the function to avoid circular import
    log = UserLog(
        user_id=user_id,
        log_type='user_request',
        log_timestamp=datetime.utcnow(),
        details=details
    )
    db.session.add(log)
    db.session.commit()

def log_custom_action(user_id, log_type, details=None):
    """Log a custom user action with a specified log_type."""
    from app import db, UserLog  # Import inside the function to avoid circular import
    log = UserLog(
        user_id=user_id,
        log_type=log_type,
        log_timestamp=datetime.utcnow(),
        details=details
    )
    db.session.add(log)

    db.session.commit()