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
from flask import Flask, render_template, redirect, url_for, flash, request, current_app, abort, jsonify, session,make_response,Blueprint
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

# IMPORTANT FOR ROUTES
# NOTE: HREF -> /<prefix>/<orginal_route>
# e.g. /admin/users_dashboard
# NOTE: URL_FOR ->/<blueprint_prefix>.<orginal_route_function>
# e.g. url_for('admin.users_dashboard')
# --- Custom Module Imports ---


# Models
from models import (
    db, User, Role, Permission, Event, EventParticipant, Post, PostImage, PostLike,
    Notification, Report, Chat, ChatParticipant, Message, 
    Friendship, AdminAction, UserLog, ModSecLog, ErrorLog, 
    WebAuthnCredential, user_role_assignments,Event,FriendChatMap,BlockedUser,UserPublicKey, ChatKeyEnvelope


)
from decorators import user_required, admin_required, role_required, admin_or_editor_required


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

# func
from functions import get_relative_time
user_bp = Blueprint('user', __name__, url_prefix='/user')


# Add this after your existing imports
from splunk_logger import splunk_logger

# Add this test route to your user.py
@user_bp.route('/test-logging')
def test_logging():
    """Test route to verify Splunk logging is working"""
    try:
        # Test basic security event
        splunk_logger.log_security_event('test_event', {
            'message': 'This is a test event',
            'timestamp': datetime.now().isoformat(),
            'test_data': 'Hello from Flask'
        }, 'INFO')
        
        # Test login attempt logging
        splunk_logger.log_login_attempt('testuser', True)
        
        # Test access violation logging
        splunk_logger.log_access_violation('/test-resource', 'GET', 'Testing access violation')
        
        flash('Test events sent to Splunk! Check Splunk search.', 'success')
        return render_template('test_logging.html')
        
    except Exception as e:
        flash(f'Logging test failed: {str(e)}', 'error')
        return f"<h1>Logging Error</h1><p>{str(e)}</p><a href='/'>Back</a>"


# -- User security management --
@user_bp.route('/account_security', methods=['GET', 'POST'])
@role_required('user')
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

# --- User Reporting ---
@user_bp.route('/report_user', methods=['GET', 'POST'])
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
                current_app.logger.error("Current user has no user_id - this should not happen")
                flash('Authentication error. Please log in again.', 'error')
                return redirect(url_for('login'))
            
            new_report = Report(
                reporter_id=current_user.user_id, 
                reported_user_id=reported_user.user_id,
                report_type=form.report_type.data,
                description=form.description.data,
                submitted_at=datetime.utcnow(),
                status='open'
            )
            db.session.add(new_report)
            db.session.flush()  # Get the report_id
            
            current_app.logger.info(f"📝 Creating report - Reporter: {current_user.user_id}, Reported: {reported_user.user_id}, Report ID: {new_report.report_id}")
            
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
            
            current_app.logger.info(f"Report #{new_report.report_id} created successfully with notification")
            
            report_submitted = True
            reported_username = reported_user.username
            form = ReportForm()  # Reset form
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"❌ Error creating report: {str(e)}")
            flash('An error occurred while submitting your report. Please try again.', 'error')
            
    return render_template('users/UserReport.html',
                          form=form,
                          report_submitted=report_submitted,
                          reported_username=reported_username)

from functions import send_user_event_reminders
@user_bp.route('/verify_2fa', methods=['GET', 'POST'])
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

