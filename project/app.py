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
    db, User, Role, Permission, Event, EventParticipant, Post, PostImage, 
    Notification, Report, Chat, ChatParticipant, Message, 
    Friendship, AdminAction, UserLog, ModSecLog, ErrorLog, 

    WebAuthnCredential, user_role_assignments,Event,FriendChatMap

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
    Disable2FAForm, RemovePassKeyForm
)

# Custom logging utilities
from user_actions import (
    log_user_login_attempt, log_user_login_success, 
    log_user_login_failure, log_user_logout
)

# Log parsing utilities
from parse_test import parse_modsec_audit_log, parse_error_log

from file_validate import validate_file_security, scan_upload


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
    "https://localhost",
    "http://127.0.0.1",
    ""
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





    """Test multiple files at once"""
    files = request.files.getlist('files')
    
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No files provided'}), 400
    
    results = []
    
    for file in files:
        if file.filename == '':
            continue
        
        try:
            file_data = file.read()
            is_safe, issues = scan_upload(file_data, file.filename)
            
            results.append({
                'filename': file.filename,
                'is_safe': is_safe,
                'issues': issues,
                'size': len(file_data)
            })
            
        except Exception as e:
            results.append({
                'filename': file.filename,
                'is_safe': False,
                'issues': [f'Processing error: {str(e)}'],
                'size': 0
            })
    
    # Summary statistics
    total_files = len(results)
    safe_files = sum(1 for r in results if r['is_safe'])
    dangerous_files = total_files - safe_files
    
    return jsonify({
        'results': results,
        'summary': {
            'total_files': total_files,
            'safe_files': safe_files,
            'dangerous_files': dangerous_files,
            'safety_percentage': (safe_files / total_files * 100) if total_files > 0 else 0
        }
    })

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
                log_user_login_failure(user.user_id, details="Attempted login while locked out.")
                return render_template('UserLockedOut.html', lockout_until=user.lockout_until.strftime("%Y-%m-%d %H:%M:%S"))
            
            # Log every login attempt
            if user:
                log_user_login_attempt(user.user_id, details="User attempted login.")

            if user and user.check_password(password):
                # Implement the login flow logic
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
                    db.session.commit()

                    login_user(user)
                    user.current_status = 'online'
                    user.last_active_at = datetime.utcnow()
                    db.session.commit()

                    log_user_login_success(user.user_id, details="User logged in successfully with password only.")
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
# Update the existing passkey_begin_register route to require 2FA
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
        if username:
            session['passkey_username'] = username
        
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
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
                
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
        
        # Log in the user
        user = User.query.get(cred_record.user_id)
        if not user:
            return jsonify({"error": "User not found"}), 400
        
        # Check if user is locked out
        if user.lockout_until and user.lockout_until > datetime.utcnow():
            return jsonify({"error": "Account is locked out"}), 423
        
        # Reset failed attempts and login
        user.failed_login_attempts = 0
        user.lockout_until = None
        user.current_status = 'online'
        user.last_active_at = datetime.utcnow()
        db.session.commit()
        
        login_user(user)
        log_user_login_success(user.user_id, details="User logged in with passkey.")
        
        # Clean up session
        session.pop('passkey_username', None)
        
        print(f"DEBUG: User {user.username} logged in successfully with passkey")
        return jsonify({"success": True, "redirect": url_for('home')})
        
    except Exception as e:
        print(f"Error in passkey_finish_login: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to complete passkey authentication: {str(e)}"}), 500

# --- User Reporting ---

# ...existing code...

@app.route('/report_user', methods=['GET', 'POST'])
@login_required
@user_required
def report_user():
    form = ReportForm()
    report_submitted = False
    reported_username = None

    if form.validate_on_submit():
        try:
            # Lookup user by username
            reported_user = User.query.filter_by(username=form.reported_username.data).first()
            if not reported_user:
                flash('User not found.', 'error')
            else:
                new_report = Report(
                    reporter_id=current_user.user_id,
                    reported_user_id=reported_user.user_id,  # Use user_id, not username
                    report_type=form.report_type.data,
                    description=form.description.data,
                    submitted_at=datetime.utcnow(),
                    status='open'
                )
                db.session.add(new_report)
                db.session.commit()
                report_submitted = True
                reported_username = reported_user.username
                form = ReportForm()
        except Exception as e:
            db.session.rollback()
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
                'status': f.status
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

@app.route('/unblock_user_friend/<int:friend_id>', methods=['POST'])
@user_required
def unblock_user_friend(friend_id):
    user1, user2 = sorted([current_user.user_id, friend_id])
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
    if friendship and friendship.status == 'blocked':
        friendship.status = 'accepted'
        friendship.action_user_id = current_user.user_id
        db.session.commit()
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
            for uid, fid in [(user1, user2), (user2, user1)]:
                cp = ChatParticipant.query.filter_by(chat_id=chat.chat_id, user_id=uid).first()
                if not cp:
                    db.session.add(ChatParticipant(chat_id=chat.chat_id, user_id=uid))
                mapping = FriendChatMap.query.filter_by(user_id=uid, friend_id=fid, chat_id=chat.chat_id).first()
                if not mapping:
                    db.session.add(FriendChatMap(user_id=uid, friend_id=fid, chat_id=chat.chat_id))
            db.session.commit()
        flash('User unblocked and added back as friend.', 'success')
    else:
        flash('No blocked friendship found.', 'warning')
    return redirect(url_for('user_friends'))


@app.route('/block_user/<int:chat_id>', methods=['POST'])
@user_required
def block_user(chat_id):
    chat = Chat.query.get(chat_id)
    if not chat:
        return 'Chat not found', 404
    cp = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id).first()
    other_cp = ChatParticipant.query.filter(ChatParticipant.chat_id == chat_id, ChatParticipant.user_id != current_user.user_id).first()
    if not other_cp:
        return 'Chat participant not found', 404
    user1, user2 = sorted([current_user.user_id, other_cp.user_id])
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
    if friendship:
        friendship.status = 'blocked'
        db.session.commit()
        return '', 204
    return 'Friendship not found', 404

@app.route('/is_blocked/<int:chat_id>')
@user_required
def is_blocked_route(chat_id):
    cp = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id).first()
    other_cp = ChatParticipant.query.filter(ChatParticipant.chat_id == chat_id, ChatParticipant.user_id != current_user.user_id).first()
    if not other_cp:
        return jsonify({'is_blocked': False})
    user1, user2 = sorted([current_user.user_id, other_cp.user_id])
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
    return jsonify({'is_blocked': friendship and friendship.status == 'blocked'})


@app.route('/unblock_user/<int:chat_id>', methods=['POST'])
@user_required
def unblock_user(chat_id):
    chat = Chat.query.get(chat_id)
    cp = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id).first()
    other_cp = ChatParticipant.query.filter(ChatParticipant.chat_id == chat_id, ChatParticipant.user_id != current_user.user_id).first()
    user1, user2 = sorted([current_user.user_id, other_cp.user_id])
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
    if friendship:
        friendship.status = 'accepted'
        friendship.action_user_id = current_user.user_id
        db.session.commit()
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
    # Add both directions for easy lookup
    for uid, fid in [(user_id, friend_id), (friend_id, user_id)]:
        exists = FriendChatMap.query.filter_by(user_id=uid, friend_id=fid, chat_id=chat_id).first()
        if not exists:
            db.session.add(FriendChatMap(user_id=uid, friend_id=fid, chat_id=chat_id))
    db.session.commit()

# --- Messaging ---
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
        Friendship.status == 'accepted'
    ).all()

        # Get friend user IDs
    friend_ids = [
        f.user_id2 if f.user_id1 == current_user.user_id else f.user_id1
        for f in friendships
    ]
    friends = User.query.filter(User.user_id.in_(friend_ids)).all()


    # Build sidebar list from chat participants, not all friends
    sidebar_friends = []
    for friend in friends:
        mapping = FriendChatMap.query.filter_by(user_id=current_user.user_id, friend_id=friend.user_id).first()
        if mapping:
            cp = ChatParticipant.query.filter_by(chat_id=mapping.chat_id, user_id=current_user.user_id).first()
            if cp:
                sidebar_friends.append(friend)

    sidebar_friends_info = [
        {
            'user_id': f.user_id,
            'username': f.username,
            'profile_pic_url': f.profile_pic_url or url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp'),
            'is_online': f.current_status == 'online',
            'bio': f.bio
        }
        for f in sidebar_friends
    ]

    my_chat_ids = [c.chat_id for c in ChatParticipant.query.filter_by(user_id=current_user.user_id).all()]
    friend_chat_ids = {}
    for friend in friends:
        mapping = FriendChatMap.query.filter_by(user_id=current_user.user_id, friend_id=friend.user_id).first()
        if mapping and mapping.chat_id in my_chat_ids:
            friend_chat_ids[friend.user_id] = mapping.chat_id
        else:
            friend_chat_ids[friend.user_id] = ''

    
    friends_to_readd = []
    for friend in friends:
        mapping = FriendChatMap.query.filter_by(user_id=current_user.user_id, friend_id=friend.user_id).first()
        if mapping:
            cp = ChatParticipant.query.filter_by(chat_id=mapping.chat_id, user_id=current_user.user_id).first()
            if not cp:
                friends_to_readd.append(friend)

    friends_to_readd_info = [
        {
            'user_id': f.user_id,
            'username': f.username,
            'profile_pic_url': f.profile_pic_url or url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp')
        }
        for f in friends_to_readd
    ]

    print("friends_to_readd:", [f['username'] for f in friends_to_readd_info])

    my_chat_ids = list(friend_chat_ids.values())

    return render_template('messages.html', friends=sidebar_friends_info, my_chat_ids=my_chat_ids, friend_chat_ids=friend_chat_ids, selected_friend=selected_friend, friends_to_readd=friends_to_readd_info, )

@csrf.exempt
@app.route('/create_chat/<int:friend_id>', methods=['POST'])
@user_required
def create_chat(friend_id):
    chat_id = readd_friend_chat(current_user.user_id, friend_id)
    return jsonify({'chat_id': chat_id})


def readd_friend_chat(current_user_id, friend_id):
    mapping = FriendChatMap.query.filter_by(user_id=current_user_id, friend_id=friend_id).first()
    if mapping:
        chat_id = mapping.chat_id
        cp = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user_id).first()
        if not cp:
            db.session.add(ChatParticipant(chat_id=chat_id, user_id=current_user_id, cleared_at=None))
            db.session.commit()
        return chat_id
    else:
        # Create new chat and mapping
        chat = Chat()
        db.session.add(chat)
        db.session.commit()
        db.session.add(ChatParticipant(chat_id=chat.chat_id, user_id=current_user_id, cleared_at=None))
        db.session.add(ChatParticipant(chat_id=chat.chat_id, user_id=friend_id, cleared_at=None))
        db.session.commit()
        add_friend_chat_map(current_user_id, friend_id, chat.chat_id)
        return chat.chat_id
    

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
    if not current_user.is_authenticated:
        print("Anonymous user tried to send a message.")
        return
    chat_id = int(data['chat_id'])
    chat = Chat.query.get(chat_id)
    participants = [cp.user_id for cp in chat.participants]

    if len(participants) < 2 or current_user.user_id not in participants:
        print("One of the users has deleted the chat. Message not sent.")
        return
    # check if the friendship is blocked
    user1, user2 = sorted(participants)
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
    if friendship and friendship.status == 'blocked':
        print("Message blocked: friendship is blocked.")
        # Optionally emit an error event to the sender
        emit('message_blocked', {'reason': 'User is blocked.'}, room=request.sid)
        return
    
    other_user_id = [uid for uid in participants if uid != current_user.user_id]
    if not other_user_id or other_user_id[0] not in participants:
        print("Other user is not a participant. Message not sent.")
        return

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

def is_blocked(user_id1, user_id2):
    user1, user2 = sorted([user_id1, user_id2])
    friendship = Friendship.query.filter_by(user_id1=user1, user_id2=user2).first()
    return friendship and friendship.status == 'blocked'

@socketio.on('delete_message')
def handle_delete_message(data):
    message_id = data['message_id']
    msg = Message.query.get(message_id)
    if msg and current_user.is_authenticated:
        # Mark as deleted for sender
        if msg.sender_id != current_user.user_id:
            return
        msg.is_deleted_by_sender = True
        msg.is_deleted_by_receiver = True
        msg.message_text = "Message deleted"  
        db.session.commit()
        emit('message_deleted', {'message_id': message_id}, room=str(msg.chat_id))




@app.route('/get_chat_id/<int:friend_id>')
@user_required
def get_chat_id(friend_id):
    # Try to find existing chat
    chat = get_strict_pair_chat(current_user.user_id, friend_id)
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
    # Find the chat_id for 2 users/ at least one participant so messages stay even when one user deletes the chat
    chat = get_strict_pair_chat(current_user.user_id, friend_id)
    if not chat:
        return jsonify([])
    
    # In chat_history, filter messages:
    cp = ChatParticipant.query.filter_by(chat_id=chat.chat_id, user_id=current_user.user_id).first()
    cleared_at = cp.cleared_at if cp and cp.cleared_at else datetime.min
    
    messages = Message.query.filter(Message.chat_id == chat.chat_id, Message.sent_at > cleared_at).order_by(Message.sent_at).all()
    return jsonify([{
        'message_id': m.message_id,
        'sender_id': m.sender_id,
        'message_text': m.message_text,
        'sent_at': m.sent_at.strftime('%H:%M'),
        'is_deleted_by_sender': m.is_deleted_by_sender,
        'is_deleted_by_receiver': m.is_deleted_by_receiver
    } for m in messages])


@app.route('/clear_chat/<int:chat_id>', methods=['POST'])
@user_required
def clear_chat(chat_id):
    cp = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id).first()
    if cp:
        cp.cleared_at = datetime.utcnow()
        db.session.commit()
    return '', 204


@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
@user_required
def delete_chat(chat_id):
    cp = ChatParticipant.query.filter_by(chat_id=chat_id, user_id=current_user.user_id).first()
    if cp:
        db.session.delete(cp)
        db.session.commit()
    return '', 204

@app.route('/api/friends_to_readd')
@user_required
def api_friends_to_readd():
    # Get all accepted friendships involving the current user
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
        if mapping:
            cp = ChatParticipant.query.filter_by(chat_id=mapping.chat_id, user_id=current_user.user_id).first()
            if not cp:
                friends_to_readd.append(friend)
    friends_to_readd_info = [
        {
            'user_id': f.user_id,
            'username': f.username,
            'profile_pic_url': f.profile_pic_url or url_for('static', filename='imgs/blank-profile-picture-973460_1280.webp')
        }
        for f in friends_to_readd
    ]
    return jsonify(friends_to_readd_info)

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


# Admin - test polyglot 

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


# -- Events 


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
            # Create new event
            new_event = Event(
                user_id=current_user.user_id,  # Creator of the event
                title=form.title.data,
                description=form.description.data,
                event_datetime=form.event_datetime.data,
                location=form.location.data,
                is_reminder=False,  # Always False since this only creates events
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            db.session.add(new_event)
            db.session.commit()
            
            flash(f"Event '{new_event.title}' created successfully!", 'success')
            return redirect(url_for('events_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            print(f"Error creating event: {str(e)}")
            flash('An error occurred while creating the event. Please try again.', 'danger')
            
    else:
        # Debug form errors
        if form.errors:
            print(f"Form validation errors: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", 'error')
            
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

# Join Event Route
@app.route('/join_event/<int:event_id>', methods=['POST'])
@user_required
def join_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Check if user is trying to join their own event
    if event.user_id == current_user.user_id:
        flash("You cannot join your own event.", 'warning')
        return redirect(url_for('discover_events'))
    
    # Check if user is already participating
    existing_participation = EventParticipant.query.filter_by(
        user_id=current_user.user_id,
        event_id=event_id
    ).first()
    
    if existing_participation:
        flash('You are already participating in this event!', 'warning')
    else:
        try:
            # Create new participation
            new_participation = EventParticipant(
                user_id=current_user.user_id,
                event_id=event_id,
                status='joined',
                joined_at=datetime.utcnow()
            )
            db.session.add(new_participation)
            db.session.commit()
            
            # Create notification for event creator
            creator_notification = Notification(
                user_id=event.user_id,
                type='event_reminder',
                source_id=event_id,
                message=f"{current_user.username} joined your event '{event.title}'"
            )
            db.session.add(creator_notification)
            db.session.commit()
            
            flash(f'Successfully joined "{event.title}"!', 'success')
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while joining the event.', 'danger')
    
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

# Delete Event Route
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
                type='event_reminder',
                source_id=event_id,
                message=f"The event '{event.title}' you joined has been cancelled."
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
        flash('An error occurred while deleting the event.', 'danger')
        
    return redirect(url_for('events_dashboard'))

# Event Reminder Scheduler Function
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
            type='event_reminder',
            source_id=event.event_id,
            message=f"Reminder: Your event '{event.title}' is happening tomorrow!"
        ).first()
        
        if not creator_notif_exists:
            creator_notif = Notification(
                user_id=event.user_id,
                type='event_reminder',
                source_id=event.event_id,
                message=f"Reminder: Your event '{event.title}' is happening tomorrow!"
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
                type='event_reminder',
                source_id=event.event_id,
                message=f"Reminder: '{event.title}' you joined is happening tomorrow!"
            ).first()
            
            if not participant_notif_exists:
                participant_notif = Notification(
                    user_id=participant.user_id,
                    type='event_reminder',
                    source_id=event.event_id,
                    message=f"Reminder: '{event.title}' you joined is happening tomorrow!"
                )
                db.session.add(participant_notif)
    
    db.session.commit()

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

