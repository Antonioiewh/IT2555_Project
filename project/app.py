from flask import Flask, render_template, redirect, url_for, flash, request, current_app, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import datetime # Keep datetime for datetime.utcnow()
import re
# antonio: forms
from forms import SignupForm,LoginForm,ReportForm,UpdateUserStatusForm # Assuming you have a SignupForm defined

from sqlalchemy.dialects.mysql import ENUM
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

#parsing stufff
from parse_test import parse_modsec_audit_log
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LdQNVsrAAAAAMp8AX4H_J4CwZ5OXVixltEf4RaC'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LdQNVsrAAAAAMOmgh-7Tp-KAwQUQ6iIbi8_pRvM'

# --- Configuration ---
# Use environment variables for database connection
DB_USER = os.getenv('MYSQL_USER', 'flaskuser')
DB_PASSWORD = os.getenv('MYSQL_PASSWORD', 'password')
DB_NAME = os.getenv('MYSQL_DATABASE', 'flaskdb')
DB_HOST = os.getenv('MYSQL_HOST', 'db') # 'db' is the service name in docker-compose

app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secret_key_for_dev') # Change in production!

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login if user not authenticated

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    """Loads a user from the database given their ID."""
    return db.session.get(User, int(user_id))


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
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    log_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f"<UserLog {self.log_type} for User:{self.user_id}>"

class ModSecLog(db.Model): #actually in use
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(50), nullable=False)
    request = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    attack_detected = db.Column(db.Text, nullable=False)

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


# --- Routes ---
# index = home

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

            if user and user.check_password(password):
                login_user(user)
                # --- NEW: Update user status and last active on login ---
                user.current_status = 'online'
                user.last_active_at = datetime.utcnow()
                db.session.commit()
                # --- END NEW ---
                flash('Logged in successfully!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('home'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('UserLogin.html', form=form)

@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        # --- NEW: Update user status on logout ---
        current_user.current_status = 'offline'
        db.session.commit()
        # --- END NEW ---
    logout_user()
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm() # Make sure SignupForm is imported or defined
    if form.validate_on_submit():
        username = form.username.data
        phone_no = form.phone_no.data # Corrected to phone_number
        password = form.password.data

        # 1. REMOVED EMAIL FROM THE EXISTING USER CHECK
        existing_user = User.query.filter(
            (User.username == username) |
            (User.phone_number == phone_no) # Check phone_number as well
        ).first()

        if existing_user:
            # 2. Updated flash message to reflect no email check
            return redirect(url_for('signup'))

        # 3. Ensure 'email' is NOT passed to the User constructor
        new_user = User(
            username=username,
            phone_number=phone_no, # Pass phone_no here
            password_hash=generate_password_hash(password),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()

        default_role = Role.query.filter_by(role_name='user').first() # Ensure 'user' role exists
        if default_role:
            new_user.roles.append(default_role)
            new_user.current_status = 'online' # Set default status to online
            db.session.commit() # Commit again to save the role assignment
            flash('Your account has been created successfully!', 'success')
            login_user(new_user)
            return redirect(url_for('home')) # Redirect to a dashboard or home page after login
        else:
            
            return redirect(url_for('login')) # Redirect to login if role assignment fails

    return render_template('UserSignup.html', form=form)

# --- User Reporting ---

@app.route('/report_user', methods=['GET', 'POST'])
@login_required # Ensure only logged-in users can access this page
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
@login_required
def report_confirmation():
    # You can get the reported_username from the query parameters if passed
    reported_username = request.args.get('reported_username', 'the user')
    return render_template('UserReportConfirmed.html', reported_username=reported_username)



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
        reported_username=reported_username
    )

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
    # When running directly, ensure context is set up for db operations
    with app.app_context():
        # IMPORTANT: DO NOT run initdb_command() here automatically in production!
        # This command should be run manually once via `flask initdb`
        # after your .sql schema has been applied.
        pass

    app.run(debug=True, host='0.0.0.0')