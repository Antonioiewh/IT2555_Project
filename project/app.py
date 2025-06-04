from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import datetime # Keep datetime for datetime.utcnow()

# antonio: forms
from forms import SignupForm,LoginForm # Assuming you have a SignupForm defined

app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

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
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to login if user not authenticated

# --- Models ---

# Association table for User-Role Many-to-Many
user_role_assignments = db.Table('user_role_assignments',
    db.Column('user_id', db.Integer, db.ForeignKey('users.user_id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('roles.role_id'), primary_key=True),
    db.Column('assigned_at', db.DateTime, nullable=False, default=datetime.utcnow)
)

# Association table for Role-Permission Many-to-Many
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.role_id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.permission_id'), primary_key=True)
)


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=True)
    last_name = db.Column(db.String(50), nullable=True)
    profile_pic_url = db.Column(db.String(255), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_active_at = db.Column(db.DateTime, nullable=True)

    roles = db.relationship('Role', secondary=user_role_assignments, backref='users_with_role', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, role_name):
        return self.roles.filter_by(role_name=role_name).first() is not None

    def has_permission(self, permission_name):
        for role in self.roles:
            if role.permissions.filter_by(permission_name=permission_name).first():
                return True
        return False

    def get_id(self):
        return str(self.user_id)

    def __repr__(self):
        return f'<User {self.username}>'


class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)

    permissions = db.relationship('Permission', secondary=role_permissions, backref='roles_with_permission', lazy='dynamic')

    def __repr__(self):
        return f'<Role {self.role_name}>'

class Permission(db.Model):
    __tablename__ = 'permissions'
    permission_id = db.Column(db.Integer, primary_key=True)
    permission_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<Permission {self.permission_name}>'

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
def index():
    return render_template('UserHome.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user)
                flash('Logged in successfully!', 'success')
                next_page = request.args.get('next')
                return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('UserLogin.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', current_user=current_user)

'''
@app.route('/editor_panel')
@permission_required('edit_any_post')
def editor_panel():
    return render_template('editor_panel.html', current_user=current_user)

@app.route('/admin_panel')
@permission_required('view_admin_panel')
def admin_panel():
    return render_template('admin_panel.html', current_user=current_user)


@app.route('/create_post')
@permission_required('create_post')
def create_post():
    return "<h1>Create Post Page (Requires 'create_post' permission)</h1>"
'''

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        phone_number = form.phone_number.data
        password = form.password.data

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or Email already exists. Please choose a different one.', 'danger')
            return redirect(url_for('signup'))

        new_user = User(
            username=username,
            phone_number = phone_number,
            password_hash=generate_password_hash(password),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.session.add(new_user)
        db.session.commit()

        default_role = Role.query.filter_by(role_name='user').first()
        if default_role:
            new_user.roles.append(default_role)
            db.session.commit()
            flash('Your account has been created successfully!', 'success')
            login_user(new_user)
            return redirect(url_for('dashboard'))
        else:
            flash('User account created, but default role not found. Please contact support.', 'warning')
            return redirect(url_for('login'))

    return render_template('UserSignup.html', form=form)


# --- Initial Database Setup (for first run) ---
@app.cli.command('initdb')
def initdb_command():
    """
    Initializes the database by inserting roles, permissions, and default users.
    Assumes database schema is already created by running the .sql file.
    """
    with app.app_context():
        print("Checking for existing roles and permissions...")

        # --- Create Roles if they don't exist ---
        admin_role = Role.query.filter_by(role_name='admin').first()
        if not admin_role:
            admin_role = Role(role_name='admin', description='Full administrative privileges.')
            db.session.add(admin_role)
        editor_role = Role.query.filter_by(role_name='editor').first()
        if not editor_role:
            editor_role = Role(role_name='editor', description='Can manage content and moderate.')
            db.session.add(editor_role)
        user_role = Role.query.filter_by(role_name='user').first()
        if not user_role:
            user_role = Role(role_name='user', description='Standard user with basic application access.')
            db.session.add(user_role)
        guest_role = Role.query.filter_by(role_name='guest').first()
        if not guest_role:
            guest_role = Role(role_name='guest', description='Can view public content only.')
            db.session.add(guest_role)
        db.session.commit() # Commit roles to ensure their IDs are available for permissions

        print("Roles ensured.")

        # --- Create Permissions if they don't exist ---
        # Helper to get or create a permission
        def get_or_create_permission(name, desc):
            perm = Permission.query.filter_by(permission_name=name).first()
            if not perm:
                perm = Permission(permission_name=name, description=desc)
                db.session.add(perm)
            return perm

        manage_users_perm = get_or_create_permission('manage_users', 'Ability to create, update, and delete user accounts.')
        delete_any_post_perm = get_or_create_permission('delete_any_post', 'Ability to delete any post in the system.')
        edit_any_post_perm = get_or_create_permission('edit_any_post', 'Ability to edit any post in the system.')
        create_post_perm = get_or_create_permission('create_post', 'Ability to create new posts.')
        create_event_perm = get_or_create_permission('create_event', 'Ability to create new events/reminders.')
        send_message_perm = get_or_create_permission('send_message', 'Ability to send private messages.')
        view_admin_panel_perm = get_or_create_permission('view_admin_panel', 'Ability to access the administrative dashboard.')
        resolve_reports_perm = get_or_create_permission('resolve_reports', 'Ability to change the status of user-submitted reports.')
        edit_own_post_perm = get_or_create_permission('edit_own_post', 'Ability to edit own posts.')

        db.session.commit() # Commit permissions

        print("Permissions ensured.")

        # --- Assign Permissions to Roles (only if not already assigned) ---
        def assign_permissions_to_role(role_obj, permission_objs):
            existing_perms = {p.permission_name for p in role_obj.permissions}
            for perm_obj in permission_objs:
                if perm_obj.permission_name not in existing_perms:
                    role_obj.permissions.append(perm_obj)
                    print(f"  Assigned '{perm_obj.permission_name}' to '{role_obj.role_name}'")
        
        print("Assigning permissions to roles...")
        assign_permissions_to_role(admin_role, [
            manage_users_perm, delete_any_post_perm, edit_any_post_perm,
            create_post_perm, create_event_perm, send_message_perm,
            view_admin_panel_perm, resolve_reports_perm, edit_own_post_perm
        ])
        assign_permissions_to_role(editor_role, [
            create_post_perm, edit_any_post_perm, delete_any_post_perm,
            create_event_perm, send_message_perm, edit_own_post_perm
        ])
        assign_permissions_to_role(user_role, [
            create_post_perm, create_event_perm, send_message_perm, edit_own_post_perm
        ])
        # Guest role typically gets no special permissions here

        db.session.commit() # Commit role-permission assignments
        print("Role-permission assignments ensured.")


        # --- Create Default Users and Assign Roles (only if they don't exist) ---
        print("Creating/Ensuring default users and their role assignments...")

        # Admin User
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('adminpass'),
                first_name='System', last_name='Admin',
                created_at=datetime.utcnow(), updated_at=datetime.utcnow()
            )
            db.session.add(admin_user)
            db.session.commit() # Commit to get user_id

        if not admin_user.has_role('admin'):
            admin_user.roles.append(admin_role)
            print(f"  Assigned 'admin' role to {admin_user.username}")
        if not admin_user.has_role('user'):
            admin_user.roles.append(user_role) # Can also be a standard user
            print(f"  Assigned 'user' role to {admin_user.username}")


        # Editor User
        editor_user = User.query.filter_by(username='editor').first()
        if not editor_user:
            editor_user = User(
                username='editor',
                email='editor@example.com',
                password_hash=generate_password_hash('editorpass'),
                first_name='Content', last_name='Editor',
                created_at=datetime.utcnow(), updated_at=datetime.utcnow()
            )
            db.session.add(editor_user)
            db.session.commit() # Commit to get user_id

        if not editor_user.has_role('editor'):
            editor_user.roles.append(editor_role)
            print(f"  Assigned 'editor' role to {editor_user.username}")
        if not editor_user.has_role('user'):
            editor_user.roles.append(user_role)
            print(f"  Assigned 'user' role to {editor_user.username}")


        # Standard User
        standard_user = User.query.filter_by(username='standard_user').first()
        if not standard_user:
            standard_user = User(
                username='standard_user',
                email='user@example.com',
                password_hash=generate_password_hash('userpass'),
                first_name='Regular', last_name='User',
                created_at=datetime.utcnow(), updated_at=datetime.utcnow()
            )
            db.session.add(standard_user)
            db.session.commit() # Commit to get user_id

        if not standard_user.has_role('user'):
            standard_user.roles.append(user_role)
            print(f"  Assigned 'user' role to {standard_user.username}")

        db.session.commit() # Final commit for all new assignments
        print('Database initialization script (data insertion) complete.')


# --- Run the App ---
if __name__ == '__main__':
    # When running directly, ensure context is set up for db operations
    with app.app_context():
        # IMPORTANT: DO NOT run initdb_command() here automatically in production!
        # This command should be run manually once via `flask initdb`
        # after your .sql schema has been applied.
        pass

    app.run(debug=True, host='0.0.0.0')