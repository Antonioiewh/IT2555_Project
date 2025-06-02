from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from datetime import timedelta
import sqlconnect
from sqlalchemy import create_engine,URL
#may be useful later for mysql queries
from sqlalchemy.sql import text
#antonio: impt to ensure can connect to mysql
import cryptography
#antonio: forms
from forms import SignupForm
#antonio: to generate secret KEY to use for CSRF for Flask-WTF
import os
app = Flask(__name__)

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

# --- User Model ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    # Roles stored as a comma-separated string for simplicity
    # In a larger app, you'd use a separate Role model and a many-to-many relationship
    roles = db.Column(db.String(255), default="") # e.g., "user,admin"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, role):
        """Checks if the user has a specific role."""
        return role in self.roles.split(',') if self.roles else False

    def __repr__(self):
        return f'<User {self.username}>'

# --- Flask-Login User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# --- RBAC Decorator ---
def role_required(role):
    """
    Decorator to restrict access to a route based on persistent user roles.
    """
    def decorator(f):
        @wraps(f)
        @login_required # Ensure user is logged in first
        def decorated_function(*args, **kwargs):
            if not current_user.has_role(role):
                flash(f'You do not have the required role: {role}', 'danger')
                return redirect(url_for('dashboard')) # Redirect to a default page or 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required # Anyone logged in can see their dashboard
def dashboard():
    return render_template('dashboard.html', current_user=current_user)

@app.route('/editor_panel')
@role_required('editor') # Only users with 'editor' role
def editor_panel():
    return render_template('editor_panel.html', current_user=current_user)

@app.route('/admin_panel')
@role_required('admin') # Only users with 'admin' role
def admin_panel():
    return render_template('admin_panel.html', current_user=current_user)

# --- Initial Database Setup (for first run) ---
@app.cli.command('initdb')
def initdb_command():
    """Initializes the database and creates a default admin user."""
    with app.app_context(): # Essential for CLI commands to access app context
        db.create_all()
        # Create default users if they don't exist
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', roles='user,editor,admin')
            admin_user.set_password('adminpass')
            db.session.add(admin_user)

        if not User.query.filter_by(username='editor').first():
            editor_user = User(username='editor', roles='user,editor')
            editor_user.set_password('editorpass')
            db.session.add(editor_user)

        if not User.query.filter_by(username='user').first():
            regular_user = User(username='user', roles='user')
            regular_user.set_password('userpass')
            db.session.add(regular_user)

        db.session.commit()
        print('Database initialized and default users created.')

if __name__ == '__main__':
    app.run(debug=True) # debug=True is for development only!