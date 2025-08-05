from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.dialects.mysql import ENUM

# Initialize db here - it will be imported and configured in app.py
db = SQLAlchemy()

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
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.String(32), nullable=True)
    
    # Relationships
    roles = db.relationship('Role', secondary=user_role_assignments,
                            backref=db.backref('users', lazy='dynamic'), lazy='dynamic')
    
    # FIX: Remove the conflicting 'events' relationship and keep only 'created_events'
    # events = db.relationship('Event', backref='user', lazy=True)  # REMOVE THIS LINE
    created_events = db.relationship('Event', backref='creator', lazy=True, overlaps="user")
    
    posts = db.relationship('Post', backref='user', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    submitted_reports = db.relationship(
        'Report',
        primaryjoin="User.user_id == Report.reporter_id",
        backref=db.backref('reporter_obj', lazy=True),
        lazy=True
    )
    received_reports = db.relationship(
        'Report',
        primaryjoin="User.user_id == Report.reported_user_id",
        backref=db.backref('reported_user_obj', lazy=True),
        lazy=True
    )
    chat_participants = db.relationship('ChatParticipant', backref='user', lazy=True)
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    webauthn_credentials = db.relationship('WebAuthnCredential', lazy=True, overlaps="user")
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

class EventParticipant(db.Model):
    __tablename__ = 'event_participants'
    
    participation_id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.event_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    joined_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(ENUM('joined', 'left', 'cancelled', name='participation_status'), nullable=False, default='joined')
    
    __table_args__ = (db.UniqueConstraint('event_id', 'user_id', name='_event_user_uc'),)
    
    # Relationships
    event = db.relationship('Event', backref=db.backref('participants', lazy='dynamic'))
    participant = db.relationship('User', backref=db.backref('event_participations', lazy='dynamic'))
    
    def __repr__(self):
        return f"<EventParticipant Event:{self.event_id} User:{self.user_id}>"

class Event(db.Model):
    __tablename__ = 'events'
    event_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)  # Event creator
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    event_datetime = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(255), nullable=True)
    is_reminder = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    # FIX: Remove the conflicting 'creator' relationship since it's defined in User model
    # creator = db.relationship('User', backref=db.backref('created_events', lazy='dynamic'))  # REMOVE THIS LINE
    
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

    # Relationships
    reporter = db.relationship('User', foreign_keys=[reporter_id],
                               overlaps="reporter_obj,submitted_reports")
    reported_user = db.relationship('User', foreign_keys=[reported_user_id],
                                    overlaps="received_reports,reported_user_obj")

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
    log_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    details = db.Column(db.Text, nullable=True)

class ModSecLog(db.Model):
    __tablename__ = 'ModSecLog'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(50), nullable=False)
    request = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text, nullable=False)
    attack_detected = db.Column(db.Text, nullable=False)

class ErrorLog(db.Model):
    __tablename__ = 'ErrorLog'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    level = db.Column(db.Enum('notice', 'error', 'warning', 'critical'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    client_ip = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f"<ErrorLog id={self.id} date={self.date} time={self.time} level={self.level} client_ip={self.client_ip}>"

# **************************************
# WebAuthn Credentials
# **************************************
class WebAuthnCredential(db.Model):
    __tablename__ = 'webauthn_credentials'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    credential_id = db.Column(db.String(255), unique=True, nullable=False)
    public_key = db.Column(db.LargeBinary, nullable=False)
    sign_count = db.Column(db.Integer, default=0)
    nickname = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Define the relationship here (not in User model with backref)
    user = db.relationship('User', overlaps="webauthn_credentials")
    
    def __repr__(self):
        return f"<WebAuthnCredential {self.credential_id[:10]}...>"