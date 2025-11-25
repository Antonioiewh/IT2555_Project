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
    banner_url = db.Column(db.String(255), nullable=True)
    bio = db.Column(db.Text, nullable=True)
    current_status = db.Column(db.Enum('online', 'offline', 'suspended', 'terminated'), 
                              nullable=False, default='offline')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_active_at = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.String(32), nullable=True)
    
    # Relationships
    roles = db.relationship('Role', secondary=user_role_assignments,
                            backref=db.backref('users', lazy='dynamic'), lazy='dynamic')
    
    
    created_events = db.relationship('Event', backref='creator', lazy=True, overlaps="user")
    
    posts = db.relationship('Post', back_populates='user', lazy=True)
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
    notifications = db.relationship('Notification', backref='user', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship("PostLike", back_populates="user", cascade="all, delete-orphan")
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
    
    def is_suspended(self):
        """Check if user is suspended"""
        return self.current_status == 'suspended'
    
    def is_terminated(self):
        """Check if user is terminated"""
        return self.current_status == 'terminated'
    
    def can_login(self):
        """Check if user can log in"""
        return self.current_status in ['online', 'offline']
    
    def get_status_display(self):
        """Get human-readable status"""
        status_map = {
            'online': 'Online',
            'offline': 'Offline', 
            'suspended': 'Suspended',
            'terminated': 'Terminated'
        }
        return status_map.get(self.current_status, self.current_status.title())
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
    event_id = db.Column(db.Integer, db.ForeignKey('events.event_id'), nullable=False)  # This is correct
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
    __tablename__ = 'events'  # Change from 'event' to 'events'
    
    event_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)  # Change from 'user.user_id' to 'users.user_id'
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    event_datetime = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(200), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    is_reminder = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships - this will now work correctly
    def __repr__(self):
        return f"<Event {self.title}>"

# **************************************
# 4. Posts
# **************************************
class Post(db.Model):
    __tablename__ = 'posts'
    
    post_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    post_content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship("User", back_populates="posts")
    images = db.relationship("PostImage", back_populates="post", cascade="all, delete-orphan")
    likes = db.relationship("PostLike", back_populates="post", cascade="all, delete-orphan")
    
    def get_like_count(self):
        """Get the number of likes for this post"""
        return len(self.likes)
    
    def is_liked_by_user(self, user_id):
        """Check if a specific user has liked this post"""
        if not user_id:
            return False
        return any(like.user_id == user_id for like in self.likes)
    
    def to_dict(self, current_user_id=None):
        """Convert post to dictionary with like information"""
        return {
            'post_id': self.post_id,
            'user_id': self.user_id,
            'post_content': self.post_content,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'like_count': self.get_like_count(),
            'is_liked': self.is_liked_by_user(current_user_id) if current_user_id else False,
            'user': {
                'user_id': self.user.user_id,
                'username': self.user.username,
                'profile_pic_url': self.user.profile_pic_url
            } if self.user else None,
            'images': [img.to_dict() if hasattr(img, 'to_dict') else {
                'image_id': img.image_id,
                'image_url': img.image_url,
                'order_index': img.order_index
            } for img in self.images] if self.images else []
        }
    
    def __repr__(self):
        return f"<Post {self.post_id} by User {self.user_id}>"
    
class PostImage(db.Model):
    __tablename__ = 'post_images'
    
    image_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.post_id'), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    order_index = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    post = db.relationship("Post", back_populates="images")
    
    def to_dict(self):
        return {
            'image_id': self.image_id,
            'post_id': self.post_id,
            'image_url': self.image_url,
            'order_index': self.order_index,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
    
    def __repr__(self):
        return f"<PostImage {self.image_id} for Post {self.post_id}>"
class PostLike(db.Model):
    __tablename__ = 'post_likes'
    
    like_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.post_id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship("User", back_populates="likes")
    post = db.relationship("Post", back_populates="likes")
    
    # Ensure unique likes per user per post
    __table_args__ = (
        db.UniqueConstraint('user_id', 'post_id', name='unique_user_post_like'),
    )
    
    def to_dict(self):
        return {
            'like_id': self.like_id,
            'user_id': self.user_id,
            'post_id': self.post_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'user': {
                'user_id': self.user.user_id,
                'username': self.user.username,
                'profile_pic_url': self.user.profile_pic_url
            } if self.user else None
        }
    
    def __repr__(self):
        return f"<PostLike User:{self.user_id} Post:{self.post_id}>"

# **************************************
# 5. Notifications
# **************************************
class Notification(db.Model):
    __tablename__ = 'notifications'
    
    notification_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)  
    source_id = db.Column(db.Integer, nullable=True)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    

# **************************************
# 6. Customer Service
# **************************************
class Report(db.Model):
    __tablename__ = 'reports'

    report_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)  # ← FIXED: nullable=False
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
    #chat_secret_key = db.Column(db.String(64), nullable=False, default=lambda: os.urandom(32).hex())

    participants = db.relationship('ChatParticipant', backref='chat', lazy=True)
    messages = db.relationship('Message', backref='chat', lazy=True)

    def __repr__(self):
        return f"<Chat {self.chat_id}>"

class ChatParticipant(db.Model):
    __tablename__ = 'chat_participants'
    chat_participant_id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.chat_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    cleared_at = db.Column(db.DateTime, nullable=True)
    is_in_chat = db.Column(db.Boolean, nullable=False, default=True)
    __table_args__ = (db.UniqueConstraint('chat_id', 'user_id', name='_chat_user_uc'),)

    def __repr__(self):
        return f"<ChatParticipant Chat:{self.chat_id} User:{self.user_id}>"
    
class FriendChatMap(db.Model):
    __tablename__ = 'friend_chat_map'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.chat_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<FriendChatMap user_id={self.user_id} friend_id={self.friend_id} chat_id={self.chat_id}>"

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
    
class BlockedUser(db.Model):
    __tablename__ = 'blocked_users'
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey('users.user_id', ondelete='CASCADE'), nullable=False)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.chat_id', ondelete='SET NULL'), nullable=True)
    reason = db.Column(db.String(255), nullable=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    removed_at = db.Column(db.DateTime, nullable=True)

    # relationships (optional, helpful in ORM usage)
    blocker = db.relationship('User', foreign_keys=[blocker_id], backref=db.backref('blocks_made', lazy='dynamic'))
    blocked = db.relationship('User', foreign_keys=[blocked_id], backref=db.backref('blocks_received', lazy='dynamic'))
    chat = db.relationship('Chat', foreign_keys=[chat_id])

    __table_args__ = (
        db.UniqueConstraint('blocker_id', 'blocked_id', name='uq_blocker_blocked'),
    )

class UserPublicKey(db.Model):
    __tablename__ = 'user_public_keys'
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), primary_key=True)
    alg = db.Column(db.String(32), nullable=False, default='P-256')
    public_key_spki_b64 = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('public_key', uselist=False))

class ChatKeyEnvelope(db.Model):
    __tablename__ = 'chat_key_envelopes'
    id = db.Column(db.Integer, primary_key=True)
    chat_id = db.Column(db.Integer, db.ForeignKey('chats.chat_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    key_version = db.Column(db.Integer, nullable=False, default=1)
    envelope_b64 = db.Column(db.Text, nullable=False)  # chat key encrypted to this user’s public key (base64)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('chat_id', 'user_id', 'key_version', name='uq_chat_user_version'),
    )

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

    sign_count = db.Column(db.Integer, default=0)
    nickname = db.Column(db.String(100), nullable=True)
    added_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Define the relationship here (not in User model with backref)
    user = db.relationship('User', overlaps="webauthn_credentials")
    
    def __repr__(self):
        return f"<WebAuthnCredential {self.credential_id[:10]}...>"
    

class SupportAgent(db.Model):
    """Support agent with clearance levels"""
    __tablename__ = 'support_agents'
    
    agent_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False, unique=True)
    clearance_level = db.Column(db.Integer, nullable=False)  # 1-5 clearance levels
    department = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(255))
    created_by = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    
    # Relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='support_agent_profile')
    created_by_user = db.relationship('User', foreign_keys=[created_by])
    assignments = db.relationship('TicketAssignment', backref='agent', lazy='dynamic')

class TicketCategory(db.Model):
    """Ticket categories with clearance requirements"""
    __tablename__ = 'ticket_categories'
    
    category_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    default_priority = db.Column(db.Enum('low', 'medium', 'high', 'critical', 'security'), default='medium')
    required_clearance = db.Column(db.Integer, nullable=False, default=1)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    tickets = db.relationship('Ticket', backref='category', lazy='dynamic')
    articles = db.relationship('KnowledgeBaseArticle', backref='category', lazy='dynamic')

class Ticket(db.Model):
    """Support tickets with priority-based access control"""
    __tablename__ = 'tickets'
    
    ticket_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('ticket_categories.category_id'), nullable=False)
    priority = db.Column(db.Enum('low', 'medium', 'high', 'critical', 'security'), default='medium')
    status = db.Column(db.Enum('open', 'in_progress', 'pending', 'resolved', 'closed', 'cancelled'), default='open')
    resolution = db.Column(db.Text)
    resolved_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='tickets')
    messages = db.relationship('TicketMessage', backref='ticket', lazy='dynamic', cascade='all, delete-orphan')
    assignments = db.relationship('TicketAssignment', backref='ticket', lazy='dynamic')
    escalations = db.relationship('TicketEscalation', backref='ticket', lazy='dynamic')

class TicketMessage(db.Model):
    """Messages/replies within tickets"""
    __tablename__ = 'ticket_messages'
    
    message_id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.ticket_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_internal = db.Column(db.Boolean, nullable=False, default=False)  # Internal agent notes
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='ticket_messages')

class TicketAssignment(db.Model):
    """Ticket assignments to support agents"""
    __tablename__ = 'ticket_assignments'
    
    assignment_id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.ticket_id'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('support_agents.agent_id'), nullable=False)
    assigned_by = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    assigned_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    
    # Relationships
    assigned_by_user = db.relationship('User', foreign_keys=[assigned_by])

class TicketEscalation(db.Model):
    """Ticket escalation history"""
    __tablename__ = 'ticket_escalations'
    
    escalation_id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.ticket_id'), nullable=False)
    escalated_by = db.Column(db.Integer, db.ForeignKey('support_agents.agent_id'), nullable=False)
    escalated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    previous_priority = db.Column(db.Enum('low', 'medium', 'high', 'critical', 'security'), nullable=False)
    new_priority = db.Column(db.Enum('low', 'medium', 'high', 'critical', 'security'), nullable=False)
    reason = db.Column(db.Text, nullable=False)
    
    # Relationships
    escalated_by_agent = db.relationship('SupportAgent', foreign_keys=[escalated_by])

class KnowledgeBaseArticle(db.Model):
    """Knowledge base articles with clearance-based access"""
    __tablename__ = 'knowledge_base_articles'
    
    article_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('ticket_categories.category_id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    required_clearance = db.Column(db.Integer, nullable=False, default=1)
    is_public = db.Column(db.Boolean, nullable=False, default=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    author = db.relationship('User', backref='authored_articles')