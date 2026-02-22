from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import re

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """User model with role-based access and 2FA"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='buyer')
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_code = db.Column(db.String(6))
    two_factor_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    products = db.relationship('Product', backref='seller', lazy=True, foreign_keys='Product.seller_id')
    orders = db.relationship('Order', backref='buyer', lazy=True)
    cart_items = db.relationship('CartItem', backref='user', lazy=True, cascade='all, delete-orphan')
    favorites = db.relationship('Favorite', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_2fa_code(self):
        from datetime import timedelta
        self.two_factor_code = str(secrets.randbelow(999999)).zfill(6)
        self.two_factor_expiry = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()
        return self.two_factor_code
    
    def verify_2fa_code(self, code):
        if not self.two_factor_code or not self.two_factor_expiry:
            return False
        if datetime.utcnow() > self.two_factor_expiry:
            return False
        return self.two_factor_code == code

class Product(db.Model):
    """Product listing with PII detection"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, default=1)
    image_filename = db.Column(db.String(200))
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    visibility = db.Column(db.String(20), default='public')
    pii_scan_status = db.Column(db.String(20), default='pending')
    
    cart_items = db.relationship('CartItem', backref='product', lazy=True)
    favorites = db.relationship('Favorite', backref='product', lazy=True)
    
    @staticmethod
    def detect_pii(text):
        """SECURITY FEATURE: Detect Personal Identifiable Information"""
        violations = []
        
        # Singapore NRIC pattern
        nric_pattern = r'\b[STFG]\d{7}[A-Z]\b'
        if re.search(nric_pattern, text, re.IGNORECASE):
            violations.append('NRIC number detected')
        
        # Phone number patterns
        phone_patterns = [
            r'\b[689]\d{7}\b',
            r'\b\+65[689]\d{7}\b',
            r'\b\d{4}[-\s]?\d{4}\b',
        ]
        for pattern in phone_patterns:
            if re.search(pattern, text):
                violations.append('Phone number detected')
                break
        
        # Email pattern
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        if re.search(email_pattern, text):
            violations.append('Email address detected')
        
        # Singapore postal code
        postal_pattern = r'\b\d{6}\b'
        if re.search(postal_pattern, text):
            violations.append('Postal code detected')
        
        # Address keywords
        address_keywords = ['blk', 'block', 'street', 'road', 'avenue', 'drive', 'singapore']
        text_lower = text.lower()
        if any(keyword in text_lower for keyword in address_keywords):
            if re.search(r'(blk|block)\s*\d+', text_lower) or re.search(r'\d+\s+(street|road|avenue)', text_lower):
                violations.append('Address information detected')
        
        return (len(violations) == 0, violations)

class CartItem(db.Model):
    """Shopping cart items"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

class Favorite(db.Model):
    """User favorites/likes"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('user_id', 'product_id', name='unique_favorite'),)

class Order(db.Model):
    """Order with shipping and 2FA verification"""
    id = db.Column(db.Integer, primary_key=True)
    order_number = db.Column(db.String(50), unique=True, nullable=False)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shipping_name = db.Column(db.String(100))
    shipping_phone = db.Column(db.String(20))
    shipping_address = db.Column(db.Text)
    shipping_postal_code = db.Column(db.String(10))
    stripe_payment_intent_id = db.Column(db.String(200))
    total_amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')
    payment_2fa_verified = db.Column(db.Boolean, default=False)
    payment_2fa_code = db.Column(db.String(6))
    payment_2fa_attempts = db.Column(db.Integer, default=0)
    confirmation_sent = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('OrderItem', backref='order', lazy=True, cascade='all, delete-orphan')
    
    @staticmethod
    def generate_order_number():
        return f"ORD-{secrets.token_hex(8).upper()}"

class OrderItem(db.Model):
    """Individual items in an order"""
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_at_purchase = db.Column(db.Float, nullable=False)
    product = db.relationship('Product')

class AuditLog(db.Model):
    """Security audit logging"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    severity = db.Column(db.String(20), default='info')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    @staticmethod
    def log_action(user_id, action, details, ip_address, severity='info'):
        log = AuditLog(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address,
            severity=severity
        )
        db.session.add(log)
        db.session.commit()

class PIIViolation(db.Model):
    """Log PII detection violations"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    violation_type = db.Column(db.String(100))
    detected_content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    action_taken = db.Column(db.String(50))