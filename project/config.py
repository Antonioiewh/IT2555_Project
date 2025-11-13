# config.py
import os
import socket
from datetime import timedelta

class Config:
    """Base configuration class"""
    
    # Basic Flask configuration
    TEMPLATES_AUTO_RELOAD = True
    
    # External APIs
    RECAPTCHA_PUBLIC_KEY = os.getenv('RECAPTCHA_PUBLIC_KEY')
    RECAPTCHA_PRIVATE_KEY = os.getenv('RECAPTCHA_PRIVATE_KEY')
    GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY')
    
    # Database configuration
    DB_USER = os.getenv('MYSQL_USER', 'flaskuser')
    DB_PASSWORD = os.getenv('MYSQL_PASSWORD', 'password')
    DB_NAME = os.getenv('MYSQL_DATABASE', 'flaskdb')
    DB_HOST = os.getenv('MYSQL_HOST', 'mysql')
    SQLALCHEMY_DATABASE_URI = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security configuration
    CONTAINER_ID = os.environ.get('HOSTNAME', socket.gethostname())
    BASE_SECRET = os.getenv('SECRET_KEY', 'a_very_secret_key_for_dev')
    SECRET_KEY = f"{BASE_SECRET}-{CONTAINER_ID}"
    
    # Session configuration
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_PERMANENT = False
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_NAME = f'session_{CONTAINER_ID}'
    
    # File upload configuration
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Redis configuration
    REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')
    
    # Allowed domains
    ALLOWED_SESSION_DOMAINS = [
        'localhost',
        '127.0.0.1',
        'glowing-briefly-cicada.ngrok-free.app'
    ]
    
    # SocketIO configuration
    SOCKETIO_CORS_ORIGINS = [
        "http://localhost",
        "https://localhost",
        "http://127.0.0.1",
        "https://127.0.0.1",
        "https://glowing-briefly-cicada.ngrok-free.app"
    ]

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}