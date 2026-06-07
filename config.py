import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///medsecure.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production')
    JWT_ACCESS_TOKEN_EXPIRES = int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 3600))

    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024))
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = 'Lax'

    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = '100/hour'
    RATELIMIT_STORAGE_URL = 'memory://'

    LOG_DIR = 'logs'
    LOG_FILE = 'app.log'
    AUDIT_LOG_FILE = 'audit.log'

    PASSWORD_MIN_LENGTH = 8
    PASSWORD_REQUIRE_SPECIAL = True
    PASSWORD_REQUIRE_UPPER = True
    PASSWORD_REQUIRE_DIGIT = True

    ACCOUNT_LOCKOUT_ATTEMPTS = 5
    ACCOUNT_LOCKOUT_MINUTES = 15

    UPLOAD_SCAN_ENABLED = True
    MAX_FILE_SIZE_MB = 10

    ENCRYPT_UPLOADS = True
    ENCRYPTION_KEY_FILE = 'encryption.key'

    RESET_TOKEN_EXPIRY_HOURS = 1

    SUSPICIOUS_IP_THRESHOLD = 10
    SUSPICIOUS_IP_BLOCK_MINUTES = 60

    SESSION_CHECK_BROWSER = True
    MAX_ACTIVE_SESSIONS = 5

    TWOFA_MAX_ATTEMPTS = 5
    TWOFA_LOCKOUT_MINUTES = 15

    PASSWORD_EXPIRY_DAYS = 90
    SESSION_TIMEOUT_MINUTES = 30
    TRUSTED_DEVICE_DAYS = 30
