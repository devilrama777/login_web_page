import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

# Detect Vercel serverless environment
IS_VERCEL = bool(os.environ.get('VERCEL'))

class Config:
    # Core Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'mfa-super-secret-dev-key-change-in-production-38472910')
    APP_NAME = os.environ.get('APP_NAME', 'SecureAuth MFA')
    
    # Database (On Vercel serverless, only /tmp is writable)
    DEFAULT_DB = '/tmp/auth.db' if IS_VERCEL else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'auth.db')
    DB_PATH = os.environ.get('DB_PATH', DEFAULT_DB)
    
    # Session Security (Roadmap 05)
    SESSION_COOKIE_NAME = 'secure_mfa_session'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True' if IS_VERCEL else 'False').lower() in ('true', '1', 't')
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(os.environ.get('SESSION_TIMEOUT_MINUTES', 30)))
    
    # MFA Settings (Roadmap 03 & 04)
    OTP_EXPIRY_SECONDS = int(os.environ.get('OTP_EXPIRY_SECONDS', 300))  # 5 minutes
    MAX_FAILED_LOGIN_ATTEMPTS = int(os.environ.get('MAX_FAILED_LOGIN_ATTEMPTS', 5))
    LOCKOUT_DURATION_MINUTES = int(os.environ.get('LOCKOUT_DURATION_MINUTES', 15))
    MAX_OTP_ATTEMPTS = int(os.environ.get('MAX_OTP_ATTEMPTS', 3))
    
    # HTTP Email API Keys (Ideal for Vercel serverless deployment where SMTP ports are restricted)
    RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '')
    MAIL_FROM = os.environ.get('MAIL_FROM', '')

    # SMTP Configuration (Roadmap 03 smtplib)
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'True').lower() in ('true', '1', 't')
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
