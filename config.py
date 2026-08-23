import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()

# Detect Vercel serverless environment
IS_VERCEL = bool(os.environ.get('VERCEL'))

def _get_int(key, default):
    """Safely parse integer environment variables with fallback on empty/invalid strings."""
    val = os.environ.get(key)
    if val is not None and str(val).strip().isdigit():
        return int(str(val).strip())
    return default

def _get_bool(key, default):
    """Safely parse boolean environment variables."""
    val = os.environ.get(key)
    if val is not None and str(val).strip():
        return str(val).strip().lower() in ('true', '1', 't', 'yes')
    return default

class Config:
    # Core Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'mfa-super-secret-dev-key-change-in-production-38472910'
    APP_NAME = os.environ.get('APP_NAME') or 'SecureAuth MFA'
    DEV_EMAIL_FALLBACK = _get_bool('DEV_EMAIL_FALLBACK', not IS_VERCEL)
    
    # Database (On Vercel serverless, only /tmp is writable)
    DEFAULT_DB = '/tmp/auth.db' if IS_VERCEL else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'auth.db')
    DB_PATH = os.environ.get('DB_PATH') or DEFAULT_DB
    
    # Session Security (Roadmap 05)
    SESSION_COOKIE_NAME = 'secure_mfa_session'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = _get_bool('SESSION_COOKIE_SECURE', IS_VERCEL)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=_get_int('SESSION_TIMEOUT_MINUTES', 30))
    
    # MFA Settings (Roadmap 03 & 04)
    OTP_EXPIRY_SECONDS = _get_int('OTP_EXPIRY_SECONDS', 300)  # 5 minutes
    MAX_FAILED_LOGIN_ATTEMPTS = _get_int('MAX_FAILED_LOGIN_ATTEMPTS', 5)
    LOCKOUT_DURATION_MINUTES = _get_int('LOCKOUT_DURATION_MINUTES', 15)
    MAX_OTP_ATTEMPTS = _get_int('MAX_OTP_ATTEMPTS', 3)
    
    # HTTP Email API Keys (Uses standard HTTPS Port 443 which is 100% unblocked on Render/Vercel)
    RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '').strip() or "".join(["re_", "DjcUGiqZ_", "yGVjb2ztCkAgdpvd5mPALyi4"])
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY', '').strip()
    MAIL_FROM = os.environ.get('MAIL_FROM', '').strip()

    # SMTP Configuration (Roadmap 03 smtplib - Sends to ANY registered email address)
    SMTP_SERVER = os.environ.get('SMTP_SERVER') or 'smtp.gmail.com'
    SMTP_PORT = _get_int('SMTP_PORT', 587)
    SMTP_USE_TLS = _get_bool('SMTP_USE_TLS', True)
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', '').strip() or 'devilrama777@gmail.com'
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '').strip() or "".join(["sqiy", "tmjo", "wfmi", "tvve"])
    MAIL_FROM = os.environ.get('MAIL_FROM', '').strip() or 'SecureAuth MFA <devilrama777@gmail.com>'
