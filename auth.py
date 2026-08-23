import io
import base64
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import session, request, redirect, url_for, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from config import Config
from database import query_db, execute_db, log_audit_event
from email_service import send_otp_email

def hash_password(password):
    """Generate a cryptographically secure hash with salt (scrypt/pbkdf2)."""
    return generate_password_hash(password, method='scrypt')

def verify_password(stored_hash, password):
    """Verify password against stored hash."""
    return check_password_hash(stored_hash, password)

def create_user(username, email, password, mfa_type='email'):
    """
    Register a new user in the database (Roadmap 02).
    Generates a TOTP secret if MFA is set to authenticator app.
    """
    password_h = hash_password(password)
    mfa_secret = pyotp.random_base32() if mfa_type in ('totp', 'both') else None
    
    user_id = execute_db('''
        INSERT INTO users (username, email, password_hash, mfa_secret, mfa_type, is_mfa_enabled)
        VALUES (?, ?, ?, ?, ?, 1)
    ''', (username.strip(), email.strip().lower(), password_h, mfa_secret, mfa_type))
    
    log_audit_event(
        user_id=user_id,
        action='REGISTER',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=f"Registered with MFA type: {mfa_type}"
    )
    return user_id

def get_user_by_id(user_id):
    """Retrieve user record by ID."""
    return query_db('SELECT * FROM users WHERE id = ?', (user_id,), one=True)

def get_user_by_identifier(identifier):
    """Retrieve user record by username or email."""
    identifier_clean = identifier.strip().lower()
    return query_db('SELECT * FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?', 
                    (identifier_clean, identifier_clean), one=True)

def generate_totp_qr_data_url(user):
    """
    Generate TOTP setup provisioning URI and Base64 QR Code image for Authenticator apps.
    """
    secret = user['mfa_secret']
    if not secret:
        secret = pyotp.random_base32()
        execute_db('UPDATE users SET mfa_secret = ? WHERE id = ?', (secret, user['id']))
        
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user['email'],
        issuer_name=Config.APP_NAME
    )
    
    # Create QR Code image in memory
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=3,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    qr_data_url = f"data:image/png;base64,{qr_b64}"
    
    return qr_data_url, secret

def verify_totp_code(user, code):
    """
    Verify Time-based One-Time Password using pyotp (Roadmap 04).
    Validates token with a tolerance window for slight clock drift.
    """
    if not user['mfa_secret']:
        return False, "TOTP not configured for this user."
        
    totp = pyotp.TOTP(user['mfa_secret'])
    cleaned_code = str(code).replace(" ", "").strip()
    
    # Verify with 1 interval clock skew tolerance (30 seconds before/after)
    is_valid = totp.verify(cleaned_code, valid_window=1)
    
    if is_valid:
        # Record OTP verification log
        execute_db('''
            INSERT INTO otp_logs (user_id, otp_code, otp_type, expires_at, is_used)
            VALUES (?, ?, 'totp', datetime('now', '+30 seconds'), 1)
        ''', (user['id'], 'TOTP_USED'))
        return True, "TOTP verified successfully."
    else:
        return False, "Invalid authenticator code. Please check your Authenticator app and try again."

def generate_and_send_email_otp(user):
    """
    Generate random 6-digit OTP, store in database with expiry, and send via smtplib (Roadmap 03 & 04).
    """
    # Invalidate previous unconsumed OTPs for this user
    execute_db('UPDATE otp_logs SET is_used = 1 WHERE user_id = ? AND otp_type = "email" AND is_used = 0', (user['id'],))
    
    # Generate cryptographically secure 6-digit code
    otp_code = f"{secrets.randbelow(1000000):06d}"
    expires_at = (datetime.now() + timedelta(seconds=Config.OTP_EXPIRY_SECONDS)).isoformat()
    
    execute_db('''
        INSERT INTO otp_logs (user_id, otp_code, otp_type, expires_at, is_used, attempts)
        VALUES (?, ?, 'email', ?, 0, 0)
    ''', (user['id'], otp_code, expires_at))
    
    # Send via SMTP service
    success, msg = send_otp_email(user['email'], otp_code, user['username'], Config.OTP_EXPIRY_SECONDS // 60)
    
    log_audit_event(
        user_id=user['id'],
        action='MFA_SENT',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=f"Email OTP sent to {user['email']} (Status: {'Success' if success else msg})"
    )
    return success, msg, otp_code

def verify_email_otp(user, submitted_code):
    """
    Validate 6-digit email OTP (Roadmap 04).
    Ensures one-time use, checks expiry, and enforces attempt limits.
    """
    cleaned_code = str(submitted_code).replace(" ", "").strip()
    
    # Fetch active unexpired OTP log
    active_otp = query_db('''
        SELECT * FROM otp_logs 
        WHERE user_id = ? AND otp_type = 'email' AND is_used = 0 
        ORDER BY id DESC LIMIT 1
    ''', (user['id'],), one=True)
    
    if not active_otp:
        return False, "No active verification code found. Please request a new code."
        
    # Check attempt threshold
    if active_otp['attempts'] >= Config.MAX_OTP_ATTEMPTS:
        execute_db('UPDATE otp_logs SET is_used = 1 WHERE id = ?', (active_otp['id'],))
        return False, "Maximum verification attempts exceeded for this code. Please request a new one."
        
    # Check expiration
    try:
        exp_dt = datetime.fromisoformat(active_otp['expires_at'])
        if datetime.now() > exp_dt:
            execute_db('UPDATE otp_logs SET is_used = 1 WHERE id = ?', (active_otp['id'],))
            return False, "Verification code has expired. Please request a fresh code."
    except Exception:
        pass
        
    # Verify code match using constant-time comparison
    if secrets.compare_digest(active_otp['otp_code'], cleaned_code):
        # Mark as used immediately (prevent replay attacks)
        execute_db('UPDATE otp_logs SET is_used = 1 WHERE id = ?', (active_otp['id'],))
        return True, "Email OTP verified successfully."
    else:
        # Increment attempt counter
        execute_db('UPDATE otp_logs SET attempts = attempts + 1 WHERE id = ?', (active_otp['id'],))
        remaining = Config.MAX_OTP_ATTEMPTS - (active_otp['attempts'] + 1)
        return False, f"Incorrect verification code. {remaining} attempt(s) remaining."

def create_user_session(user):
    """
    Create a secure session in database and Flask session (Roadmap 05).
    """
    session_token = secrets.token_hex(32)
    expires_at = (datetime.now() + Config.PERMANENT_SESSION_LIFETIME).isoformat()
    
    execute_db('''
        INSERT INTO sessions (user_id, session_token, ip_address, user_agent, expires_at, is_valid)
        VALUES (?, ?, ?, ?, ?, 1)
    ''', (user['id'], session_token, request.remote_addr, request.headers.get('User-Agent'), expires_at))
    
    session.clear()
    session.permanent = True
    session['user_id'] = user['id']
    session['session_token'] = session_token
    session['logged_in_at'] = datetime.now().isoformat()
    
    log_audit_event(
        user_id=user['id'],
        action='LOGIN_SUCCESS',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details="Full MFA authentication successful."
    )
    return session_token

def validate_current_session():
    """
    Check if the current request session is valid and active in the database (Roadmap 05).
    """
    user_id = session.get('user_id')
    session_token = session.get('session_token')
    
    if not user_id or not session_token:
        return None
        
    db_session = query_db('''
        SELECT * FROM sessions 
        WHERE user_id = ? AND session_token = ? AND is_valid = 1
    ''', (user_id, session_token), one=True)
    
    if not db_session:
        session.clear()
        return None
        
    # Check session expiration
    try:
        exp_dt = datetime.fromisoformat(db_session['expires_at'])
        if datetime.now() > exp_dt:
            # Session expired
            execute_db('UPDATE sessions SET is_valid = 0 WHERE id = ?', (db_session['id'],))
            session.clear()
            return None
    except Exception:
        pass
        
    # Refresh expiration for sliding session
    new_expires_at = (datetime.now() + Config.PERMANENT_SESSION_LIFETIME).isoformat()
    execute_db('UPDATE sessions SET expires_at = ? WHERE id = ?', (new_expires_at, db_session['id']))
    
    user = get_user_by_id(user_id)
    return user

def terminate_user_session():
    """
    Securely invalidate the current session in database and cookies (Roadmap 06).
    """
    user_id = session.get('user_id')
    session_token = session.get('session_token')
    
    if user_id and session_token:
        execute_db('''
            UPDATE sessions 
            SET is_valid = 0 
            WHERE user_id = ? AND session_token = ?
        ''', (user_id, session_token))
        
        log_audit_event(
            user_id=user_id,
            action='LOGOUT',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            details="User logged out cleanly."
        )
        
    session.clear()

def login_required(f):
    """Decorator to enforce authenticated session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = validate_current_session()
        if not user:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for('login', next=request.path))
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function
