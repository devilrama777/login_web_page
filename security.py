import secrets
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import request, session, abort, current_app
from config import Config
from database import query_db, execute_db, log_audit_event

def generate_csrf_token():
    """Generate or retrieve the session CSRF token."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_urlsafe(32)
    return session['_csrf_token']

def validate_csrf_token(token):
    """Verify submitted CSRF token matches session token."""
    stored_token = session.get('_csrf_token')
    if not stored_token or not token:
        return False
    return secrets.compare_digest(stored_token, token)

def validate_password_strength(password):
    """
    Validate password complexity (Roadmap 02):
    - At least 8 characters
    - At least 1 uppercase
    - At least 1 lowercase
    - At least 1 digit
    - At least 1 special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit (0-9)."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\/`~]", password):
        return False, "Password must contain at least one special character."
    return True, "Password meets all security criteria."

def validate_email_format(email):
    """Validate email address format."""
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return False, "Invalid email address format."
    return True, "Valid email."

def validate_username_format(username):
    """Validate username (3-30 chars, alphanumeric + underscores/hyphens)."""
    if not re.match(r'^[a-zA-Z0-9_.-]{3,30}$', username):
        return False, "Username must be 3-30 characters and contain only letters, numbers, dots, hyphens, or underscores."
    return True, "Valid username."

def check_account_lockout(user):
    """
    Check if the user account is temporarily locked due to failed attempts (Roadmap 05 & 07).
    """
    if not user:
        return False, 0
        
    locked_until = user['locked_until']
    if locked_until:
        try:
            lock_dt = datetime.fromisoformat(locked_until)
            if datetime.now() < lock_dt:
                remaining_mins = int((lock_dt - datetime.now()).total_seconds() / 60) + 1
                return True, remaining_mins
            else:
                # Lockout expired, reset attempts
                execute_db('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?', (user['id'],))
        except (ValueError, TypeError):
            pass
            
    return False, 0

def record_failed_login(user_id, ip_address, user_agent):
    """
    Increment failed login count and trigger lockout if threshold reached.
    """
    user = query_db('SELECT failed_login_attempts FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return
        
    new_count = (user['failed_login_attempts'] or 0) + 1
    
    if new_count >= Config.MAX_FAILED_LOGIN_ATTEMPTS:
        lock_until = (datetime.now() + timedelta(minutes=Config.LOCKOUT_DURATION_MINUTES)).isoformat()
        execute_db('''
            UPDATE users 
            SET failed_login_attempts = ?, locked_until = ? 
            WHERE id = ?
        ''', (new_count, lock_until, user_id))
        
        log_audit_event(
            user_id=user_id,
            action='ACCOUNT_LOCKED',
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Locked for {Config.LOCKOUT_DURATION_MINUTES} mins after {new_count} failed attempts."
        )
    else:
        execute_db('UPDATE users SET failed_login_attempts = ? WHERE id = ?', (new_count, user_id))
        log_audit_event(
            user_id=user_id,
            action='LOGIN_FAILED',
            ip_address=ip_address,
            user_agent=user_agent,
            details=f"Failed attempt {new_count}/{Config.MAX_FAILED_LOGIN_ATTEMPTS}"
        )

def reset_failed_login(user_id):
    """Reset failed login attempts on successful authentication."""
    execute_db('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?', (user_id,))

def apply_security_headers(response):
    """
    Apply comprehensive HTTP Security Headers (Roadmap 07).
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # Modern Content Security Policy (allows inline styles/scripts used for smooth UI animations & font awesome / google fonts)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    
    # If running with HTTPS, enforce HSTS
    if request.is_secure or Config.SESSION_COOKIE_SECURE:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
    return response
