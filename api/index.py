import sys
import os
import traceback

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from datetime import datetime, timedelta
    from flask import Flask, render_template, request, redirect, url_for, flash, session, g, jsonify, abort
    from config import Config
    from database import init_db, query_db, execute_db, log_audit_event
    from security import (
        generate_csrf_token, validate_csrf_token, validate_password_strength,
        validate_email_format, validate_username_format, check_account_lockout,
        record_failed_login, reset_failed_login, apply_security_headers
    )
    from auth import (
        create_user, get_user_by_id, get_user_by_identifier, verify_password,
        generate_totp_qr_data_url, verify_totp_code, generate_and_send_email_otp,
        verify_email_otp, create_user_session, validate_current_session,
        terminate_user_session, login_required
    )
    from email_service import get_dev_latest_otp

    BASE_DIR = root_dir

    app = Flask(
        __name__,
        template_folder=os.path.join(BASE_DIR, 'templates'),
        static_folder=os.path.join(BASE_DIR, 'static')
    )
    app.config.from_object(Config)

    import urllib.parse
    from werkzeug.middleware.proxy_fix import ProxyFix
    from werkzeug.exceptions import HTTPException

    class VercelPrefixMiddleware:
        """Normalize PATH_INFO from real request path on Vercel."""
        def __init__(self, wsgi_app):
            self.wsgi_app = wsgi_app

        def __call__(self, environ, start_response):
            # 1. Parse __path from Vercel query string rewrite
            query_string = environ.get('QUERY_STRING', '')
            if '__path=' in query_string:
                params = urllib.parse.parse_qs(query_string)
                if '__path' in params and params['__path']:
                    subpath = params['__path'][0].lstrip('/')
                    environ['PATH_INFO'] = '/' + subpath if subpath else '/'
                    return self.wsgi_app(environ, start_response)
            
            # 2. Fallback to standard path candidates
            path = environ.get('PATH_INFO', '')
            if path.startswith('/api/index.py'):
                path = path[13:] or '/'
            elif path.startswith('/api/index'):
                path = path[10:] or '/'
            elif path.startswith('/api'):
                path = path[4:] or '/'
                
            environ['PATH_INFO'] = path or '/'
            return self.wsgi_app(environ, start_response)

    app.wsgi_app = ProxyFix(VercelPrefixMiddleware(app.wsgi_app), x_for=1, x_proto=1, x_host=1, x_prefix=1)

    @app.before_request
    def security_middleware():
        """
        Execute security checks and CSRF validation before every request (Roadmap 07).
        """
        # 0. Ensure database tables exist safely on first request
        if not getattr(app, '_db_initialized', False):
            try:
                init_db()
                app._db_initialized = True
            except Exception as e:
                print(f"[DB INIT ERROR] {e}")

        # 1. CSRF Protection for unsafe HTTP methods
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not validate_csrf_token(token):
                flash("Security check failed (CSRF token missing or expired). Please try again.", "danger")
                return redirect(request.referrer or url_for('login'))
                
        # 2. Check session expiry for authenticated users
        g.current_user = validate_current_session()

    @app.after_request
    def add_security_headers(response):
        """Inject HTTP hardening headers to response (Roadmap 07)."""
        return apply_security_headers(response)

    @app.context_processor
    def inject_template_globals():
        """Provide helper variables to all Jinja templates."""
        return {
            'csrf_token': generate_csrf_token,
            'current_user': g.get('current_user'),
            'app_name': Config.APP_NAME,
            'now': datetime.now
        }

    # ----------------------------------------------------------------------
    # Authentication Routes
    # ----------------------------------------------------------------------

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """
        User registration route (Roadmap 02).
        Validates input, enforces password policy, hashes password, and initializes MFA.
        """
        if g.get('current_user'):
            return redirect(url_for('dashboard'))
            
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')
            mfa_type = request.form.get('mfa_type', 'email')
            
            # Validations
            valid_u, msg_u = validate_username_format(username)
            if not valid_u:
                flash(msg_u, 'danger')
                return render_template('register.html', username=username, email=email, mfa_type=mfa_type)
                
            valid_e, msg_e = validate_email_format(email)
            if not valid_e:
                flash(msg_e, 'danger')
                return render_template('register.html', username=username, email=email, mfa_type=mfa_type)
                
            if password != confirm_password:
                flash("Passwords do not match. Please re-enter.", 'danger')
                return render_template('register.html', username=username, email=email, mfa_type=mfa_type)
                
            valid_p, msg_p = validate_password_strength(password)
            if not valid_p:
                flash(msg_p, 'danger')
                return render_template('register.html', username=username, email=email, mfa_type=mfa_type)
                
            # Check uniqueness
            if query_db('SELECT id FROM users WHERE LOWER(username) = ?', (username.lower(),), one=True):
                flash("Username is already taken. Please choose another.", 'danger')
                return render_template('register.html', username=username, email=email, mfa_type=mfa_type)
                
            if query_db('SELECT id FROM users WHERE LOWER(email) = ?', (email,), one=True):
                flash("An account with this email address already exists.", 'danger')
                return render_template('register.html', username=username, email=email, mfa_type=mfa_type)
                
            # Create user
            try:
                user_id = create_user(username, email, password, mfa_type=mfa_type)
                user = get_user_by_id(user_id)
                
                if mfa_type == 'totp':
                    session['pre_auth_user_id'] = user_id
                    session['pre_auth_expires'] = (datetime.now() + timedelta(minutes=10)).isoformat()
                    flash("Account registered successfully! Now scan the QR code to finish TOTP MFA setup.", "success")
                    return redirect(url_for('mfa_setup'))
                else:
                    flash("Registration successful! You can now sign in with your credentials.", "success")
                    return redirect(url_for('login'))
                    
            except Exception as e:
                flash(f"An unexpected error occurred during registration: {str(e)}", 'danger')
                return render_template('register.html', username=username, email=email, mfa_type=mfa_type)
                
        return render_template('register.html', mfa_type='email')

    @app.route('/', methods=['GET', 'POST'])
    @app.route('/index', methods=['GET', 'POST'])
    @app.route('/api/index', methods=['GET', 'POST'])
    @app.route('/api', methods=['GET', 'POST'])
    def index():
        """Root endpoint that delegates directly to login handler."""
        return login()

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        """
        Login route with MFA challenge trigger and brute-force protection (Roadmap 03 & 05).
        """
        if g.get('current_user'):
            return redirect(url_for('dashboard'))
            
        if request.method == 'POST':
            identifier = request.form.get('identifier', '').strip()
            password = request.form.get('password', '')
            
            if not identifier or not password:
                flash("Please enter both your identifier (username or email) and password.", "danger")
                return render_template('login.html', identifier=identifier)
                
            user = get_user_by_identifier(identifier)
            
            # Check Account Lockout
            is_locked, remaining_mins = check_account_lockout(user)
            if is_locked:
                flash(f"Account is temporarily locked due to multiple failed login attempts. Please try again in {remaining_mins} minute(s).", "danger")
                return render_template('login.html', identifier=identifier)
                
            # Verify credentials
            if not user or not verify_password(user['password_hash'], password):
                if user:
                    record_failed_login(user['id'], request.remote_addr, request.headers.get('User-Agent'))
                else:
                    log_audit_event(
                        user_id=None,
                        action='LOGIN_FAILED',
                        ip_address=request.remote_addr,
                        user_agent=request.headers.get('User-Agent'),
                        details=f"Unknown identifier attempted: {identifier}"
                    )
                flash("Invalid credentials. Please verify your username/email and password.", "danger")
                return render_template('login.html', identifier=identifier)
                
            # Reset failed login count on successful password entry
            reset_failed_login(user['id'])
            
            # Check MFA requirement
            if user['is_mfa_enabled']:
                # Store temporary pre-auth state in server-side session (5 min limit)
                session['pre_auth_user_id'] = user['id']
                session['pre_auth_expires'] = (datetime.now() + timedelta(minutes=5)).isoformat()
                
                if user['mfa_type'] == 'email':
                    success, msg, otp = generate_and_send_email_otp(user)
                    if success:
                        flash(f"A 6-digit verification code has been sent to your email ({user['email']}).", "info")
                    else:
                        flash(f"Notice: {msg}", "warning")
                elif user['mfa_type'] == 'totp':
                    flash("Please enter the 6-digit security code from your Authenticator app.", "info")
                    
                return redirect(url_for('mfa_verify'))
            else:
                # Direct login without MFA (if disabled)
                create_user_session(user)
                flash(f"Welcome back, {user['username']}!", "success")
                return redirect(url_for('dashboard'))
                
        return render_template('login.html')

    @app.route('/mfa/verify', methods=['GET', 'POST'])
    def mfa_verify():
        """
        OTP and TOTP verification route (Roadmap 04).
        Validates code, enforces single-use, and promotes session to fully authenticated state.
        """
        user_id = session.get('pre_auth_user_id')
        expires = session.get('pre_auth_expires')
        
        if not user_id or not expires:
            flash("MFA session expired or missing. Please sign in again.", "warning")
            return redirect(url_for('login'))
            
        try:
            if datetime.now() > datetime.fromisoformat(expires):
                session.pop('pre_auth_user_id', None)
                session.pop('pre_auth_expires', None)
                flash("MFA verification session expired. Please sign in again.", "warning")
                return redirect(url_for('login'))
        except Exception:
            pass
            
        user = get_user_by_id(user_id)
        if not user:
            session.clear()
            return redirect(url_for('login'))
            
        if request.method == 'POST':
            # Collect 6-box input or single input
            code_parts = [request.form.get(f'code_{i}', '') for i in range(1, 7)]
            code = "".join(code_parts) if any(code_parts) else request.form.get('code', '')
            code = code.replace(" ", "").strip()
            
            if not code or len(code) != 6:
                flash("Please enter the complete 6-digit verification code.", "danger")
                return render_template('mfa_verify.html', user=user)
                
            # Verify according to MFA type
            if user['mfa_type'] == 'totp':
                is_valid, msg = verify_totp_code(user, code)
            else:
                is_valid, msg = verify_email_otp(user, code)
                
            if is_valid:
                # Invalidate pre-auth state
                session.pop('pre_auth_user_id', None)
                session.pop('pre_auth_expires', None)
                
                # Create full authenticated session
                create_user_session(user)
                log_audit_event(
                    user_id=user['id'],
                    action='MFA_SUCCESS',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    details=f"MFA verified via {user['mfa_type']}"
                )
                flash(f"MFA verification successful! Welcome, {user['username']}.", "success")
                return redirect(url_for('dashboard'))
            else:
                log_audit_event(
                    user_id=user['id'],
                    action='MFA_FAILED',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    details=f"Invalid OTP entered: {msg}"
                )
                flash(msg, "danger")
                return render_template('mfa_verify.html', user=user)
                
        return render_template('mfa_verify.html', user=user)

    @app.route('/mfa/resend', methods=['POST'])
    def mfa_resend():
        """Resend a new Email OTP (Roadmap 03)."""
        user_id = session.get('pre_auth_user_id')
        if not user_id:
            flash("No active login session found. Please sign in.", "warning")
            return redirect(url_for('login'))
            
        user = get_user_by_id(user_id)
        if not user or user['mfa_type'] != 'email':
            flash("Resend is only applicable for Email OTP.", "warning")
            return redirect(url_for('mfa_verify'))
            
        # Generate and send fresh OTP
        success, msg, otp = generate_and_send_email_otp(user)
        session['pre_auth_expires'] = (datetime.now() + timedelta(minutes=5)).isoformat()
        if success:
            flash(f"A new verification code has been dispatched to {user['email']}.", "info")
        else:
            flash(f"Notice: {msg}", "warning")
        return redirect(url_for('mfa_verify'))

    @app.route('/mfa/setup', methods=['GET', 'POST'])
    def mfa_setup():
        """
        TOTP Authenticator Setup Route: Generates QR Code and verifies first token.
        """
        user = g.get('current_user')
        # Support setup right after registration using pre_auth_user_id
        if not user:
            pre_auth_id = session.get('pre_auth_user_id')
            if pre_auth_id:
                user = get_user_by_id(pre_auth_id)
                
        if not user:
            flash("Please log in to configure Multi-Factor Authentication.", "warning")
            return redirect(url_for('login'))
            
        qr_data_url, secret = generate_totp_qr_data_url(user)
        
        if request.method == 'POST':
            code_parts = [request.form.get(f'code_{i}', '') for i in range(1, 7)]
            code = "".join(code_parts) if any(code_parts) else request.form.get('code', '')
            code = code.replace(" ", "").strip()
            
            is_valid, msg = verify_totp_code(user, code)
            if is_valid:
                execute_db('UPDATE users SET mfa_type = "totp", is_mfa_enabled = 1 WHERE id = ?', (user['id'],))
                log_audit_event(
                    user_id=user['id'],
                    action='MFA_SETUP_COMPLETE',
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    details="TOTP Authenticator app successfully paired."
                )
                
                # If user was in pre-auth mode, log them in
                if session.get('pre_auth_user_id'):
                    session.pop('pre_auth_user_id', None)
                    session.pop('pre_auth_expires', None)
                    create_user_session(user)
                    
                flash("TOTP Authenticator app paired and verified successfully!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid code. Please ensure your authenticator app time is synchronized and try again.", "danger")
                
        return render_template('mfa_setup.html', user=user, qr_data_url=qr_data_url, secret=secret)

    @app.route('/dashboard')
    @login_required
    def dashboard():
        """
        Protected User Dashboard (Roadmap 05 & 06).
        Displays user details, active sessions, and security audit log.
        """
        user = g.current_user
        
        # Fetch recent security audit logs
        audit_logs = query_db('''
            SELECT * FROM audit_logs 
            WHERE user_id = ? 
            ORDER BY id DESC LIMIT 15
        ''', (user['id'],))
        
        # Fetch active sessions
        active_sessions = query_db('''
            SELECT * FROM sessions 
            WHERE user_id = ? AND is_valid = 1 
            ORDER BY id DESC LIMIT 5
        ''', (user['id'],))
        
        return render_template('dashboard.html', user=user, audit_logs=audit_logs, active_sessions=active_sessions)

    @app.route('/mfa/toggle', methods=['POST'])
    @login_required
    def toggle_mfa():
        """Toggle or change MFA method from user dashboard."""
        user = g.current_user
        new_type = request.form.get('mfa_type', 'email')
        
        if new_type not in ('email', 'totp', 'disabled'):
            flash("Invalid MFA selection.", "danger")
            return redirect(url_for('dashboard'))
            
        if new_type == 'disabled':
            execute_db('UPDATE users SET is_mfa_enabled = 0 WHERE id = ?', (user['id'],))
            log_audit_event(user['id'], 'MFA_DISABLED', request.remote_addr, request.headers.get('User-Agent'), "MFA was disabled.")
            flash("MFA has been disabled for your account.", "warning")
        elif new_type == 'totp':
            execute_db('UPDATE users SET is_mfa_enabled = 1 WHERE id = ?', (user['id'],))
            return redirect(url_for('mfa_setup'))
        else: # email
            execute_db('UPDATE users SET mfa_type = "email", is_mfa_enabled = 1 WHERE id = ?', (user['id'],))
            log_audit_event(user['id'], 'MFA_CHANGED', request.remote_addr, request.headers.get('User-Agent'), "MFA changed to Email OTP.")
            flash("MFA method updated to Email OTP.", "success")
            
        return redirect(url_for('dashboard'))

    @app.route('/logout', methods=['GET', 'POST'])
    def logout():
        """
        Secure Logout Route (Roadmap 06).
        Invalidates database session token, clears server-side session, and wipes client cookies.
        """
        terminate_user_session()
        flash("You have been securely signed out.", "info")
        return redirect(url_for('login'))

    @app.route('/api/dev/latest-otp')
    def api_dev_latest_otp():
        """Development API to inspect the latest OTP code for verification testing."""
        if not Config.DEV_EMAIL_FALLBACK:
            abort(404)
        email = request.args.get('email', '').strip().lower()
        otp_data = get_dev_latest_otp(email)
        return jsonify(otp_data or {'status': 'none'})

    @app.errorhandler(500)
    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        if isinstance(error, HTTPException):
            return error
        error_trace = traceback.format_exc()
        print(f"[UNHANDLED EXCEPTION] {error_trace}")
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>System Error</title><style>body{{font-family:sans-serif;background:#090d16;color:#f8fafc;padding:40px;}}pre{{background:#1e293b;padding:20px;border-radius:8px;overflow:auto;color:#f87171;}}</style></head>
        <body>
            <h2>Application Notice (500)</h2>
            <p>An unexpected error occurred:</p>
            <pre>{error}</pre>
            <p><a href="/login" style="color:#38bdf8;">Return to Login</a></p>
        </body>
        </html>
        """, 500

except Exception as startup_error:
    from flask import Flask
    app = Flask(__name__)
    startup_trace = traceback.format_exc()
    
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def fallback_error_route(path):
        return f"""
        <!DOCTYPE html>
        <html>
        <head><title>Startup Error Diagnostic</title></head>
        <body style="background:#090d16;color:#f8fafc;font-family:monospace;padding:30px;">
            <h2 style="color:#ef4444;">Serverless Function Startup Exception:</h2>
            <pre style="background:#1e293b;padding:20px;border-radius:8px;overflow:auto;color:#fca5a5;">{startup_trace}</pre>
        </body>
        </html>
        """, 200

# Export app for Vercel WSGI
application = app
