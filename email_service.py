import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import json
import urllib.request
import urllib.error
import logging
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)

# In-memory storage for developer convenience / fallback demo
DEV_LATEST_OTPS = {}

def get_dev_latest_otp(email):
    """Retrieve the most recent OTP for testing convenience."""
    return DEV_LATEST_OTPS.get(email)

def _send_via_resend(recipient_email, otp_code, username, html_content, text_content, subject):
    """Dispatch email via Resend HTTP REST API (Ideal for Vercel / serverless)."""
    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {Config.RESEND_API_KEY.strip()}",
        "Content-Type": "application/json",
        "User-Agent": "SecureAuth-Flask/1.0"
    }
    
    # For Resend free tier without a custom domain, 'from' MUST be 'onboarding@resend.dev'
    from_addr = Config.MAIL_FROM.strip() if Config.MAIL_FROM else ""
    if not from_addr or any(d in from_addr.lower() for d in ('@gmail.', '@yahoo.', '@outlook.', '@hotmail.', '@icloud.')):
        sender = f"{Config.APP_NAME} <onboarding@resend.dev>"
    else:
        sender = from_addr
    
    payload = {
        "from": sender,
        "to": [recipient_email.strip()],
        "subject": subject,
        "html": html_content,
        "text": text_content
    }
    
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=10) as response:
            res_body = response.read().decode('utf-8')
            print(f"[EMAIL SERVICE - RESEND] OTP successfully sent to {recipient_email}. Response: {res_body}")
            return True, "Verification email delivered to your inbox."
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8')
        try:
            err_json = json.loads(err_body)
            err_msg = err_json.get('message', err_body)
        except Exception:
            err_msg = err_body
        print(f"[EMAIL SERVICE ERROR - RESEND] HTTP {e.code}: {err_msg}")
        return False, f"Resend API Error: {err_msg}"
    except Exception as e:
        print(f"[EMAIL SERVICE ERROR - RESEND] {e}")
        return False, f"Resend Error: {str(e)}"

def _send_via_brevo(recipient_email, otp_code, username, html_content, text_content, subject):
    """Dispatch email via Brevo / Sendinblue HTTP REST API."""
    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "api-key": Config.BREVO_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "sender": {"name": Config.APP_NAME, "email": Config.MAIL_FROM or "no-reply@secureauth.local"},
        "to": [{"email": recipient_email, "name": username}],
        "subject": subject,
        "htmlContent": html_content,
        "textContent": text_content
    }
    
    req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
    with urllib.request.urlopen(req, timeout=10) as response:
        if response.status in (200, 201):
            print(f"[EMAIL SERVICE - BREVO] OTP successfully sent to {recipient_email}")
            return True, "Email dispatched via Brevo API."
        else:
            return False, f"Brevo API returned status {response.status}"

def _send_via_smtp(recipient_email, subject, html_content, text_content):
    """Dispatch email via smtplib with automated Port 587 (TLS) / 465 (SSL) fallback."""
    smtp_user = Config.SMTP_USERNAME.strip()
    smtp_pass = Config.SMTP_PASSWORD.replace(" ", "").strip()
    smtp_server = Config.SMTP_SERVER.strip() or 'smtp.gmail.com'
    sender = Config.MAIL_FROM.strip() if Config.MAIL_FROM else smtp_user

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient_email
    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    ports_to_try = [int(Config.SMTP_PORT or 587)]
    if 587 in ports_to_try:
        ports_to_try.append(465)
    elif 465 in ports_to_try:
        ports_to_try.append(587)

    last_error = ""
    for port in ports_to_try:
        try:
            if port == 465:
                with smtplib.SMTP_SSL(smtp_server, port, timeout=12) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_server, port, timeout=12) as server:
                    if Config.SMTP_USE_TLS:
                        server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            print(f"[EMAIL SERVICE - SMTP] Successfully dispatched OTP email to {recipient_email} via port {port}")
            return True, "Verification code sent to your email."
        except smtplib.SMTPAuthenticationError as auth_err:
            last_error = "Gmail Authentication Failed: Please verify that you are using a 16-character Google App Password (not your regular account password)."
            print(f"[EMAIL SERVICE ERROR - SMTP AUTH] {auth_err}")
            break
        except Exception as e:
            last_error = str(e)
            print(f"[EMAIL SERVICE NOTICE] SMTP attempt on port {port} encountered: {e}. Trying alternate port...")

    return False, f"SMTP Delivery Error: {last_error}"

def send_otp_email(recipient_email, otp_code, username="User", expiry_minutes=5):
    """
    Send real-time OTP to recipient email.
    Supports:
    1. Resend HTTP API
    2. Brevo HTTP API
    3. smtplib (Gmail, Outlook, custom SMTP) with automated fallback
    """
    DEV_LATEST_OTPS[recipient_email] = {
        'code': otp_code,
        'timestamp': datetime.now().isoformat(),
        'username': username
    }
    
    subject = f"Your {Config.APP_NAME} Verification Code: {otp_code}"
    
    # HTML formatted email body
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #0f172a; color: #f8fafc; padding: 20px; }}
            .card {{ max-width: 500px; margin: 0 auto; background-color: #1e293b; border-radius: 12px; padding: 32px; border: 1px solid #334155; }}
            .header {{ font-size: 20px; font-weight: bold; color: #38bdf8; margin-bottom: 20px; text-align: center; }}
            .otp-box {{ background: #0f172a; border: 2px dashed #38bdf8; border-radius: 8px; font-size: 32px; font-weight: 800; letter-spacing: 8px; text-align: center; padding: 16px; margin: 24px 0; color: #38bdf8; }}
            .footer {{ font-size: 12px; color: #94a3b8; text-align: center; margin-top: 24px; }}
        </style>
    </head>
    <body>
        <div class="card">
            <div class="header">{Config.APP_NAME} Security</div>
            <p>Hello <strong>{username}</strong>,</p>
            <p>Your one-time multi-factor authentication (MFA) verification code is:</p>
            <div class="otp-box">{otp_code}</div>
            <p>This code will expire in <strong>{expiry_minutes} minutes</strong>. If you did not request this login, please secure your account immediately.</p>
            <div class="footer">
                &copy; {datetime.now().year} {Config.APP_NAME}. Protected with multi-factor authentication.
            </div>
        </div>
    </body>
    </html>
    """
    
    text_content = f"""
    Hello {username},

    Your {Config.APP_NAME} verification code is: {otp_code}

    This code is valid for {expiry_minutes} minutes.
    If you did not request this code, please secure your account immediately.
    """

    # 1. Try Resend HTTP API (if configured)
    if Config.RESEND_API_KEY:
        try:
            success, msg = _send_via_resend(recipient_email, otp_code, username, html_content, text_content, subject)
            if success:
                return True, msg
            print(f"[EMAIL SERVICE NOTICE] Resend delivery returned notice: {msg}. Checking SMTP fallback...")
        except Exception as e:
            print(f"[EMAIL SERVICE ERROR - RESEND] {e}")

    # 2. Try Brevo HTTP API (if configured)
    if Config.BREVO_API_KEY:
        try:
            success, msg = _send_via_brevo(recipient_email, otp_code, username, html_content, text_content, subject)
            if success:
                return True, msg
        except Exception as e:
            print(f"[EMAIL SERVICE ERROR - BREVO] {e}")

    # 3. Try smtplib credentials (Gmail, Outlook, custom SMTP)
    if Config.SMTP_SERVER and Config.SMTP_USERNAME and Config.SMTP_PASSWORD:
        return _send_via_smtp(recipient_email, subject, html_content, text_content)

    # 4. If nothing configured
    err_msg = "No email credentials configured. Please set SMTP_USERNAME and SMTP_PASSWORD (Google App Password) in environment variables."
    print(f"[EMAIL SERVICE WARNING] {err_msg}")
    return False, err_msg
