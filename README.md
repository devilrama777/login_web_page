# 🛡️ SecureAuth MFA — Python Flask & SQLite Login System with Multi-Factor Authentication

A complete, production-grade, secure Multi-Factor Authentication (MFA) application built strictly with **Python (Flask)** and **SQLite**, supporting **TOTP Authenticator Apps (`pyotp`)** and **Real-Time Email OTP (`smtplib` & Resend API)**.

---

## ✨ Features Implemented (Full 7-Step Roadmap)

| Roadmap Step | Feature Description | Implementation Details |
| :--- | :--- | :--- |
| **01. Setup Flask & SQLite** | Relational schema with foreign keys and indexes | Tables for `users`, `sessions`, `otp_logs`, and `audit_logs` in `database.py`. |
| **02. User Registration** | Secure signup with password hashing | Input validation (regex, length), live password strength meter, salted `scrypt` hashing. |
| **03. Login with MFA** | Two-step credential challenge | Password verification triggers a 5-minute pre-auth challenge with TOTP or Email OTP. |
| **04. OTP Verification** | Time-based and random OTP validation | `pyotp` TOTP with clock drift tolerance + 6-digit Email OTP with expiry and single-use guarantee (`is_used=1`). |
| **05. Secure Sessions** | Hardened session state management | `HttpOnly`, `SameSite=Lax`, database-tracked session tokens, sliding 30-min idle timeout, and account lockout after 5 failed attempts. |
| **06. Secure Logout** | Session invalidation and re-auth | Revocation of database sessions (`is_valid=0`), clearing cookies and memory, `@login_required` route protection. |
| **07. Communication Hardening**| Full defense-in-depth | 100% Parameterized SQLite queries (`?`), cryptographic CSRF tokens, strict CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options`. |

---

## 📁 Project Structure

```
login_page/
├── app.py                # Main Flask application and route handlers
├── config.py             # Security, session, SMTP, and MFA configuration
├── database.py           # SQLite database schema, connections, and audit logger
├── auth.py               # Password hashing, pyotp TOTP, email OTP, and sessions
├── email_service.py      # Resend API & smtplib email dispatcher
├── security.py           # CSRF tokens, rate limiting, lockout defense, CSP headers
├── requirements.txt      # Dependencies (Flask, pyotp, qrcode, pillow, python-dotenv)
├── test_auth_flow.py     # Unit test suite covering core security logic
├── test_e2e_http.py      # End-to-end HTTP lifecycle test suite
├── vercel.json           # Vercel serverless deployment configuration
├── .env.example          # Environment variables template
├── templates/            # Modern Glassmorphic Jinja2 HTML templates
│   ├── base.html         # Base layout with CSRF injection and toasts
│   ├── login.html        # Login card with password reveal
│   ├── register.html     # Registration card with live strength meter
│   ├── mfa_verify.html   # 6-box animated OTP input with clipboard paste
│   ├── mfa_setup.html    # Base64 QR code scanner for Google Authenticator
│   └── dashboard.html    # Protected user portal & live security audit log
└── static/
    ├── css/style.css     # Glassmorphic dark theme, glowing accents, responsive CSS
    └── js/app.js         # 6-box OTP auto-tabbing, clipboard paste, strength meter
```

---

## 🚀 Quick Start Guide

### 1. Clone & Setup Virtual Environment
```powershell
git clone https://github.com/devilrama777/login_web_page.git
cd login_web_page
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and configure your preferences:
```bash
cp .env.example .env
```

### 3. Run the Application
```bash
python app.py
```
Open your browser and navigate to: **`http://127.0.0.1:5000`**

---

## ☁️ Deploying to Vercel

1. Push this repository to GitHub.
2. Import the repository in [Vercel](https://vercel.com).
3. In Project Settings > Environment Variables, add:
   - `SECRET_KEY`: A random strong secret string
   - `RESEND_API_KEY`: Your free Resend API key
4. Deploy!
