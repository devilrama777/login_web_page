# 🛡️ SecureAuth MFA — Multi-Factor Authentication Web Portal

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/SQLite-3-003B57.svg?logo=sqlite&logoColor=white)](https://sqlite.org)
[![Security](https://img.shields.io/badge/Security-MFA%20%7C%20TOTP%20%7C%20CSRF%20%7C%20CSP-success.svg)](https://owasp.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A modern, production-ready, secure **Multi-Factor Authentication (MFA)** web portal built strictly with **Python (Flask)** and **SQLite**. Supports **TOTP Authenticator Apps (Google Authenticator / Microsoft Authenticator)** and **Real-Time Email OTP delivery (Gmail SMTP / Resend API)** wrapped in a responsive Glassmorphic UI.

---

## 🌐 Live Deployments

- 🚀 **PythonAnywhere Live**: [https://devilrama.pythonanywhere.com/](https://devilrama.pythonanywhere.com/)
- ⚡ **Render Live**: [https://login-web-page-4r6f.onrender.com/](https://login-web-page-4r6f.onrender.com/)

---

## ✨ Features & Architecture

| Feature Category | Capabilities & Implementation |
| :--- | :--- |
| 🔐 **Authentication & Security** | Salted `scrypt` password hashing via Werkzeug, live client-side password strength meter, case-insensitive identifier lookup, account lockout defense after 5 failed attempts. |
| 📲 **Multi-Factor Auth (MFA)** | **TOTP Authenticator App** (`pyotp`) with QR code provisioning (`qrcode`), and **Real-time 6-digit Email OTP** with single-use enforcement (`is_used=1`) and 5-minute expiration. |
| 🛡️ **Defense-in-Depth** | 100% Parameterized SQLite queries (`?`), Cryptographic CSRF tokens on all state-changing forms, Strict Content Security Policy (CSP), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`. |
| 🗄️ **Persistent Storage & Audit** | Clean relational SQLite database with tables for `users`, `sessions`, `otp_logs`, and immutable `audit_logs` tracking IP addresses, User-Agents, and timestamps. |
| 🎨 **Glassmorphic UI / UX** | Dark-mode glassmorphism theme, smooth animations, interactive password reveal toggles, 6-digit auto-tabbing OTP boxes with clipboard paste support, and real-time security alerts. |

---

## 📁 Project Structure

```
login_page/
├── api/
│   └── index.py          # Main Flask web application, route controllers & middleware
├── static/
│   ├── css/
│   │   └── style.css     # Glassmorphic dark UI, glow effects, responsive grid
│   └── js/
│       └── app.js        # Password visibility toggle, OTP auto-tabbing, strength meter
├── templates/
│   ├── base.html         # Base layout with CSRF token injection & flash alerts
│   ├── login.html        # Sign-in portal with password reveal
│   ├── register.html     # Registration card with real-time complexity validation
│   ├── mfa_verify.html   # 6-box numeric OTP challenge screen with resend timer
│   ├── mfa_setup.html    # Authenticator QR code scanner & manual secret display
│   └── dashboard.html    # Protected user hub with live security audit timeline
├── app.py                # WSGI entry point for PythonAnywhere & local servers
├── auth.py               # Authentication helpers, TOTP generator & password verifier
├── config.py             # Application settings, secrets, and SMTP/API configurations
├── database.py           # SQLite database schema, connections, and audit logging
├── email_service.py      # Multi-provider email dispatcher (Gmail SMTP & Resend API)
├── security.py           # CSRF protection, rate limiting, lockout check, CSP headers
├── test_app.py           # Automated unit and integration test suite (7/7 tests)
├── requirements.txt      # Production dependencies
├── Procfile              # Gunicorn configuration for cloud hosting
└── vercel.json           # Vercel serverless configuration
```

---

## 🚀 Quick Start (Local Setup)

### 1. Clone the Repository
```bash
git clone https://github.com/devilrama777/login_web_page.git
cd login_web_page
```

### 2. Create and Activate Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser.

---

## 🧪 Running Automated Tests

Run the complete 7-part security test suite:
```bash
python test_app.py
```

---

## 🔒 Security Best Practices Implemented

1. **Zero Secret Leaks**: Passwords and OTP codes are strictly validated in private memory and never exposed in browser sources or URLs.
2. **Session Hardening**: Sessions use `HttpOnly`, `SameSite=Lax`, database-tracked tokens, and automatic 30-minute idle expiration.
3. **Multi-Factor Redundancy**: Users can choose between Authenticator Apps (Google/Microsoft Authenticator) or Email OTP.
4. **Brute Force Protection**: Accounts are locked automatically for 15 minutes upon detecting 5 consecutive failed attempts.
