import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime
from config import Config

def get_db_connection():
    """Create and configure a SQLite connection with Row factory."""
    conn = sqlite3.connect(Config.DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

@contextmanager
def db_session():
    """Context manager for safe database transactions."""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def query_db(query, args=(), one=False):
    """Execute a parameterized query and fetch rows (prevents SQL injection)."""
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute(query, args)
        rv = cur.fetchall()
        return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    """Execute a parameterized insert/update/delete and return lastrowid / rowcount."""
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute(query, args)
        return cur.lastrowid

def init_db():
    """Initialize database tables according to the MFA roadmap."""
    os.makedirs(os.path.dirname(os.path.abspath(Config.DB_PATH)), exist_ok=True)
    with db_session() as conn:
        cursor = conn.cursor()
        
        # 1. Users Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                mfa_secret TEXT,
                mfa_type TEXT DEFAULT 'email',
                is_mfa_enabled INTEGER DEFAULT 1,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TEXT,
                created_at TEXT DEFAULT (datetime('now', 'localtime'))
            )
        ''')
        
        # 2. Sessions Table (Roadmap 05 & 06)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TEXT DEFAULT (datetime('now', 'localtime')),
                expires_at TEXT NOT NULL,
                is_valid INTEGER DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # 3. OTP Logs Table (Roadmap 01, 03, 04)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS otp_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                otp_code TEXT NOT NULL,
                otp_type TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now', 'localtime')),
                expires_at TEXT NOT NULL,
                is_used INTEGER DEFAULT 0,
                attempts INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # 4. Security Audit Logs Table (Roadmap 01 & 07)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                timestamp TEXT DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        
        # Indexes for fast and secure lookups
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_otp_user ON otp_logs(user_id, is_used)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)')

def log_audit_event(user_id, action, ip_address=None, user_agent=None, details=None):
    """Record a security audit log entry."""
    execute_db('''
        INSERT INTO audit_logs (user_id, action, ip_address, user_agent, details, timestamp)
        VALUES (?, ?, ?, ?, ?, datetime('now', 'localtime'))
    ''', (user_id, action, ip_address, user_agent, details))
