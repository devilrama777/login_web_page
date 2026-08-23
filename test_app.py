import os
import re
import unittest
import pyotp
from datetime import datetime, timedelta
from app import app
from database import init_db, query_db, execute_db
from security import validate_password_strength, check_account_lockout, record_failed_login, reset_failed_login
from auth import (
    create_user, get_user_by_identifier, verify_password,
    generate_and_send_email_otp, verify_email_otp, verify_totp_code
)
from email_service import get_dev_latest_otp
from config import Config

class MFASystemTestCase(unittest.TestCase):
    def setUp(self):
        self.test_db = os.path.join(os.path.dirname(__file__), 'test_auth.db')
        self.orig_db = Config.DB_PATH
        Config.DB_PATH = self.test_db
        app.config['TESTING'] = True
        app.config['DB_PATH'] = self.test_db
        self.client = app.test_client()
        with app.app_context():
            init_db()

    def tearDown(self):
        Config.DB_PATH = self.orig_db
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass

    def _extract_csrf(self, html):
        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
        return match.group(1) if match else None

    def test_01_password_policy(self):
        """Test password complexity requirements (Roadmap 02)."""
        valid, _ = validate_password_strength("weak")
        self.assertFalse(valid)
        
        valid, _ = validate_password_strength("NoDigitsOrSymbols!")
        self.assertFalse(valid)
        
        valid, _ = validate_password_strength("SuperSecret123!")
        self.assertTrue(valid)

    def test_02_user_registration_and_hashing(self):
        """Test password hashing and user creation (Roadmap 02)."""
        with app.test_request_context():
            user_id = create_user("testuser", "test@example.com", "SecurePass123!", mfa_type="email")
            self.assertIsNotNone(user_id)
            
            user = get_user_by_identifier("testuser")
            self.assertIsNotNone(user)
            self.assertEqual(user['email'], "test@example.com")
            self.assertNotEqual(user['password_hash'], "SecurePass123!")
            self.assertTrue(verify_password(user['password_hash'], "SecurePass123!"))
            self.assertFalse(verify_password(user['password_hash'], "WrongPassword!"))

    def test_03_brute_force_lockout(self):
        """Test account lockout after 5 consecutive failed login attempts (Roadmap 05 & 07)."""
        with app.test_request_context():
            user_id = create_user("locktest", "lock@example.com", "SecurePass123!", mfa_type="email")
            
            for _ in range(5):
                record_failed_login(user_id, "127.0.0.1", "UnitTestAgent")
                
            user_updated = get_user_by_identifier("locktest")
            is_locked, remaining_mins = check_account_lockout(user_updated)
            self.assertTrue(is_locked)
            self.assertGreater(remaining_mins, 0)
            
            reset_failed_login(user_id)
            user_reset = get_user_by_identifier("locktest")
            is_locked_after, _ = check_account_lockout(user_reset)
            self.assertFalse(is_locked_after)

    def test_04_email_otp_lifecycle_and_replay_prevention(self):
        """Test Email OTP generation, verification, and single-use guarantee (Roadmap 03 & 04)."""
        with app.test_request_context():
            user_id = create_user("emailmfa", "mfa@example.com", "SecurePass123!", mfa_type="email")
            user = get_user_by_identifier("emailmfa")
            
            success, msg, code = generate_and_send_email_otp(user)
            self.assertEqual(len(code), 6)
            
            # Incorrect OTP
            is_valid, _ = verify_email_otp(user, "000000")
            self.assertFalse(is_valid)
            
            # Correct OTP
            is_valid, _ = verify_email_otp(user, code)
            self.assertTrue(is_valid)
            
            # Replay attack prevention
            is_replay_valid, _ = verify_email_otp(user, code)
            self.assertFalse(is_replay_valid)

    def test_05_pyotp_totp_flow(self):
        """Test TOTP Authenticator verification via pyotp (Roadmap 04)."""
        with app.test_request_context():
            create_user("totpuser", "totp@example.com", "SecurePass123!", mfa_type="totp")
            user = get_user_by_identifier("totpuser")
            self.assertIsNotNone(user['mfa_secret'])
            
            totp = pyotp.TOTP(user['mfa_secret'])
            current_code = totp.now()
            
            is_valid, _ = verify_totp_code(user, current_code)
            self.assertTrue(is_valid)
            
            is_invalid, _ = verify_totp_code(user, "999999")
            self.assertFalse(is_invalid)

    def test_06_sql_injection_resistance(self):
        """Verify SQL injection payloads fail safely (Roadmap 07)."""
        with app.test_request_context():
            create_user("legituser", "legit@example.com", "SecurePass123!", mfa_type="email")
            
            sqli_user = get_user_by_identifier("legituser' OR '1'='1")
            self.assertIsNone(sqli_user)
            
            sqli_user2 = get_user_by_identifier("admin' --")
            self.assertIsNone(sqli_user2)

    def test_07_full_http_lifecycle(self):
        """Test complete HTTP registration, login, MFA, and logout flow."""
        # 1. Register
        res = self.client.get('/register')
        csrf = self._extract_csrf(res.get_data(as_text=True))
        
        res = self.client.post('/register', data={
            'csrf_token': csrf,
            'username': 'e2e_user',
            'email': 'e2e@domain.com',
            'password': 'SecureE2EPass123!',
            'confirm_password': 'SecureE2EPass123!',
            'mfa_type': 'email'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # 2. Login
        res = self.client.get('/login')
        csrf = self._extract_csrf(res.get_data(as_text=True))
        
        res = self.client.post('/login', data={
            'csrf_token': csrf,
            'identifier': 'e2e_user',
            'password': 'SecureE2EPass123!'
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.headers['Location'].endswith('/mfa/verify'))

        # 3. Verify OTP
        res = self.client.get('/mfa/verify')
        csrf = self._extract_csrf(res.get_data(as_text=True))
        otp_info = get_dev_latest_otp('e2e@domain.com')
        code = otp_info['code']

        res = self.client.post('/mfa/verify', data={
            'csrf_token': csrf,
            'code_1': code[0], 'code_2': code[1], 'code_3': code[2],
            'code_4': code[3], 'code_5': code[4], 'code_6': code[5]
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn('Security Dashboard', res.get_data(as_text=True))

        # 4. Logout
        res = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn('You have been securely signed out', res.get_data(as_text=True))

if __name__ == '__main__':
    unittest.main()
