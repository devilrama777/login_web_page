import os
import re
import unittest
import pyotp
from app import app
from database import init_db, query_db
from email_service import get_dev_latest_otp

from config import Config

class E2EHttpFlowTestCase(unittest.TestCase):
    def setUp(self):
        self.test_db = os.path.join(os.path.dirname(__file__), 'test_e2e_auth.db')
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

    def test_full_email_mfa_flow(self):
        """Test full HTTP lifecycle with Email OTP (Roadmap 01-07)."""
        # 1. Access Registration Page
        res = self.client.get('/register')
        self.assertEqual(res.status_code, 200)
        csrf = self._extract_csrf(res.get_data(as_text=True))
        self.assertIsNotNone(csrf)

        # 2. Register Account
        res = self.client.post('/register', data={
            'csrf_token': csrf,
            'username': 'alice_crypto',
            'email': 'alice@domain.com',
            'password': 'SecureAlice2026!',
            'confirm_password': 'SecureAlice2026!',
            'mfa_type': 'email'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn('Registration successful', res.get_data(as_text=True))

        # 3. Access Login Page
        res = self.client.get('/login')
        csrf = self._extract_csrf(res.get_data(as_text=True))

        # 4. Submit Credentials
        res = self.client.post('/login', data={
            'csrf_token': csrf,
            'identifier': 'alice_crypto',
            'password': 'SecureAlice2026!'
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.headers['Location'].endswith('/mfa/verify'))

        # 5. Access MFA Verification Challenge
        res = self.client.get('/mfa/verify')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn('Two-Factor Authentication', html)
        csrf = self._extract_csrf(html)

        # Retrieve generated Email OTP
        otp_info = get_dev_latest_otp('alice@domain.com')
        self.assertIsNotNone(otp_info)
        code = otp_info['code']
        self.assertEqual(len(code), 6)

        # 6. Submit 6-digit OTP
        res = self.client.post('/mfa/verify', data={
            'csrf_token': csrf,
            'code_1': code[0],
            'code_2': code[1],
            'code_3': code[2],
            'code_4': code[3],
            'code_5': code[4],
            'code_6': code[5]
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        dash_html = res.get_data(as_text=True)
        self.assertIn('Security Dashboard', dash_html)
        self.assertIn('alice_crypto', dash_html)
        self.assertIn('MFA_SUCCESS', dash_html)

        # 7. Test Logout (Roadmap 06)
        res = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn('You have been securely signed out', res.get_data(as_text=True))

        # 8. Verify Protected Route cannot be accessed after logout
        res = self.client.get('/dashboard', follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.headers['Location'].startswith('/login'))

    def test_full_totp_authenticator_flow(self):
        """Test full HTTP lifecycle with pyotp TOTP (Roadmap 01-07)."""
        # 1. Register with TOTP
        res = self.client.get('/register')
        csrf = self._extract_csrf(res.get_data(as_text=True))

        res = self.client.post('/register', data={
            'csrf_token': csrf,
            'username': 'bob_totp',
            'email': 'bob@domain.com',
            'password': 'SecureBob2026!',
            'confirm_password': 'SecureBob2026!',
            'mfa_type': 'totp'
        }, follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertTrue(res.headers['Location'].endswith('/mfa/setup'))

        # 2. Access Setup page to get TOTP secret
        res = self.client.get('/mfa/setup')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn('data:image/png;base64', html)
        csrf = self._extract_csrf(html)

        user = query_db('SELECT * FROM users WHERE username = ?', ('bob_totp',), one=True)
        totp = pyotp.TOTP(user['mfa_secret'])
        current_token = totp.now()

        # 3. Confirm Setup
        res = self.client.post('/mfa/setup', data={
            'csrf_token': csrf,
            'code': current_token
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn('Security Dashboard', res.get_data(as_text=True))
        self.assertIn('Authenticator App', res.get_data(as_text=True))

if __name__ == '__main__':
    unittest.main()
