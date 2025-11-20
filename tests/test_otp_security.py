"""
Test Suite: OTP Generation Security (CRITICAL)
Tests for: SECURITY_AUDIT_REPORT.md Section 2.3, 7.1
Issue: Weak OTP Generation
Status: ✅ FIXED
"""
import os
import sys
import django
from django.test import TestCase

# Setup Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eLMS.settings')
django.setup()

from main.views import generate_otp
import secrets


class OTPGenerationTests(TestCase):
    """Test OTP generation security"""
    
    def test_otp_is_six_digits(self):
        """Test that OTP is always 6 digits"""
        for _ in range(10):
            otp = generate_otp()
            self.assertEqual(len(otp), 6)
            self.assertTrue(otp.isdigit())
    
    def test_otp_is_random(self):
        """Test that OTPs are not predictable"""
        otps = [generate_otp() for _ in range(20)]
        unique_otps = set(otps)
        
        # Should have high uniqueness (at least 15 unique out of 20)
        self.assertGreaterEqual(len(unique_otps), 15)
    
    def test_otp_not_sequential(self):
        """Test that OTPs are not sequential"""
        otps = [int(generate_otp()) for _ in range(10)]
        
        # Check if they're sequential
        sequential = all(otps[i] == otps[0] + i for i in range(len(otps)))
        self.assertFalse(sequential, "OTPs should not be sequential")
    
    def test_otp_uses_secrets_module(self):
        """Test that OTP generation uses secrets module (cryptographically secure)"""
        # Verify by checking the implementation uses secrets.randbelow
        import inspect
        source = inspect.getsource(generate_otp)
        self.assertIn('secrets', source.lower(), "OTP generation should use secrets module")
    
    def test_otp_range(self):
        """Test that OTPs are in valid range (100000-999999)"""
        for _ in range(50):
            otp = int(generate_otp())
            self.assertGreaterEqual(otp, 100000)
            self.assertLessEqual(otp, 999999)

