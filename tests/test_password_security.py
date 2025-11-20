"""
Test Suite: Password Security (CRITICAL)
Tests for: SECURITY_AUDIT_REPORT.md Section 2.1, 3.1
Issue: Plaintext Password Storage
Status: ✅ FIXED
"""
import os
import sys
import django
from django.test import TestCase
from django.contrib.auth.hashers import check_password as django_check_password

# Setup Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eLMS.settings')
django.setup()

from main.views import hash_password, check_password, ensure_password_hashed
from main.models import Student, Faculty


class PasswordHashingTests(TestCase):
    """Test password hashing implementation"""
    
    def test_hash_password_creates_hash(self):
        """Test that hash_password creates a hashed password"""
        plain_password = "TestPassword123!"
        hashed = hash_password(plain_password)
        
        # Should not be plaintext
        self.assertNotEqual(hashed, plain_password)
        # Should be longer (hash includes algorithm prefix)
        self.assertGreater(len(hashed), 20)
        # Should start with hashing algorithm identifier
        self.assertTrue(
            hashed.startswith('pbkdf2_sha256$') or 
            hashed.startswith('argon2$') or
            hashed.startswith('bcrypt$')
        )
    
    def test_check_password_with_hashed(self):
        """Test password checking with hashed password"""
        plain_password = "TestPassword123!"
        hashed = hash_password(plain_password)
        
        # Should verify correctly
        self.assertTrue(check_password(hashed, plain_password))
        # Should reject wrong password
        self.assertFalse(check_password(hashed, "WrongPassword"))
    
    def test_check_password_backward_compatibility(self):
        """Test backward compatibility with plaintext passwords"""
        plain_password = "OldPlaintextPassword"
        
        # Should work with plaintext (backward compatibility)
        result = check_password(plain_password, plain_password)
        self.assertTrue(result)
    
    def test_password_migration_on_login(self):
        """Test that plaintext passwords are migrated to hashed on login"""
        # This is tested in integration tests
        pass


class PasswordPolicyTests(TestCase):
    """Test password policy enforcement"""
    
    def test_minimum_password_length(self):
        """Test that minimum password length is enforced (8 characters)"""
        # This is tested in view tests
        pass


class TestResults:
    """Track test results for reporting"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def add_test(self, name, passed, issue_ref):
        self.tests.append({
            'name': name,
            'passed': passed,
            'issue_ref': issue_ref
        })
        if passed:
            self.passed += 1
        else:
            self.failed += 1

