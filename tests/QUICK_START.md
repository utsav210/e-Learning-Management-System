# Quick Start - Security Testing

## Run All Security Tests

```bash
# Option 1: Using the test runner script
python tests/test_runner.py

# Option 2: Using Django's test runner
python manage.py test tests

# Option 3: Using the quick script
python run_security_tests.py
```

## What Gets Tested

The test suite verifies all security fixes from `SECURITY_AUDIT_REPORT.md`:

### ✅ CRITICAL Issues (4)
1. Password Hashing
2. OTP Generation Security
3. Session Storage
4. Security Configuration

### ✅ HIGH Priority Issues (5)
5. Rate Limiting
6. XSS Prevention
7. Authorization Checks
8. Safe Data Access
9. Session Fixation

## Expected Output

```
================================================================================
SECURITY FIXES VERIFICATION TEST SUITE
================================================================================
Test Run Date: 2025-11-15 12:00:00

[Test execution output...]

================================================================================
TEST SUMMARY
================================================================================
Total Tests: 25
✅ Passed: 25
❌ Failed: 0
⚠️  Errors: 0

================================================================================
ISSUE RESOLUTION STATUS
================================================================================

🔴 CRITICAL: 2.1 Plaintext Password Storage
   Section: Cryptographic Failures
   Status: ✅ RESOLVED

🔴 CRITICAL: 2.3 Weak OTP Generation
   Section: Cryptographic Failures
   Status: ✅ RESOLVED

[... more issues ...]

================================================================================
RESOLUTION SUMMARY
================================================================================
🔴 CRITICAL Issues Resolved: 4
🟠 HIGH Issues Resolved: 5
📊 Total Issues Tested: 9

🎉 All security tests passed!
```

## View Detailed Report

After running tests, check:
```
tests/SECURITY_TEST_REPORT.txt
```

## Troubleshooting

**Import Errors?**
```bash
# Make sure you're in project root
cd Learning-management-system-using-Django-main
python manage.py test tests
```

**Database Errors?**
```bash
python manage.py migrate
```

**Module Not Found?**
```bash
pip install -r requirements.txt
```

