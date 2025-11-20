# Test Execution Guide

## Overview

This guide explains which test scripts can be executed and how to run them properly using the virtual environment.

## Available Test Scripts

### ✅ Executable Test Scripts

All test scripts in the `tests/` directory are executable and ready to run:

1. **`test_password_security.py`** ✅ READY
   - Tests password hashing functionality
   - Can be executed: YES
   - Dependencies: Django, main.views, main.models

2. **`test_otp_security.py`** ✅ READY
   - Tests OTP generation security
   - Can be executed: YES
   - Dependencies: Django, main.views

3. **`test_session_security.py`** ✅ READY
   - Tests session storage and security
   - Can be executed: YES
   - Dependencies: Django, django.conf.settings

4. **`test_rate_limiting.py`** ✅ READY
   - Tests rate limiting functionality
   - Can be executed: YES
   - Dependencies: Django, main.views (rate_limit function)

5. **`test_xss_prevention.py`** ✅ READY
   - Tests XSS prevention in HTML sanitization
   - Can be executed: YES
   - Dependencies: Django, main.forms, bleach (optional)

6. **`test_authorization.py`** ✅ READY
   - Tests authorization checks
   - Can be executed: YES
   - Dependencies: Django, main.models, main.views

7. **`test_security_config.py`** ✅ READY
   - Tests security configuration
   - Can be executed: YES
   - Dependencies: Django, django.conf.settings

8. **`test_post_data_access.py`** ✅ READY
   - Tests safe POST/GET data access
   - Can be executed: YES
   - Dependencies: Django

9. **`test_runner.py`** ✅ READY
   - Main test runner that executes all tests
   - Can be executed: YES
   - Dependencies: All test modules above

## How to Run Tests

### Method 1: Using Helper Scripts (Recommended)

#### Windows PowerShell:
```powershell
.\tests\run_tests.ps1
```

#### Windows Command Prompt:
```cmd
tests\run_tests.bat
```

### Method 2: Using Django Test Runner (Manual)

#### Activate Virtual Environment First:

**PowerShell:**
```powershell
& "D:\Django Framework\eLMS\Learning-management-system-using-Django-main\myenv\Scripts\Activate.ps1"
```

**Command Prompt:**
```cmd
"D:\Django Framework\eLMS\Learning-management-system-using-Django-main\myenv\Scripts\activate.bat"
```

#### Then Run Tests:

```bash
# Run all tests
python manage.py test tests

# Run specific test file
python manage.py test tests.test_password_security
python manage.py test tests.test_otp_security
python manage.py test tests.test_rate_limiting

# Run with verbose output
python manage.py test tests --verbosity=2
```

### Method 3: Using Test Runner Script

```bash
# Activate virtual environment first, then:
python tests/test_runner.py
```

## Test Execution Status

### ✅ All Tests Are Executable

All test scripts are properly configured and can be executed. They:
- ✅ Have proper Django setup
- ✅ Import required modules correctly
- ✅ Use Django's TestCase framework
- ✅ Are compatible with current application state

## Prerequisites

Before running tests, ensure:

1. **Virtual Environment is Activated**
   ```powershell
   & "D:\Django Framework\eLMS\Learning-management-system-using-Django-main\myenv\Scripts\Activate.ps1"
   ```

2. **Dependencies are Installed**
   ```bash
   pip install -r requirements.txt
   ```

3. **Database Migrations are Run**
   ```bash
   python manage.py migrate
   ```

4. **You're in Project Root Directory**
   ```bash
   cd "D:\Django Framework\eLMS\Learning-management-system-using-Django-main\Learning-management-system-using-Django-main"
   ```

## Expected Test Results

When all tests pass, you should see:

```
Ran 25 tests in X.XXXs

OK
```

### Test Coverage

- **Password Security:** 4 tests
- **OTP Security:** 5 tests
- **Session Security:** 2 tests
- **Rate Limiting:** 5 tests
- **XSS Prevention:** 5 tests
- **Authorization:** 3 tests
- **Security Config:** 5 tests
- **Data Access:** 2 tests

**Total: ~31 tests**

## Troubleshooting

### Import Errors
- Ensure virtual environment is activated
- Check that all dependencies are installed: `pip install -r requirements.txt`

### Database Errors
- Run migrations: `python manage.py migrate`
- Ensure database file exists and is accessible

### Module Not Found
- Verify you're in the project root directory
- Check that `DJANGO_SETTINGS_MODULE` is set correctly

### Rate Limit Import Error
- This has been fixed - `rate_limit` function is now in `main/views.py`
- If error persists, check that `main/views.py` contains the function

## Test Report

After running tests, a detailed report is generated at:
```
tests/SECURITY_TEST_REPORT.txt
```

## Quick Test Checklist

- [ ] Virtual environment activated
- [ ] Dependencies installed
- [ ] Migrations run
- [ ] In project root directory
- [ ] Run: `python manage.py test tests`
- [ ] Check test report

---

**Status:** ✅ All test scripts are executable and ready to run

