@echo off
REM Batch script to run security tests with virtual environment
REM Usage: tests\run_tests.bat

echo ========================================
echo Security Tests Execution Script
echo ========================================
echo.

REM Get project root (parent of tests directory)
cd /d "%~dp0\.."
set PROJECT_ROOT=%CD%
set VENV_PATH=D:\Django Framework\eLMS\Learning-management-system-using-Django-main\myenv\Scripts\activate.bat

echo Project Root: %PROJECT_ROOT%
echo Virtual Environment: %VENV_PATH%
echo.

REM Check if virtual environment exists
if not exist "%VENV_PATH%" (
    echo ERROR: Virtual environment not found at: %VENV_PATH%
    echo Please ensure the virtual environment is set up correctly.
    exit /b 1
)

REM Activate virtual environment
echo Activating virtual environment...
call "%VENV_PATH%"

if errorlevel 1 (
    echo ERROR: Failed to activate virtual environment
    exit /b 1
)

echo.
echo Running security tests...
echo.

REM Run tests using Django's test runner
python manage.py test tests --verbosity=2

set TEST_EXIT_CODE=%ERRORLEVEL%

echo.
echo ========================================
if %TEST_EXIT_CODE% equ 0 (
    echo All tests completed successfully!
) else (
    echo Some tests failed. Check output above.
)
echo ========================================

exit /b %TEST_EXIT_CODE%

