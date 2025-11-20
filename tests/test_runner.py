"""
Comprehensive Security Test Runner
Runs all security tests and generates a report showing which issues are resolved.
"""
import os
import sys
import django
import unittest
from io import StringIO
from datetime import datetime

# Setup Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eLMS.settings')
django.setup()

# Import all test modules
from tests.test_password_security import PasswordHashingTests, PasswordPolicyTests
from tests.test_otp_security import OTPGenerationTests
from tests.test_session_security import SessionStorageTests, SessionFixationTests
from tests.test_rate_limiting import RateLimitingTests
from tests.test_xss_prevention import XSSPreventionTests
from tests.test_authorization import AuthorizationTests
from tests.test_security_config import SecurityConfigurationTests
from tests.test_post_data_access import SafeDataAccessTests


# Map tests to security audit issues
TEST_TO_ISSUE_MAP = {
    # CRITICAL Issues
    'PasswordHashingTests': {
        'issue': '2.1 Plaintext Password Storage',
        'priority': 'CRITICAL',
        'section': 'Cryptographic Failures'
    },
    'OTPGenerationTests': {
        'issue': '2.3 Weak OTP Generation',
        'priority': 'CRITICAL',
        'section': 'Cryptographic Failures'
    },
    'SessionStorageTests': {
        'issue': '3.2 Session Management Issues',
        'priority': 'CRITICAL',
        'section': 'Authentication Failures'
    },
    'SecurityConfigurationTests': {
        'issue': '4 Security Misconfiguration',
        'priority': 'CRITICAL',
        'section': 'Security Misconfiguration'
    },
    # HIGH Issues
    'RateLimitingTests': {
        'issue': '3.4 Password Reset Without Rate Limiting',
        'priority': 'HIGH',
        'section': 'Authentication Failures'
    },
    'XSSPreventionTests': {
        'issue': '5.3 XSS Vulnerabilities',
        'priority': 'HIGH',
        'section': 'Injection'
    },
    'AuthorizationTests': {
        'issue': '1.1 Insufficient Authorization Checks',
        'priority': 'HIGH',
        'section': 'Broken Access Control'
    },
    'SafeDataAccessTests': {
        'issue': '1.2, 5.1 Unsafe POST/GET Access',
        'priority': 'HIGH',
        'section': 'Broken Access Control / Injection'
    },
    'SessionFixationTests': {
        'issue': '11 Session Fixation',
        'priority': 'HIGH',
        'section': 'Additional Security Concerns'
    },
}


def run_security_tests():
    """Run all security tests and generate report"""
    print("="*80)
    print("SECURITY FIXES VERIFICATION TEST SUITE")
    print("="*80)
    print(f"Test Run Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        PasswordHashingTests,
        PasswordPolicyTests,
        OTPGenerationTests,
        SessionStorageTests,
        SessionFixationTests,
        RateLimitingTests,
        XSSPreventionTests,
        AuthorizationTests,
        SecurityConfigurationTests,
        SafeDataAccessTests,
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    stream = StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)
    
    # Parse results
    output = stream.getvalue()
    print(output)
    
    # Generate summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    passed = total_tests - failures - errors
    
    print(f"Total Tests: {total_tests}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failures}")
    print(f"⚠️  Errors: {errors}")
    print()
    
    # Map results to issues
    print("="*80)
    print("ISSUE RESOLUTION STATUS")
    print("="*80)
    print()
    
    # Count resolved issues
    critical_resolved = 0
    high_resolved = 0
    total_issues_tested = 0
    
    for test_class_name, issue_info in TEST_TO_ISSUE_MAP.items():
        # Check if there were any failures or errors for this class
        # result.failures is a list of (test_case, traceback_string) tuples
        class_failures = [f for f in result.failures if test_class_name in str(type(f[0]).__name__)]
        class_errors = [e for e in result.errors if test_class_name in str(type(e[0]).__name__)]
        
        resolved = len(class_failures) == 0 and len(class_errors) == 0
        status = "✅ RESOLVED" if resolved else "❌ NOT RESOLVED"
        
        priority_icon = "🔴" if issue_info['priority'] == 'CRITICAL' else "🟠"
        
        print(f"{priority_icon} {issue_info['priority']}: {issue_info['issue']}")
        print(f"   Section: {issue_info['section']}")
        print(f"   Status: {status}")
        print()
        
        if resolved:
            if issue_info['priority'] == 'CRITICAL':
                critical_resolved += 1
            else:
                high_resolved += 1
        total_issues_tested += 1
    
    # Final summary
    print("="*80)
    print("RESOLUTION SUMMARY")
    print("="*80)
    print(f"🔴 CRITICAL Issues Resolved: {critical_resolved}")
    print(f"🟠 HIGH Issues Resolved: {high_resolved}")
    print(f"📊 Total Issues Tested: {total_issues_tested}")
    print()
    
    if failures > 0 or errors > 0:
        print("⚠️  Some tests failed. Review the output above for details.")
    else:
        print("🎉 All security tests passed!")
    
    # Save report to file
    report_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'tests',
        'SECURITY_TEST_REPORT.txt'
    )
    
    with open(report_path, 'w') as f:
        f.write("SECURITY FIXES VERIFICATION TEST REPORT\n")
        f.write("="*80 + "\n")
        f.write(f"Test Run Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(output)
        f.write("\n" + "="*80 + "\n")
        f.write("SUMMARY\n")
        f.write("="*80 + "\n")
        f.write(f"Total Tests: {total_tests}\n")
        f.write(f"Passed: {passed}\n")
        f.write(f"Failed: {failures}\n")
        f.write(f"Errors: {errors}\n")
        f.write(f"\nCRITICAL Issues Resolved: {critical_resolved}\n")
        f.write(f"HIGH Issues Resolved: {high_resolved}\n")
    
    print(f"\n📄 Detailed report saved to: {report_path}")
    
    return result


if __name__ == '__main__':
    result = run_security_tests()
    sys.exit(0 if result.wasSuccessful() else 1)

