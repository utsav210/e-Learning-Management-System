#!/usr/bin/env python
"""
Quick script to run security tests
Usage: python run_security_tests.py
"""
import os
import sys

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Change to project root
os.chdir(project_root)

# Run the test runner
if __name__ == '__main__':
    from tests.test_runner import run_security_tests
    result = run_security_tests()
    sys.exit(0 if result.wasSuccessful() else 1)

