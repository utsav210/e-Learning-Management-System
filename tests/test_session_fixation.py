import os
import sys
import django
from django.test import TestCase

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eLMS.settings')
django.setup()

from main.views import verifyLoginOTP
import inspect

class SessionFixationTests(TestCase):
    def test_verifyLoginOTP_cycles_session_key(self):
        src = inspect.getsource(verifyLoginOTP)
        self.assertIn('cycle_key', src)