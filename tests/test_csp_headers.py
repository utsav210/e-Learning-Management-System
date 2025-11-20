import os
import sys
import django
from django.test import TestCase, Client

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eLMS.settings')
django.setup()

class CSPHeaderTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_csp_header_present_on_login(self):
        resp = self.client.get('/')
        self.assertIn('Content-Security-Policy', resp.headers)