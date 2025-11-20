import os
import sys
import django
from django.test import TestCase

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eLMS.settings')
django.setup()

from main.views import rate_limit
from django.http import HttpRequest
from django.http import HttpResponse

class RateLimitIPForwardedTests(TestCase):
    def test_uses_x_forwarded_for(self):
        @rate_limit(max_requests=1, window_seconds=60, key_prefix='rlf')
        def view(request):
            return HttpResponse('ok')

        req = HttpRequest()
        req.META['HTTP_X_FORWARDED_FOR'] = '203.0.113.1, 198.51.100.2'

        r1 = view(req)
        r2 = view(req)
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 429)