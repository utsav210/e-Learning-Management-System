import os
import sys
import django
from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eLMS.settings')
django.setup()

from main.forms import sanitize_html, AnnouncementForm
from quiz.forms import sanitize_text


class XSSPreventionTests(TestCase):
    def test_html_sanitizer_removes_script_tags(self):
        malicious = '<script>alert(1)</script><p>a</p>'
        cleaned = sanitize_html(malicious)
        self.assertNotIn('<script', cleaned.lower())
        self.assertIn('<p>', cleaned)

    def test_html_sanitizer_removes_event_handlers(self):
        malicious = '<p onclick="alert(1)" onerror="alert(1)">x</p>'
        cleaned = sanitize_html(malicious)
        self.assertNotIn('onclick', cleaned.lower())
        self.assertNotIn('onerror', cleaned.lower())

    def test_html_sanitizer_removes_disallowed_tags(self):
        malicious = '<img src=x onerror=alert(1)><svg/onload=alert(1)><p>a</p>'
        cleaned = sanitize_html(malicious)
        self.assertNotIn('<img', cleaned.lower())
        self.assertNotIn('<svg', cleaned.lower())
        self.assertIn('<p>', cleaned)

    def test_link_protocol_sanitization(self):
        html = '<a href="javascript:alert(1)">x</a><a href="mailto:test@example.com">m</a><a href="https://example.com">s</a>'
        cleaned = sanitize_html(html)
        self.assertNotIn('javascript:', cleaned.lower())
        self.assertIn('mailto:', cleaned.lower())
        self.assertIn('https://example.com', cleaned)

    def test_span_style_allowed_only_for_span(self):
        html = '<span style="color:red">x</span><p style="color:red">y</p>'
        cleaned = sanitize_html(html)
        self.assertIn('<span', cleaned)
        self.assertIn('style=', cleaned)
        self.assertIn('<p', cleaned)
        self.assertNotIn('<p style=', cleaned)

    def test_bleach_import_error_fallback_strips_html(self):
        test_html = '<script>alert(1)</script><p>Test</p>'
        real_import = __import__
        def import_block(name, *args, **kwargs):
            if name == 'bleach':
                raise ImportError('blocked')
            return real_import(name, *args, **kwargs)
        with patch('builtins.__import__', side_effect=import_block):
            cleaned = sanitize_html(test_html)
        self.assertNotIn('<', cleaned)
        self.assertNotIn('>', cleaned)

    def test_quiz_text_sanitizer_strips_html(self):
        html = '<script>alert(1)</script><p>x</p>'
        cleaned = sanitize_text(html)
        self.assertNotIn('<', cleaned)
        self.assertNotIn('>', cleaned)

    def test_form_clean_description_applies_sanitization(self):
        data = {'description': '<script>alert(1)</script><p>c</p>'}
        form = AnnouncementForm(data=data)
        self.assertTrue(form.is_valid())
        cleaned = form.cleaned_data['description']
        self.assertNotIn('<script', cleaned.lower())
