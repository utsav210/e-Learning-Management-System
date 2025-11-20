"""
Authorization Integrity & Security Tests (HIGH)
Covers OWASP Top 10 (2025) – Broken Access Control / IDOR
Verifies that profile access is properly enforced via session-bound IDs,
and that unauthorized attempts are redirected and logged.
"""
import os
import sys
import django
from django.test import TestCase, Client
from django.urls import reverse
import logging

# Setup Django
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eLMS.settings')
django.setup()

from main.models import Department, Student
from main.views import profile


class AuthorizationTests(TestCase):
    """Test authorization checks"""
    
    def setUp(self):
        """Set up test data using proper Department FK"""
        self.client = Client()
        self.dept = Department.objects.create(department_id=1, name="CSE")
        self.student1 = Student.objects.create(
            student_id=1,
            name="Student1",
            password="hashed_password_here",
            email="student1@test.com",
            department=self.dept,
        )
        self.student2 = Student.objects.create(
            student_id=2,
            name="Student2",
            password="hashed_password_here",
            email="student2@test.com",
            department=self.dept,
        )
    
    def test_profile_authorized_access_renders_profile(self):
        """Authorized user can access own profile (prevents IDOR)"""
        session = self.client.session
        session['student_id'] = self.student1.student_id
        session.save()
        url = reverse('profile', args=[str(self.student1.student_id)])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertIn('main/profile.html', [t.name for t in resp.templates])
    
    def test_profile_prevents_unauthorized_access(self):
        """User cannot access another user's profile (Broken Access Control)"""
        session = self.client.session
        session['student_id'] = self.student1.student_id
        session.save()
        url = reverse('profile', args=[str(self.student2.student_id)])
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse('std_login'), resp['Location'])
    
    def test_authorization_logs_unresolvable_profile(self):
        """Profile view logs errors when user reference is invalid"""
        # Set session to an ID that does not exist and request that profile
        session = self.client.session
        session['student_id'] = 999
        session.save()
        url = reverse('profile', args=['999'])
        with self.assertLogs('main.views', level='ERROR') as cm:
            resp = self.client.get(url)
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(any('Error in profile view' in m for m in cm.output))

