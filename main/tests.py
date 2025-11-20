from django.test import TestCase, Client
from django.urls import reverse
from django.template.loader import render_to_string
from main.models import Department, Student, Course
from django.conf import settings
from unittest.mock import patch

class ForgotPasswordFlowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.dept = Department.objects.create(department_id=20, name='IT')
        self.student = Student.objects.create(student_id=2001, name='Carl', email='c@example.com', password='pass', department=self.dept)

    @patch('main.views.send_mail')
    def test_forgot_password_sends_otp_and_sets_session(self, mock_send_mail):
        mock_send_mail.return_value = 1
        r = self.client.post(reverse('forgotPassword'), {'email': self.student.email})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.client.session.get('reset_email'), self.student.email)
        self.assertEqual(self.client.session.get('reset_student_id'), str(self.student.student_id))

    @patch('main.views.send_mail')
    def test_forgot_password_requires_valid_email(self, mock_send_mail):
        mock_send_mail.return_value = 1
        r = self.client.post(reverse('forgotPassword'), {'email': ''})
        self.assertEqual(r.status_code, 200)

class ChangeEmailTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.dept = Department.objects.create(department_id=21, name='ECE')
        self.student = Student.objects.create(student_id=3001, name='Dana', email='d@example.com', password='pass', department=self.dept)
        s = self.client.session
        s['student_id'] = str(self.student.student_id)
        s.save()

    def test_change_email_requires_password(self):
        r = self.client.post(reverse('changeEmail'), {'new_email': 'new@example.com', 'password': ''})
        self.assertEqual(r.status_code, 200)

    def test_change_email_updates(self):
        r = self.client.post(reverse('changeEmail'), {'new_email': 'new@example.com', 'password': 'pass'})
        self.assertEqual(r.status_code, 302)

class FacultyChangeEmailTests(TestCase):
    def setUp(self):
        self.client = Client()
        from main.models import Faculty
        self.dept = Department.objects.create(department_id=22, name='ME')
        self.faculty = Faculty.objects.create(faculty_id=5001, name='ProfX', email='px@example.com', password='pass', department=self.dept)
        s = self.client.session
        s['faculty_id'] = str(self.faculty.faculty_id)
        s.save()

    def test_faculty_change_email_requires_password(self):
        r = self.client.post(reverse('changeEmailFaculty'), {'new_email': 'newf@example.com', 'password': ''})
        self.assertEqual(r.status_code, 200)

    def test_faculty_change_email_updates(self):
        r = self.client.post(reverse('changeEmailFaculty'), {'new_email': 'newf@example.com', 'password': 'pass'})
        self.assertEqual(r.status_code, 302)


class StudentDashboardEnrollmentTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.dept = Department.objects.create(department_id=30, name='CE')
        self.student = Student.objects.create(student_id=7001, name='Evan', email='evan@example.com', password='pass', department=self.dept)
        self.course_enrolled = Course.objects.create(code=301, name='Strength of Materials', department=self.dept, studentKey=1234, facultyKey=9999)
        self.course_not_enrolled = Course.objects.create(code=302, name='Fluid Mechanics', department=self.dept, studentKey=5678, facultyKey=8888)
        self.student.course.add(self.course_enrolled)
        s = self.client.session
        s['student_id'] = str(self.student.student_id)
        s.save()

    def test_dashboard_shows_only_enrolled_courses(self):
        context = {
            'courses': self.student.course.all(),
            'student': self.student,
            'show_email_popup': False,
            'attendance_stats': {},
            'recent_absences': 0,
        }
        html = render_to_string('main/myCourses.html', context)
        self.assertIn('Strength of Materials', html)
        self.assertNotIn('Fluid Mechanics', html)

    def test_dashboard_shows_message_when_no_enrollments(self):
        self.student.course.clear()
        context = {
            'courses': self.student.course.all(),
            'student': self.student,
            'show_email_popup': False,
            'attendance_stats': {},
            'recent_absences': 0,
        }
        html = render_to_string('main/myCourses.html', context)
        self.assertIn('You are not enrolled in any courses', html)