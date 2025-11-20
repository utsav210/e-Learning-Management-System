from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from datetime import date
from main.models import Department, Faculty, Course, Student
from .models import Attendance
from django.urls import reverse
from datetime import date, timedelta

class AttendanceFlowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.dept = Department.objects.create(department_id=10, name='CS')
        self.faculty = Faculty.objects.create(faculty_id=1, name='Teacher', email='t@example.com', password='pass', department=self.dept)
        self.course = Course.objects.create(code=101, name='Algorithms', department=self.dept, faculty=self.faculty, studentKey=1111, facultyKey=1)
        self.student1 = Student.objects.create(student_id=1001, name='Alice', email='a@example.com', password='pass', department=self.dept)
        self.student2 = Student.objects.create(student_id=1002, name='Bob', email='b@example.com', password='pass', department=self.dept)
        self.student1.course.add(self.course)
        self.student2.course.add(self.course)
        session = self.client.session
        session['faculty_id'] = str(self.faculty.faculty_id)
        session.save()

    def test_export_with_range_and_status(self):
        d0 = date.today()
        Attendance.objects.create(student=self.student1, course=self.course, date=d0, status=True, is_late=False)
        Attendance.objects.create(student=self.student2, course=self.course, date=d0 + timedelta(days=1), status=True, is_late=True)
        Attendance.objects.create(student=self.student1, course=self.course, date=d0 + timedelta(days=2), status=False, is_late=False)
        url = reverse('exportAttendance', args=[self.course.code])
        r = self.client.get(url + f"?start={d0.isoformat()}&end={(d0+timedelta(days=2)).isoformat()}&status=late")
        self.assertEqual(r.status_code, 200)
        content = r.content.decode('utf-8')
        self.assertIn('Late', content)
        self.assertNotIn('Present', content)
        self.assertNotIn('Absent', content)

    def test_load_attendance_range(self):
        d0 = date.today()
        Attendance.objects.create(student=self.student1, course=self.course, date=d0, status=True, is_late=False)
        Attendance.objects.create(student=self.student2, course=self.course, date=d0 + timedelta(days=1), status=True, is_late=True)
        Attendance.objects.create(student=self.student1, course=self.course, date=d0 + timedelta(days=2), status=False, is_late=False)
        url = reverse('loadAttendanceRange', args=[self.course.code])
        r = self.client.get(url + f"?start={d0.isoformat()}&end={(d0+timedelta(days=2)).isoformat()}&status=present")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'Present')

    def test_create_record_and_prevent_duplicate(self):
        url = reverse('createRecord', args=[self.course.code])
        d = date.today().isoformat()
        r1 = self.client.post(url, {'dateCreate': d})
        self.assertEqual(r1.status_code, 302)
        self.assertEqual(Attendance.objects.filter(course=self.course, date=d).count(), 2)
        r2 = self.client.post(url, {'dateCreate': d})
        self.assertEqual(Attendance.objects.filter(course=self.course, date=d).count(), 2)

    def test_submit_attendance_present_and_late(self):
        d = date.today().isoformat()
        payload = {
            'datehidden': d,
            str(self.student1.student_id): 'present',
            str(self.student2.student_id): 'late',
            'ajax': 'true'
        }
        r = self.client.post(reverse('submitAttendance', args=[self.course.code]), payload, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertEqual(r.status_code, 200)
        json = r.json()
        self.assertTrue(json.get('success'))
        a1 = Attendance.objects.get(student=self.student1, course=self.course, date=d)
        a2 = Attendance.objects.get(student=self.student2, course=self.course, date=d)
        self.assertTrue(a1.status)
        self.assertFalse(a1.is_late)
        self.assertTrue(a2.status)
        self.assertTrue(a2.is_late)

    def test_conflict_detection_skips_update(self):
        d = date.today().isoformat()
        self.client.post(reverse('createRecord', args=[self.course.code]), {'dateCreate': d})
        self.client.post(reverse('submitAttendance', args=[self.course.code]), {
            'datehidden': d,
            str(self.student1.student_id): 'present',
            str(self.student2.student_id): 'present'
        })
        r = self.client.post(reverse('submitAttendance', args=[self.course.code]), {
            'datehidden': d,
            str(self.student1.student_id): '0',
            str(self.student2.student_id): '0',
            'ajax': 'true',
            'client_ts': '0'
        }, HTTP_X_REQUESTED_WITH='XMLHttpRequest')
        self.assertEqual(r.status_code, 200)
        self.assertGreaterEqual(r.json().get('conflicts', 0), 1)
        a1 = Attendance.objects.get(student=self.student1, course=self.course, date=d)
        a2 = Attendance.objects.get(student=self.student2, course=self.course, date=d)
        self.assertTrue(a1.status)
        self.assertTrue(a2.status)

    def test_export_csv(self):
        d = date.today().isoformat()
        self.client.post(reverse('createRecord', args=[self.course.code]), {'dateCreate': d})
        self.client.post(reverse('submitAttendance', args=[self.course.code]), {
            'datehidden': d,
            str(self.student1.student_id): 'present',
            str(self.student2.student_id): 'late'
        })
        url = reverse('exportAttendance', args=[self.course.code]) + f'?date={d}'
        r = self.client.get(url)
        self.assertEqual(r.status_code, 200)
        content = r.content.decode('utf-8')
        self.assertIn('Student ID,Name,Date,Status', content)
        self.assertIn('Present', content)
        self.assertIn('Late', content)
