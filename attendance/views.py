from django.contrib import messages
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from . models import Attendance
from main.models import Student, Course, Faculty
from main.views import is_faculty_authorised
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.core.paginator import Paginator
from datetime import datetime as dt
import csv
import logging

logger = logging.getLogger(__name__)


def attendance(request, code):
    if is_faculty_authorised(request, code):
        course = Course.objects.get(code=code)
        students = Student.objects.filter(course__code=code)

        return render(request, 'attendance/attendance.html', {'students': students, 'course': course, 'faculty': Faculty.objects.get(course=course)})


def createRecord(request, code):
    if is_faculty_authorised(request, code):
        if request.method == 'POST':
            date = request.POST['dateCreate']
            course = Course.objects.get(code=code)
            students = Student.objects.filter(course__code=code)
            # check if attendance record already exists for the date
            if Attendance.objects.filter(date=date, course=course).exists():
                return render(request, 'attendance/attendance.html', {'code': code, 'students': students, 'course': course, 'faculty': Faculty.objects.get(course=course), 'error': "Attendance record already exists for the date " + date})
            else:
                for student in students:
                    attendance = Attendance(
                        student=student, course=course, date=date, status=False)
                    attendance.save()

                messages.success(
                    request, 'Attendance record created successfully for the date ' + date)
                return redirect('/attendance/' + str(code))
        else:
            return redirect('/attendance/' + str(code))
    else:
        return redirect('std_login')


def loadAttendance(request, code):
    if is_faculty_authorised(request, code):
        if request.method == 'POST':
            date = request.POST.get('date', '').strip()
            course = Course.objects.get(code=code)
            students = Student.objects.filter(course__code=code)
            attendance = Attendance.objects.filter(course=course, date=date).select_related('student')
            # check if attendance record exists for the date
            if attendance.exists():
                return render(request, 'attendance/attendance.html', {'code': code, 'students': students, 'course': course, 'faculty': Faculty.objects.get(course=course), 'attendance': attendance, 'date': date})
            else:
                return render(request, 'attendance/attendance.html', {'code': code, 'students': students, 'course': course, 'faculty': Faculty.objects.get(course=course), 'error': 'Could not load. Attendance record does not exist for the date ' + date})

    else:
        return redirect('std_login')


@require_http_methods(["GET"])
def loadAttendanceRange(request, code):
    if is_faculty_authorised(request, code):
        course = Course.objects.get(code=code)
        students = Student.objects.filter(course__code=code)
        start = request.GET.get('start', '').strip()
        end = request.GET.get('end', '').strip()
        status = request.GET.get('status', '').strip()
        qs = Attendance.objects.filter(course=course).select_related('student')
        if start:
            try:
                s = dt.fromisoformat(start).date()
                qs = qs.filter(date__gte=s)
            except Exception:
                pass
        if end:
            try:
                e = dt.fromisoformat(end).date()
                qs = qs.filter(date__lte=e)
            except Exception:
                pass
        if status == 'present':
            qs = qs.filter(status=True, is_late=False)
        elif status == 'late':
            qs = qs.filter(status=True, is_late=True)
        elif status == 'absent':
            qs = qs.filter(status=False)
        try:
            page_num = int(request.GET.get('page', '1'))
        except Exception:
            page_num = 1
        paginator = Paginator(qs.order_by('-date', 'student__student_id'), 25)
        page_obj = paginator.get_page(page_num)
        return render(request, 'attendance/attendance.html', {
            'students': students,
            'course': course,
            'faculty': Faculty.objects.get(course=course),
            'attendance': page_obj.object_list,
            'page_obj': page_obj,
            'start': start,
            'end': end,
            'status': status
        })
    else:
        return redirect('std_login')


@require_http_methods(["GET", "POST"])
def submitAttendance(request, code):
    if is_faculty_authorised(request, code):
        try:
            students = Student.objects.filter(course__code=code)
            course = Course.objects.get(code=code)
            if request.method == 'POST':
                date = request.POST.get('datehidden')
                if not date:
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return JsonResponse({'success': False, 'message': 'Missing date'}, status=400)
                    messages.error(request, 'Missing date. Please load attendance for a specific date and try again.')
                    return redirect('/attendance/' + str(code))
                if not Attendance.objects.filter(course=course, date=date).exists():
                    for student in students:
                        Attendance.objects.create(student=student, course=course, date=date, status=False, is_late=False)
                client_ts = request.POST.get('client_ts')
                conflicts = 0
                updated = 0
                for student in students:
                    attendance = Attendance.objects.get(
                        student=student, course=course, date=date)
                    val = request.POST.get(str(student.student_id))
                    # Conflict detection using updated_at vs client_ts (milliseconds)
                    if client_ts:
                        try:
                            client_ms = int(client_ts)
                            server_ms = int(attendance.updated_at.timestamp() * 1000)
                            if server_ms > client_ms:
                                conflicts += 1
                                # Skip updating conflicting record to avoid overwriting newer data
                                continue
                        except Exception:
                            pass
                    if val in ('1', 'present'):
                        attendance.status = True
                        attendance.is_late = False
                    elif val in ('late', '2'):
                        attendance.status = True
                        attendance.is_late = True
                    else:
                        attendance.status = False
                        attendance.is_late = False
                    attendance.save()
                    updated += 1
                logger.info(f"Attendance submit: course={code}, date={date}, updated={updated}, conflicts={conflicts}, ajax={'XMLHttpRequest' in request.headers.get('X-Requested-With', '')}")
                messages.success(
                    request, 'Attendance record submitted successfully for the date ' + date)
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.POST.get('ajax') == 'true':
                    return JsonResponse({'success': True, 'message': 'Saved', 'date': date, 'conflicts': conflicts})
                return redirect('/attendance/' + str(code))

            else:
                return render(request, 'attendance/attendance.html', {'code': code, 'students': students, 'course': course, 'faculty': Faculty.objects.get(course=course)})
        except Exception as e:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'message': 'Error saving attendance'}, status=500)
            return render(request, 'attendance/attendance.html', {'code': code, 'error': "Error! could not save", 'students': students, 'course': course, 'faculty': Faculty.objects.get(course=course)})


@require_http_methods(["GET"]) 
def exportAttendance(request, code):
    if is_faculty_authorised(request, code):
        date = request.GET.get('date')
        course = Course.objects.get(code=code)
        qs = Attendance.objects.filter(course=course).select_related('student')
        start = request.GET.get('start')
        end = request.GET.get('end')
        status = request.GET.get('status')
        if date:
            qs = qs.filter(date=date)
        if start:
            try:
                s = dt.fromisoformat(start).date()
                qs = qs.filter(date__gte=s)
            except Exception:
                pass
        if end:
            try:
                e = dt.fromisoformat(end).date()
                qs = qs.filter(date__lte=e)
            except Exception:
                pass
        if status == 'present':
            qs = qs.filter(status=True, is_late=False)
        elif status == 'late':
            qs = qs.filter(status=True, is_late=True)
        elif status == 'absent':
            qs = qs.filter(status=False)
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="attendance_{code}_{date or start or "all"}.csv"'
        writer = csv.writer(response)
        writer.writerow(['Student ID', 'Name', 'Date', 'Status'])
        count = 0
        for a in qs.order_by('date', 'student__student_id'):
            st = 'Late' if (a.status and a.is_late) else ('Present' if a.status else 'Absent')
            writer.writerow([a.student.student_id, a.student.name, a.date.isoformat(), st])
            count += 1
        logger.info(f"Attendance export: course={code}, date={date or 'all'}, start={start or ''}, end={end or ''}, status={status or ''}, rows={count}")
        return response
    else:
        return redirect('std_login')
