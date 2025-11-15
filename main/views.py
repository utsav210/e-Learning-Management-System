import datetime
import logging
from django.shortcuts import redirect, render
from django.contrib import messages
from .models import Student, Course, Announcement, Assignment, Submission, Material, Faculty, Department, PasswordResetOTP, LoginOTP
from django.template.defaulttags import register
from django.db.models import Count, Q
from django.http import HttpResponseRedirect, Http404, JsonResponse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from .forms import AnnouncementForm, AssignmentForm, MaterialForm
from django import forms
from django.core import validators
from django.contrib.auth.hashers import make_password, check_password
from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.cache import never_cache
from django.core.mail import send_mail
from django.conf import settings
import random
import smtplib
from datetime import timedelta

# Configure logging
logger = logging.getLogger(__name__)


class LoginForm(forms.Form):
    username = forms.CharField(
        label='Username', 
        max_length=100, 
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your username'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Enter your password'}),
        min_length=1,
        max_length=255
    )
    
    def clean_username(self):
        username = self.cleaned_data.get('username')
        if username:
            # Basic username validation
            if len(username.strip()) == 0:
                raise forms.ValidationError('Username cannot be empty')
        return username
    
    def clean_password(self):
        password = self.cleaned_data.get('password')
        if password:
            # Basic password validation
            if len(password.strip()) == 0:
                raise forms.ValidationError('Password cannot be empty')
        return password


def is_student_authorised(request, code):
    try:
        course = Course.objects.get(code=code)
        if request.session.get('student_id'):
            student = Student.objects.get(student_id=request.session['student_id'])
            return course in student.course.all()
        return False
    except (ObjectDoesNotExist, KeyError) as e:
        logger.warning(f"Authorization check failed for student: {e}")
        return False


def is_faculty_authorised(request, code):
    try:
        if request.session.get('faculty_id'):
            faculty_id = request.session['faculty_id']
            # Authorize if the faculty is directly assigned OR matches via facultyKey
            faculty_courses = Course.objects.filter(
                Q(faculty_id=faculty_id) | Q(faculty__isnull=True, facultyKey=faculty_id)
            ).values_list('code', flat=True)
            return code in faculty_courses
        return False
    except (ObjectDoesNotExist, KeyError) as e:
        logger.warning(f"Authorization check failed for faculty: {e}")
        return False


# Custom Login page for both student and faculty with 2FA
@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def std_login(request):
    error_messages = []

    if request.method == 'POST':
        form = LoginForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            # Check student login - working with plaintext passwords
            try:
                student = Student.objects.get(name=username)
                # Direct comparison for plaintext passwords
                if student.password == password:
                    # Check if email is set (required for 2FA)
                    if not student.email:
                        error_messages.append('Email address is required for login. Please contact administrator to add your email.')
                        context = {'form': form, 'error_messages': error_messages}
                        return render(request, 'login_page.html', context)
                    
                    # Generate OTP for 2FA
                    otp = generate_otp()
                    
                    # Invalidate previous login OTPs for this student
                    LoginOTP.objects.filter(student=student, is_used=False).update(is_used=True)
                    
                    # Create new login OTP
                    login_otp = LoginOTP.objects.create(
                        student=student,
                        email=student.email,
                        otp=otp,
                        user_type='student'
                    )
                    
                    # Send OTP email
                    try:
                        send_mail(
                            subject='Login Verification OTP - eLMS',
                            message=f'''Hello {student.name},

You are attempting to login to your eLMS account.

Your login verification OTP (One-Time Password) is: {otp}

This OTP is valid for {getattr(settings, 'OTP_EXPIRY_MINUTES', 10)} minutes.

If you did not attempt to login, please ignore this email and contact administrator immediately.

Best regards,
eLMS Team''',
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            recipient_list=[student.email],
                            fail_silently=False,
                        )
                        # Store pending login info in session
                        request.session['pending_login_user_type'] = 'student'
                        request.session['pending_login_id'] = str(student.student_id)
                        request.session['pending_login_email'] = student.email
                        messages.success(request, f'OTP has been sent to your email: {student.email}')
                        return redirect('verifyLoginOTP')
                    except Exception as e:
                        logger.error(f"Error sending login OTP email: {str(e)}")
                        login_otp.delete()
                        error_messages.append('Failed to send OTP. Please check your email configuration or contact administrator.')
                        context = {'form': form, 'error_messages': error_messages}
                        return render(request, 'login_page.html', context)
            except Student.DoesNotExist:
                pass
            
            # Check faculty login - working with plaintext passwords
            try:
                faculty = Faculty.objects.get(name=username)
                # Direct comparison for plaintext passwords
                if faculty.password == password:
                    # Check if email is set (required for 2FA)
                    if not faculty.email:
                        error_messages.append('Email address is required for login. Please contact administrator to add your email.')
                        context = {'form': form, 'error_messages': error_messages}
                        return render(request, 'login_page.html', context)
                    
                    # Generate OTP for 2FA
                    otp = generate_otp()
                    
                    # Invalidate previous login OTPs for this faculty
                    LoginOTP.objects.filter(faculty=faculty, is_used=False).update(is_used=True)
                    
                    # Create new login OTP
                    login_otp = LoginOTP.objects.create(
                        faculty=faculty,
                        email=faculty.email,
                        otp=otp,
                        user_type='faculty'
                    )
                    
                    # Send OTP email
                    try:
                        send_mail(
                            subject='Login Verification OTP - eLMS',
                            message=f'''Hello {faculty.name},

You are attempting to login to your eLMS account.

Your login verification OTP (One-Time Password) is: {otp}

This OTP is valid for {getattr(settings, 'OTP_EXPIRY_MINUTES', 10)} minutes.

If you did not attempt to login, please ignore this email and contact administrator immediately.

Best regards,
eLMS Team''',
                            from_email=settings.DEFAULT_FROM_EMAIL,
                            recipient_list=[faculty.email],
                            fail_silently=False,
                        )
                        # Store pending login info in session
                        request.session['pending_login_user_type'] = 'faculty'
                        request.session['pending_login_id'] = str(faculty.faculty_id)
                        request.session['pending_login_email'] = faculty.email
                        messages.success(request, f'OTP has been sent to your email: {faculty.email}')
                        return redirect('verifyLoginOTP')
                    except Exception as e:
                        logger.error(f"Error sending login OTP email: {str(e)}")
                        login_otp.delete()
                        error_messages.append('Failed to send OTP. Please check your email configuration or contact administrator.')
                        context = {'form': form, 'error_messages': error_messages}
                        return render(request, 'login_page.html', context)
            except Faculty.DoesNotExist:
                pass
            
            error_messages.append('Invalid login credentials.')
        else:
            error_messages.append('Invalid form data.')
    else:
        form = LoginForm()

    if 'student_id' in request.session:
        return redirect('/my/')
    elif 'faculty_id' in request.session:
        return redirect('/facultyCourses/')

    context = {'form': form, 'error_messages': error_messages}
    return render(request, 'login_page.html', context)


# Two-Factor Authentication - Verify Login OTP
@csrf_protect
@require_http_methods(["GET", "POST"])
def verifyLoginOTP(request):
    """Verify OTP for login 2FA"""
    user_type = request.session.get('pending_login_user_type')
    user_id = request.session.get('pending_login_id')
    email = request.session.get('pending_login_email')
    
    if not user_type or not user_id or not email:
        messages.error(request, 'Session expired. Please login again.')
        return redirect('std_login')
    
    if request.method == 'POST':
        otp = request.POST.get('otp', '').strip()
        
        if not otp:
            messages.error(request, 'Please enter the OTP.')
            return render(request, 'main/verifyLoginOTP.html', {'email': email})
        
        # Validate OTP format (6 digits)
        if not otp.isdigit() or len(otp) != 6:
            messages.error(request, 'OTP must be a 6-digit number.')
            return render(request, 'main/verifyLoginOTP.html', {'email': email})
        
        try:
            if user_type == 'student':
                student = Student.objects.get(student_id=user_id, email=email)
                login_otp = LoginOTP.objects.filter(
                    student=student,
                    email=email,
                    otp=otp,
                    is_used=False,
                    user_type='student'
                ).order_by('-created_at').first()
                
                if login_otp and not login_otp.is_expired():
                    # Mark OTP as verified and used
                    login_otp.is_verified = True
                    login_otp.is_used = True
                    login_otp.save()
                    
                    # Clear pending login session data
                    request.session.pop('pending_login_user_type', None)
                    request.session.pop('pending_login_id', None)
                    request.session.pop('pending_login_email', None)
                    
                    # Complete login
                    request.session['student_id'] = student.student_id
                    # Check if email is set, if not, mark for popup
                    if not student.email:
                        request.session['show_email_popup'] = True
                    
                    messages.success(request, 'Login successful! Welcome back.')
                    return redirect('myCourses')
                else:
                    if login_otp and login_otp.is_expired():
                        messages.error(request, 'OTP has expired. Please login again.')
                    else:
                        messages.error(request, 'Invalid OTP. Please try again.')
                    
            elif user_type == 'faculty':
                faculty = Faculty.objects.get(faculty_id=user_id, email=email)
                login_otp = LoginOTP.objects.filter(
                    faculty=faculty,
                    email=email,
                    otp=otp,
                    is_used=False,
                    user_type='faculty'
                ).order_by('-created_at').first()
                
                if login_otp and not login_otp.is_expired():
                    # Mark OTP as verified and used
                    login_otp.is_verified = True
                    login_otp.is_used = True
                    login_otp.save()
                    
                    # Clear pending login session data
                    request.session.pop('pending_login_user_type', None)
                    request.session.pop('pending_login_id', None)
                    request.session.pop('pending_login_email', None)
                    
                    # Complete login
                    request.session['faculty_id'] = faculty.faculty_id
                    
                    messages.success(request, 'Login successful! Welcome back.')
                    return redirect('facultyCourses')
                else:
                    if login_otp and login_otp.is_expired():
                        messages.error(request, 'OTP has expired. Please login again.')
                    else:
                        messages.error(request, 'Invalid OTP. Please try again.')
            else:
                messages.error(request, 'Invalid user type. Please login again.')
                return redirect('std_login')
                
        except (Student.DoesNotExist, Faculty.DoesNotExist):
            messages.error(request, 'User not found. Please login again.')
            # Clear session
            request.session.pop('pending_login_user_type', None)
            request.session.pop('pending_login_id', None)
            request.session.pop('pending_login_email', None)
            return redirect('std_login')
        except Exception as e:
            logger.error(f"Error in verifyLoginOTP: {str(e)}")
            messages.error(request, 'An error occurred. Please try again.')
    
    return render(request, 'main/verifyLoginOTP.html', {'email': email})


# Clears the session on logout
@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def std_logout(request):
    # Clear all session data including pending login data
    request.session.flush()
    # Also clear any pending login session variables explicitly
    request.session.pop('pending_login_user_type', None)
    request.session.pop('pending_login_id', None)
    request.session.pop('pending_login_email', None)
    return redirect('std_login')


# Display all courses (student view)
@require_GET
def myCourses(request):
    try:
        if request.session.get('student_id'):
            student = Student.objects.get(student_id=request.session['student_id'])
            courses = student.course.all()
            faculty = student.course.all().values_list('faculty_id', flat=True)
            
            # Check if email popup should be shown
            show_email_popup = request.session.get('show_email_popup', False) and not student.email

            context = {
                'courses': courses,
                'student': student,
                'faculty': faculty,
                'show_email_popup': show_email_popup
            }

            return render(request, 'main/myCourses.html', context)
        else:
            return redirect('std_login')
    except ObjectDoesNotExist:
        logger.error(f"Student not found: {request.session.get('student_id')}")
        messages.error(request, 'Student account not found. Please contact administrator.')
        return redirect('std_login')
    except Exception as e:
        logger.error(f"Error in myCourses: {str(e)}")
        return render(request, 'error.html')


# Display all courses (faculty view)
@require_GET
def facultyCourses(request):
    try:
        if request.session.get('faculty_id'):
            faculty = Faculty.objects.get(faculty_id=request.session['faculty_id'])
            # Include courses explicitly assigned to this faculty and those pending assignment but matching the facultyKey
            courses = Course.objects.filter(
                Q(faculty_id=request.session['faculty_id']) | Q(faculty__isnull=True, facultyKey=request.session['faculty_id'])
            )
            # Student count of each course to show on the faculty page
            studentCount = Course.objects.all().annotate(student_count=Count('students'))

            studentCountDict = {}

            for course in studentCount:
                studentCountDict[course.code] = course.student_count

            @register.filter
            def get_item(dictionary, course_code):
                return dictionary.get(course_code)

            context = {
                'courses': courses,
                'faculty': faculty,
                'studentCount': studentCountDict
            }

            return render(request, 'main/facultyCourses.html', context)
        else:
            return redirect('std_login')
    except ObjectDoesNotExist:
        logger.error(f"Faculty not found: {request.session.get('faculty_id')}")
        messages.error(request, 'Faculty account not found. Please contact administrator.')
        return redirect('std_login')
    except Exception as e:
        logger.error(f"Error in facultyCourses: {str(e)}")
        return redirect('std_login')


# Particular course page (student view)
@require_GET
def course_page(request, code):
    try:
        course = Course.objects.get(code=code)
        if is_student_authorised(request, code):
            try:
                announcements = Announcement.objects.filter(course_code=course)
                assignments = Assignment.objects.filter(course_code=course.code)
                materials = Material.objects.filter(course_code=course.code)
            except Exception as e:
                logger.warning(f"Error loading course content: {e}")
                announcements = None
                assignments = None
                materials = None

            context = {
                'course': course,
                'announcements': announcements,
                'assignments': assignments[:3] if assignments else [],
                'materials': materials,
                'student': Student.objects.get(student_id=request.session['student_id'])
            }

            return render(request, 'main/course.html', context)
        else:
            return redirect('std_login')
    except ObjectDoesNotExist:
        logger.error(f"Course not found: {code}")
        raise Http404("Course not found")
    except Exception as e:
        logger.error(f"Error in course_page: {str(e)}")
        return render(request, 'error.html')


# Particular course page (faculty view)
@require_GET
def course_page_faculty(request, code):
    course = Course.objects.get(code=code)
    if request.session.get('faculty_id'):
        try:
            announcements = Announcement.objects.filter(course_code=course)
            assignments = Assignment.objects.filter(
                course_code=course.code)
            materials = Material.objects.filter(course_code=course.code)
            studentCount = Student.objects.filter(course=course).count()

        except:
            announcements = None
            assignments = None
            materials = None

        context = {
            'course': course,
            'announcements': announcements,
            'assignments': assignments[:3],
            'materials': materials,
            'faculty': Faculty.objects.get(faculty_id=request.session['faculty_id']),
            'studentCount': studentCount
        }

        return render(request, 'main/faculty_course.html', context)
    else:
        return redirect('std_login')


@require_GET
def error(request):
    return render(request, 'error.html')


# Display user profile(student & faculty)
@require_GET
def profile(request, id):
    try:
        # Check if student is logged in and ID matches
        if request.session.get('student_id') and str(request.session['student_id']) == str(id):
            student = Student.objects.get(student_id=id)
            return render(request, 'main/profile.html', {'student': student})
        # Check if faculty is logged in and ID matches
        elif request.session.get('faculty_id') and str(request.session['faculty_id']) == str(id):
            faculty = Faculty.objects.get(faculty_id=id)
            return render(request, 'main/faculty_profile.html', {'faculty': faculty})
        else:
            return redirect('std_login')
    except Exception as e:
        logger.error(f"Error in profile view: {str(e)}")
        return redirect('std_login')


@csrf_protect
@require_http_methods(["GET", "POST"])
def addAnnouncement(request, code):
    if is_faculty_authorised(request, code):
        if request.method == 'POST':
            form = AnnouncementForm(request.POST)
            form.instance.course_code = Course.objects.get(code=code)
            if form.is_valid():
                form.save()
                messages.success(
                    request, 'Announcement added successfully.')
                return redirect('/faculty/' + str(code))
        else:
            form = AnnouncementForm()
        return render(request, 'main/announcement.html', {'course': Course.objects.get(code=code), 'faculty': Faculty.objects.get(faculty_id=request.session['faculty_id']), 'form': form})
    else:
        return redirect('std_login')


@csrf_protect
@require_POST
def deleteAnnouncement(request, code, id):
    if is_faculty_authorised(request, code):
        try:
            announcement = Announcement.objects.get(course_code=code, id=id)
            announcement.delete()
            messages.warning(request, 'Announcement deleted successfully.')
            return redirect('/faculty/' + str(code))
        except:
            return redirect('/faculty/' + str(code))
    else:
        return redirect('std_login')


@require_GET
def editAnnouncement(request, code, id):
    if is_faculty_authorised(request, code):
        announcement = Announcement.objects.get(course_code_id=code, id=id)
        form = AnnouncementForm(instance=announcement)
        context = {
            'announcement': announcement,
            'course': Course.objects.get(code=code),
            'faculty': Faculty.objects.get(faculty_id=request.session['faculty_id']),
            'form': form
        }
        return render(request, 'main/update-announcement.html', context)
    else:
        return redirect('std_login')


@csrf_protect
@require_POST
def updateAnnouncement(request, code, id):
    if is_faculty_authorised(request, code):
        try:
            announcement = Announcement.objects.get(course_code_id=code, id=id)
            form = AnnouncementForm(request.POST, instance=announcement)
            if form.is_valid():
                form.save()
                messages.info(request, 'Announcement updated successfully.')
                return redirect('/faculty/' + str(code))
        except:
            return redirect('/faculty/' + str(code))

    else:
        return redirect('std_login')


@csrf_protect
@require_http_methods(["GET", "POST"])
def addAssignment(request, code):
    if is_faculty_authorised(request, code):
        if request.method == 'POST':
            form = AssignmentForm(request.POST, request.FILES)
            form.instance.course_code = Course.objects.get(code=code)
            if form.is_valid():
                form.save()
                messages.success(request, 'Assignment added successfully.')
                return redirect('/faculty/' + str(code))
        else:
            form = AssignmentForm()
        return render(request, 'main/assignment.html', {'course': Course.objects.get(code=code), 'faculty': Faculty.objects.get(faculty_id=request.session['faculty_id']), 'form': form})
    else:
        return redirect('std_login')


@require_GET
def assignmentPage(request, code, id):
    course = Course.objects.get(code=code)
    if is_student_authorised(request, code):
        assignment = Assignment.objects.get(course_code=course.code, id=id)
        try:

            submission = Submission.objects.get(assignment=assignment, student=Student.objects.get(
                student_id=request.session['student_id']))

            context = {
                'assignment': assignment,
                'course': course,
                'submission': submission,
                'time': timezone.now(),
                'student': Student.objects.get(student_id=request.session['student_id']),
                'courses': Student.objects.get(student_id=request.session['student_id']).course.all()
            }

            return render(request, 'main/assignment-portal.html', context)

        except:
            submission = None

        context = {
            'assignment': assignment,
            'course': course,
            'submission': submission,
            'time': timezone.now(),
            'student': Student.objects.get(student_id=request.session['student_id']),
            'courses': Student.objects.get(student_id=request.session['student_id']).course.all()
        }

        return render(request, 'main/assignment-portal.html', context)
    else:

        return redirect('std_login')


@require_GET
def allAssignments(request, code):
    if is_faculty_authorised(request, code):
        course = Course.objects.get(code=code)
        assignments = Assignment.objects.filter(course_code=course)
        studentCount = Student.objects.filter(course=course).count()

        context = {
            'assignments': assignments,
            'course': course,
            'faculty': Faculty.objects.get(faculty_id=request.session['faculty_id']),
            'studentCount': studentCount

        }
        return render(request, 'main/all-assignments.html', context)
    else:
        return redirect('std_login')


@require_GET
def allAssignmentsSTD(request, code):
    if is_student_authorised(request, code):
        course = Course.objects.get(code=code)
        assignments = Assignment.objects.filter(course_code=course)
        context = {
            'assignments': assignments,
            'course': course,
            'student': Student.objects.get(student_id=request.session['student_id']),

        }
        return render(request, 'main/all-assignments-std.html', context)
    else:
        return redirect('std_login')


@csrf_protect
@require_http_methods(["GET", "POST"])
def addSubmission(request, code, id):
    try:
        course = Course.objects.get(code=code)
        if is_student_authorised(request, code):
            # check if assignment is open
            assignment = Assignment.objects.get(course_code=course.code, id=id)
            if assignment.deadline < timezone.now():

                return redirect('/assignment/' + str(code) + '/' + str(id))

            if request.method == 'POST' and request.FILES['file']:
                assignment = Assignment.objects.get(
                    course_code=course.code, id=id)
                submission = Submission(assignment=assignment, student=Student.objects.get(
                    student_id=request.session['student_id']), file=request.FILES['file'],)
                submission.status = 'Submitted'
                submission.save()
                return HttpResponseRedirect(request.path_info)
            else:
                assignment = Assignment.objects.get(
                    course_code=course.code, id=id)
                submission = Submission.objects.get(assignment=assignment, student=Student.objects.get(
                    student_id=request.session['student_id']))
                context = {
                    'assignment': assignment,
                    'course': course,
                    'submission': submission,
                    'time': timezone.now(),
                    'student': Student.objects.get(student_id=request.session['student_id']),
                    'courses': Student.objects.get(student_id=request.session['student_id']).course.all()
                }

                return render(request, 'main/assignment-portal.html', context)
        else:
            return redirect('std_login')
    except:
        return HttpResponseRedirect(request.path_info)


@require_GET
def viewSubmission(request, code, id):
    course = Course.objects.get(code=code)
    if is_faculty_authorised(request, code):
        try:
            assignment = Assignment.objects.get(course_code_id=code, id=id)
            submissions = Submission.objects.filter(
                assignment_id=assignment.id)

            context = {
                'course': course,
                'submissions': submissions,
                'assignment': assignment,
                'totalStudents': len(Student.objects.filter(course=course)),
                'faculty': Faculty.objects.get(faculty_id=request.session['faculty_id']),
                'courses': Course.objects.filter(faculty_id=request.session['faculty_id'])
            }

            return render(request, 'main/assignment-view.html', context)

        except:
            return redirect('/faculty/' + str(code))
    else:
        return redirect('std_login')


@csrf_protect
@require_http_methods(["GET", "POST"])
def gradeSubmission(request, code, id, sub_id):
    try:
        course = Course.objects.get(code=code)
        if is_faculty_authorised(request, code):
            if request.method == 'POST':
                assignment = Assignment.objects.get(course_code_id=code, id=id)
                submissions = Submission.objects.filter(
                    assignment_id=assignment.id)
                submission = Submission.objects.get(
                    assignment_id=id, id=sub_id)
                submission.marks = request.POST['marks']
                if request.POST['marks'] == 0:
                    submission.marks = 0
                submission.save()
                return HttpResponseRedirect(request.path_info)
            else:
                assignment = Assignment.objects.get(course_code_id=code, id=id)
                submissions = Submission.objects.filter(
                    assignment_id=assignment.id)
                submission = Submission.objects.get(
                    assignment_id=id, id=sub_id)

                context = {
                    'course': course,
                    'submissions': submissions,
                    'assignment': assignment,
                    'totalStudents': len(Student.objects.filter(course=course)),
                    'faculty': Faculty.objects.get(faculty_id=request.session['faculty_id']),
                    'courses': Course.objects.filter(faculty_id=request.session['faculty_id'])
                }

                return render(request, 'main/assignment-view.html', context)

        else:
            return redirect('std_login')
    except:
        return redirect('/error/')


@csrf_protect
@require_http_methods(["GET", "POST"])
def addCourseMaterial(request, code):
    if is_faculty_authorised(request, code):
        if request.method == 'POST':
            form = MaterialForm(request.POST, request.FILES)
            form.instance.course_code = Course.objects.get(code=code)
            if form.is_valid():
                form.save()
                messages.success(request, 'New course material added')
                return redirect('/faculty/' + str(code))
            else:
                return render(request, 'main/course-material.html', {'course': Course.objects.get(code=code), 'faculty': Faculty.objects.get(faculty_id=request.session['faculty_id']), 'form': form})
        else:
            form = MaterialForm()
            return render(request, 'main/course-material.html', {'course': Course.objects.get(code=code), 'faculty': Faculty.objects.get(faculty_id=request.session['faculty_id']), 'form': form})
    else:
        return redirect('std_login')


@csrf_protect
@require_POST
def deleteCourseMaterial(request, code, id):
    if is_faculty_authorised(request, code):
        course = Course.objects.get(code=code)
        course_material = Material.objects.get(course_code=course, id=id)
        course_material.delete()
        messages.warning(request, 'Course material deleted')
        return redirect('/faculty/' + str(code))
    else:
        return redirect('std_login')


@require_GET
def courses(request):
    if request.session.get('student_id') or request.session.get('faculty_id'):

        courses = Course.objects.all()
        if request.session.get('student_id'):
            student = Student.objects.get(
                student_id=request.session['student_id'])
        else:
            student = None
        if request.session.get('faculty_id'):
            faculty = Faculty.objects.get(
                faculty_id=request.session['faculty_id'])
        else:
            faculty = None

        enrolled = student.course.all() if student else None
        accessed = Course.objects.filter(
            faculty_id=faculty.faculty_id) if faculty else None

        context = {
            'faculty': faculty,
            'courses': courses,
            'student': student,
            'enrolled': enrolled,
            'accessed': accessed
        }

        return render(request, 'main/all-courses.html', context)

    else:
        return redirect('std_login')


@require_GET
def departments(request):
    if request.session.get('student_id') or request.session.get('faculty_id'):
        departments = Department.objects.all()
        if request.session.get('student_id'):
            student = Student.objects.get(
                student_id=request.session['student_id'])
        else:
            student = None
        if request.session.get('faculty_id'):
            faculty = Faculty.objects.get(
                faculty_id=request.session['faculty_id'])
        else:
            faculty = None
        context = {
            'faculty': faculty,
            'student': student,
            'deps': departments
        }

        return render(request, 'main/departments.html', context)

    else:
        return redirect('std_login')


@csrf_protect
@require_http_methods(["GET", "POST"])
def access(request, code):
    if request.session.get('student_id'):
        course = Course.objects.get(code=code)
        student = Student.objects.get(student_id=request.session['student_id'])
        if request.method == 'POST':
            if (request.POST['key']) == str(course.studentKey):
                student.course.add(course)
                student.save()
                return redirect('/my/')
            else:
                messages.error(request, 'Invalid key')
                return HttpResponseRedirect(request.path_info)
        else:
            return render(request, 'main/access.html', {'course': course, 'student': student})

    else:
        return redirect('std_login')


@require_GET
def search(request):
    if request.session.get('student_id') or request.session.get('faculty_id'):
        q = request.GET.get('q')
        if q and q.strip():  # Check if query exists and is not empty/whitespace
            courses = Course.objects.filter(Q(code__icontains=q) | Q(
                name__icontains=q) | Q(faculty__name__icontains=q))

            if request.session.get('student_id'):
                student = Student.objects.get(
                    student_id=request.session['student_id'])
            else:
                student = None
            if request.session.get('faculty_id'):
                faculty = Faculty.objects.get(
                    faculty_id=request.session['faculty_id'])
            else:
                faculty = None
            enrolled = student.course.all() if student else None
            accessed = Course.objects.filter(
                faculty_id=faculty.faculty_id) if faculty else None

            context = {
                'courses': courses,
                'faculty': faculty,
                'student': student,
                'enrolled': enrolled,
                'accessed': accessed,
                'q': q
            }
            return render(request, 'main/search.html', context)
        else:
            # No query parameter or empty query - redirect to safe default
            referer = request.META.get('HTTP_REFERER')
            if referer and url_has_allowed_host_and_scheme(referer, allowed_hosts=None):
                return HttpResponseRedirect(referer)
            return redirect('courses')
    else:
        return redirect('std_login')


@require_GET
def changePasswordPrompt(request):
    if request.session.get('student_id'):
        student = Student.objects.get(student_id=request.session['student_id'])
        return render(request, 'main/changePassword.html', {'student': student})
    elif request.session.get('faculty_id'):
        faculty = Faculty.objects.get(faculty_id=request.session['faculty_id'])
        return render(request, 'main/changePasswordFaculty.html', {'faculty': faculty})
    else:
        return redirect('std_login')


@require_GET
def changePhotoPrompt(request):
    if request.session.get('student_id'):
        student = Student.objects.get(student_id=request.session['student_id'])
        return render(request, 'main/changePhoto.html', {'student': student})
    elif request.session.get('faculty_id'):
        faculty = Faculty.objects.get(faculty_id=request.session['faculty_id'])
        return render(request, 'main/changePhotoFaculty.html', {'faculty': faculty})
    else:
        return redirect('std_login')


@csrf_protect
@require_http_methods(["GET", "POST"])
def changePassword(request):
    if request.session.get('student_id'):
        student = Student.objects.get(
            student_id=request.session['student_id'])
        if request.method == 'POST':
            old_password = request.POST['oldPassword']
            new_password = request.POST['newPassword']
            
            # Check old password - working with plaintext passwords
            if student.password == old_password:
                # Save new password as plaintext
                student.password = new_password
                student.save()
                messages.success(request, 'Password was changed successfully')
                return redirect('/profile/' + str(student.student_id))
            else:
                messages.error(
                    request, 'Password is incorrect. Please try again')
                return redirect('/changePassword/')
        else:
            return render(request, 'main/changePassword.html', {'student': student})
    else:
        return redirect('std_login')


@csrf_protect
@require_http_methods(["GET", "POST"])
def changePasswordFaculty(request):
    if request.session.get('faculty_id'):
        faculty = Faculty.objects.get(
            faculty_id=request.session['faculty_id'])
        if request.method == 'POST':
            old_password = request.POST['oldPassword']
            new_password = request.POST['newPassword']
            
            # Check old password - working with plaintext passwords
            if faculty.password == old_password:
                # Save new password as plaintext
                faculty.password = new_password
                faculty.save()
                messages.success(request, 'Password was changed successfully')
                return redirect('profile', id=str(faculty.faculty_id))
            else:
                messages.error(
                    request, 'Password is incorrect. Please try again')
                return redirect('/changePasswordFaculty/')
        else:
            print(faculty)
            return render(request, 'main/changePasswordFaculty.html', {'faculty': faculty})
    else:
        return redirect('std_login')


@csrf_protect
@require_http_methods(["GET", "POST"])
def changePhoto(request):
    if request.session.get('student_id'):
        student = Student.objects.get(
            student_id=request.session['student_id'])
        if request.method == 'POST':
            if request.FILES['photo']:
                student.photo = request.FILES['photo']
                student.save()
                messages.success(request, 'Photo was changed successfully')
                return redirect('/profile/' + str(student.student_id))
            else:
                messages.error(
                    request, 'Please select a photo')
                return redirect('/changePhoto/')
        else:
            return render(request, 'main/changePhoto.html', {'student': student})
    else:
        return redirect('std_login')


@csrf_protect
@require_http_methods(["GET", "POST"])
def changePhotoFaculty(request):
    if request.session.get('faculty_id'):
        faculty = Faculty.objects.get(
            faculty_id=request.session['faculty_id'])
        if request.method == 'POST':
            if request.FILES['photo']:
                faculty.photo = request.FILES['photo']
                faculty.save()
                messages.success(request, 'Photo was changed successfully')
                return redirect('profile', id=str(faculty.faculty_id))
            else:
                messages.error(
                    request, 'Please select a photo')
                return redirect('/changePhotoFaculty/')
        else:
            return render(request, 'main/changePhotoFaculty.html', {'faculty': faculty})
    else:
        return redirect('std_login')


@never_cache
@csrf_protect
@require_POST
def guestStudent(request):
    request.session.flush()
    try:
        student = Student.objects.get(name='Guest Student')
        request.session['student_id'] = str(student.student_id)
        return redirect('myCourses')
    except:
        return redirect('std_login')


@never_cache
@csrf_protect
@require_POST
def guestFaculty(request):
    request.session.flush()
    try:
        faculty = Faculty.objects.get(name='Guest Faculty')
        request.session['faculty_id'] = str(faculty.faculty_id)
        return redirect('facultyCourses')
    except:
        return redirect('std_login')


# Forgot Password Functionality
def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))


@csrf_protect
@require_http_methods(["GET", "POST"])
def forgotPassword(request):
    """Request OTP for password reset - email only"""
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        
        if not email:
            messages.error(request, 'Please provide your email address.')
            return render(request, 'main/forgotPassword.html')
        
        # Validate email format
        from django.core.validators import validate_email
        from django.core.exceptions import ValidationError
        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Please enter a valid email address.')
            return render(request, 'main/forgotPassword.html')
        
        try:
            # Find student by email only
            students = Student.objects.filter(email=email)
            
            if not students.exists():
                messages.error(request, 'No account found with the provided email address.')
                return render(request, 'main/forgotPassword.html')
            
            # If multiple students have the same email, that's a data integrity issue
            # For security, we'll only proceed if exactly one student has this email
            if students.count() > 1:
                logger.warning(f"Multiple students found with email: {email}")
                messages.error(request, 'Multiple accounts found with this email. Please contact administrator.')
                return render(request, 'main/forgotPassword.html')
            
            student = students.first()
            
            # Generate OTP
            otp = generate_otp()
            
            # Invalidate previous OTPs for this student
            PasswordResetOTP.objects.filter(student=student, is_used=False).update(is_used=True)
            
            # Create new OTP
            otp_obj = PasswordResetOTP.objects.create(
                student=student,
                email=email,
                otp=otp
            )
            
            # Send OTP email
            try:
                send_mail(
                    subject='Password Reset OTP - eLMS',
                    message=f'''Hello {student.name},

You have requested to reset your password for your eLMS account.

Your OTP (One-Time Password) is: {otp}

This OTP is valid for {getattr(settings, 'OTP_EXPIRY_MINUTES', 10)} minutes.

If you did not request this password reset, please ignore this email.

Best regards,
eLMS Team''',
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
                messages.success(request, f'OTP has been sent to your email: {email}')
                request.session['reset_email'] = email
                request.session['reset_student_id'] = str(student.student_id)
                return redirect('verifyOTP')
            except smtplib.SMTPAuthenticationError as e:
                logger.error(f"Email authentication error while sending OTP to {email}: {str(e)}")
                messages.error(request, 'Email service rejected the credentials. Please contact the administrator to update the email configuration.')
                otp_obj.delete()
                return render(request, 'main/forgotPassword.html')
            except smtplib.SMTPException as e:
                logger.error(f"SMTP error while sending OTP to {email}: {str(e)}")
                messages.error(request, 'Unable to send OTP due to email service issues. Please try again later or contact support.')
                otp_obj.delete()
                return render(request, 'main/forgotPassword.html')
            except Exception as e:
                logger.error(f"Error sending email to {email}: {str(e)}")
                messages.error(request, 'Failed to send OTP. Please check your email configuration or contact administrator.')
                otp_obj.delete()
                return render(request, 'main/forgotPassword.html')
                
        except Exception as e:
            logger.error(f"Error in forgotPassword: {str(e)}")
            messages.error(request, 'An error occurred. Please try again.')
    
    return render(request, 'main/forgotPassword.html')


@csrf_protect
@require_http_methods(["GET", "POST"])
def verifyOTP(request):
    """Verify OTP and allow password reset"""
    email = request.session.get('reset_email')
    student_id = request.session.get('reset_student_id')
    
    if not email:
        messages.error(request, 'Session expired. Please start the password reset process again.')
        return redirect('forgotPassword')
    
    if request.method == 'POST':
        otp = request.POST.get('otp', '').strip()
        
        if not otp:
            messages.error(request, 'Please enter the OTP.')
            return render(request, 'main/verifyOTP.html', {'email': email})
        
        # Validate OTP format (6 digits)
        if not otp.isdigit() or len(otp) != 6:
            messages.error(request, 'OTP must be a 6-digit number.')
            return render(request, 'main/verifyOTP.html', {'email': email})
        
        try:
            # Find student by email (student_id is stored in session for verification)
            if student_id:
                student = Student.objects.get(student_id=student_id, email=email)
            else:
                # Fallback: find by email only if student_id not in session
                students = Student.objects.filter(email=email)
                if students.count() != 1:
                    messages.error(request, 'Account verification failed. Please start the process again.')
                    return redirect('forgotPassword')
                student = students.first()
            
            otp_obj = PasswordResetOTP.objects.filter(
                student=student,
                email=email,
                otp=otp,
                is_used=False
            ).order_by('-created_at').first()
            
            if otp_obj and not otp_obj.is_expired():
                otp_obj.is_verified = True
                otp_obj.save()
                request.session['otp_verified'] = True
                # Ensure student_id is in session for resetPassword
                request.session['reset_student_id'] = str(student.student_id)
                messages.success(request, 'OTP verified successfully. You can now reset your password.')
                return redirect('resetPassword')
            else:
                if otp_obj and otp_obj.is_expired():
                    messages.error(request, 'OTP has expired. Please request a new OTP.')
                else:
                    messages.error(request, 'Invalid OTP. Please try again.')
        except Student.DoesNotExist:
            messages.error(request, 'Student not found. Please start the process again.')
            return redirect('forgotPassword')
        except Exception as e:
            logger.error(f"Error in verifyOTP: {str(e)}")
            messages.error(request, 'An error occurred. Please try again.')
    
    return render(request, 'main/verifyOTP.html', {'email': email})


@csrf_protect
@require_http_methods(["GET", "POST"])
def resetPassword(request):
    """Reset password after OTP verification"""
    email = request.session.get('reset_email')
    student_id = request.session.get('reset_student_id')
    otp_verified = request.session.get('otp_verified', False)
    
    if not email or not student_id or not otp_verified:
        messages.error(request, 'Session expired or OTP not verified. Please start the process again.')
        return redirect('forgotPassword')
    
    if request.method == 'POST':
        new_password = request.POST.get('new_password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()
        
        if not new_password or not confirm_password:
            messages.error(request, 'Please fill in all fields.')
            return render(request, 'main/resetPassword.html')
        
        if new_password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'main/resetPassword.html')
        
        if len(new_password) < 6:
            messages.error(request, 'Password must be at least 6 characters long.')
            return render(request, 'main/resetPassword.html')
        
        try:
            student = Student.objects.get(student_id=student_id, email=email)
            
            # Verify OTP was used
            otp_obj = PasswordResetOTP.objects.filter(
                student=student,
                email=email,
                is_verified=True,
                is_used=False
            ).order_by('-created_at').first()
            
            if otp_obj and not otp_obj.is_expired():
                # Update password
                student.password = new_password
                student.save()
                
                # Mark OTP as used
                otp_obj.is_used = True
                otp_obj.save()
                
                # Clear session
                request.session.pop('reset_email', None)
                request.session.pop('reset_student_id', None)
                request.session.pop('otp_verified', None)
                
                messages.success(request, 'Password reset successfully! You can now login with your new password.')
                return redirect('std_login')
            else:
                messages.error(request, 'OTP verification expired. Please start the process again.')
                return redirect('forgotPassword')
        except Student.DoesNotExist:
            messages.error(request, 'Student not found.')
            return redirect('forgotPassword')
        except Exception as e:
            logger.error(f"Error in resetPassword: {str(e)}")
            messages.error(request, 'An error occurred. Please try again.')
    
    return render(request, 'main/resetPassword.html')


# Email Management
@csrf_protect
@require_http_methods(["GET", "POST"])
def saveEmail(request):
    """Save email on first login (popup)"""
    if request.session.get('student_id'):
        try:
            student = Student.objects.get(student_id=request.session['student_id'])
            
            if request.method == 'POST':
                # Handle skip case
                if request.POST.get('skip'):
                    request.session.pop('show_email_popup', None)
                    return JsonResponse({'success': True, 'message': 'You can add your email later from your profile.'})
                
                email = request.POST.get('email', '').strip()
                
                if not email:
                    return JsonResponse({'success': False, 'message': 'Email is required.'})
                
                # Validate email format
                from django.core.validators import validate_email
                from django.core.exceptions import ValidationError
                try:
                    validate_email(email)
                except ValidationError:
                    return JsonResponse({'success': False, 'message': 'Please enter a valid email address.'})
                
                # Check if email is already used by another student
                if Student.objects.filter(email=email).exclude(student_id=student.student_id).exists():
                    return JsonResponse({'success': False, 'message': 'This email is already registered with another account.'})
                
                student.email = email
                student.save()
                
                # Clear the popup flag
                request.session.pop('show_email_popup', None)
                request.session['email_saved'] = True
                
                return JsonResponse({'success': True, 'message': 'Email saved successfully!'})
            else:
                return JsonResponse({'success': False, 'message': 'Invalid request method.'})
        except Student.DoesNotExist:
            return JsonResponse({'success': False, 'message': 'Student not found.'})
        except Exception as e:
            logger.error(f"Error in saveEmail: {str(e)}")
            return JsonResponse({'success': False, 'message': 'An error occurred. Please try again.'})
    else:
        return JsonResponse({'success': False, 'message': 'Please login first.'})


@csrf_protect
@require_http_methods(["GET", "POST"])
def changeEmail(request):
    """Change email for logged in student"""
    if request.session.get('student_id'):
        try:
            student = Student.objects.get(student_id=request.session['student_id'])
            
            if request.method == 'POST':
                new_email = request.POST.get('new_email', '').strip()
                password = request.POST.get('password', '').strip()
                
                if not new_email or not password:
                    messages.error(request, 'Please fill in all fields.')
                    return render(request, 'main/changeEmail.html', {'student': student})
                
                # Verify password
                if student.password != password:
                    messages.error(request, 'Incorrect password. Please try again.')
                    return render(request, 'main/changeEmail.html', {'student': student})
                
                # Validate email format
                from django.core.validators import validate_email
                from django.core.exceptions import ValidationError
                try:
                    validate_email(new_email)
                except ValidationError:
                    messages.error(request, 'Please enter a valid email address.')
                    return render(request, 'main/changeEmail.html', {'student': student})
                
                # Check if email is already used
                if Student.objects.filter(email=new_email).exclude(student_id=student.student_id).exists():
                    messages.error(request, 'This email is already registered with another account.')
                    return render(request, 'main/changeEmail.html', {'student': student})
                
                student.email = new_email
                student.save()
                
                messages.success(request, 'Email updated successfully!')
                return redirect('profile', id=str(student.student_id))
            else:
                return render(request, 'main/changeEmail.html', {'student': student})
        except Student.DoesNotExist:
            messages.error(request, 'Student not found.')
            return redirect('std_login')
        except Exception as e:
            logger.error(f"Error in changeEmail: {str(e)}")
            messages.error(request, 'An error occurred. Please try again.')
            return redirect('profile', id=str(request.session.get('student_id')))
    else:
        return redirect('std_login')