import datetime
import logging
from django.shortcuts import redirect, render
from django.contrib import messages
from .models import Student, Course, Announcement, Assignment, Submission, Material, Faculty, Department, PasswordResetOTP, LoginOTP
from django.template.defaulttags import register
from django.db.models import Count, Q
from django.http import HttpResponseRedirect, Http404, JsonResponse
from attendance.models import Attendance
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
import secrets  # SECURITY FIX: Use secrets module for cryptographically secure random
import random  # Keep for backward compatibility if needed
import smtplib
from datetime import timedelta
from functools import wraps
from django.core.cache import cache
from django.http import HttpResponse
import re

# Configure logging
logger = logging.getLogger(__name__)


@register.filter
def get_item(dictionary, key):
    try:
        return dictionary.get(key)
    except Exception:
        return None

# SECURITY FIX: Rate limiting decorator to prevent brute force attacks
def rate_limit(max_requests=5, window_seconds=300, key_prefix='rate_limit'):
    """
    Rate limiting decorator to prevent brute force attacks.
    
    Args:
        max_requests: Maximum number of requests allowed
        window_seconds: Time window in seconds (default 5 minutes)
        key_prefix: Prefix for cache key
    
    Usage:
        @rate_limit(max_requests=5, window_seconds=300)
        def my_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            xff = request.META.get('HTTP_X_FORWARDED_FOR')
            if xff:
                parts = [p.strip() for p in xff.split(',') if p.strip()]
                client_ip = parts[0] if parts else request.META.get('REMOTE_ADDR', 'unknown')
            else:
                client_ip = request.META.get('REMOTE_ADDR', 'unknown')
            
            # Create cache key
            cache_key = f'{key_prefix}:{client_ip}'
            
            # Get current request count
            request_count = cache.get(cache_key, 0)
            
            if request_count >= max_requests:
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                try:
                    messages.error(request, 'Too many requests. Please try again later.', fail_silently=True)
                except Exception:
                    pass
                return HttpResponse('Too many requests. Please try again later.', status=429)
            
            # Increment request count
            cache.set(cache_key, request_count + 1, window_seconds)
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# SECURITY FIX: Password hashing helper functions
# These functions provide secure password handling with backward compatibility
def hash_password(password):
    """
    Hash a password using Django's password hasher.
    This ensures passwords are stored securely using PBKDF2 or Argon2.
    """
    from django.contrib.auth.hashers import make_password
    return make_password(password)


def check_password(stored_password, provided_password):
    """
    Check if a provided password matches the stored password.
    Supports both hashed (new) and plaintext (legacy) passwords for backward compatibility.
    Automatically migrates plaintext passwords to hashed format on successful login.
    """
    from django.contrib.auth.hashers import check_password as django_check_password, make_password
    
    # First, try checking as if it's a hashed password
    try:
        if django_check_password(provided_password, stored_password):
            return True
    except (ValueError, TypeError):
        # If stored_password is not a valid hash, it might be plaintext (legacy)
        pass
    
    # Fallback: check if it's a plaintext match (for backward compatibility)
    if stored_password == provided_password:
        return True
    
    return False


def ensure_password_hashed(user, password_field_name='password'):
    """
    Ensure a user's password is hashed. If it's plaintext, hash it.
    This is called after successful authentication to migrate legacy passwords.
    """
    from django.contrib.auth.hashers import make_password, is_password_usable
    
    current_password = getattr(user, password_field_name)
    
    # Check if password is already hashed (Django hashes start with algorithm identifier)
    # Valid Django password hashes start with: pbkdf2_sha256$, pbkdf2_sha1$, argon2$, bcrypt_sha256$
    if not is_password_usable(current_password) or not current_password.startswith(('pbkdf2_', 'argon2$', 'bcrypt_', 'scrypt_')):
        # Password is not hashed (plaintext), hash it now
        hashed_password = make_password(current_password)
        setattr(user, password_field_name, hashed_password)
        user.save(update_fields=[password_field_name])
        logger.info(f"Migrated plaintext password to hashed format for user: {getattr(user, 'name', 'Unknown')}")


class LoginForm(forms.Form):
    username = forms.CharField(
        label='Username', 
        max_length=100, 
        widget=forms.TextInput(attrs={'class': 'form-control block w-full rounded-lg border border-gray-300 pl-5 pr-3 py-2.5 text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500', 'placeholder': 'Enter your username'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control block w-full rounded-lg border border-gray-300 pl-10 pr-3 py-2.5 text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500', 'placeholder': 'Enter your password'}),
        min_length=1,
        max_length=255
    )
    user_type = forms.ChoiceField(
        choices=[('student', 'Student'), ('teacher', 'Teacher')],
        widget=forms.Select(attrs={'class': 'form-control block w-full rounded-lg border border-gray-300 pl-10 pr-8 py-2.5 text-gray-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500', 'id': 'user_type_select'}),
        initial='student',
        required=True
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
    
    def clean_user_type(self):
        user_type = self.cleaned_data.get('user_type')
        if user_type not in ['student', 'teacher']:
            raise forms.ValidationError('Invalid user type selected')
        return user_type


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
# SECURITY FIX: Role-based authentication - user must select their role
@never_cache
@csrf_protect
@rate_limit(max_requests=10, window_seconds=300, key_prefix='login')
@require_http_methods(["GET", "POST"])
def std_login(request):
    error_messages = []

    if request.method == 'POST':
        form = LoginForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user_type = form.cleaned_data['user_type']  # 'student' or 'teacher'

            # SECURITY FIX: Check only the selected role's table
            # This prevents users from logging in with wrong role credentials
            if user_type == 'student':
                # Only check Student table
                try:
                    student = Student.objects.get(name=username)
                    # SECURITY FIX: Use secure password checking with backward compatibility
                    if check_password(student.password, password):
                        # SECURITY FIX: Migrate plaintext password to hashed on successful login
                        ensure_password_hashed(student, 'password')
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
                            if not (getattr(settings, 'EMAIL_HOST_USER', None) and getattr(settings, 'EMAIL_HOST_PASSWORD', None)):
                                raise ValueError('Email credentials not configured')
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
                    else:
                        # Password doesn't match
                        error_messages.append('Invalid login credentials. Please check your username and password.')
                except Student.DoesNotExist:
                    # Student not found in Student table
                    error_messages.append('Invalid login credentials. Student account not found.')
            
            elif user_type == 'teacher':
                # Only check Faculty table
                try:
                    faculty = Faculty.objects.get(name=username)
                    # SECURITY FIX: Use secure password checking with backward compatibility
                    if check_password(faculty.password, password):
                        # SECURITY FIX: Migrate plaintext password to hashed on successful login
                        ensure_password_hashed(faculty, 'password')
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
                            if not (getattr(settings, 'EMAIL_HOST_USER', None) and getattr(settings, 'EMAIL_HOST_PASSWORD', None)):
                                raise ValueError('Email credentials not configured')
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
                    else:
                        # Password doesn't match
                        error_messages.append('Invalid login credentials. Please check your username and password.')
                except Faculty.DoesNotExist:
                    # Faculty not found in Faculty table
                    error_messages.append('Invalid login credentials. Teacher account not found.')
            else:
                error_messages.append('Invalid user type selected.')
            
            # If we reach here, login failed
            if not error_messages:
                error_messages.append('Invalid login credentials.')
        else:
            # Form validation errors
            for field, errors in form.errors.items():
                for error in errors:
                    error_messages.append(f'{field}: {error}')
            if not error_messages:
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
# SECURITY FIX: Add rate limiting to prevent brute force attacks on OTP verification
@rate_limit(max_requests=5, window_seconds=300, key_prefix='otp_verify')
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
                    request.session.cycle_key()
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
                    request.session.cycle_key()
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
            try:
                student_id = int(str(request.session['student_id']))
                student = Student.objects.get(student_id=student_id)
            except Exception:
                messages.error(request, 'Session invalid. Please login again.')
                return redirect('std_login')
            try:
                courses = student.course.all()
            except Exception:
                courses = []
            
            # Check if email popup should be shown
            show_email_popup = request.session.get('show_email_popup', False) and not student.email

            stats = {}
            try:
                for c in courses:
                    total = Attendance.objects.filter(student=student, course=c).count()
                    present = Attendance.objects.filter(student=student, course=c, status=True).count()
                    late = Attendance.objects.filter(student=student, course=c, status=True, is_late=True).count()
                    absent = Attendance.objects.filter(student=student, course=c, status=False).count()
                    percentage = round((present / total) * 100, 2) if total else None
                    stats[c.code] = {'total': total, 'present': present, 'late': late, 'absent': absent, 'percentage': percentage}
            except Exception:
                stats = {}

            try:
                from datetime import timedelta
                recent_absences = Attendance.objects.filter(student=student, status=False, date__gte=(timezone.now().date() - timedelta(days=7))).count()
            except Exception:
                recent_absences = 0

            context = {
                'courses': courses,
                'student': student,
                'show_email_popup': show_email_popup,
                'attendance_stats': stats,
                'recent_absences': recent_absences
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
        if request.session.get('student_id'):
            try:
                student_id = int(str(request.session['student_id']))
                student = Student.objects.get(student_id=student_id)
                context = {
                    'courses': [],
                    'student': student,
                    'show_email_popup': False,
                    'attendance_stats': {},
                    'recent_absences': 0
                }
                return render(request, 'main/myCourses.html', context)
            except Exception:
                pass
        messages.error(request, 'Unexpected error. Please login again.')
        return redirect('std_login')


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
                frm = request.GET.get('from')
                to = request.GET.get('to')
                entries = Attendance.objects.filter(student=Student.objects.get(student_id=request.session['student_id']), course=course)
                if frm:
                    try:
                        from datetime import datetime as dt
                        frm_date = dt.fromisoformat(frm).date()
                        entries = entries.filter(date__gte=frm_date)
                    except Exception:
                        pass
                if to:
                    try:
                        from datetime import datetime as dt
                        to_date = dt.fromisoformat(to).date()
                        entries = entries.filter(date__lte=to_date)
                    except Exception:
                        pass
                entries = entries.order_by('-date')
                status = request.GET.get('status')
                if status == 'present':
                    entries = entries.filter(status=True, is_late=False)
                elif status == 'late':
                    entries = entries.filter(status=True, is_late=True)
                elif status == 'absent':
                    entries = entries.filter(status=False)
                from django.core.paginator import Paginator
                try:
                    page_num = int(request.GET.get('page', '1'))
                except Exception:
                    page_num = 1
                paginator = Paginator(entries, 25)
                entries = paginator.get_page(page_num)
            except Exception as e:
                logger.warning(f"Error loading course content: {e}")
                announcements = None
                assignments = None
                materials = None
                entries = Attendance.objects.none()

            context = {
                'course': course,
                'announcements': announcements,
                'assignments': assignments[:3] if assignments else [],
                'materials': materials,
                'student': Student.objects.get(student_id=request.session['student_id']),
                'attendance_entries': entries
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

        except Exception as e:
            logger.warning(f"Error loading faculty course content: {e}")
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
        except Announcement.DoesNotExist:
            return redirect('/faculty/' + str(code))
        except Exception as e:
            logger.error(f"deleteAnnouncement error: {e}")
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
        except Announcement.DoesNotExist:
            return redirect('/faculty/' + str(code))
        except Exception as e:
            logger.error(f"updateAnnouncement error: {e}")
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

        except Submission.DoesNotExist:
            submission = None
        except Exception as e:
            logger.error(f"assignmentPage error: {e}")
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
    except Exception as e:
        logger.error(f"addSubmission error: {e}")
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

        except Assignment.DoesNotExist:
            return redirect('/faculty/' + str(code))
        except Exception as e:
            logger.error(f"viewSubmission error: {e}")
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
                # SECURITY FIX: Use .get() to safely access POST data with validation
                marks_str = request.POST.get('marks', '0')
                try:
                    marks_value = float(marks_str)
                    if marks_value < 0:
                        marks_value = 0
                    submission.marks = marks_value
                except (ValueError, TypeError):
                    messages.error(request, 'Invalid marks value.')
                    return HttpResponseRedirect(request.path_info)
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
    except Exception as e:
        logger.error(f"gradeSubmission error: {e}")
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
            # SECURITY FIX: Use .get() to safely access POST data
            provided_key = request.POST.get('key', '').strip()
            if provided_key and provided_key == str(course.studentKey):
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
            old_password = request.POST.get('oldPassword', '').strip()
            new_password = request.POST.get('newPassword', '').strip()
            
            # SECURITY FIX: Validate input
            if not old_password or not new_password:
                messages.error(request, 'Please fill in all fields.')
                return redirect('/changePassword/')
            
            def _password_policy_valid(p):
                if len(p) < 8:
                    return False
                if not re.search(r'[a-z]', p):
                    return False
                if not re.search(r'[A-Z]', p):
                    return False
                if not re.search(r'\d', p):
                    return False
                if not re.search(r'[^A-Za-z0-9]', p):
                    return False
                return True

            if not _password_policy_valid(new_password):
                messages.error(request, 'Password must be at least 8 characters and include uppercase, lowercase, number, and a special character.')
                return redirect('/changePassword/')
            
            # SECURITY FIX: Use secure password checking
            if check_password(student.password, old_password):
                # SECURITY FIX: Hash the new password before saving
                student.password = hash_password(new_password)
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
            old_password = request.POST.get('oldPassword', '').strip()
            new_password = request.POST.get('newPassword', '').strip()
            
            # SECURITY FIX: Validate input
            if not old_password or not new_password:
                messages.error(request, 'Please fill in all fields.')
                return redirect('/changePasswordFaculty/')
            
            def _password_policy_valid(p):
                if len(p) < 8:
                    return False
                if not re.search(r'[a-z]', p):
                    return False
                if not re.search(r'[A-Z]', p):
                    return False
                if not re.search(r'\d', p):
                    return False
                if not re.search(r'[^A-Za-z0-9]', p):
                    return False
                return True

            if not _password_policy_valid(new_password):
                messages.error(request, 'Password must be at least 8 characters and include uppercase, lowercase, number, and a special character.')
                return redirect('/changePasswordFaculty/')
            
            # SECURITY FIX: Use secure password checking
            if check_password(faculty.password, old_password):
                # SECURITY FIX: Hash the new password before saving
                faculty.password = hash_password(new_password)
                faculty.save()
                messages.success(request, 'Password was changed successfully')
                return redirect('profile', id=str(faculty.faculty_id))
            else:
                messages.error(
                    request, 'Password is incorrect. Please try again')
                return redirect('/changePasswordFaculty/')
        else:
            # SECURITY FIX: Removed debug print statement
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
# SECURITY FIX: Use cryptographically secure random for OTP generation
def generate_otp():
    """Generate a cryptographically secure 6-digit OTP"""
    # Use secrets.randbelow() for cryptographically secure random number generation
    # This prevents predictable OTPs that could be guessed by attackers
    return str(secrets.randbelow(900000) + 100000)  # Generates 100000-999999


# SECURITY FIX: Add rate limiting to prevent brute force attacks on password reset
@rate_limit(max_requests=5, window_seconds=300, key_prefix='password_reset')
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
                if not (getattr(settings, 'EMAIL_HOST_USER', None) and getattr(settings, 'EMAIL_HOST_PASSWORD', None)):
                    raise ValueError('Email credentials not configured')
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
        
        def _password_policy_valid(p):
            if len(p) < 8:
                return False
            if not re.search(r'[a-z]', p):
                return False
            if not re.search(r'[A-Z]', p):
                return False
            if not re.search(r'\d', p):
                return False
            if not re.search(r'[^A-Za-z0-9]', p):
                return False
            return True

        if not _password_policy_valid(new_password):
            messages.error(request, 'Password must be at least 8 characters and include uppercase, lowercase, number, and a special character.')
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
                # SECURITY FIX: Hash the new password before saving
                student.password = hash_password(new_password)
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
                
                # SECURITY FIX: Use secure password checking
                if not check_password(student.password, password):
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


@csrf_protect
@require_http_methods(["GET", "POST"])
def changeEmailFaculty(request):
    if request.session.get('faculty_id'):
        try:
            faculty = Faculty.objects.get(faculty_id=request.session['faculty_id'])
            if request.method == 'POST':
                new_email = request.POST.get('new_email', '').strip()
                password = request.POST.get('password', '').strip()
                if not new_email or not password:
                    messages.error(request, 'Please fill in all fields.')
                    return render(request, 'main/changeEmail.html', {'faculty': faculty})
                if not check_password(faculty.password, password):
                    messages.error(request, 'Incorrect password. Please try again.')
                    return render(request, 'main/changeEmail.html', {'faculty': faculty})
                from django.core.validators import validate_email
                from django.core.exceptions import ValidationError
                try:
                    validate_email(new_email)
                except ValidationError:
                    messages.error(request, 'Please enter a valid email address.')
                    return render(request, 'main/changeEmail.html', {'faculty': faculty})
                if Faculty.objects.filter(email=new_email).exclude(faculty_id=faculty.faculty_id).exists():
                    messages.error(request, 'This email is already registered with another account.')
                    return render(request, 'main/changeEmail.html', {'faculty': faculty})
                faculty.email = new_email
                faculty.save()
                messages.success(request, 'Email updated successfully!')
                return redirect('profile', id=str(faculty.faculty_id))
            else:
                return render(request, 'main/changeEmail.html', {'faculty': faculty})
        except Faculty.DoesNotExist:
            messages.error(request, 'Faculty not found.')
            return redirect('std_login')
        except Exception as e:
            logger.error(f"Error in changeEmailFaculty: {str(e)}")
            messages.error(request, 'An error occurred. Please try again.')
            return redirect('profile', id=str(request.session.get('faculty_id')))
    else:
        return redirect('std_login')