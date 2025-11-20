from django.contrib import admin
from .models import Attendance

class AttendanceAdmin(admin.ModelAdmin):
    list_display = ('student', 'course', 'date', 'status', 'is_late')
    list_filter = ('course', 'date', 'status', 'is_late')
    search_fields = ('student__name', 'student__student_id', 'course__name', 'course__code')
    date_hierarchy = 'date'

admin.site.register(Attendance, AttendanceAdmin)
