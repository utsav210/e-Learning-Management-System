from django.contrib import admin

# Register your models here.
from .models import Student, Faculty, Course, Department, Assignment, Announcement, PasswordResetOTP


class CourseAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'department', 'faculty', 'studentKey', 'facultyKey')

    def save_model(self, request, obj, form, change):
        """
        Ensure courses saved via admin are linked to a Faculty when possible.
        If the faculty field is empty but facultyKey corresponds to a Faculty.faculty_id,
        auto-assign it securely.
        """
        if obj.faculty is None and obj.facultyKey is not None:
            try:
                matched_faculty = Faculty.objects.get(faculty_id=obj.facultyKey)
                obj.faculty = matched_faculty
            except Faculty.DoesNotExist:
                pass
        super().save_model(request, obj, form, change)

admin.site.register(Student)
admin.site.register(Faculty)
admin.site.register(Course, CourseAdmin)
admin.site.register(Department)
admin.site.register(Assignment)
admin.site.register(Announcement)
admin.site.register(PasswordResetOTP)
