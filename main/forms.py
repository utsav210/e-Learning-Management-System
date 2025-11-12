from django import forms
from froala_editor.widgets import FroalaEditor
from .models import Announcement, Assignment, Material
from django.core.validators import FileExtensionValidator, MaxValueValidator, MinValueValidator
from django.core.exceptions import ValidationError
import os
from django.utils.html import strip_tags


def sanitize_html(value):
    """Best-effort HTML sanitizer that preserves basic formatting if 'bleach' is available.
    Falls back to returning original value to avoid breaking rich-text functionality.
    """
    try:
        import bleach  # type: ignore
        allowed_tags = [
            'p', 'br', 'strong', 'b', 'em', 'i', 'u', 'ul', 'ol', 'li', 'a', 'blockquote',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'span'
        ]
        allowed_attrs = {
            'a': ['href', 'title', 'rel', 'target'],
            'span': ['style'],
        }
        allowed_protocols = ['http', 'https', 'mailto']
        cleaned = bleach.clean(
            value,
            tags=allowed_tags,
            attributes=allowed_attrs,
            protocols=allowed_protocols,
            strip=True,
        )
        # Add rel and target safety on links
        cleaned = bleach.linkify(cleaned, callbacks=[bleach.linkifier.DEFAULT_CALLBACK])
        return cleaned
    except Exception:
        # If bleach is unavailable or errors, return original content to avoid breaking editor output
        return value


class AnnouncementForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(AnnouncementForm, self).__init__(*args, **kwargs)
        self.fields['description'].required = True
        self.fields['description'].label = ''

    class Meta:
        model = Announcement
        fields = ['description']
        widgets = {
            'description': FroalaEditor(),
        }

    def clean_description(self):
        description = self.cleaned_data.get('description')
        if description:
            description = sanitize_html(description)
            # Lightweight length guard using stripped text
            if len(strip_tags(description)) > 5000:
                raise ValidationError("Description cannot exceed 5000 characters")
        return description


class AssignmentForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(AssignmentForm, self).__init__(*args, **kwargs)
        for field in self.fields.values():
            field.required = True
            field.label = ''
        self.fields['file'].required = False
        
        # Add validation to file field
        self.fields['file'].validators = [
            FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'gif']),
        ]
        
        # Add validation to marks field
        self.fields['marks'].validators = [
            MinValueValidator(0, message="Marks cannot be negative"),
            MaxValueValidator(1000, message="Marks cannot exceed 1000")
        ]

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            # Check file size (10MB limit)
            if file.size > 10 * 1024 * 1024:
                raise ValidationError("File size cannot exceed 10MB")
            
            # Additional security check for file content
            allowed_mime_types = [
                'application/pdf',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'text/plain',
                'image/jpeg',
                'image/png',
                'image/gif'
            ]
            if file.content_type not in allowed_mime_types:
                raise ValidationError("File type not allowed")
                
        return file

    def clean_title(self):
        title = self.cleaned_data.get('title')
        if title:
            # Remove potentially dangerous characters
            title = title.strip()
            if len(title) > 255:
                raise ValidationError("Title cannot exceed 255 characters")
        return title

    def clean_description(self):
        description = self.cleaned_data.get('description')
        if description:
            description = sanitize_html(description)
            if len(strip_tags(description)) > 5000:
                raise ValidationError("Description cannot exceed 5000 characters")
        return description

    class Meta:
        model = Assignment
        fields = ('title', 'description', 'deadline', 'marks', 'file')
        widgets = {
            'description': FroalaEditor(),
            'title': forms.TextInput(attrs={'class': 'form-control mt-1', 'id': 'title', 'name': 'title', 'placeholder': 'Title', 'maxlength': '255'}),
            'deadline': forms.DateTimeInput(attrs={'class': 'form-control mt-1', 'id': 'deadline', 'name': 'deadline', 'type': 'datetime-local'}),
            'marks': forms.NumberInput(attrs={'class': 'form-control mt-1', 'id': 'marks', 'name': 'marks', 'placeholder': 'Marks', 'min': '0', 'max': '1000'}),
            'file': forms.FileInput(attrs={'class': 'form-control mt-1', 'id': 'file', 'name': 'file', 'aria-describedby': 'file', 'aria-label': 'Upload', 'accept': '.pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.gif'}),
        }


class MaterialForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(MaterialForm, self).__init__(*args, **kwargs)
        for field in self.fields.values():
            field.required = True
            field.label = ""
        self.fields['file'].required = False
        
        # Add validation to file field
        self.fields['file'].validators = [
            FileExtensionValidator(allowed_extensions=['pdf', 'doc', 'docx', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'ppt', 'pptx']),
        ]

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            # Check file size (10MB limit)
            if file.size > 10 * 1024 * 1024:
                raise ValidationError("File size cannot exceed 10MB")
            
            # Additional security check for file content
            allowed_mime_types = [
                'application/pdf',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-powerpoint',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                'text/plain',
                'image/jpeg',
                'image/png',
                'image/gif'
            ]
            if file.content_type not in allowed_mime_types:
                raise ValidationError("File type not allowed")
                
        return file

    def clean_description(self):
        description = self.cleaned_data.get('description')
        if description:
            description = sanitize_html(description)
            clean_text = strip_tags(description)
            if len(clean_text) > 2000:
                raise ValidationError("Description cannot exceed 2000 characters")
        return description

    class Meta:
        model = Material
        fields = ('description', 'file')
        widgets = {
            'description': FroalaEditor(),
            'file': forms.FileInput(attrs={'class': 'form-control', 'id': 'file', 'name': 'file', 'aria-describedby': 'file', 'aria-label': 'Upload', 'accept': '.pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.gif,.ppt,.pptx'}),
        }