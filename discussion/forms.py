from django import forms
from .models import StudentDiscussion, FacultyDiscussion
from django.core.exceptions import ValidationError
from django.utils.html import strip_tags


def sanitize_text(value: str) -> str:
    """Sanitize user-submitted discussion content; keep plain text only.
    Uses a simple strip to avoid XSS while preserving functionality.
    """
    if value is None:
        return value
    return strip_tags(value).strip()


class StudentDiscussionForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(StudentDiscussionForm, self).__init__(*args, **kwargs)
        self.fields['content'].required = True
        self.fields['content'].label = ''

    class Meta:
        model = StudentDiscussion
        fields = ['content']
        widgets = {
            'content': forms.TextInput(attrs={'class': 'form-control', 'id': 'content', 'name': 'content', 'placeholder': 'Write message...', 'type': 'text'}),
        }

    def clean_content(self):
        content = self.cleaned_data.get('content')
        content = sanitize_text(content)
        if content and len(content) > 1500:
            raise ValidationError('Message cannot exceed 1500 characters')
        return content


class FacultyDiscussionForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(FacultyDiscussionForm, self).__init__(*args, **kwargs)
        self.fields['content'].required = True
        self.fields['content'].label = ''

    class Meta:
        model = FacultyDiscussion
        fields = ['content']
        widgets = {
            'content': forms.TextInput(attrs={'class': 'form-control', 'id': 'content', 'name': 'content', 'placeholder': 'Write message...', 'type': 'text'}),
        }

    def clean_content(self):
        content = self.cleaned_data.get('content')
        content = sanitize_text(content)
        if content and len(content) > 1500:
            raise ValidationError('Message cannot exceed 1500 characters')
        return content
