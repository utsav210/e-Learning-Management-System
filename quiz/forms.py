from django import forms
from django.utils.html import strip_tags
from .models import Question

def sanitize_text(value: str) -> str:
    if value is None:
        return value
    return strip_tags(value).strip()

class QuestionForm(forms.ModelForm):
    class Meta:
        model = Question
        fields = ['question', 'option1', 'option2', 'option3', 'option4', 'answer', 'marks', 'explanation']

    def clean_question(self):
        v = sanitize_text(self.cleaned_data.get('question'))
        if v and len(v) > 2000:
            raise forms.ValidationError('Question cannot exceed 2000 characters')
        return v

    def clean_option1(self):
        v = sanitize_text(self.cleaned_data.get('option1'))
        if v and len(v) > 1000:
            raise forms.ValidationError('Option A too long')
        return v

    def clean_option2(self):
        v = sanitize_text(self.cleaned_data.get('option2'))
        if v and len(v) > 1000:
            raise forms.ValidationError('Option B too long')
        return v

    def clean_option3(self):
        v = sanitize_text(self.cleaned_data.get('option3'))
        if v and len(v) > 1000:
            raise forms.ValidationError('Option C too long')
        return v

    def clean_option4(self):
        v = sanitize_text(self.cleaned_data.get('option4'))
        if v and len(v) > 1000:
            raise forms.ValidationError('Option D too long')
        return v

    def clean_explanation(self):
        v = sanitize_text(self.cleaned_data.get('explanation'))
        if v and len(v) > 2000:
            raise forms.ValidationError('Explanation cannot exceed 2000 characters')
        return v

    def clean_marks(self):
        m = self.cleaned_data.get('marks')
        if m is None:
            raise forms.ValidationError('Marks required')
        if m < 0:
            raise forms.ValidationError('Marks cannot be negative')
        return m