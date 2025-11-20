import os
import sys
import django
from django.test import TestCase

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'eLMS.settings')
django.setup()

from quiz.forms import QuestionForm

class QuizValidationTests(TestCase):
    def test_question_length_limit(self):
        data = {
            'question': 'x' * 3000,
            'option1': 'A',
            'option2': 'B',
            'option3': 'C',
            'option4': 'D',
            'answer': 'A',
            'marks': 1,
            'explanation': 'ok'
        }
        form = QuestionForm(data)
        self.assertFalse(form.is_valid())

    def test_marks_negative_rejected(self):
        data = {
            'question': 'Q',
            'option1': 'A',
            'option2': 'B',
            'option3': 'C',
            'option4': 'D',
            'answer': 'A',
            'marks': -5,
            'explanation': ''
        }
        form = QuestionForm(data)
        self.assertFalse(form.is_valid())