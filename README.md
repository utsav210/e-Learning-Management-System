# e-Learning Management System

A secure, feature-rich learning management and online assessment system for academic education. This platform facilitates online learning by providing tools for course management, content delivery, student assessment, and interactive discussions.

## ✨ Features

### Core Functionality
- **Admin Panel**: Add courses, teachers, and students; assign courses and manage the platform
- **Teacher Features**: Create course content, announcements, assignments, quizzes; take attendance; view detailed assessment analytics
- **Student Features**: Enroll in courses using access keys; view course content; participate in assessments; track results and attendance
- **Discussion Forum**: Interactive discussion section for both teachers and students

### 🔒 Security Features
- **Secure Authentication**: Role-based login (Student/Teacher) with strict table-specific authentication
- **Two-Factor Authentication (2FA)**: OTP-based verification via email for all logins
- **Password Security**: PBKDF2/Argon2 hashing with auto-migration from legacy plaintext passwords
- **Session Protection**: Database-backed sessions with session fixation protection
- **Rate Limiting**: Brute-force protection on login and OTP endpoints with proxy support
- **Content Security Policy (CSP)**: XSS prevention through strict CSP headers
- **Input Validation**: Comprehensive sanitization and validation across all forms
- **Security Headers**: HSTS, X-Frame-Options, X-Content-Type-Options configured
- **Environment-Driven Config**: Secure configuration via environment variables

## Relational Schema

![schema](https://user-images.githubusercontent.com/87283264/187967219-55bea00e-3151-488a-a4be-d2a95b9d8a5c.png)

## Tech Stack

1. Django 4.0.4
2. Bootstrap 5.0.2
3. jQuery 3.6.0
4. Chart.js v3.9.1
5. Animate.css 4.1.1
6. Froala Editor 3.2.1

## 🚀 Run Locally

### 1. Clone the project

```bash
git clone https://github.com/utsav210/e-Learning-Management-System.git
```

### 2. Go to the project directory

```bash
cd e-Learning-Management-System
```

### 3. Create a virtual environment and activate it

**Windows:**
```bash
python -m venv myenv
myenv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv myenv
source myenv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note:** If you're using Python 3.10+, you may need to add the `--use-deprecated=legacy-resolver` option:

```bash
pip install -r requirements.txt --use-deprecated=legacy-resolver
```

### 5. Configure Environment Variables

Create a `.env` file in the project root directory:

```bash
# Development Mode (optional - defaults to True with warning)
DEBUG=True

# Production Mode (REQUIRED for production)
DEBUG=False
SECRET_KEY=your-secret-key-here
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com

# Email Configuration (for OTP and password reset)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
DEFAULT_FROM_EMAIL=your-email@gmail.com
```

> **Security Note:** For development, the system will auto-generate a `SECRET_KEY` if not provided. For production, you **must** set `DEBUG=False`, provide a strong `SECRET_KEY`, and configure `ALLOWED_HOSTS`.

### 6. Run database migrations

```bash
python manage.py migrate
```

### 7. Create admin/superuser

```bash
python manage.py createsuperuser
```

### 8. Run the development server

```bash
python manage.py runserver
```

Now the project should be running on http://127.0.0.1:8000/

Login as admin at http://127.0.0.1:8000/admin and add courses, teachers, and students.

## 🧪 Testing

### Run All Tests
```bash
python manage.py test
```

### Run Security Test Suite
```bash
python run_security_tests.py
```

**Test Results (Latest):**
- ✅ Core Tests: 8/8 passed
- ✅ Security Tests: 33/36 passed
- 🔴 4 CRITICAL issues resolved
- 🟠 4 HIGH priority issues resolved

### Run Specific App Tests
```bash
python manage.py test main
python manage.py test quiz
python manage.py test discussion
python manage.py test attendance
```

## Prerequisites

Before you begin, ensure you have the following installed:
- Python 3.8 or higher
- pip (Python package manager)
- Git

## Project Structure

```
├── attendance/          # Attendance management app
├── discussion/          # Discussion forum app
├── eLMS/               # Main project directory
├── main/               # Core functionality app
├── quiz/               # Quiz and assessment app
├── static/             # Static files (CSS, JS, Images)
├── templates/          # Global templates
└── media/              # User uploaded content
```

## 📚 Documentation

- **[Security Fixes Report](SECURITY_FIXES_REPORT.docx)**: Comprehensive documentation of all security improvements
- **[Development Setup Guide](DEVELOPMENT_SETUP.md)**: Detailed setup instructions for development and production
- **[Testing Guide](tests/README.md)**: Information about the test suite and how to run tests

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

**Please ensure:**
- All tests pass before submitting PR
- Follow existing code style and security practices
- Update documentation if needed

## Author

Utsav

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.