# e-Learning Management System

A learning management and online assessment system for academic education. This platform facilitates online learning by providing tools for course management, content delivery, student assessment, and interactive discussions.

## Features

- Admin adds courses, teachers, and students and assigns them courses.
- The teacher creates course content, announcements, assignments, quizzes, takes attendance, etc. A teacher can see the details and analysis of the assessments.
- Students can enroll in the courses using the access key, see the course content of the enrolled courses, participate in assessments and see their results in detail.
- Discussion section for both teacher and student.

## Relational Schema

![schema](https://user-images.githubusercontent.com/87283264/187967219-55bea00e-3151-488a-a4be-d2a95b9d8a5c.png)

## Tech Stack

1. Django 4.0.4
2. Bootstrap 5.0.2
3. jQuery 3.6.0
4. Chart.js v3.9.1
5. Animate.css 4.1.1
6. Froala Editor 3.2.1

## Run Locally

1. Clone the project

```bash
git clone https://github.com/utsav210/e-Learning-Management-System.git
```

2. Go to the project directory

```bash
cd ProjectDirectoryName
```

3. Create a virtual environment and activate it (Windows)

```bash
python -m venv myenv
```

```bash
env\Scripts\activate
```

4. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note:** If you're using newer versions of python(3.10+), you may need to add the `--use-deprecated=legacy-resolver` option when installing dependencies with `pip` to avoid errors :

```bash
pip install -r requirements.txt --use-deprecated=legacy-resolver
```

5. Make migrations and migrate

```bash
python manage.py makemigrations
```

```bash
python manage.py migrate
```

6. Create admin/superuser

```bash
python manage.py createsuperuser
```

7. Finally run the project

```bash
python manage.py runserver
```

Now the project should be running on http://127.0.0.1:8000/

Login as admin and add some courses, teacher and students.

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

## Contributing

Contributions are welcome! Here's how you can help:

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Author

Utsav

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.