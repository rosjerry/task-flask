# Flask Application

This is a Flask web application. Follow the instructions below to set up and run the application.

## Prerequisites

- Python 3.6 or higher
- pip (Python package installer)

## Setup Instructions

### 1. Clone the repository

```bash
git clone <repository-url>
cd task-flask
```

### 2. Create a virtual environment

```bash
python -m venv venv
```

### 3. Activate the virtual environment

On Windows:
```bash
venv\Scripts\activate
```

On macOS/Linux:
```bash
source venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Application

### Development server

```bash
flask run
```

The application will be available at http://127.0.0.1:5000/

### Production server (using Gunicorn, if installed)

```bash
gunicorn app:app
```

## Environment Variables

Create a `.env` file in the project root with the following variables (if needed):

```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your_secret_key
```

## Additional Commands

To exit the virtual environment:
```bash
deactivate
```