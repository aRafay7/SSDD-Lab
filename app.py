"""
Secure Flask Application with 5 Security Practices Implemented
Lab-08: Secure Coding Practices-II

Security Features:
1. Security Headers with Talisman - Prevents Clickjacking and XSS
2. Rate Limiting - Prevents brute-force attacks on login
3. Secure File Uploads - Sanitizes uploaded files
4. Environment Variables - Manages secrets securely
5. Role-Based Access Control (RBAC) - Admin-only routes
"""
from flask import Flask, render_template, redirect, url_for, flash, session, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from functools import wraps
import os
from datetime import timedelta

# Load environment variables from .env file
load_dotenv()

# Import models and forms
from models import db, bcrypt, User
from forms import RegistrationForm, LoginForm, FeedbackForm


app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///secure_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

# Initialize extensions
db.init_app(app)
bcrypt.init_app(app)
csrf = CSRFProtect(app)

# Task 1: Initialize Talisman for security headers
Talisman(app, force_https=False)  # force_https=False for local development

# Task 2: Initialize Limiter for rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


# Task 3: File upload configuration and validation
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'docx'}

def allowed_file(filename):
    """Check if uploaded file has an allowed extension"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Task 5: RBAC - Admin Required Decorator
def admin_required(f):
    """Decorator to restrict access to admin users only"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            abort(403)  # Forbidden
        
        return f(*args, **kwargs)
    return decorated_function
def page_not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500


@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Task 2: Rate limiting - only 5 login attempts per minute per IP
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'danger')
    
    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)


@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    form = FeedbackForm()
    
    if form.validate_on_submit():
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('home'))
    
    return render_template('feedback.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))


# Task 3: Secure File Upload Route
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file uploads with security measures"""
    if 'user_id' not in session:
        flash('You must be logged in to upload files.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Check if file is in request
        if 'file' not in request.files:
            flash('No file selected. Please choose a file.', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        # Check if file has a filename
        if file.filename == '':
            flash('No file selected. Please choose a file.', 'danger')
            return redirect(request.url)
        
        # Validate file extension
        if not allowed_file(file.filename):
            flash('File type not allowed. Allowed types: png, jpg, jpeg, gif, pdf, txt, docx', 'danger')
            return redirect(request.url)
        
        # Secure the filename to prevent directory traversal attacks
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(filepath)
            flash(f'File "{filename}" uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error uploading file: {str(e)}', 'danger')
            return redirect(request.url)
    
    return render_template('upload.html')


# Task 5: Admin-only Route - Delete User
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user (admin only)"""
    user_to_delete = User.query.get_or_404(user_id)
    
    # Prevent admin from deleting themselves
    if user_to_delete.id == session.get('user_id'):
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('dashboard'))
    
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash(f'User "{user_to_delete.username}" deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_dashboard'))


# Task 5: Admin Dashboard Route
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard - list all users"""
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)


def init_db():
    with app.app_context():
        db.create_all()
        print("Database initialized successfully!")


if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='127.0.0.1', port=4444)
