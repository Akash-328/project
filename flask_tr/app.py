from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash  # **New import for password hashing**
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///project.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/'  # Folder for image uploads
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed image file extensions
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Ensure the uploads folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

login_manager = LoginManager(app)
login_manager.login_view = 'login'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')

# Event model
class Event(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    disc = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    reg_start_date = db.Column(db.DateTime, nullable=False)
    reg_end_date = db.Column(db.DateTime, nullable=False)
    event_start_date = db.Column(db.DateTime, nullable=False)
    event_end_date = db.Column(db.DateTime, nullable=False)
    image_filename = db.Column(db.String(100), nullable=True)

    def __repr__(self) -> str:
        return f"{self.sno} - {self.title}"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/", methods=['GET'])
def hello_world():
    allEvent = Event.query.all()
    return render_template("index.html", allEvent=allEvent)

@app.route("/add_event", methods=['GET', 'POST'])
@login_required
@admin_required
def add_event():
    if request.method == "POST":
        title = request.form['title']
        disc = request.form['disc']
        reg_start_date = datetime.strptime(request.form['reg_start_date'], '%Y-%m-%dT%H:%M')
        reg_end_date = datetime.strptime(request.form['reg_end_date'], '%Y-%m-%dT%H:%M')
        event_start_date = datetime.strptime(request.form['event_start_date'], '%Y-%m-%dT%H:%M')
        event_end_date = datetime.strptime(request.form['event_end_date'], '%Y-%m-%dT%H:%M')
        
        # Handling the image upload
        image_filename = None
        if 'image' in request.files:
            image = request.files['image']
            if image and allowed_file(image.filename):
                image_filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        new_event = Event(title=title, disc=disc, reg_start_date=reg_start_date,
                          reg_end_date=reg_end_date, event_start_date=event_start_date,
                          event_end_date=event_end_date, image_filename=image_filename)
        db.session.add(new_event)
        db.session.commit()
        return redirect(url_for('hello_world'))  # Redirect to the event listing page or dashboard

    return render_template('add_event.html')

@app.route("/delete/<int:sno>")
@login_required
@admin_required
def delete(sno):
    event = Event.query.filter_by(sno=sno).first()
    db.session.delete(event)
    db.session.commit()
    return redirect(url_for('hello_world'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):  # **Updated to check hashed password**
            login_user(user)
            return redirect(url_for('hello_world'))  # Redirect back to the homepage
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')

        # Ensure passwords match
        if password != password_confirm:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        # Check if email already exists in the database
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email is already registered. Please log in or use a different email.', 'danger')
            return redirect(url_for('register'))

        request_admin = 'request_admin' in request.form  # Check if the checkbox for admin privileges is checked

        # **Hashing the password before saving to the database**
        password_hash = generate_password_hash(password)

        # **Check if the database is empty, and if so, assign the first user as admin**
        if User.query.count() == 0:
            role = 'admin'  # First user becomes an admin
        else:
            role = 'pending_admin' if request_admin else 'user'  # Subsequent users may request admin privileges

        user = User(username=username, email=email, password=password_hash, role=role)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful. Admin approval is required if you requested admin privileges.', 'success')
        return redirect(url_for('login'))  # Redirect to the login page after registering

    return render_template('register.html')


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('hello_world'))

@app.route("/dashboard")
@login_required
def dashboard():
    allEvent = Event.query.all()
    return render_template('dashboard.html', allEvent=allEvent)

@app.route("/admin_dashboard")
@login_required
@admin_required
def admin_dashboard():
    pending_users = User.query.filter_by(role='pending_admin').all()
    return render_template('admin_dashboard.html', pending_users=pending_users)

@app.route("/approve_user/<int:user_id>")
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get(user_id)
    if user and user.role == 'pending_admin':
        user.role = 'admin'
        db.session.commit()
        flash('User approved successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/deny_user/<int:user_id>")
@login_required
@admin_required
def deny_user(user_id):
    user = User.query.get(user_id)
    if user and user.role == 'pending_admin':
        # **Instead of deleting the user, just change their role**
        user.role = 'user'  # Change role instead of deleting
        db.session.commit()
        flash('User denied admin privileges.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route("/event_details/<int:sno>")
def event_details(sno):
    event = Event.query.get_or_404(sno)
    return render_template("event_details.html", event=event)

@app.route("/club")
def club():
    return render_template("club.html")


if __name__ == "__main__":
    #with app.app_context():
        #db.create_all()  # Create database tables
        #print("Database tables created successfully.")
    app.run(debug=True, host='0.0.0.0')
