from flask import Flask, render_template, url_for, flash, redirect, request,session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from datetime import datetime, timedelta
import os
import random
from flask import abort
from flask_mail import Mail, Message
import requests
from sqlalchemy import func
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from flask import send_from_directory

app = Flask(__name__)
app.config['SECRET_KEY'] = 'f0c23d880346d1ef4f61655511699260'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/jobs'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


app.config['MAIL_SERVER'] = 'smtp.gmail.com'          # For example, Gmail SMTP server
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'mounikaannarapu560@gmail.com'  # Your email address
app.config['MAIL_PASSWORD'] = 'zkgn xefd dxer ywbk'   # Your email password or app-specific password
app.config['MAIL_DEFAULT_SENDER'] = ('Job Portal', 'mounikaannarapu560@gmail.com')

mail = Mail(app)

UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'png'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


# Models

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    usertype = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200))
    contact = db.Column(db.String(20))  
    gender = db.Column(db.String(10))
    jobs = db.relationship('Jobs', backref='job_applier', lazy=True)
    applications = db.relationship('Application', backref='application_submiter', lazy=True)

    def __repr__(self):
        return f"User('{self.id}', '{self.username}', '{self.usertype}', '{self.email}')"
class OTPVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    gender = db.Column(db.String(20), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    degree = db.Column(db.String(20), nullable=False)
    industry = db.Column(db.String(50), nullable=False)
    experience = db.Column(db.Integer, nullable=False)
    applicant_name = db.Column(db.String(100), nullable=False)
    college_name = db.Column(db.String(100), nullable=False)
    passout_year = db.Column(db.Integer)
    percentage = db.Column(db.Float, nullable=False)
    cv = db.Column(db.Text)
    cover_letter = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey('jobs.id'), nullable=False)

    def __repr__(self):
        return f"Application('{self.id}','{self.gender}', '{self.date_posted}', '{self.degree}', '{self.industry}', '{self.experience}', '{self.user_id}', '{self.job_id}')"

class Jobs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    industry = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    salary = db.Column(db.String(50), nullable=False)  # New field
    experience_required = db.Column(db.Integer, nullable=False)  # New field (in years)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    activation_start = db.Column(db.DateTime, nullable=False)
    activation_end = db.Column(db.DateTime, nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    applications = db.relationship('Application', backref='job', lazy=True)
    @property
    def is_active(self):
        now = datetime.now()
        return self.activation_start <= now <= self.activation_end

    def __repr__(self):
        return f"Jobs('{self.id}','{self.title}', '{self.industry}', '{self.salary}', '{self.experience_required}', '{self.date_posted}')"
    
def send_otp_email(to_email, otp_code):
    try:
        msg = Message("Your OTP Code",
                      recipients=[to_email])
        msg.body = f"Your OTP code is: {otp_code}. It will expire in 10 minutes."
        mail.send(msg)
        return True
    except Exception as e:
        print("Email sending failed:", e)
        return False

# Routes

@app.route('/')
def home():
    now = datetime.now()

    if current_user.is_authenticated and current_user.usertype == 'Company':
        base_query = Jobs.query.filter_by(company_id=current_user.id).join(User).add_columns(
            Jobs.id, Jobs.title, Jobs.industry, Jobs.date_posted, Jobs.description,
            Jobs.salary, Jobs.experience_required,
            Jobs.activation_start, Jobs.activation_end,
            User.username.label('company_name')
        )
        company_view = True
        heading = "Manage Posted Jobs"

    elif current_user.is_authenticated and current_user.usertype == 'Job_Seeker':
        applied_job_ids = db.session.query(Application.job_id).filter_by(user_id=current_user.id).subquery()
        base_query = Jobs.query.join(User).filter(
            ~Jobs.id.in_(applied_job_ids),
            Jobs.activation_start <= now,
            Jobs.activation_end >= now
        ).add_columns(
            Jobs.id, Jobs.title, Jobs.industry, Jobs.date_posted, Jobs.description,
            Jobs.salary, Jobs.experience_required,
            Jobs.activation_start, Jobs.activation_end,
            User.username.label('company_name')
        )
        company_view = False
        heading = "Active Jobs You Haven’t Applied For"

    else:
        base_query = Jobs.query.join(User).add_columns(
            Jobs.id, Jobs.title, Jobs.industry, Jobs.date_posted, Jobs.description,
            Jobs.salary, Jobs.experience_required,
            Jobs.activation_start, Jobs.activation_end,
            User.username.label('company_name')
        )
        company_view = False
        heading = "Available Jobs"

    jobs = base_query.order_by(Jobs.date_posted.desc()).all()

    return render_template('home.html', jobs=jobs, company_view=company_view, heading=heading, now=now)
@app.route('/search')
def search_jobs():
    search = request.args.get('search', '').strip()
    search_lower = search.lower()
    now = datetime.now()

    if not search:
        return redirect(url_for('home'))

    # Build the base query: Join Jobs with User
    base_query = Jobs.query.join(User).add_columns(
        Jobs.id, Jobs.title, Jobs.industry, Jobs.date_posted, Jobs.description,
        Jobs.salary, Jobs.experience_required,
        Jobs.activation_start, Jobs.activation_end,
        User.username.label('company_name')
    )

    # Filter by job title OR company name (case-insensitive)
    base_query = base_query.filter(
        db.or_(
            func.lower(Jobs.title).like(f"%{search_lower}%"),
            func.lower(Jobs.industry).like(f"%{search_lower}%")
        )
    )

    jobs = base_query.order_by(Jobs.date_posted.desc()).all()

    return render_template('home.html', jobs=jobs, company_view=False, heading=f"Search Results for '{search}'", now=now)

@app.route('/job_portal')
def job_portal():
    now = datetime.now()

    # Join Jobs and User, select all Jobs columns plus User.username as company_name
    jobs_with_company = db.session.query(
        Jobs,
        User.username.label('company_name')
    ).join(User).all()

    jobs = []
    for item in jobs_with_company:
        job = item[0]  # Jobs model object
        company_name = item[1]
        job.company_name = company_name
        jobs.append(job)

    return render_template('home.html', jobs=jobs, company_view=False, heading="Available Jobs", now=now)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form.get('role', 'Job_Seeker')
        contact = request.form['contact'].strip()
        gender = request.form['gender']

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect('/register')

        # Check if email already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please login or use another email.')
            return redirect('/register')

        # Generate OTP
        otp = str(random.randint(100000, 999999))
        sent = send_otp_email(email, otp)  # make sure you have this function
        if not sent:
            flash('Failed to send OTP email. Try again later.')
            return redirect('/register')

        # Save OTP to otp_verification table
        otp_entry = OTPVerification(email=email, otp=otp, created_at=datetime.utcnow())
        db.session.add(otp_entry)
        db.session.commit()

        # Temporarily save user info in session
        session['temp_user'] = {
            'name': name,
            'email': email,
            'password': password,
            'role': role,
            'contact': contact,
            'gender': gender
        }
        flash('OTP sent to your email. Please enter it below to verify.')
        return redirect('/otp_verify')

    return render_template('register.html')


@app.route('/otp_verify', methods=['GET', 'POST'])
def otp_verify():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        temp_user = session.get('temp_user')
        if not temp_user:
            flash('Session expired, please register again.', 'danger')
            return redirect('/register')

        # Get latest OTP for the email
        otp_record = OTPVerification.query.filter_by(email=temp_user['email']).order_by(OTPVerification.created_at.desc()).first()

        if otp_record and otp_record.otp == entered_otp:
            # ✅ Create the user
            hashed_password = generate_password_hash(temp_user['password'], method='pbkdf2:sha256')
            new_user = User(
                username=temp_user['name'],
                email=temp_user['email'],
                password=hashed_password,
                usertype=temp_user['role'],
                contact=temp_user.get('contact'),
                gender=temp_user.get('gender')
            )
            db.session.add(new_user)
            db.session.commit()

            # ✅ Send confirmation email to the user
            try:
                msg_user = Message(
                    subject='Welcome to Job Portal!',
                    sender='mounikaannarapu560@gmail.com',
                    recipients=[temp_user['email']]
                )
                msg_user.body = f"""Hi {temp_user['name']},

Thank you for registering at Job Portal!
We’re excited to have you on board.

- The Job Portal Team
"""
                mail.send(msg_user)
            except Exception as e:
                print(f"Error sending email to user: {e}")

            # ✅ Send notification email to the admin
            try:
                msg_admin = Message(
                    subject='New User Registered - Job Portal',
                    sender='mounikaannarapu560@gmail.com',
                    recipients=['mounikaannarapu560@gmail.com']  # Replace with actual admin email
                )
                msg_admin.body = f"""
A new user has just registered on the Job Portal.

Name: {temp_user['name']}
Email: {temp_user['email']}
Role: {temp_user['role']}
Contact: {temp_user['contact']}
Gender: {temp_user['gender']}
"""
                mail.send(msg_admin)
            except Exception as e:
                print(f"Error sending email to admin: {e}")

            # ✅ Clear session and clean up
            session.pop('temp_user', None)
            db.session.delete(otp_record)
            db.session.commit()

            flash('Registration complete! You can now login.', 'success')
            return redirect('/login')

        else:
            flash('Invalid OTP, please try again.', 'danger')
            return redirect('/otp_verify')

    return render_template('otp_verify.html')

@app.route('/resend_otp')
def resend_otp():
    temp_user = session.get('temp_user')
    if not temp_user:
        flash('Session expired. Please register again.', 'danger')
        return redirect(url_for('register'))

    email = temp_user.get('email')

    # Get latest OTP record
    latest_otp = OTPVerification.query.filter_by(email=email).order_by(OTPVerification.created_at.desc()).first()

    if latest_otp:
        now = datetime.utcnow()
        diff = now - latest_otp.created_at
        if diff < timedelta(seconds=60):
            wait_time = 60 - diff.seconds
            flash(f'Please wait {wait_time} seconds before resending OTP.', 'warning')
            return redirect(url_for('otp_verify'))

    # Generate new OTP and send email
    otp = str(random.randint(100000, 999999))
    sent = send_otp_email(email, otp)
    if not sent:
        flash('Failed to resend OTP. Try again later.', 'danger')
        return redirect(url_for('otp_verify'))

    # Save new OTP to DB
    new_otp = OTPVerification(email=email, otp=otp, created_at=datetime.utcnow())
    db.session.add(new_otp)
    db.session.commit()

    flash('OTP resent to your email.', 'success')
    return redirect(url_for('otp_verify'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Redirect based on usertype if already logged in
        if current_user.usertype == 'Job_Seeker':
            return redirect(url_for('show_jobs'))
        elif current_user.usertype == 'Company':
            return redirect(url_for('posted_jobs'))

    if request.method == 'POST':
        usertype = request.form.get('usertype')
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(email=email).first()

        if user:
            # Optional: check if password hash looks like bcrypt (legacy)
            if user.password.startswith('$2b$') or user.password.startswith('$2a$'):
                flash('This account uses an outdated password format. Please reset your password.', 'warning')
                return redirect(url_for('forgot_password'))  # You must have this route implemented

            if check_password_hash(user.password, password):
                if usertype == user.usertype:
                    login_user(user, remember=remember)
                    next_page = request.args.get('next')
                    if usertype == 'Company':
                        return redirect(next_page) if next_page else redirect(url_for('posted_jobs'))
                    else:
                        return redirect(next_page) if next_page else redirect(url_for('show_jobs'))
                else:
                    flash('Please select the correct user type.', 'danger')
            else:
                flash('Invalid password. Please try again.', 'danger')
        else:
            flash('No account found with this email.', 'danger')

    return render_template('login.html', title='Login')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        if user:
            # TODO: Generate a password reset token, send reset email here
            flash('A password reset link has been sent to your email.', 'success')
            # You might want to redirect to login page after sending email
            return redirect(url_for('login'))
        else:
            flash('Email address not found. Please check and try again.', 'danger')

    return render_template('forgot_password.html')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/login_with_message')
def login_with_message():
    flash('Please login to apply for jobs.', 'warning')
    next_url = request.args.get('next') or url_for('show_jobs')
    return redirect(url_for('login', next=next_url))

@app.route("/show_jobs")
@login_required
def show_jobs():
    if current_user.usertype != 'Job_Seeker':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    jobs = Jobs.query.order_by(Jobs.date_posted.desc()).all()
    return render_template('show_jobs.html', jobs=jobs)

@app.route('/post_job', methods=['GET', 'POST'])
@login_required
def post_job():
    if current_user.usertype != 'Company':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        industry = request.form.get('industry', '').strip()
        salary = request.form.get('salary', '').strip()
        experience_required = request.form.get('experience_required', '').strip()
        description = request.form.get('description', '').strip()
        activation_start_str = request.form.get('activation_start', '').strip()
        activation_end_str = request.form.get('activation_end', '').strip()

        errors = []

        # Validation
        if not title:
            errors.append("Job title is required.")
        if not industry:
            errors.append("Industry is required.")
        if not salary:
            errors.append("Salary is required.")
        if not experience_required.isdigit():
            errors.append("Experience must be a number.")
        if not description:
            errors.append("Description is required.")
        if len(description) < 10:
            errors.append("Description must be at least 10 characters.")

        # Activation time validation
        try:
            activation_start = datetime.strptime(activation_start_str, '%Y-%m-%dT%H:%M')
            activation_end = datetime.strptime(activation_end_str, '%Y-%m-%dT%H:%M')
            if activation_end <= activation_start:
                errors.append("Activation end time must be after start time.")
        except ValueError:
            errors.append("Invalid activation time format.")

        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template(
                'post_jobs.html',
                title=title,
                industry=industry,
                salary=salary,
                experience_required=experience_required,
                description=description,
                activation_start=activation_start_str,
                activation_end=activation_end_str
            )
        else:
            job = Jobs(
                title=title,
                industry=industry,
                salary=salary,
                experience_required=int(experience_required),
                description=description,
                activation_start=activation_start,
                activation_end=activation_end,
                company_id=current_user.id
            )
            db.session.add(job)
            db.session.commit()
            flash('Job posted successfully!', 'success')
            return redirect(url_for('posted_jobs'))

    # GET request — pass defaults for the template variables
    return render_template(
        'post_jobs.html',
        title='',
        industry='',
        salary='',
        experience_required='0',
        description='',
        activation_start='',
        activation_end=''
    )

@app.route('/job/<int:job_id>')
@login_required
def job_detail(job_id):
    job = Jobs.query.get(job_id)
    if job is None:
        abort(404)  # Job not found, show 404 page
    return render_template('job_detail.html', job=job)

@app.route("/posted_jobs")
@login_required
def posted_jobs():
    if current_user.usertype != 'Company':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    jobs = Jobs.query.filter_by(company_id=current_user.id).order_by(Jobs.date_posted.desc()).all()
    
    print("Looking in template folder:", os.path.abspath(app.template_folder))
    
      # Current UTC time for checking activation
    return render_template('posted_jobs.html', jobs=jobs)


@app.route("/apply/<int:job_id>", methods=['GET', 'POST'])
@login_required
def apply(job_id):
    if current_user.usertype != 'Job_Seeker':
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))

    job = Jobs.query.get_or_404(job_id)

    if request.method == 'POST':
        gender = request.form.get('gender')
        degree = request.form.get('degree')
        industry = request.form.get('industry')
        experience = request.form.get('experience')
        cover_letter = request.form.get('cover_letter')

        # Validate CV
        cv_file = request.files.get('cv')
        if not cv_file or cv_file.filename == '':
            flash('Please upload your CV.', 'danger')
            return redirect(request.url)

        filename = secure_filename(cv_file.filename)
        save_dir = os.path.join(app.root_path, 'static', 'cvs')
        os.makedirs(save_dir, exist_ok=True)
        save_path = os.path.join(save_dir, filename)
        cv_file.save(save_path)

        # Create application
        application = Application(
            gender=gender,
            degree=degree,
            industry=industry,
            experience=int(experience),
            cover_letter=cover_letter,
            cv=filename,
            user_id=current_user.id,
            job_id=job.id,
            date_posted=datetime.utcnow()
        )
        db.session.add(application)
        db.session.commit()

        flash('You have successfully applied for this job!', 'success')
        return redirect(url_for('show_jobs'))

    return render_template('apply.html', job=job)


@app.route('/uploads/<filename>')
@login_required  # Optional: use if you want only logged-in users to access CVs
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/post_cvs/<int:job_id>', methods=['GET', 'POST'])
@login_required
def post_cvs(job_id):
    job = Jobs.query.get_or_404(job_id)
    now = datetime.now()

    # 🔒 Only job seekers can apply
    if current_user.usertype != 'Job_Seeker':
        flash('Only job seekers can apply to jobs.', 'danger')
        return redirect(url_for('home'))

    # ❌ Block if job is inactive
    if not (job.activation_start and job.activation_end and job.activation_start <= now <= job.activation_end):
        flash('This job is currently inactive and not accepting applications.', 'danger')
        return redirect(url_for('job_portal'))

    # ✅ Prevent duplicate applications
    existing_application = Application.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    if existing_application:
        flash('You have already applied to this job.', 'info')
        return redirect(url_for('application_detail', job_id=job_id))

    if request.method == 'GET':
        current_year = datetime.now().year
        return render_template(
            'post_cvs.html',
            job=job,
            current_year=current_year,
            user_name=current_user.username,
            user_email=current_user.email,
            user_contact=current_user.contact
        )

    # POST: Handle file upload
    if 'cv' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['cv']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{current_user.id}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        relative_path = unique_filename

        application = Application(
            gender=request.form.get('gender'),
            date_posted=datetime.now(),
            degree=request.form.get('degree'),
            industry=job.industry,
            experience=request.form.get('experience'),
            cv=relative_path,
            cover_letter=request.form.get('cover_letter'),
            applicant_name=request.form.get('applicant_name'),
            college_name=request.form.get('college_name'),
            percentage=float(request.form.get('percentage')),
            passout_year=int(request.form.get('passout_year')),
            user_id=current_user.id,
            job_id=job_id
        )
        db.session.add(application)
        db.session.commit()

        flash('Application submitted successfully!', 'success')
        return redirect(url_for('job_detail', job_id=job_id))
    else:
        flash('Invalid file type. Allowed types: pdf, doc, docx, jpg, png, bmp', 'danger')
        return redirect(request.url)

@app.route('/view_applications/<int:job_id>')
@login_required
def view_applications(job_id):
    # Only allow company users to view applications
    if current_user.usertype != 'Company':  # use 'usertype', match exact case
        abort(403)

    job = Jobs.query.get_or_404(job_id)

    # Check that the job belongs to the current company
    if job.company_id != current_user.id:
        abort(403)

    applications = Application.query.filter_by(job_id=job_id).all()

    return render_template('view_applications.html', job=job, applications=applications)

@app.route('/profile')
@login_required
def profile():
    if current_user.usertype == 'Company':
        # Fetch company info
        posted_jobs = Jobs.query.filter_by(company_id=current_user.id).all()

        # Count applications per job
        jobs_with_counts = []
        for job in posted_jobs:
            app_count = Application.query.filter_by(job_id=job.id).count()
            jobs_with_counts.append({'job': job, 'application_count': app_count})

        return render_template('company_profile.html', user=current_user, jobs=jobs_with_counts)

    elif current_user.usertype == 'Job_Seeker':
        # Fetch job seeker info and their applications
        applications = Application.query.filter_by(user_id=current_user.id).all()
        
        # Fetch companies info with each application
        apps_with_company = []
        for app in applications:
            job = Jobs.query.get(app.job_id)
            company = User.query.get(job.company_id)
            apps_with_company.append({'application': app, 'job': job, 'company': company})

        return render_template('job_seeker_profile.html', user=current_user, applications=apps_with_company)
@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        # Update details except email
        current_user.username = request.form['username']
        current_user.contact = request.form['contact']
        current_user.gender = request.form.get('gender')
        # Add other fields as needed

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=current_user)
@app.route('/application_detail/<int:job_id>')
@login_required
def application_detail(job_id):
    # Make sure the user is a Job Seeker
    if current_user.usertype != 'Job_Seeker':
        flash('Access denied.', 'danger')
        return redirect(url_for('home'))

    # Get the application for current user and job
    application = Application.query.filter_by(user_id=current_user.id, job_id=job_id).first()
    if not application:
        flash("You haven't applied to this job yet.", "warning")
        return redirect(url_for('job_detail', job_id=job_id))

    return render_template('application_detail.html', application=application)
@app.route('/edit_job/<int:job_id>', methods=['GET', 'POST'])
@login_required
def edit_job(job_id):
    job = Jobs.query.get_or_404(job_id)

    # Only company that posted the job can edit
    if current_user.id != job.company_id:
        flash('Unauthorized access to edit this job.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Get updated data from form
        title = request.form.get('title', '').strip()
        industry = request.form.get('industry', '').strip()
        description = request.form.get('description', '').strip()
        salary = request.form.get('salary', '').strip()
        experience_required = request.form.get('experience_required', '').strip()
        activation_start_str = request.form.get('activation_start', '').strip()
        activation_end_str = request.form.get('activation_end', '').strip()

        errors = []

        # Basic validation
        if not title or not industry or not description:
            errors.append('Please fill out all required fields.')
        if not experience_required.isdigit():
            errors.append("Experience must be a number.")

        # Activation time validation
        try:
            activation_start = datetime.strptime(activation_start_str, '%Y-%m-%dT%H:%M')
            activation_end = datetime.strptime(activation_end_str, '%Y-%m-%dT%H:%M')
            if activation_end <= activation_start:
                errors.append("Activation end time must be after start time.")
        except ValueError:
            errors.append("Invalid activation time format.")

        if errors:
            for error in errors:
                flash(error, 'danger')
            # re-render form with old data and errors
            return render_template('edit_job.html', job=job)

        # Update job object
        job.title = title
        job.industry = industry
        job.description = description
        job.salary = salary
        job.experience_required = int(experience_required)
        job.activation_start = activation_start
        job.activation_end = activation_end

        # Commit changes to DB
        db.session.commit()

        flash('Job updated successfully.', 'success')
        return redirect(url_for('posted_jobs'))  # Or wherever you want to redirect

    # GET request - render form with existing data
    return render_template('edit_job.html', job=job)

@app.route('/delete_job/<int:job_id>')
@login_required
def delete_job(job_id):
    job = Jobs.query.get_or_404(job_id)

    if current_user.usertype != 'Company' or job.company_id != current_user.id:
        flash('Unauthorized access to delete job.', 'danger')
        return redirect(url_for('home'))

    # Delete all applications related to this job
    Application.query.filter_by(job_id=job.id).delete()

    # Now delete the job itself
    db.session.delete(job)
    db.session.commit()
    flash('Job deleted successfully.', 'success')
    return redirect(url_for('home'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/contact', methods=['GET', 'POST'])
@login_required
def contact():
    if request.method == 'POST':
        message = request.form.get('message')

        if not message:
            flash('Please enter a message.', 'danger')
            return redirect(url_for('contact'))

        try:
            msg = Message(
                subject="Job Portal - Contact Message",
                sender=app.config['MAIL_USERNAME'],  # Your app's sender email
                recipients=[app.config['MAIL_USERNAME']]  # Admin's email
            )

            msg.body = f"""
New message from a user on the Job Portal:

Name: {getattr(current_user, 'username', 'N/A')}
Email: {getattr(current_user, 'email', 'N/A')}
Role: {getattr(current_user, 'usertype', 'N/A')}

Message:
{message}
"""
            mail.send(msg)
            flash('Your message has been sent to the admin!', 'success')
        except Exception as e:
            flash(f"Failed to send message: {str(e)}", 'danger')

        return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route('/analytics')
@login_required
def analytics():
    if current_user.usertype == 'Job_Seeker':
        applications = (
            Application.query
            .filter_by(user_id=current_user.id)
            .join(Jobs, Application.job_id == Jobs.id)
            .add_columns(Jobs.title, Jobs.industry, Jobs.company_id, Application.date_posted)
            .all()
        )

        job_titles = []
        industries = []
        dates = []

        for app, title, industry, company_id, date_posted in applications:
            job_titles.append(title)
            industries.append(industry)
            dates.append(date_posted.strftime('%Y-%m-%d'))

        # Use industry instead of company name
        applications_list = list(zip(job_titles, industries, dates))

        return render_template(
            'analytics.html',
            usertype='Job_Seeker',
            total_applications=len(applications),
            applications=applications_list,  # contains (title, industry, date)
            dates=dates,
            industries=industries,
        )

    elif current_user.usertype == 'Company':
        jobs = Jobs.query.filter_by(company_id=current_user.id).all()
        total_jobs = len(jobs)

        applications_data = []
        post_dates = []

        for job in jobs:
            count = Application.query.filter_by(job_id=job.id).count()
            applications_data.append({'title': job.title, 'count': count})
            post_dates.append(job.date_posted.strftime('%Y-%m-%d'))

        total_applications = sum(item['count'] for item in applications_data)

        return render_template(
            'analytics.html',
            usertype='Company',
            total_jobs=total_jobs,
            total_applications=total_applications,
            applications_data=applications_data,
            post_dates=post_dates,
        )

    else:
        flash('Invalid user type for analytics.', 'danger')
        return redirect(url_for('home'))
@app.route('/ask-ai', methods=['GET'])
def ask_ai():
    user_question = request.args.get('question')
    ai_response = None

    if user_question:
        url = "https://open-ai21.p.rapidapi.com/conversationllama"
        payload = {
            "messages": [
                {
                    "role": "user",
                    "content": user_question
                }
            ],
            "web_access": False
        }
        headers = {
            "x-rapidapi-key": "77aa9411a2msh8993e12b084d258p1fdd57jsnabd1a0858026",
            "x-rapidapi-host": "open-ai21.p.rapidapi.com",
            "Content-Type": "application/json"
        }

        try:
            response = requests.post(url, json=payload, headers=headers)
            data = response.json()
            ai_response = data.get("result", "No response from AI.")
        except Exception as e:
            ai_response = f"Error: {str(e)}"

    return render_template('ask_ai.html', ai_response=ai_response, user_question=user_question)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # This will create tables for User, Application, Jobs, and Review if they don't exist
    app.run(debug=True)

