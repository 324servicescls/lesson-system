from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
from flask import make_response
from flask import send_file
from io import BytesIO
from xhtml2pdf import pisa
from io import BytesIO
from flask import make_response, render_template
import os

# --------------------
# APP CONFIG
# --------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# --------------------
# DATABASE MODELS
# --------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.String(20))  # headmaster or teacher

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100))
    class_name = db.Column(db.String(50))
    week_ending = db.Column(db.String(50))
    class_size = db.Column(db.Integer)
    day = db.Column(db.String(20))
    period = db.Column(db.String(20))
    lesson_title = db.Column(db.String(200))
    strand = db.Column(db.String(200))
    sub_strand = db.Column(db.String(200))
    indicator_code = db.Column(db.String(100))
    content_standard_code = db.Column(db.String(100))
    performance_indicator = db.Column(db.Text)
    core_competencies = db.Column(db.Text)
    keywords = db.Column(db.Text)
    tlr = db.Column(db.Text)
    reference = db.Column(db.Text)
    phase1 = db.Column(db.Text)
    phase2 = db.Column(db.Text)
    phase3 = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending')
    feedback = db.Column(db.Text)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    teacher = db.relationship('User', backref='lessons')
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

# --------------------
# LOGIN MANAGER
# --------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --------------------
# ROUTES
# --------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.password == password:
            session['user_id'] = user.id
            session['role'] = user.role
            session['name'] = user.name

            if user.role == 'headmaster':
                return redirect(url_for('headmaster_dashboard'))
            else:
                return redirect(url_for('teacher_dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('No account found with that email', 'danger')
            return redirect(url_for('forgot_password'))

        if new_password != confirm_password:
            flash('Passwords do not match', 'warning')
            return redirect(url_for('forgot_password'))

        user.password = new_password
        db.session.commit()

        flash('Password reset successful. You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/headmaster', methods=['GET', 'POST'])
def headmaster_dashboard():
    if 'user_id' not in session or session['role'] != 'headmaster':
        return redirect(url_for('login'))

    # Create teacher
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        teacher = User(
            name=name,
            email=email,
            password=password,
            role='teacher'
        )
        db.session.add(teacher)
        db.session.commit()

        flash('Teacher account created successfully', 'success')

    submitted_lessons = Lesson.query.filter_by(status='submitted').order_by(
        Lesson.date_created.desc()
    ).all()

    return render_template('headmaster.html', lessons=submitted_lessons)

@app.route('/headmaster/submitted-lessons')
def headmaster_submitted_lessons():
    if 'user_id' not in session or session.get('role') != 'headmaster':
        return redirect(url_for('login'))

    lessons = Lesson.query.filter_by(status='submitted').all()
    return render_template('headmaster_submitted_lessons.html', lessons=lessons)

@app.route('/headmaster/lesson/<int:lesson_id>', methods=['GET', 'POST'])
def headmaster_view_lesson(lesson_id):
    if 'user_id' not in session or session.get('role') != 'headmaster':
        return redirect(url_for('login'))

    lesson = Lesson.query.get_or_404(lesson_id)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'approve':
            lesson.status = 'approved'
        elif action == 'reject':
            lesson.status = 'rejected'

        lesson.feedback = request.form.get('remark')
        db.session.commit()

        flash('Lesson reviewed successfully', 'success')
        return redirect(url_for('headmaster_submitted_lessons'))

    return render_template('headmaster_view_lesson.html', lesson=lesson)

@app.route('/edit-lesson/<int:lesson_id>', methods=['GET', 'POST'])
def edit_lesson(lesson_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    lesson = Lesson.query.get_or_404(lesson_id)

    if lesson.teacher_id != session['user_id']:
        return redirect(url_for('teacher_dashboard'))

    if lesson.status != 'pending':
        return redirect(url_for('teacher_dashboard'))

    if request.method == 'POST':
        lesson.subject = request.form['subject']
        lesson.class_name = request.form['class_name']
        lesson.week_ending = request.form.get('week_ending')
        lesson.class_size = request.form.get('class_size')
        lesson.day = request.form.get('day')
        lesson.period = request.form.get('period')
        lesson.lesson_title = request.form['lesson_title']
        lesson.strand = request.form.get('strand')
        lesson.sub_strand = request.form.get('sub_strand')
        lesson.indicator_code = request.form.get('indicator_code')
        lesson.content_standard_code = request.form.get('content_standard_code')
        lesson.performance_indicator = request.form.get('performance_indicator')
        lesson.core_competencies = request.form.get('core_competencies')
        lesson.keywords = request.form.get('keywords')
        lesson.tlr = request.form.get('tlr')
        lesson.reference = request.form.get('reference')
        lesson.phase1 = request.form['phase1']
        lesson.phase2 = request.form['phase2']
        lesson.phase3 = request.form['phase3']

        db.session.commit()
        flash('Lesson updated successfully!', 'success')
        return redirect(url_for('teacher_dashboard'))

    return render_template('edit_lesson.html', lesson=lesson)

@app.route('/lesson/<int:lesson_id>/export')
def export_lesson(lesson_id):
    lesson = Lesson.query.get_or_404(lesson_id)

    html = render_template('lesson_pdf.html', lesson=lesson)

    result = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=result)

    if pisa_status.err:
        return "Error generating PDF", 500

    response = make_response(result.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=lesson_{lesson.id}.pdf'

    return response


@app.route('/teacher', methods=['GET', 'POST'])
def teacher_dashboard():
    if 'user_id' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))

    if request.method == 'POST':
        lesson = Lesson(
            subject=request.form['subject'],
            class_name=request.form['class_name'],
            week_ending=request.form['week_ending'],
            class_size=request.form['class_size'],
            day=request.form['day'],
            period=request.form['period'],
            lesson_title=request.form['lesson_title'],
            strand=request.form['strand'],
            sub_strand=request.form['sub_strand'],
            indicator_code=request.form['indicator_code'],
            content_standard_code=request.form['content_standard_code'],
            performance_indicator=request.form['performance_indicator'],
            core_competencies=request.form['core_competencies'],
            keywords=request.form['keywords'],
            tlr=request.form['tlr'],
            reference=request.form['reference'],
            phase1=request.form['phase1'],
            phase2=request.form['phase2'],
            phase3=request.form['phase3'],
            teacher_id=int(session['user_id'])
        )

        db.session.add(lesson)
        db.session.commit()
        flash('Lesson submitted successfully!', 'success')
        return redirect(url_for('teacher_dashboard'))

    lessons = Lesson.query.filter_by(teacher_id=int(session['user_id'])).all()
    submitted_lessons = Lesson.query.filter(Lesson.teacher_id == session['user_id'], Lesson.status != 'pending').all()

    return render_template('teacher.html', teacher_name=session['name'], lessons=lessons, submitted_lessons=submitted_lessons)

@app.route('/submit-lesson/<int:lesson_id>', methods=['POST'])
def submit_lesson(lesson_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    lesson = Lesson.query.get_or_404(lesson_id)

    if lesson.teacher_id != session['user_id']:
        return redirect(url_for('teacher_dashboard'))

    if lesson.status != 'pending':
        flash('Lesson already submitted.', 'warning')
        return redirect(url_for('teacher_dashboard'))

    lesson.status = 'submitted'
    db.session.commit()
    flash('Lesson submitted successfully!', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please login to access this page', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if user.password != current_password:
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))

        user.password = new_password
        db.session.commit()

        flash('Password changed successfully', 'success')

        if session['role'] == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        else:
            return redirect(url_for('headmaster_dashboard'))

    return render_template('change_password.html')

@app.route('/teacher/lesson/<int:lesson_id>')
def teacher_view_lesson(lesson_id):
    if 'user_id' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))

    lesson = Lesson.query.get_or_404(lesson_id)

    if lesson.teacher_id != session['user_id']:
        return redirect(url_for('teacher_dashboard'))

    return render_template('teacher_view_lesson.html', lesson=lesson)

# --------------------
# CREATE TABLES & DEFAULT ADMIN ON STARTUP
# --------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="admin@example.com").first():
        admin_user = User(
            name="Admin",
            email="admin@example.com",
            password="admin123",
            role="headmaster"
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created.")

# --------------------
# RUN APP
# --------------------
if __name__ == '__main__':
    app.run(debug=True)
