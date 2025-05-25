from flask import Flask, render_template, request, redirect, session, url_for, flash
import csv
import sqlite3
import os
import enum  
from datetime import datetime
from pydantic import BaseModel, EmailStr, field_validator, Field
from typing import List, Optional
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'
DATABASE = 'database.db'
# Set to True to reset the DB every time the app runs (dev only!)
RESET_DB = True


# Feature flag to control access to advanced features
# Set to True to enable graduation process and ranking list features
ENABLE_ADVANCED_FEATURES = True

# Context processor to make current year available to all templates
@app.context_processor
def inject_current_year():
    return {'current_year': datetime.utcnow().year}

# Define enums from the database schema
class Grade(enum.Enum):
    AA = "AA"
    BA = "BA"
    BB = "BB"
    CB = "CB"
    CC = "CC"
    DC = "DC"
    DD = "DD"
    FD = "FD"
    FF = "FF"

class Roles(enum.Enum):
    LIBRARY = "library"
    ALUMNI = "alumni"  # Changed from ALUMNI_OFFICE
    SKS = "sks"        # Changed from HEALTH_CULTURE_SPORTS
    IT = "it"          # Changed from IT_DEPARTMENT
    STUDENT_AFFAIRS = "student_affairs"

class ApprovalStatus(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

class NotificationType(enum.Enum):
    GRADUATION_REQUEST_SUBMITTED = "graduation_request_submitted"
    GRADUATION_APPROVED_BY_ADVISOR = "graduation_approved_by_advisor"
    GRADUATION_APPROVED_BY_SECRETARY = "graduation_approved_by_secretary"
    GRADUATION_APPROVED_BY_DEANERY = "graduation_approved_by_deanery"
    GRADUATION_REJECTED = "graduation_rejected"
    TERMINATION_REQUEST_SUBMITTED = "termination_request_submitted"
    TERMINATION_APPROVED_BY_STUDENT_AFFAIRS = "termination_approved_by_student_affairs"
    TERMINATION_APPROVED_BY_DEANERY = "termination_approved_by_deanery"
    TERMINATION_REJECTED_BY_UNIT = "termination_rejected_by_unit"
    TERMINATION_FULLY_APPROVED = "termination_fully_approved"
    ADVISOR_LIST_SUBMITTED = "advisor_list_submitted"
    DEPARTMENT_LIST_SUBMITTED = "department_list_submitted"
    DEANERY_APPROVED_DEPARTMENT_LIST = "deanery_approved_department_list"
    DEANERY_REJECTED_DEPARTMENT_LIST = "deanery_rejected_department_list"
    FACULTY_LIST_SUBMITTED_TO_STUDENT_AFFAIRS = "faculty_list_submitted_to_student_affairs"
    STUDENT_AFFAIRS_APPROVED_FACULTY_LIST = "student_affairs_approved_faculty_list"
    STUDENT_AFFAIRS_REJECTED_FACULTY_LIST = "student_affairs_rejected_faculty_list"
    UNIVERSITY_LIST_FINALIZED = "university_list_finalized"
    STUDENT_GRADUATED = "student_graduated"

class UserRole(enum.Enum):
    STUDENT = "student"
    ADVISOR = "advisor"
    DEPARTMENT_SECRETARY = "department_secretary"
    STUDENT_AFFAIRS = "student_affairs"
    DEANERY = "deanery"
    UNIT = "unit"

class GraduationStatus(enum.Enum):
    ELIGIBLE = "eligible"
    NOT_ELIGIBLE = "not_eligible"
    APPLIED = "applied"
    GRADUATED = "graduated"

class TerminationStatus(enum.Enum):
    NOT_YET = "not_yet"
    PENDING = "pending"
    PENDING_FINAL_APPROVAL = "pending_final_approval"
    APPROVED = "approved"
    REJECTED = "rejected"

class UnitApprovalStatus(enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

# Define Pydantic models for validation
class UserBase(BaseModel):
    email: EmailStr
    userID: Optional[int] = None
    
    @field_validator('email')
    def validate_email_domain(cls, v):
        if not (v.endswith('@std.iyte.edu.tr') or v.endswith('@iyte.edu.tr')):
            raise ValueError('Email must be an IZTECH email (@std.iyte.edu.tr or @iyte.edu.tr)')
        return v

class CourseModel(BaseModel):
    course_code: str
    course_name: str
    semester: int
    credits: int
    ects: int

class TranscriptModel(BaseModel):
    student_id: int
    course_code: str
    grade: str
    semester: int
    passed: bool

class DiplomaModel(BaseModel):
    diploma_id: str
    student_id: int
    student_name: str
    department: str
    faculty: str
    graduation_date: str
    final_gpa: float

class StudentModel(UserBase):
    studentID: str
    faculty: str
    department: str
    graduation_status: str
    total_credits: int = 0
    total_ects: int = 0
    gpa: float = 0.0

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserRegister(UserLogin):
    confirm_password: str
    
    @field_validator('confirm_password')
    def passwords_match(cls, v, values):
        if 'password' in values.data and v != values.data['password']:
            raise ValueError('Passwords do not match')
        return v

# Initialize DB with the full schema
def init_db():
    if RESET_DB and os.path.exists(DATABASE):
        os.remove(DATABASE)
        print("Old database deleted.")

    if not os.path.exists(DATABASE):
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            with open('database_script.sql', 'r') as f:
                script = f.read()
                c.executescript(script)
            
        print("Database initialized with full schema.")

@app.route('/')
def home():
    if 'email' not in session:
        return redirect(url_for('login'))
    
    # Common context for all user roles
    context = {
        'name': session['email'],
        'role': session['role'],
        'enable_advanced_features': ENABLE_ADVANCED_FEATURES
    }
    
    # Add role-specific context
    role = session['role']
    
    if role == UserRole.STUDENT.value:
        # Add student-specific context
        context.update({
            'student_id': session.get('student_id', ''),
            'faculty': session.get('faculty', ''),
            'department': session.get('department', ''),
            'graduation_status': session.get('graduation_status', '')
        })
    
    elif role == UserRole.ADVISOR.value:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT department_name FROM advisors WHERE id = ?', (session['user_id'],))
            advisor = c.fetchone()
            if advisor:
                context['department_name'] = advisor['department_name']
    
    elif role == UserRole.DEPARTMENT_SECRETARY.value:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT department_name FROM department_secretaries WHERE id = ?', (session['user_id'],))
            secretary = c.fetchone()
            if secretary:
                # Store both role and department_name in session
                session['role'] = 'department_secretary'  # Use string directly
                session['department_name'] = secretary['department_name']
    
    elif role == UserRole.DEANERY.value:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT faculty_name FROM deaneries WHERE id = ?', (session['user_id'],))
            deanery = c.fetchone()
            if deanery:
                context['faculty_name'] = deanery['faculty_name']
    
    elif role == UserRole.UNIT.value:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            # Get unit role
            c.execute('SELECT role FROM units WHERE id = ?', (session['user_id'],))
            unit = c.fetchone()
            if unit:
                session['unit_role'] = unit['role']  # Set session variable
                context['unit_role'] = unit['role']
                # Get pending count
                c.execute('''SELECT COUNT(*) as count
                            FROM unit_approvals ua
                            WHERE ua.unit_role = ?
                            AND ua.status = 'pending' ''',
                         (unit['role'],))
                pending = c.fetchone()
                context['pending_count'] = pending['count'] if pending else 0
    
    return render_template('home.html', **context)

# Remove the duplicate route and keep only one login function
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']

        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = c.fetchone()
            if not user:
                flash('No account found with this email.', 'error')
                return redirect(url_for('login'))

            c.execute('SELECT password_hash FROM user_passwords WHERE user_id = ?', (user['id'],))
            pw_row = c.fetchone()
            if not pw_row or not check_password_hash(pw_row['password_hash'], password):
                flash('Invalid password.', 'error')
                return redirect(url_for('login'))

            # Set session, etc.
            session['email'] = user['email']
            session['user_id'] = user['id']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('login'))

# Utility functions for authentication
def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(*roles):
    """Decorator to check if user has required role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in [role.value for role in roles]:
                flash('You do not have permission to access this page.')
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def feature_required(f):
    """Decorator to check if advanced features are enabled"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not ENABLE_ADVANCED_FEATURES:
            flash('This feature is currently unavailable.')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# Student routes
@app.route('/view_transcript')
@login_required
@role_required(UserRole.STUDENT)
def view_transcript():
    student_user_id = session.get('user_id')
    
    if not student_user_id:
        flash('User information not found. Please log in again.', 'error')
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Fetch transcript data with course details and grades
            c.execute('''
                SELECT t.semester, c.course_code, c.course_name, c.credits, c.ects,
                       t.grade, gs.numeric_value, t.passed
                FROM transcripts t
                JOIN courses c ON t.course_code = c.course_code
                JOIN grade_scale gs ON t.grade = gs.grade
                WHERE t.student_id = ?
                ORDER BY t.semester, c.course_code
            ''', (student_user_id,))
            
            transcript_data = c.fetchall()
            
            # Fetch student academic summary from student_status view
            c.execute('''
                SELECT gpa, total_credits, total_ects, is_eligible
                FROM student_status
                WHERE student_id = ?
            ''', (student_user_id,))
            
            academic_summary = c.fetchone()
            
    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        return redirect(url_for('home'))
        
    return render_template('transcript.html', 
                         transcript=transcript_data,
                         summary=academic_summary)

@app.route('/view_diploma')
@login_required
@role_required(UserRole.STUDENT)
def view_diploma():
    student_user_id = session.get('user_id')
    
    if not student_user_id:
        flash('User information not found. Please log in again.', 'error')
        return redirect(url_for('login'))
        
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Check if student has graduated and has a diploma
            c.execute('''
                SELECT d.*, s.graduation_status
                FROM diplomas d
                JOIN students s ON d.student_id = s.id
                WHERE d.student_id = ? AND s.graduation_status = ?
            ''', (student_user_id, GraduationStatus.GRADUATED.value))
            
            diploma = c.fetchone()
            
            if not diploma:
                flash('No diploma found. You must complete graduation requirements first.', 'info')
                return redirect(url_for('home'))
                
    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        return redirect(url_for('home'))
        
    return render_template('diploma.html', diploma=diploma)

@app.route('/request_graduation', methods=['GET', 'POST'])
@login_required
@role_required(UserRole.STUDENT)
@feature_required
def request_graduation():
    student_user_id = session.get('user_id')

    if not student_user_id:
        flash('User information not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            # Get student data directly from students table
            c.execute('''
                SELECT s.graduation_status, s.total_credits, s.total_ects, s.gpa,
                       s.student_id, s.department, s.faculty
                FROM students s
                WHERE s.id = ?
            ''', (student_user_id,))
            student_data = c.fetchone()

            if not student_data:
                flash('Student record not found.', 'error')
                return redirect(url_for('home'))

            # Check if student meets graduation requirements
            is_eligible = (student_data['gpa'] >= 2.00 and 
                          student_data['total_credits'] >= 140 and 
                          student_data['total_ects'] >= 240)

            if request.method == 'POST':
                # Check if already applied
                if student_data['graduation_status'] in ['applied', 'graduated']:
                    flash('You have already submitted a graduation request or graduated.', 'info')
                    return redirect(url_for('request_graduation'))

                # Check eligibility
                if not is_eligible:
                    flash('You are not eligible to request graduation yet.', 'error')
                    return redirect(url_for('request_graduation'))

                # Submit graduation request
                c.execute('''
                    UPDATE students 
                    SET graduation_status = ? 
                    WHERE id = ?
                ''', (GraduationStatus.APPLIED.value, student_user_id))

                # Update session
                session['graduation_status'] = GraduationStatus.APPLIED.value

                # Find and notify advisor
                c.execute('''
                    SELECT advisor_id FROM advisor_students WHERE student_id = ?
                ''', (student_user_id,))
                advisor_link = c.fetchone()

                if advisor_link:
                    c.execute('''
                        INSERT INTO notifications (sender_id, receiver_id, notification_type, timestamp)
                        VALUES (?, ?, ?, ?)
                    ''', (student_user_id, advisor_link['advisor_id'], 
                          NotificationType.GRADUATION_REQUEST_SUBMITTED.value, datetime.now()))

                conn.commit()
                flash('Graduation request submitted successfully! Your advisor has been notified.', 'success')
                return redirect(url_for('home'))

            # GET request - show the form
            return render_template('request_graduation.html', 
                                 student=student_data, 
                                 is_eligible=is_eligible)

    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        return redirect(url_for('home'))
    except Exception as e:
        flash(f'An unexpected error occurred: {e}', 'error')
        return redirect(url_for('home'))

@app.route('/request_termination', methods=['GET', 'POST'])
@login_required
@role_required(UserRole.STUDENT)
def request_termination():
    student_id = session.get('user_id')
    student_info = None
    existing_request = None

    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Check for existing request
            c.execute('''SELECT * FROM termination_requests 
                        WHERE student_id = ? AND status != 'rejected' 
                        ORDER BY request_date DESC LIMIT 1''', (student_id,))
            existing_request = c.fetchone()
            
            if existing_request:
                flash('You already have a pending termination request.', 'warning')
                return redirect(url_for('home'))

            # Get student info
            c.execute('''SELECT s.student_id as student_number, s.faculty, s.department, u.email
                        FROM students s
                        JOIN users u ON s.id = u.id
                        WHERE s.id = ?''', (student_id,))
            student_info = c.fetchone()

            if request.method == 'POST':
                reason = request.form.get('reason')
                if not reason:
                    flash('Please provide a reason for termination.', 'error')
                    return render_template('request_termination.html', student_info=student_info)

                # Insert termination request
                c.execute('''INSERT INTO termination_requests 
                           (student_id, request_date, status, reason)
                           VALUES (?, DATETIME('now'), 'pending', ?)''',
                        (student_id, reason))
                
                request_id = c.lastrowid

                # Insert unit approvals for each unit
                c.execute('SELECT role FROM units')
                units = c.fetchall()
                
                for unit in units:
                    c.execute('''INSERT INTO unit_approvals 
                               (termination_request_id, unit_role, status)
                               VALUES (?, ?, 'pending')''',
                            (request_id, unit['role']))

                conn.commit()
                flash('Termination request submitted successfully.', 'success')
                return redirect(url_for('home'))

            return render_template('request_termination.html', 
                                student_info=student_info,
                                existing_request=existing_request)

    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        return render_template('request_termination.html',
                             student_info=student_info,
                             existing_request=existing_request)

@app.route('/view_pending_terminations')
@login_required
@role_required(UserRole.UNIT)
def view_pending_terminations():
    user_id = session.get('user_id')
    
    unit_role = get_unit_role_for_user(user_id)
    if not unit_role:
        flash('Unit role not found for your account.', 'error')
        return redirect(url_for('home'))

    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            # Get unit information
            c.execute('''
                SELECT role as unit_role, title, display_name, is_final_approver
                FROM units 
                WHERE role = ?
            ''', (unit_role,))
            
            unit_info = c.fetchone()
            if not unit_info:
                flash('Unit information not found.', 'error')
                return redirect(url_for('home'))

            # Get pending approvals for this unit
            c.execute('''
                SELECT tr.*, ua.*, s.student_id as student_number, u.email,
                       units.display_name as unit_display_name
                FROM termination_requests tr
                JOIN unit_approvals ua ON tr.id = ua.termination_request_id
                JOIN students s ON tr.student_id = s.id
                JOIN users u ON s.id = u.id
                JOIN units ON ua.unit_role = units.role
                WHERE ua.unit_role = ? AND ua.status = 'pending'
                ORDER BY tr.request_date ASC
            ''', (unit_role,))

            pending_requests = c.fetchall()

            return render_template('view_pending_terminations.html',
                                 requests=pending_requests,
                                 unit_info=unit_info)

    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        print(f"Database error in view_pending_terminations: {e}")

    return redirect(url_for('home'))

@app.route('/approve_termination/<int:request_id>', methods=['POST'])
@login_required
@role_required(UserRole.UNIT)
def approve_termination(request_id):
    user_id = session.get('user_id')
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get user email and map to unit role
            c.execute('SELECT email FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('view_pending_terminations'))
            
            # Map email to unit role
            email = user['email']
            unit_role_map = {
                'tarik@library.edu': 'library',
                'alumni@alumni.edu': 'alumni', 
                'sks@sks.edu': 'sks',
                'it@it.edu': 'it',
                'affairs@affairs.edu': 'student_affairs'
            }
            
            unit_role = unit_role_map.get(email)
            if not unit_role:
                flash('Unit role not found for your account.', 'error')
                return redirect(url_for('view_pending_terminations'))
            
            # Get approval reason from form
            reason = request.form.get('reason', '')
            
            # Update this unit's approval with reason
            c.execute('''UPDATE unit_approvals 
                       SET status = ?, approval_date = ?, comments = ?
                       WHERE termination_request_id = ? AND unit_role = ?''',
                    ('approved', 
                     datetime.now(),
                     reason,
                     request_id,
                     unit_role))
            
            if c.rowcount == 0:
                flash('No pending approval found for this request.', 'error')
                return redirect(url_for('view_pending_terminations'))
            
            # Check if this was the last unit to approve
            c.execute('''
                SELECT COUNT(*) as pending_count 
                FROM unit_approvals 
                WHERE termination_request_id = ? AND status = 'pending'
            ''', (request_id,))
            pending_count = c.fetchone()['pending_count']
            
            if pending_count == 0:
                # All units have approved, update main request status
                c.execute('''
                    UPDATE termination_requests 
                    SET status = 'approved', 
                        completion_date = ?,
                        final_notes = ?
                    WHERE id = ?
                ''', (datetime.now(), "All units approved", request_id))
                
                # Notify student
                c.execute('SELECT student_id FROM termination_requests WHERE id = ?', (request_id,))
                student_id = c.fetchone()['student_id']
                
                c.execute('''INSERT INTO notifications 
                           (sender_id, receiver_id, notification_type, timestamp)
                        VALUES (?, ?, ?, ?)''',
                        (user_id, student_id, 
                         NotificationType.TERMINATION_FULLY_APPROVED.value,
                         datetime.now()))
            
            conn.commit()
            flash('Termination request approved successfully.', 'success')
            
    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        
    return redirect(url_for('view_pending_terminations'))

@app.route('/reject_termination/<int:request_id>', methods=['POST'])
@login_required
@role_required(UserRole.UNIT)
def reject_termination(request_id):
    user_id = session.get('user_id')
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get user email and map to unit role
            c.execute('SELECT email FROM users WHERE id = ?', (user_id,))
            user = c.fetchone()
            
            if not user:
                flash('User not found.', 'error')
                return redirect(url_for('view_pending_terminations'))
            
            # Map email to unit role
            email = user['email']
            unit_role_map = {
                'tarik@library.edu': 'library',
                'alumni@alumni.edu': 'alumni', 
                'sks@sks.edu': 'sks',
                'it@it.edu': 'it',
                'affairs@affairs.edu': 'student_affairs'
            }
            
            unit_role = unit_role_map.get(email)
            if not unit_role:
                flash('Unit role not found for your account.', 'error')
                return redirect(url_for('view_pending_terminations'))
            
            # Get rejection reason from form (required)
            reason = request.form.get('reason')
            if not reason:
                flash('Rejection reason is required.', 'error')
                return redirect(url_for('view_pending_terminations'))
            
            # Update this unit's approval status with reason
            c.execute('''UPDATE unit_approvals 
                       SET status = ?, approval_date = ?, comments = ?
                       WHERE termination_request_id = ? AND unit_role = ?''',
                    ('rejected', 
                     datetime.now(),
                     reason,
                     request_id,
                     unit_role))
            
            if c.rowcount == 0:
                flash('No pending approval found for this request.', 'error')
                return redirect(url_for('view_pending_terminations'))
            
            # Update main request status to rejected
            c.execute('''
                UPDATE termination_requests 
                SET status = 'rejected',
                    completion_date = ?,
                    final_notes = ?
                WHERE id = ?
            ''', (datetime.now(), f"Rejected by {unit_role}: {reason}", request_id))
            
            # Notify student
            c.execute('SELECT student_id FROM termination_requests WHERE id = ?', (request_id,))
            student_id = c.fetchone()['student_id']
            
            c.execute('''INSERT INTO notifications 
                       (sender_id, receiver_id, notification_type, timestamp)
                       VALUES (?, ?, ?, ?)''',
                    (user_id, student_id, 
                     NotificationType.TERMINATION_REJECTED_BY_UNIT.value,
                     datetime.now()))
            
            conn.commit()
            flash('Termination request rejected with provided reason.', 'info')
            
    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        
    return redirect(url_for('view_pending_terminations'))

# Advisor routes
@app.route('/view_advisees')
@login_required
@role_required(UserRole.ADVISOR)
@feature_required
def view_advisees():
    advisor_user_id = session.get('user_id')
    advisees = []
    if not advisor_user_id:
        flash('User information not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Updated query to include s.id AS student_user_id
            c.execute('''
                SELECT s.id AS student_user_id, s.student_id, u.email, 
                       s.faculty, s.department, s.graduation_status
                FROM students s
                JOIN users u ON s.id = u.id
                JOIN advisor_students as_map ON s.id = as_map.student_id
                WHERE as_map.advisor_id = ?
            ''', (advisor_user_id,))
            advisees_data = c.fetchall()

            if advisees_data:
                for row in advisees_data:
                    advisees.append(dict(row))
            else:
                flash('You currently have no advisees assigned or no advisees found.', 'info')

    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        print(f"Database error in view_advisees: {e}")
    except Exception as e:
        flash(f'An unexpected error occurred: {e}', 'error')
        print(f"Unexpected error in view_advisees: {e}")
        
    return render_template('view_advisees.html', advisees=advisees)

# Fix line 805 - change course_id to course_code
@app.route('/view_advisee_transcript/<int:student_id>')
@login_required
@role_required(UserRole.ADVISOR)
def view_advisee_transcript(student_id):
    advisor_user_id = session.get('user_id')
    # Check if this student is assigned to the advisor
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('''
            SELECT 1 FROM advisor_students 
            WHERE advisor_id = ? AND student_id = ?
        ''', (advisor_user_id, student_id))
        if not c.fetchone():
            flash('You do not have permission to view this student\'s transcript.', 'error')
            return redirect(url_for('view_advisees'))

        # FIX: Change course_id to course_code in both SELECT and JOIN
        c.execute('''
            SELECT t.semester, c.course_code, c.course_name, c.credits, c.ects,
                   t.grade, gs.numeric_value, t.passed
            FROM transcripts t
            JOIN courses c ON t.course_code = c.course_code
            JOIN grade_scale gs ON t.grade = gs.grade
            WHERE t.student_id = ?
            ORDER BY t.semester, c.course_code
        ''', (student_id,))
        transcript_data = c.fetchall()

        # Fetch student academic summary
        c.execute('''
            SELECT gpa, total_credits, total_ects, graduation_status
            FROM students
            WHERE id = ?
        ''', (student_id,))
        academic_summary = c.fetchone()

    return render_template('transcript.html', 
                          transcript=transcript_data,
                          summary=academic_summary)

@app.route('/prepare_graduation_list', methods=['GET', 'POST'])
@login_required
@role_required(UserRole.ADVISOR)
@feature_required
def prepare_graduation_list():
    advisor_user_id = session.get('user_id')
    advisor_department_name = session.get('department_name') # Ensure this is in session for advisor

    if not advisor_user_id or not advisor_department_name:
        flash('User or department information not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    if request.method == 'POST':
        selected_student_ids_str = request.form.getlist('student_ids')
        if not selected_student_ids_str:
            flash('No students selected to include in the graduation list.', 'warning')
            conn.close()
            return redirect(url_for('prepare_graduation_list'))
        
        selected_student_ids = [int(sid) for sid in selected_student_ids_str]

        try:
            # Create the graduation list entry with academic year and semester
            current_date = datetime.now()
            academic_year = f"{current_date.year}/{current_date.year + 1}"
            semester = "fall" if current_date.month >= 9 else "spring" if current_date.month >= 2 else "summer"
            
            c.execute('''INSERT INTO graduation_lists 
                        (list_type, owner_id, created_date, updated_date, academic_year, semester, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      ('advisor', advisor_user_id, current_date, current_date, 
                       academic_year, semester, 'pending_secretary_review'))
            list_id = c.lastrowid

            # Add selected students to the list with their current academic info
            for student_user_id in selected_student_ids:
                # Fetch current student info
                c.execute('''SELECT gpa, total_credits, total_ects 
                           FROM students WHERE id = ?''', (student_user_id,))
                student_info = c.fetchone()
                
                c.execute('''INSERT INTO graduation_list_students 
                           (list_id, student_id, rank, gpa, total_credits, total_ects, added_date)
                           VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                         (list_id, student_user_id, 0, student_info['gpa'], 
                          student_info['total_credits'], student_info['total_ects'], current_date))
            
            # Notify Department Secretary
            # Find the department secretary for the advisor's department
            c.execute('''SELECT u.id FROM users u 
                        JOIN department_secretaries ds ON u.id = ds.id 
                        WHERE ds.department_name = ? AND u.role = ?''',
                      (advisor_department_name, UserRole.DEPARTMENT_SECRETARY.value))
            secretary = c.fetchone()

            if secretary:
                secretary_user_id = secretary['id']
                c.execute('''INSERT INTO notifications (sender_id, receiver_id, notification_type, timestamp)
                            VALUES (?, ?, ?, ?)''',
                          (advisor_user_id, secretary_user_id, NotificationType.ADVISOR_LIST_SUBMITTED.value, datetime.now()))
            else:
                # This case should be handled, e.g., log a warning or inform admin
                print(f"Warning: No department secretary found for department: {advisor_department_name} to send notification.")

            conn.commit()
            flash(f'Graduation list (ID: {list_id}) submitted successfully for review by the department secretary!', 'success')
            conn.close()
            return redirect(url_for('home'))
        
        except sqlite3.Error as e:
            conn.rollback()
            flash(f'Database error while preparing list: {e}', 'error')
            print(f"DB error in prepare_graduation_list POST: {e}")
        except Exception as e:
            conn.rollback()
            flash(f'An unexpected error occurred: {e}', 'error')
            print(f"Unexpected error in prepare_graduation_list POST: {e}")
        finally:
            if conn:
                conn.close()
        return redirect(url_for('prepare_graduation_list')) # Redirect back on error to try again

    # GET request: Fetch advisees who have applied for graduation and are not already in a list
    eligible_advisees = []
    try:
        c.execute('''
            SELECT s.id AS student_user_id, s.student_id, u.email, s.faculty, s.department, s.graduation_status
            FROM students s
            JOIN users u ON s.id = u.id
            JOIN advisor_students as_map ON s.id = as_map.student_id
            WHERE as_map.advisor_id = ?
              AND s.graduation_status = ?
              AND s.id NOT IN (
                  SELECT gls.student_id
                  FROM graduation_list_students gls
                  JOIN graduation_lists gl ON gls.list_id = gl.id
                  WHERE gl.owner_id = ? AND gl.list_type = 'advisor'
              )
        ''', (advisor_user_id, GraduationStatus.APPLIED.value, advisor_user_id))
        
        rows = c.fetchall()
        if rows:
            for row in rows:
                eligible_advisees.append(dict(row))
        else:
            flash('No advisees have applied for graduation yet, or all applied advisees are already in lists.', 'info')
            # We might also want to check if they are already in an *active* list by this advisor

    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        print(f"DB error in prepare_graduation_list GET: {e}")
    except Exception as e:
        flash(f'An unexpected error occurred: {e}', 'error')
        print(f"Unexpected error in prepare_graduation_list GET: {e}")
    finally:
        if conn:
            conn.close()
            
    return render_template('prepare_graduation_list.html', advisees=eligible_advisees)

# Add this helper function to get unit role properly
def get_unit_role_for_user(user_id):
    """Get unit role for a user based on their email"""
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('SELECT email FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        
        if not user:
            return None
        
        # Map email to unit role - this should be improved in production
        unit_role_map = {
            'tarik@library.edu': 'library',
            'alumni@alumni.edu': 'alumni', 
            'sks@sks.edu': 'sks',
            'it@it.edu': 'it',
            'affairs@affairs.edu': 'student_affairs'
        }
        
        return unit_role_map.get(user['email'])

# Department Secretary routes
@app.route('/view_advisor_lists')
@login_required
@role_required(UserRole.DEPARTMENT_SECRETARY)
@feature_required
def view_advisor_lists():
    secretary_user_id = session.get('user_id')
    department_name = session.get('department_name') # Assuming department_name is stored in session for secretary
    advisor_lists = []

    if not secretary_user_id or not department_name:
        flash('User or department information not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()

            c.execute('''
                SELECT gl.id, gl.created_date, gl.status, u.email as advisor_email
                FROM graduation_lists gl
                JOIN users u ON gl.owner_id = u.id
                JOIN advisors a ON gl.owner_id = a.id
                WHERE gl.list_type = ? AND a.department_name = ?
                ORDER BY gl.created_date DESC
            ''', ('advisor', department_name))
            
            lists_data = c.fetchall()

            if lists_data:
                for row_data in lists_data:
                    item = dict(row_data) # Convert row to dict to modify
                    if item['created_date']:
                        try:
                            # Attempt to parse with microseconds
                            item['created_date'] = datetime.strptime(item['created_date'], '%Y-%m-%d %H:%M:%S.%f')
                        except ValueError:
                            try:
                                # Try without microseconds
                                item['created_date'] = datetime.strptime(item['created_date'], '%Y-%m-%d %H:%M:%S')
                            except ValueError:
                                try:
                                    # Try date only
                                    item['created_date'] = datetime.strptime(item['created_date'], '%Y-%m-%d')
                                except ValueError:
                                    # Leave as string if all parsing fails
                                    pass
                    advisor_lists.append(item)
            else:
                flash(f'No advisor graduation lists found for the {department_name} department.', 'info')

    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        print(f"Database error in view_advisor_lists: {e}") # For server-side logging
    except Exception as e:
        flash(f'An unexpected error occurred: {e}', 'error')
        print(f"Unexpected error in view_advisor_lists: {e}") # For server-side logging
        
    return render_template('view_advisor_lists.html', advisor_lists=advisor_lists, department_name=department_name)

@app.route('/prepare_department_list', methods=['GET', 'POST'])
@login_required
@role_required(UserRole.DEPARTMENT_SECRETARY)
@feature_required
def prepare_department_list():
    secretary_user_id = session.get('user_id')
    
    if not secretary_user_id:
        flash('User information not found. Please log in again.', 'error')
        return redirect(url_for('login'))

    # Get secretary's department
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get secretary's department name
            c.execute('SELECT department_name FROM department_secretaries WHERE id = ?', (secretary_user_id,))
            secretary_info = c.fetchone()
            if not secretary_info:
                flash('Department secretary information not found.', 'error')
                return redirect(url_for('home'))
            
            department_name = secretary_info['department_name']
            
    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # Handle "Send List" functionality
        selected_student_ids = request.form.getlist('student_ids')
        ready_for_deanery = request.form.get('ready_for_deanery')
        
        if not selected_student_ids:
            flash('No students selected for the department list.', 'warning')
            return redirect(url_for('prepare_department_list'))
            
        if not ready_for_deanery:
            flash('Please confirm the list is ready for sending to Deanery.', 'warning')
            return redirect(url_for('prepare_department_list'))

        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()
                
                # Create new department graduation list
                current_date = datetime.now()
                academic_year = f"{current_date.year}/{current_date.year + 1}"
                semester = "fall" if current_date.month >= 9 else "spring" if current_date.month >= 2 else "summer"
                
                c.execute("""
                    INSERT INTO graduation_lists 
                    (list_type, owner_id, created_date, updated_date, academic_year, semester, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, ('department', secretary_user_id, current_date, current_date, 
                      academic_year, semester, 'pending_deanery_review'))
                
                department_list_id = c.lastrowid
                
                # Add selected students to the department list
                for rank, student_id in enumerate(selected_student_ids, 1):
                    # Get student's academic info
                    c.execute('''
                        SELECT gpa, total_credits, total_ects 
                        FROM students WHERE id = ?
                    ''', (int(student_id),))
                    student_info = c.fetchone()
                    
                    c.execute("""
                        INSERT INTO graduation_list_students 
                        (list_id, student_id, rank, gpa, total_credits, total_ects, added_date)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (department_list_id, int(student_id), rank, 
                          student_info['gpa'], student_info['total_credits'], 
                          student_info['total_ects'], current_date))
                
                # Update advisor lists status to indicate they've been processed
                c.execute("""
                    UPDATE graduation_lists 
                    SET status = 'consolidated_by_department' 
                    WHERE list_type = 'advisor' 
                    AND status = 'pending_secretary_review'
                    AND owner_id IN (
                        SELECT a.id FROM advisors a WHERE a.department_name = ?
                    )
                """, (department_name,))
                
                conn.commit()
                flash(f'Department graduation list created successfully! Sent to Deanery for review. List ID: {department_list_id}', 'success')
                return redirect(url_for('home'))
                
        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'error')
            print(f"Database error in prepare_department_list POST: {e}")
            return redirect(url_for('prepare_department_list'))

    # GET request: Show graduate candidates from advisor lists
    try:
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            
            # Get all advisor graduation lists for this department that are pending secretary review
            c.execute("""
                SELECT gl.id as advisor_list_id, gl.created_date, 
                       u.email as advisor_email, a.advisor_id
                FROM graduation_lists gl
                JOIN advisors a ON gl.owner_id = a.id
                JOIN users u ON a.id = u.id
                WHERE gl.list_type = 'advisor'
                  AND a.department_name = ?
                  AND gl.status = 'pending_secretary_review'
                ORDER BY gl.created_date ASC
            """, (department_name,))
            advisor_lists = c.fetchall()

            # Collect all students from all advisor lists
            all_students = []
            for advisor_list in advisor_lists:
                c.execute("""
                    SELECT s.id as student_user_id, s.student_id, u_stud.email as student_email, 
                           s.faculty, s.department, s.gpa, s.total_credits, s.total_ects,
                           gls.rank, gls.added_date
                    FROM graduation_list_students gls
                    JOIN students s ON gls.student_id = s.id
                    JOIN users u_stud ON s.id = u_stud.id
                    WHERE gls.list_id = ?
                    ORDER BY gls.rank, s.student_id
                """, (advisor_list['advisor_list_id'],))
                students_in_list = c.fetchall()
                
                for student in students_in_list:
                    student_dict = dict(student)
                    student_dict['advisor_email'] = advisor_list['advisor_email']
                    all_students.append(student_dict)

            if not all_students:
                flash('No advisor lists are currently pending your review for this department.', 'info')

    except sqlite3.Error as e:
        flash(f'Database error: {e}', 'error')
        print(f"DB error in prepare_department_list GET: {e}")
    except Exception as e:
        flash(f'An unexpected error occurred: {e}', 'error')
        print(f"Unexpected error in prepare_department_list GET: {e}")
    finally:
        if conn:
            conn.close()
            
    return render_template('prepare_graduation_list.html', advisees=eligible_advisees)

# Admin route to create staff accounts (for demo purposes)
@app.route('/admin/create_staff', methods=['GET', 'POST'])
def create_staff():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        role = request.form['role']

        if not email.endswith('@iyte.edu.tr'):
            flash('Staff email must end with @iyte.edu.tr')
            return redirect(url_for('create_staff'))

        try:
            with sqlite3.connect(DATABASE) as conn:
                conn.row_factory = sqlite3.Row
                c = conn.cursor()

                # Add to register table if not already present
                c.execute('SELECT * FROM register WHERE email = ?', (email,))
                if c.fetchone():
                    flash('This staff email is already pre-approved.')
                    return redirect(url_for('create_staff'))

                c.execute('INSERT INTO register (email, role) VALUES (?, ?)', (email, role))
                conn.commit()
                flash(f'Staff pre-approval created: {email} ({role}). The staff member must now register via the registration page.', 'success')
                return redirect(url_for('create_staff'))

        except sqlite3.IntegrityError:
            flash('Staff already exists in register table.')
        except sqlite3.Error as e:
            flash(f'Database error: {e}')

    return render_template('create_staff.html',
                          roles=[role.value for role in UserRole if role != UserRole.STUDENT],
                          unit_roles=[role.value for role in Roles])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if email is pre-approved
        with sqlite3.connect(DATABASE) as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM register WHERE email = ?', (email,))
            reg_entry = c.fetchone()
            if not reg_entry:
                flash('This email is not authorized to register.', 'error')
                return redirect(url_for('register'))

            # Check if already registered
            c.execute('SELECT * FROM users WHERE email = ?', (email,))
            if c.fetchone():
                flash('This email is already registered.', 'error')
                return redirect(url_for('login'))

            if len(password) < 8:
                flash('Password must be at least 8 characters.', 'error')
                return redirect(url_for('register'))
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return redirect(url_for('register'))

            # Register user
            c.execute('INSERT INTO users (email, role, register_id) VALUES (?, ?, ?)',
                      (email, reg_entry['role'], reg_entry['id']))
            user_id = c.lastrowid
            password_hash = generate_password_hash(password)
            c.execute('INSERT INTO user_passwords (user_id, password_hash) VALUES (?, ?)',
                      (user_id, password_hash))
            conn.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
