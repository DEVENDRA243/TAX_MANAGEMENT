from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import os

# This line calculates the correct path to your project's root directory
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# When you create your app, tell it where to find the folders
app = Flask(__name__,
            template_folder=os.path.join(project_root, 'templates'),
            static_folder=os.path.join(project_root, 'static'))
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')

# Database path for Vercel
DATABASE = '/tmp/tax_regime.db' if 'VERCEL' in os.environ else 'tax_regime.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            aadhaar TEXT NOT NULL UNIQUE,
            email TEXT,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'aadhaar' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'aadhaar' not in session:
            return redirect(url_for('login'))
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE aadhaar = ?', (session['aadhaar'],))
        user = cursor.fetchone()
        conn.close()
        if not user or user['is_admin'] == 0:
            flash('Admin access required.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        aadhaar = request.form['aadhaar']
        password = request.form['password']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE aadhaar = ?', (aadhaar,))
        user = cursor.fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['aadhaar'] = user['aadhaar']
            session['name'] = user['name']
            session['is_admin'] = user['is_admin']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Aadhaar or password')
            return render_template('login.html')
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        step = request.form.get('step', '1')
        if step == '1':
            aadhaar = request.form['aadhaar']
            phone = request.form.get('phone')
            if not phone:
                flash('Phone number is required.')
                return render_template('forgot_password.html', step=1)
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('SELECT phone FROM users WHERE aadhaar = ?', (aadhaar,))
            user = cursor.fetchone()
            conn.close()
            if user and user['phone'] == phone:
                return render_template('forgot_password.html', step=2, aadhaar=aadhaar)
            else:
                flash('Aadhaar and phone number do not match.')
                return render_template('forgot_password.html', step=1)
        elif step == '2':
            aadhaar = request.form['aadhaar']
            new_password = request.form['new_password']
            confirm_password = request.form['confirm_password']
            if new_password != confirm_password:
                flash('Passwords do not match.')
                return render_template('forgot_password.html', step=2, aadhaar=aadhaar)
            new_password_hash = generate_password_hash(new_password)
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET password_hash = ? WHERE aadhaar = ?', (new_password_hash, aadhaar))
            conn.commit()
            conn.close()
            flash('Password reset successful. Please login with your new password.')
            return redirect(url_for('login'))
    return render_template('forgot_password.html', step=1)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        aadhaar = request.form['aadhaar']
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')

        password_hash = generate_password_hash(password)
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute('INSERT INTO users (name, phone, aadhaar, email, password_hash) VALUES (?, ?, ?, ?, ?)',
                           (name, phone, aadhaar, email, password_hash))
            conn.commit()
            conn.close()
            flash('User created successfully. Please login.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Aadhaar number already registered.')
            return render_template('register.html')

    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        switch_option = request.form.get('switchOption')
        session['switch_option'] = switch_option
        if switch_option == 'No':
            return redirect(url_for('tax_calculator'))
        elif switch_option == 'Yes':
            return redirect(url_for('tax_calculator_old'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT aadhaar, name, email FROM users WHERE aadhaar = ?', (session['aadhaar'],))
    user = cursor.fetchone()
    conn.close()
    return render_template('dashboard.html', user=user)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('New passwords do not match.')
            return render_template('change_password.html')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM users WHERE aadhaar = ?', (session['aadhaar'],))
        user = cursor.fetchone()

        if not user or not check_password_hash(user['password_hash'], current_password):
            flash('Current password is incorrect.')
            conn.close()
            return render_template('change_password.html')

        new_password_hash = generate_password_hash(new_password)
        cursor.execute('UPDATE users SET password_hash = ? WHERE aadhaar = ?', (new_password_hash, session['aadhaar']))
        conn.commit()
        conn.close()
        flash('Password changed successfully.')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

@app.route('/admin')
@admin_required
def admin():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, phone, aadhaar, email FROM users WHERE is_admin = 0')
    users = cursor.fetchall()
    conn.close()
    return render_template('admin.html', users=users)

@app.route('/tax_regime')
@login_required
def tax_regime():
    return render_template('tax_regime.html')

@app.route('/my_tax_regime')
@login_required
def my_tax_regime():
    switch_option = session.get('switch_option', 'No')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT aadhaar, name, email FROM users WHERE aadhaar = ?', (session['aadhaar'],))
    user = cursor.fetchone()
    conn.close()
    return render_template('my_tax_regime.html', user=user, switch_option=switch_option)

@app.route('/report')
@login_required
def report():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, name, phone, aadhaar, email FROM users WHERE is_admin = 0')
    users = cursor.fetchall()
    conn.close()
    return render_template('admin.html', users=users)

@app.route('/tax_calculator')
@login_required
def tax_calculator():
    return render_template('tax_calculator.html')

@app.route('/tax_calculator_old')
@login_required
def tax_calculator_old():
    return render_template('tax_calculator_old.html')

@app.route('/calculate_tax', methods=['POST'])
@login_required
def calculate_tax_route():
    try:
        income = float(request.form.get('income', 0))
        deductions = float(request.form.get('deductions', 0))
    except ValueError:
        flash('Invalid input for income or deductions.')
        return redirect(url_for('tax_calculator'))

    from tax_calculator import calculate_tax
    tax = calculate_tax(income, deductions)
    return render_template('tax_calculator.html', tax=tax, income=income, deductions=deductions)

@app.route('/calculate_tax_old', methods=['POST'])
@login_required
def calculate_tax_old_route():
    try:
        income = float(request.form.get('income', 0))
        deductions = float(request.form.get('deductions', 0))
    except ValueError:
        flash('Invalid input for income or deductions.')
        return redirect(url_for('tax_calculator_old'))

    from tax_calculator import calculate_tax
    tax = calculate_tax(income, deductions, regime='old')
    return render_template('tax_calculator_old.html', tax=tax, income=income, deductions=deductions)

from vercel_wsgi import wsgi_app

# Initialize database on startup
with app.app_context():
    init_db()

# Vercel serverless function handler
handler = wsgi_app(app)
