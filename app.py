import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'cyber_security_ministry_secret_key'

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

USERS_FILE = 'users.json'
REPORTS_FILE = 'reports.json'

def init_db():
    if not os.path.exists(USERS_FILE):
        default_users = {
            "admin": {
                "password": generate_password_hash("admin123"),
                "is_admin": True
            }
        }
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(default_users, f, ensure_ascii=False, indent=4)
            
    if not os.path.exists(REPORTS_FILE):
        with open(REPORTS_FILE, 'w', encoding='utf-8') as f:
            json.dump([], f, ensure_ascii=False, indent=4)

init_db()

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=4)

def load_reports():
    if os.path.exists(REPORTS_FILE):
        with open(REPORTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_reports(reports):
    with open(REPORTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(reports, f, ensure_ascii=False, indent=4)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        users = load_users()
        
        if username in users and check_password_hash(users[username]['password'], password):
            session['user'] = username
            session['is_admin'] = users[username].get('is_admin', False)
            return redirect(url_for('index'))
        flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/submit-report', methods=['POST'])
def submit_report():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    reports = load_reports()
    report_id = f"MSW-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # حفظ الملفات المرفقة إن وجدت
    files = request.files.getlist('evidence_files')
    filenames = []
    for file in files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            unique_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_name))
            filenames.append(unique_name)

    new_report = {
        "report_id": report_id,
        "officer": f"{request.form.get('user_rank')} {request.form.get('user_full_name')}",
        "source": request.form.get('m_source'),
        "platform": request.form.get('m_platform'),
        "url": request.form.get('m_url'),
        "accountName": request.form.get('m_account_name'),
        "datetime": request.form.get('m_datetime'),
        "description": request.form.get('m_description'),
        "threatType": request.form.get('m_threat_type'),
        "severity": request.form.get('m_severity'),
        "recommendation": request.form.get('m_recommendation'),
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "evidence": filenames,
        "tech_indicators": {
            "ip": request.form.get('tech_ip'),
            "domain": request.form.get('tech_domain'),
            "url": request.form.get('tech_url_ind'),
            "email": request.form.get('tech_email'),
            "username": request.form.get('tech_username'),
            "hash": request.form.get('tech_hash'),
            "ioc": request.form.get('tech_ioc'),
            "other": request.form.get('tech_other')
        }
    }
    
    reports.insert(0, new_report)
    save_reports(reports)
    flash(f'تم حفظ وتوثيق البلاغ برقم: {report_id} بنجاح', 'success')
    return redirect(url_for('index'))

@app.route('/get-records')
def get_records():
    if 'user' not in session:
        return jsonify({'records': []})
    reports = load_reports()
    return jsonify({'records': reports})

@app.route('/monthly-log')
def monthly_log():
    if 'user' not in session:
        return jsonify({'monthly_reports': []})
    reports = load_reports()
    current_month = datetime.now().strftime('%Y-%m')
    filtered = [r for r in reports if r.get('timestamp', '').startswith(current_month)]
    return jsonify({'monthly_reports': filtered})

@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    current_pass = request.form.get('current_password')
    new_pass = request.form.get('new_password')
    confirm_pass = request.form.get('confirm_password')
    
    if new_pass != confirm_pass:
        flash('كلمتا المرور الجديدتان غير متطابقتين.', 'danger')
        return redirect(url_for('index'))
        
    users = load_users()
    username = session['user']
    
    if check_password_hash(users[username]['password'], current_pass):
        users[username]['password'] = generate_password_hash(new_pass)
        save_users(users)
        flash('تم تغيير كلمة المرور بنجاح.', 'success')
    else:
        flash('كلمة المرور الحالية غير صحيحة.', 'danger')
        
    return redirect(url_for('index'))

@app.route('/add-user', methods=['POST'])
def add_user():
    if not session.get('is_admin'):
        flash('غير مسموح لك بإجراء هذه العملية.', 'danger')
        return redirect(url_for('index'))
        
    new_username = request.form.get('new_username')
    new_password = request.form.get('new_password')
    
    users = load_users()
    if new_username in users:
        flash('اسم المستخدم موجود مسبقاً.', 'danger')
    else:
        users[new_username] = {
            "password": generate_password_hash(new_password),
            "is_admin": False
        }
        save_users(users)
        flash(f'تم إضافة المستخدم {new_username} بنجاح.', 'success')
        
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
