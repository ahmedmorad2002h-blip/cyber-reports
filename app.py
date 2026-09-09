import os
import json
import sqlite3
import base64
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'cyber_security_ministry_secret_key_secure_2026'

DB_FILE = 'database.db'

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # جدول المستخدمين
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL,
            fullname TEXT,
            rank TEXT
        )
    ''')
    
    # جدول البلاغات
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            report_id TEXT PRIMARY KEY,
            officer TEXT,
            source TEXT,
            platform TEXT,
            url TEXT,
            accountName TEXT,
            datetime TEXT,
            description TEXT,
            threatType TEXT,
            severity TEXT,
            recommendation TEXT,
            timestamp TEXT,
            evidence TEXT,
            tech_indicators TEXT
        )
    ''')
    
    # التحقق من وجود حساب المشرف الأساسي
    cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',))
    if not cursor.fetchone():
        hashed_pw = generate_password_hash("admin123")
        cursor.execute('''
            INSERT INTO users (username, password, is_admin, fullname, rank)
            VALUES (?, ?, ?, ?, ?)
        ''', ('admin', hashed_pw, 1, 'مدير النظام الرئيسي', 'مدير فني'))
        
    conn.commit()
    conn.close()

init_db()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['is_admin'] = bool(user['is_admin'])
            session['fullname'] = user['fullname'] or username
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
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reports')
    rows = cursor.fetchall()
    
    reports = []
    for r in rows:
        reports.append({
            "report_id": r['report_id'],
            "officer": r['officer'],
            "source": r['source'],
            "platform": r['platform'],
            "url": r['url'],
            "accountName": r['accountName'],
            "datetime": r['datetime'],
            "description": r['description'],
            "threatType": r['threatType'],
            "severity": r['severity'],
            "recommendation": r['recommendation'],
            "timestamp": r['timestamp'],
            "evidence": json.loads(r['evidence']) if r['evidence'] else [],
            "tech_indicators": json.loads(r['tech_indicators']) if r['tech_indicators'] else {}
        })
    
    total_reports = len(reports)
    critical_reports = sum(1 for r in reports if 'حرج' in r.get('severity', ''))
    monthly_count = sum(1 for r in reports if r.get('timestamp', '').startswith(datetime.now().strftime('%Y-%m')))
    
    stats = {
        'total': total_reports,
        'critical': critical_reports,
        'monthly': monthly_count
    }
    
    users = {}
    if session.get('is_admin'):
        cursor.execute('SELECT username, is_admin, fullname, rank FROM users')
        for u in cursor.fetchall():
            users[u['username']] = {
                "is_admin": bool(u['is_admin']),
                "fullname": u['fullname'],
                "rank": u['rank']
            }
    conn.close()
    
    return render_template('index.html', stats=stats, users=users)

@app.route('/submit-report', methods=['POST'])
def submit_report():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    report_id = f"MSW-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # معالجة الصور وتحويلها مباشرة إلى Base64 لتجنب الحذف على الاستضافات السحابية
    files = request.files.getlist('evidence_files')
    evidence_base64 = []
    for file in files:
        if file and file.filename:
            file_bytes = file.read()
            encoded = base64.b64encode(file_bytes).decode('utf-8')
            filename = file.filename.lower()
            mime_type = 'image/jpeg'
            if filename.endswith('.png'):
                mime_type = 'image/png'
            elif filename.endswith('.gif'):
                mime_type = 'image/gif'
            elif filename.endswith('.webp'):
                mime_type = 'image/webp'
            data_url = f"data:{mime_type};base64,{encoded}"
            evidence_base64.append(data_url)

    officer_val = f"{request.form.get('user_rank', '')} {request.form.get('user_full_name', '')}".strip()
    source_val = request.form.get('m_source')
    platform_val = request.form.get('m_platform')
    url_val = request.form.get('m_url')
    account_name = request.form.get('m_account_name')
    dt_val = request.form.get('m_datetime')
    desc_val = request.form.get('m_description')
    threat_type = request.form.get('m_threat_type')
    severity = request.form.get('m_severity')
    recommendation = request.form.get('m_recommendation')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    tech_indicators = {
        "ip": request.form.get('tech_ip'),
        "domain": request.form.get('tech_domain'),
        "url": request.form.get('tech_url_ind'),
        "email": request.form.get('tech_email'),
        "username": request.form.get('tech_username'),
        "hash": request.form.get('tech_hash'),
        "ioc": request.form.get('tech_ioc'),
        "other": request.form.get('tech_other')
    }
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO reports (report_id, officer, source, platform, url, accountName, datetime, description, threatType, severity, recommendation, timestamp, evidence, tech_indicators)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        report_id, officer_val, source_val, platform_val, url_val, account_name, 
        dt_val, desc_val, threat_type, severity, recommendation, timestamp, 
        json.dumps(evidence_base64, ensure_ascii=False), 
        json.dumps(tech_indicators, ensure_ascii=False)
    ))
    conn.commit()
    conn.close()
    
    flash(f'تم حفظ وتوثيق البلاغ برقم: {report_id} بنجاح', 'success')
    return redirect(url_for('index'))

@app.route('/get-records')
def get_records():
    if 'user' not in session:
        return jsonify({'records': []})
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reports')
    rows = cursor.fetchall()
    
    reports = []
    for r in rows:
        reports.append({
            "report_id": r['report_id'],
            "officer": r['officer'],
            "source": r['source'],
            "platform": r['platform'],
            "url": r['url'],
            "accountName": r['accountName'],
            "datetime": r['datetime'],
            "description": r['description'],
            "threatType": r['threatType'],
            "severity": r['severity'],
            "recommendation": r['recommendation'],
            "timestamp": r['timestamp'],
            "evidence": json.loads(r['evidence']) if r['evidence'] else [],
            "tech_indicators": json.loads(r['tech_indicators']) if r['tech_indicators'] else {}
        })
    conn.close()
    return jsonify({'records': reports})

@app.route('/monthly-log')
def monthly_log():
    if 'user' not in session:
        return jsonify({'monthly_reports': []})
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM reports')
    rows = cursor.fetchall()
    conn.close()
    
    current_month = datetime.now().strftime('%Y-%m')
    filtered = []
    for r in rows:
        if r['timestamp'] and r['timestamp'].startswith(current_month):
            filtered.append({
                "report_id": r['report_id'],
                "officer": r['officer'],
                "source": r['source'],
                "platform": r['platform'],
                "url": r['url'],
                "accountName": r['accountName'],
                "datetime": r['datetime'],
                "description": r['description'],
                "threatType": r['threatType'],
                "severity": r['severity'],
                "recommendation": r['recommendation'],
                "timestamp": r['timestamp'],
                "evidence": json.loads(r['evidence']) if r['evidence'] else [],
                "tech_indicators": json.loads(r['tech_indicators']) if r['tech_indicators'] else {}
            })
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
        
    username = session['user']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if user and check_password_hash(user['password'], current_pass):
        new_hashed = generate_password_hash(new_pass)
        cursor.execute('UPDATE users SET password = ? WHERE username = ?', (new_hashed, username))
        conn.commit()
        flash('تم تغيير كلمة المرور بنجاح.', 'success')
    else:
        flash('كلمة المرور الحالية غير صحيحة.', 'danger')
        
    conn.close()
    return redirect(url_for('index'))

@app.route('/add-user', methods=['POST'])
def add_user():
    if not session.get('is_admin'):
        flash('غير مسموح لك بإجراء هذه العملية.', 'danger')
        return redirect(url_for('index'))
        
    new_username = request.form.get('new_username')
    new_password = request.form.get('new_password')
    fullname = request.form.get('new_fullname', '')
    rank = request.form.get('new_rank', '')
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (new_username,))
    if cursor.fetchone():
        flash('اسم المستخدم موجود مسبقاً.', 'danger')
    else:
        hashed_pw = generate_password_hash(new_password)
        cursor.execute('''
            INSERT INTO users (username, password, is_admin, fullname, rank)
            VALUES (?, ?, ?, ?, ?)
        ''', (new_username, hashed_pw, 0, fullname, rank))
        conn.commit()
        flash(f'تم إضافة المستخدم {new_username} بنجاح.', 'success')
        
    conn.close()
    return redirect(url_for('index'))

@app.route('/delete-user/<username>', methods=['POST'])
def delete_user(username):
    if not session.get('is_admin'):
        flash('غير مسموح لك بإجراء هذه العملية.', 'danger')
        return redirect(url_for('index'))
        
    if username == 'admin':
        flash('لا يمكن حذف حساب المشرف الرئيسي.', 'danger')
        return redirect(url_for('index'))
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    
    flash(f'تم حذف المستخدم {username} بنجاح.', 'success')
    return redirect(url_for('index'))

@app.route('/delete-report/<report_id>', methods=['POST'])
def delete_report(report_id):
    if not session.get('is_admin'):
        flash('غير مسموح لك بحذف السجلات.', 'danger')
        return redirect(url_for('index'))
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM reports WHERE report_id = ?', (report_id,))
    conn.commit()
    conn.close()
    
    flash(f'تم حذف السجل {report_id} بنجاح.', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
