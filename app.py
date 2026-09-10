import os
import json
import base64
import uuid
from io import BytesIO
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cyber_security_ministry_secret_key_secure_2026')

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

raw_url = os.environ.get("SUPABASE_URL", "").strip().strip('"').strip("'")
SUPABASE_URL = raw_url if (raw_url and raw_url.startswith("http")) else "https://kzjpmkndafsgdoakkjee.supabase.co"

raw_key = os.environ.get("SUPABASE_KEY", "").strip().strip('"').strip("'")
SUPABASE_KEY = raw_key if (raw_key and len(raw_key) > 20) else "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt6anBta25kYWZzZ2RvYWtramVlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg5NzE4MDEsImV4cCI6MjEwNDU0NzgwMX0.BWuqCd6sQU9eSQMhnQDTiJceM34aVw7FJlqqrU2No3k"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def init_admin_user():
    try:
        res = supabase.table('users').select('*').eq('username', 'admin').execute()
        admin_data = {
            "username": "admin",
            "password": generate_password_hash("07816141614"),
            "is_admin": True,
            "fullname": "مدير النظام الرئيسي",
            "rank": "مدير فني"
        }
        if not res.data:
            supabase.table('users').insert(admin_data).execute()
        else:
            supabase.table('users').update({"is_admin": True}).eq('username', 'admin').execute()
    except Exception as e:
        print(f"🚨 خطأ في تهيئة حساب الأدمن: {e}")

init_admin_user()

# --- دالة التنظيف التلقائي المؤقتة لحل مشكلة الـ Timeout وتفريغ الحجم الزائد ---
def auto_clear_heavy_evidence():
    try:
        print("🔄 جاري تفريغ الصور والأدلة الثقيلة من قاعدة البيانات لإصلاح مشكلة الـ Limit...")
        # جلب معرفات البلاغات وتفريغ الـ evidence تدريجياً لتجنب الـ Timeout
        res = supabase.table('reports').select('report_id').execute()
        reports = res.data or []
        for r in reports:
            rid = r.get('report_id')
            if rid:
                supabase.table('reports').update({'evidence': []}).eq('report_id', rid).execute()
        print("✅ تم تفريغ كافة الأدلة الثقيلة بنجاح وعادت المساحة لطبيعتها!")
    except Exception as e:
        print(f"⚠️ تنبيه أثناء التنظيف التلقائي: {e}")

# تشغيل التنظيف فور إقلاع السيرفر
auto_clear_heavy_evidence()
# --------------------------------------------------------------------------

def load_users():
    try:
        res = supabase.table('users').select('*').execute()
        return {u['username']: u for u in (res.data or [])}
    except Exception as e:
        print(f"🚨 خطأ في تحميل المستخدمين: {e}")
        return {}

def compress_and_upload_image(file_obj):
    try:
        filename = f"{uuid.uuid4().hex}.jpg"
        file_bytes = file_obj.read()
        if HAS_PIL:
            try:
                img = Image.open(BytesIO(file_bytes))
                if img.mode in ("RGBA", "P"):
                    img = img.convert("RGB")
                img.thumbnail((1920, 1080), Image.Resampling.LANCZOS)
                output = BytesIO()
                img.save(output, format="JPEG", quality=80, optimize=True)
                file_bytes = output.getvalue()
            except Exception:
                pass
        bucket_name = "evidence"
        supabase.storage.from_(bucket_name).upload(path=filename, file=file_bytes, file_options={"content-type": "image/jpeg"})
        return supabase.storage.from_(bucket_name).get_public_url(filename)
    except Exception as e:
        encoded = base64.b64encode(file_bytes).decode('utf-8')
        return f"data:image/jpeg;base64,{encoded}"

def load_reports(fetch_evidence=True):
    try:
        current_username = str(session.get('user', '')).strip().lower()
        is_admin_session = bool(session.get('is_admin', False))
        is_admin = (current_username == 'admin' or is_admin_session)
        current_fullname = str(session.get('fullname', '')).strip()

        query = supabase.table('reports').select('*')
        
        if not is_admin and current_fullname:
            query = query.ilike('officer', f"%{current_fullname}%")

        res = query.order('timestamp', desc=True).execute()
        raw_reports = res.data or []
        reports = []

        for r in raw_reports:
            reports.append({
                "report_id": r.get("report_id"),
                "officer": r.get("officer", ""),
                "source": r.get("source"),
                "platform": r.get("platform"),
                "url": r.get("url"),
                "accountName": r.get("account_name"),
                "datetime": r.get("datetime"),
                "description": r.get("description"),
                "threatType": r.get("threat_type"),
                "severity": r.get("severity"),
                "recommendation": r.get("recommendation"),
                "timestamp": r.get("timestamp"),
                "status": r.get("status", "قيد المراجعة"),
                "evidence": r.get("evidence", []) if fetch_evidence and isinstance(r.get("evidence"), list) else [],
                "tech_indicators": r.get("tech_indicators", {}) if isinstance(r.get("tech_indicators"), dict) else {}
            })
            
        return reports
    except Exception as e:
        print(f"🚨 خطأ فادح في تحميل البلاغات: {e}")
        return []

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            users = load_users()
            
            if username in users:
                user_record = users[username]
                user_db_password = user_record.get('password', '')
                is_valid = False
                try:
                    is_valid = check_password_hash(user_db_password, password)
                except Exception:
                    is_valid = (user_db_password == password)

                if is_valid:
                    session.clear()
                    session['user'] = username
                    is_adm = True if username == 'admin' else bool(user_record.get('is_admin', False))
                    session['is_admin'] = is_adm
                    session['fullname'] = user_record.get('fullname', username)
                    return redirect(url_for('index'))
                    
            flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'danger')
        except Exception as e:
            print(f"🚨 خطأ في تسجيل الدخول: {e}")
            flash('حدث خطأ تقني أثناء تسجيل الدخول، يرجى المحاولة مجدداً.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    try:
        reports = load_reports(fetch_evidence=False)
        
        total_reports = len(reports)
        critical_reports = sum(1 for r in reports if 'حرج' in str(r.get('severity', '')))
        monthly_count = sum(1 for r in reports if str(r.get('timestamp', '')).startswith(datetime.now().strftime('%Y-%m')))
        
        stats = {
            'total': total_reports,
            'critical': critical_reports,
            'monthly': monthly_count
        }
        
        current_user = session.get('user')
        is_admin_check = (current_user == 'admin' or bool(session.get('is_admin', False)))
        users = load_users() if is_admin_check else {}
        return render_template('index.html', stats=stats, users=users)
    except Exception as e:
        print(f"🚨 خطأ في الصفحة الرئيسية: {e}")
        stats = {'total': 0, 'critical': 0, 'monthly': 0}
        return render_template('index.html', stats=stats, users={})

@app.route('/submit-report', methods=['POST'])
def submit_report():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    m_url = request.form.get('m_url', '').strip()
    if m_url:
        try:
            existing_report = supabase.table('reports').select('report_id, status').eq('url', m_url).execute()
            if existing_report.data:
                prior_id = existing_report.data[0].get('report_id')
                prior_status = existing_report.data[0].get('status', 'قيد المراجعة')
                flash(f'⚠️ تنبيه: هذا الرابط مرصود ومُبلغ عنه مسبقاً برقم البلاغ ({prior_id}) وحالته الحالية: [{prior_status}].', 'warning')
                return redirect(url_for('index'))
        except Exception:
            pass

    report_id = f"MSW-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    files = request.files.getlist('evidence_files')
    evidence_urls = []
    for file in files:
        if file and file.filename:
            image_link = compress_and_upload_image(file)
            evidence_urls.append(image_link)

    db_payload = {
        "report_id": report_id,
        "officer": f"{request.form.get('user_rank', '')} {request.form.get('user_full_name', '')}".strip(),
        "source": request.form.get('m_source'),
        "platform": request.form.get('m_platform'),
        "url": m_url,
        "account_name": request.form.get('m_account_name'),
        "datetime": request.form.get('m_datetime'),
        "description": request.form.get('m_description'),
        "threat_type": request.form.get('m_threat_type'),
        "severity": request.form.get('m_severity'),
        "recommendation": request.form.get('m_recommendation'),
        "status": "قيد المراجعة",
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "evidence": evidence_urls,
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
    
    try:
        supabase.table('reports').insert(db_payload).execute()
        flash(f'تم رفع البلاغ بنجاح برقم {report_id} وهو قيد المراجعة.', 'success')
    except Exception as e:
        flash(f'حدث خطأ أثناء حفظ البلاغ: {e}', 'danger')

    return redirect(url_for('index'))

@app.route('/get-records')
def get_records():
    if 'user' not in session:
        return jsonify({'records': []})
    reports = load_reports(fetch_evidence=True)
    return jsonify({'records': reports})

@app.route('/approve-report/<report_id>', methods=['POST'])
def approve_report(report_id):
    if session.get('user') != 'admin' and not bool(session.get('is_admin', False)):
        flash('غير مسموح لك بإجراء هذه العملية.', 'danger')
        return redirect(url_for('index'))
    try:
        supabase.table('reports').update({'status': 'تمت الموافقة'}).eq('report_id', report_id).execute()
        flash(f'تمت الموافقة على البلاغ {report_id} بنجاح.', 'success')
    except Exception as e:
        flash(f'حدث خطأ أثناء الموافقة: {e}', 'danger')
    return redirect(url_for('index'))

@app.route('/reject-report/<report_id>', methods=['POST'])
def reject_report(report_id):
    if session.get('user') != 'admin' and not bool(session.get('is_admin', False)):
        flash('غير مسموح لك بإجراء هذه العملية.', 'danger')
        return redirect(url_for('index'))
    try:
        supabase.table('reports').delete().eq('report_id', report_id).execute()
        flash(f'تم رفض البلاغ {report_id} وحذفه من المنظومة.', 'info')
    except Exception as e:
        flash(f'حدث خطأ أثناء الرفض: {e}', 'danger')
    return redirect(url_for('index'))

@app.route('/monthly-log')
def monthly_log():
    if session.get('user') != 'admin' and not bool(session.get('is_admin', False)):
        return jsonify({'monthly_reports': []})
    reports = load_reports(fetch_evidence=False)
    current_month = datetime.now().strftime('%Y-%m')
    filtered = [r for r in reports if str(r.get('timestamp', '')).startswith(current_month)]
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
    if username in users and check_password_hash(users[username]['password'], current_pass):
        new_hashed = generate_password_hash(new_pass)
        supabase.table('users').update({'password': new_hashed}).eq('username', username).execute()
        flash('تم تغيير كلمة المرور بنجاح.', 'success')
    else:
        flash('كلمة المرور الحالية غير صحيحة.', 'danger')
    return redirect(url_for('index'))

@app.route('/add-user', methods=['POST'])
def add_user():
    if session.get('user') != 'admin' and not bool(session.get('is_admin', False)):
        flash('غير مسموح لك بإجراء هذه العملية.', 'danger')
        return redirect(url_for('index'))
        
    new_username = (request.form.get('new_username') or '').strip()
    new_password = (request.form.get('new_password') or '').strip()
    fullname = (request.form.get('new_fullname') or '').strip()
    rank = (request.form.get('new_rank') or '').strip()
    
    if not new_username or not new_password:
        flash('يرجى تعبئة اسم المستخدم وكلمة المرور بشكل صحيح.', 'danger')
        return redirect(url_for('index'))
    
    users = load_users()
    if new_username in users:
        flash('اسم المستخدم موجود مسبقاً.', 'danger')
        return redirect(url_for('index'))
        
    try:
        supabase.table('users').insert({
            "username": new_username,
            "password": generate_password_hash(new_password),
            "is_admin": False,
            "fullname": fullname,
            "rank": rank
        }).execute()
        flash(f'تم إضافة المستخدم {new_username} بنجاح.', 'success')
    except Exception as e:
        flash(f'حدث خطأ أثناء إضافة المستخدم: {e}', 'danger')
    return redirect(url_for('index'))

@app.route('/delete-user/<username>', methods=['POST'])
def delete_user(username):
    if session.get('user') != 'admin' and not bool(session.get('is_admin', False)):
        flash('غير مسموح لك بإجراء هذه العملية.', 'danger')
        return redirect(url_for('index'))
    if username == 'admin':
        flash('لا يمكن حذف حساب المشرف الرئيسي.', 'danger')
        return redirect(url_for('index'))
    try:
        supabase.table('users').delete().eq('username', username).execute()
        flash(f'تم حذف المستخدم {username} بنجاح.', 'success')
    except Exception as e:
        flash(f'حدث خطأ أثناء الحذف: {e}', 'danger')
    return redirect(url_for('index'))

@app.route('/delete-report/<report_id>', methods=['POST'])
def delete_report(report_id):
    if session.get('user') != 'admin' and not bool(session.get('is_admin', False)):
        flash('غير مسموح لك بحذف السجلات.', 'danger')
        return redirect(url_for('index'))
    try:
        supabase.table('reports').delete().eq('report_id', report_id).execute()
        flash(f'تم حذف السجل {report_id} بنجاح.', 'success')
    except Exception as e:
        flash(f'حدث خطأ أثناء الحذف: {e}', 'danger')
    return redirect(url_for('index'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
