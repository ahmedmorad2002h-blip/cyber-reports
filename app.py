import os
import json
import base64
import uuid
from io import BytesIO
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client

# محاولة استيراد مكتبة Pillow للضغط الذكي للصور
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'cyber_security_ministry_secret_key_secure_2026')

# حد أقصى لحجم الصور المرفوعة (16 ميجابايت) لحماية الذاكرة على Render
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 

# معالجة رابط وقاعدة بيانات Supabase
raw_url = os.environ.get("SUPABASE_URL", "").strip().strip('"').strip("'")
if raw_url and raw_url.startswith("http"):
    SUPABASE_URL = raw_url
else:
    SUPABASE_URL = "https://kzjpmkndafsgdoakkjee.supabase.co"

raw_key = os.environ.get("SUPABASE_KEY", "").strip().strip('"').strip("'")
if raw_key and len(raw_key) > 20:
    SUPABASE_KEY = raw_key
else:
    SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imt6anBta25kYWZzZ2RvYWtramVlIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODg5NzE4MDEsImV4cCI6MjEwNDU0NzgwMX0.BWuqCd6sQU9eSQMhnQDTiJceM34aVw7FJlqqrU2No3k"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- دوال المساعدة للتعامل مع قاعدة البيانات والتخزين ---

def init_admin_user():
    """إنشاء أو تحديث حساب الأدمن الرئيسي تلقائياً لضمان صلاحيات المشرف الكاملة"""
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
            print("✅ تم إنشاء حساب الأدمن الرئيسي بنجاح.")
        else:
            # ضمان تحديث صلاحية الأدمن لتكون True دائماً في حال كانت مسجلة مسبقاً بشكل خاطئ
            supabase.table('users').update({"is_admin": True}).eq('username', 'admin').execute()
    except Exception as e:
        print(f"🚨 خطأ في تهيئة حساب الأدمن: {e}")

init_admin_user()

def load_users():
    try:
        res = supabase.table('users').select('*').execute()
        return {u['username']: u for u in res.data}
    except Exception as e:
        print(f"🚨 خطأ في تحميل المستخدمين: {e}")
        return {}

def compress_and_upload_image(file_obj):
    """
    ضغط الصورة وتقليل حجمها ثم رفعها إلى Supabase Storage Bucket (evidence)
    وفي حال الفشل تعود للـ Base64 لضمان عدم توقف النظام.
    """
    try:
        filename = f"{uuid.uuid4().hex}.jpg"
        file_bytes = file_obj.read()
        
        # معالجة وضغط الصورة باستخدام Pillow إذا كانت متوفرة
        if HAS_PIL:
            try:
                img = Image.open(BytesIO(file_bytes))
                if img.mode in ("RGBA", "P"):
                    img = img.convert("RGB")
                
                # تصغير الأبعاد الكبيرة جداً للحفاظ على سرعة التحميل
                max_size = (1920, 1080)
                img.thumbnail(max_size, Image.Resampling.LANCZOS)
                
                output = BytesIO()
                img.save(output, format="JPEG", quality=80, optimize=True)
                file_bytes = output.getvalue()
            except Exception as pe:
                print(f"⚠️ فشل ضغط الصورة بـ Pillow، سيتم الرفع بالحجم الأصلي: {pe}")

        # رفع الملف إلى Supabase Storage Bucket
        bucket_name = "evidence"
        res = supabase.storage.from_(bucket_name).upload(
            path=filename,
            file=file_bytes,
            file_options={"content-type": "image/jpeg"}
        )

        # الحصول على الرابط العام المباشر للصورة
        public_url = supabase.storage.from_(bucket_name).get_public_url(filename)
        return public_url

    except Exception as e:
        print(f"⚠️ تعذر الرفع المباشر إلى Bucket (evidence)، جارٍ التحويل الآمن لـ Base64: {e}")
        # طريقة احتياطية (Fallback) بحال عدم وجود الـ Bucket أو خطأ في الصلاحية
        encoded = base64.b64encode(file_bytes).decode('utf-8')
        return f"data:image/jpeg;base64,{encoded}"

def load_reports(user_filter=None, is_admin=False, fetch_evidence=True):
    """تحميل البلاغات: الأدمن يرى الكل، والمستخدم العادي يرى بلاغاته فقط"""
    try:
        query = supabase.table('reports').select('*')
        res = query.execute()
        reports = []
        
        current_username = str(session.get('user', '')).strip().lower()
        current_fullname = str(session.get('fullname', '')).strip().lower()

        for r in res.data or []:
            # إذا لم يكن المستخدم مشرفاً، نتحقق من تطابق اسم المستخدم أو الاسم الكامل للضابط
            if not is_admin:
                r_username = str(r.get("username", "")).strip().lower()
                r_officer = str(r.get("officer", "")).strip().lower()
                
                match_user = (current_username and r_username == current_username)
                match_name = (current_fullname and current_fullname in r_officer)
                
                if not (match_user or match_name):
                    continue

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
            
        reports.sort(key=lambda x: str(x.get('timestamp') or ''), reverse=True)
        return reports
    except Exception as e:
        print(f"🚨 خطأ في تحميل البلاغات من Supabase: {e}")
        return []

# --- مسارات التطبيق (Routes) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        users = load_users()
        
        if username in users:
            user_db_password = users[username].get('password', '')
            is_valid = False
            try:
                is_valid = check_password_hash(user_db_password, password)
            except Exception:
                is_valid = (user_db_password == password)

            if is_valid:
                session['user'] = username
                session['is_admin'] = bool(users[username].get('is_admin', False))
                session['fullname'] = users[username].get('fullname', username)
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
    
    current_user_fullname = session.get('fullname', session.get('user'))
    is_admin = bool(session.get('is_admin', False))
    
    reports = load_reports(user_filter=current_user_fullname, is_admin=is_admin, fetch_evidence=False)
    
    total_reports = len(reports)
    critical_reports = sum(1 for r in reports if 'حرج' in str(r.get('severity', '')))
    monthly_count = sum(1 for r in reports if str(r.get('timestamp', '')).startswith(datetime.now().strftime('%Y-%m')))
    
    stats = {
        'total': total_reports,
        'critical': critical_reports,
        'monthly': monthly_count
    }
    
    users = load_users() if is_admin else {}
    return render_template('index.html', stats=stats, users=users)

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
                flash(f'⚠️ تنبيه: هذا الرابط مرصود ومُبلغ عنه مسبقاً برقم البلاغ ({prior_id}) وحالته الحالية: [{prior_status}]. لم يتم تكرار التسجيل.', 'warning')
                return redirect(url_for('index'))
        except Exception as e:
            print(f"🚨 خطأ أثناء التحقق من الرابط: {e}")

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
        "username": session.get('user'),
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
        print(f"🚨 خطأ أثناء حفظ البلاغ: {e}")
        flash(f'حدث خطأ أثناء حفظ البلاغ: {e}', 'danger')

    return redirect(url_for('index'))

@app.route('/get-records')
def get_records():
    if 'user' not in session:
        return jsonify({'records': []})
    
    current_user_fullname = session.get('fullname', session.get('user'))
    is_admin = bool(session.get('is_admin', False))
    reports = load_reports(user_filter=current_user_fullname, is_admin=is_admin, fetch_evidence=True)
    return jsonify({'records': reports})

@app.route('/approve-report/<report_id>', methods=['POST'])
def approve_report(report_id):
    if not bool(session.get('is_admin', False)):
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
    if not bool(session.get('is_admin', False)):
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
    if not bool(session.get('is_admin', False)):
        return jsonify({'monthly_reports': []})
    reports = load_reports(is_admin=True, fetch_evidence=False)
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
    
    if check_password_hash(users[username]['password'], current_pass):
        new_hashed = generate_password_hash(new_pass)
        supabase.table('users').update({'password': new_hashed}).eq('username', username).execute()
        flash('تم تغيير كلمة المرور بنجاح.', 'success')
    else:
        flash('كلمة المرور الحالية غير صحيحة.', 'danger')
        
    return redirect(url_for('index'))

@app.route('/add-user', methods=['POST'])
def add_user():
    if not bool(session.get('is_admin', False)):
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
        
    new_user_data = {
        "username": new_username,
        "password": generate_password_hash(new_password),
        "is_admin": False,
        "fullname": fullname,
        "rank": rank
    }
    
    try:
        supabase.table('users').insert(new_user_data).execute()
        flash(f'تم إضافة المستخدم {new_username} بنجاح.', 'success')
    except Exception as e:
        flash(f'حدث خطأ أثناء إضافة المستخدم: {e}', 'danger')
        
    return redirect(url_for('index'))

@app.route('/delete-user/<username>', methods=['POST'])
def delete_user(username):
    if not bool(session.get('is_admin', False)):
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
    if not bool(session.get('is_admin', False)):
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
