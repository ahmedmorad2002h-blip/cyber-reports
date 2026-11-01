import os
import hmac
import time
import secrets
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("cyber-reports")

app = Flask(__name__)
# Render يضع التطبيق خلف بروكسي واحد: نقرأ عنوان العميل والبروتوكول الصحيحين منه
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)


def _clean_env(name):
    return os.environ.get(name, "").strip().strip('"').strip("'")


# ---------------------------------------------------------------------------
# الإعدادات والأسرار: كلها من متغيرات البيئة (Render > Environment) وليس من الكود
# ---------------------------------------------------------------------------
SECRET_KEY = _clean_env("SECRET_KEY")
if not SECRET_KEY:
    # مفتاح عشوائي مؤقت: آمن لكن يسجّل خروج الجميع عند كل إعادة تشغيل. اضبط SECRET_KEY في Render.
    SECRET_KEY = secrets.token_hex(32)
    log.warning("SECRET_KEY غير مضبوط: تم توليد مفتاح مؤقت. اضبطه في متغيرات البيئة.")
app.secret_key = SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),  # HTTPS فقط على Render
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

SUPABASE_URL = _clean_env("SUPABASE_URL")
SUPABASE_KEY = _clean_env("SUPABASE_KEY")
if not SUPABASE_URL.startswith("http") or len(SUPABASE_KEY) < 20:
    raise RuntimeError(
        "SUPABASE_URL و SUPABASE_KEY مطلوبان في متغيرات البيئة "
        "(Render > Environment). / SUPABASE_URL and SUPABASE_KEY must be set."
    )

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

MIN_PASSWORD_LENGTH = 8
STATUS_APPROVED = 'تمت الموافقة'
STATUS_REJECTED = 'مرفوض'
STATUS_PENDING = 'قيد المراجعة'


def init_admin_user():
    """ينشئ حساب admin إن لم يوجد. إن كان ADMIN_PASSWORD مضبوطاً يصبح هو كلمة سر الأدمن."""
    admin_password = _clean_env("ADMIN_PASSWORD")
    if admin_password and len(admin_password) < MIN_PASSWORD_LENGTH:
        log.error("ADMIN_PASSWORD أقصر من %d أحرف: تم تجاهله.", MIN_PASSWORD_LENGTH)
        admin_password = ""
    try:
        res = supabase.table('users').select('username').eq('username', 'admin').limit(1).execute()
        if not res.data:
            if not admin_password:
                log.warning("لا يوجد حساب admin و ADMIN_PASSWORD غير مضبوط: لم يتم إنشاء الحساب.")
                return
            supabase.table('users').insert({
                "username": "admin",
                "password": generate_password_hash(admin_password),
                "is_admin": True,
                "fullname": "مدير النظام الرئيسي",
                "rank": "مدير فني"
            }).execute()
        else:
            update = {"is_admin": True}
            if admin_password:
                update["password"] = generate_password_hash(admin_password)
            supabase.table('users').update(update).eq('username', 'admin').execute()
    except Exception:
        log.exception("خطأ في تهيئة حساب الأدمن")


init_admin_user()


# ---------------------------------------------------------------------------
# أدوات مساعدة
# ---------------------------------------------------------------------------
def clean(value, max_len=2000):
    return (value or '').strip()[:max_len]


def is_logged_in():
    return 'user' in session


def is_admin_session():
    return session.get('user') == 'admin' or bool(session.get('is_admin', False))


def require(check, on_denied):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not check():
                return on_denied()
            return fn(*args, **kwargs)
        return wrapper
    return deco


def _to_login():
    return redirect(url_for('login'))


def _deny_json(**extra):
    def handler():
        return jsonify({'success': False, 'message': 'غير مسموح', **extra}), 403
    return handler


def _deny_page():
    flash('غير مسموح لك بإجراء هذه العملية.', 'danger')
    return redirect(url_for('index'))


login_required_page = require(is_logged_in, _to_login)
admin_required_json = require(is_admin_session, _deny_json())
admin_required_page = require(is_admin_session, _deny_page)


def _escape_like(text):
    return text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def load_users():
    try:
        res = supabase.table('users').select('*').execute()
        return {u['username']: u for u in (res.data or [])}
    except Exception:
        log.exception("خطأ في تحميل المستخدمين")
        return {}


def get_user(username):
    try:
        res = supabase.table('users').select('*').eq('username', username).limit(1).execute()
        return res.data[0] if res.data else None
    except Exception:
        log.exception("خطأ في جلب المستخدم")
        return None


def load_reports():
    try:
        is_admin = is_admin_session()
        current_fullname = str(session.get('fullname', '')).strip()

        query = supabase.table('reports').select('*')

        if not is_admin:
            if not current_fullname:
                # مستخدم بلا اسم كامل لا يرى شيئاً (بدل أن يرى كل البلاغات)
                return []
            query = query.ilike('officer', f"%{_escape_like(current_fullname)}%")

        res = query.order('timestamp', desc=True).execute()
        reports = []

        for r in (res.data or []):
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
                "status": r.get("status", STATUS_PENDING),
                "tech_indicators": r.get("tech_indicators", {}) if isinstance(r.get("tech_indicators"), dict) else {}
            })

        return reports
    except Exception:
        log.exception("خطأ فادح في تحميل البلاغات")
        return []


# ---------------------------------------------------------------------------
# حماية CSRF + الجلسة + رؤوس الأمان
# ---------------------------------------------------------------------------
def get_csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_hex(16)
    return session['_csrf']


app.jinja_env.globals['csrf_token'] = get_csrf_token


@app.before_request
def csrf_protect():
    if request.method in ('GET', 'HEAD', 'OPTIONS'):
        return None
    expected = str(session.get('_csrf', ''))
    sent = str(request.form.get('csrf_token') or request.headers.get('X-CSRF-Token', ''))
    if expected and sent and hmac.compare_digest(expected.encode(), sent.encode()):
        return None
    log.warning("رفض طلب بدون رمز CSRF صحيح: %s %s", request.method, request.path)
    if request.headers.get('X-CSRF-Token') is not None or request.is_json:
        return jsonify({'success': False, 'message': 'انتهت صلاحية الصفحة، أعد تحميلها وحاول مرة أخرى.'}), 400
    flash('انتهت صلاحية الصفحة، حاول مرة أخرى.', 'danger')
    return redirect(url_for('index') if is_logged_in() else url_for('login'))


@app.after_request
def security_headers(resp):
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    resp.headers.setdefault('Cache-Control', 'no-store')
    if request.is_secure:
        resp.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    return resp


# ---------------------------------------------------------------------------
# تحديد محاولات الدخول الفاشلة (في الذاكرة)
# ---------------------------------------------------------------------------
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 300
_failed_logins = {}
_DUMMY_HASH = generate_password_hash(secrets.token_hex(8))


def _login_key(username):
    return f"{request.remote_addr}|{username.lower()}"


def _is_locked(key):
    entry = _failed_logins.get(key)
    if not entry:
        return False
    count, first_ts = entry
    if time.time() - first_ts > LOGIN_LOCK_SECONDS:
        _failed_logins.pop(key, None)
        return False
    return count >= LOGIN_MAX_ATTEMPTS


def _register_failure(key):
    now = time.time()
    count, first_ts = _failed_logins.get(key, (0, now))
    if now - first_ts > LOGIN_LOCK_SECONDS:
        count, first_ts = 0, now
    _failed_logins[key] = (count + 1, first_ts)
    if len(_failed_logins) > 5000:
        for k in [k for k, (_, ts) in _failed_logins.items() if now - ts > LOGIN_LOCK_SECONDS]:
            _failed_logins.pop(k, None)


# ---------------------------------------------------------------------------
# المسارات
# ---------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            username = clean(request.form.get('username'), 100)
            password = (request.form.get('password') or '').strip()
            key = _login_key(username)

            if _is_locked(key):
                flash('محاولات دخول فاشلة كثيرة، حاول بعد بضع دقائق.', 'danger')
                return render_template('login.html'), 429

            user_record = get_user(username) if username else None
            stored_hash = (user_record or {}).get('password') or _DUMMY_HASH
            try:
                is_valid = check_password_hash(stored_hash, password) and user_record is not None
            except Exception:
                is_valid = False

            if is_valid:
                _failed_logins.pop(key, None)
                session.clear()
                session.permanent = True
                session['user'] = username
                session['is_admin'] = True if username == 'admin' else bool(user_record.get('is_admin', False))
                session['fullname'] = user_record.get('fullname') or username
                return redirect(url_for('index'))

            _register_failure(key)
            flash('اسم المستخدم أو كلمة المرور غير صحيحة.', 'danger')
        except Exception:
            log.exception("خطأ في تسجيل الدخول")
            flash('حدث خطأ تقني أثناء تسجيل الدخول، يرجى المحاولة مجدداً.', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required_page
def index():
    try:
        reports = load_reports()
        month_prefix = datetime.now().strftime('%Y-%m')

        stats = {
            'total': len(reports),
            'critical': sum(1 for r in reports if 'حرج' in str(r.get('severity', ''))),
            'monthly': sum(1 for r in reports if str(r.get('timestamp', '')).startswith(month_prefix)),
            'approved': sum(1 for r in reports if r.get('status') == STATUS_APPROVED),
            'rejected': sum(1 for r in reports if r.get('status') == STATUS_REJECTED),
            'pending': sum(1 for r in reports if r.get('status', STATUS_PENDING) == STATUS_PENDING),
        }

        users = {}
        if is_admin_session():
            # لا نمرر كلمات السر (الهاش) للقالب
            users = {
                name: {'fullname': u.get('fullname', ''), 'rank': u.get('rank', '')}
                for name, u in load_users().items()
            }
        return render_template('index.html', stats=stats, users=users)
    except Exception:
        log.exception("خطأ في الصفحة الرئيسية")
        stats = {'total': 0, 'critical': 0, 'monthly': 0, 'approved': 0, 'rejected': 0, 'pending': 0}
        return render_template('index.html', stats=stats, users={})


@app.route('/submit-report', methods=['POST'])
@login_required_page
def submit_report():
    m_url = clean(request.form.get('m_url'), 1000)
    if not m_url:
        flash('رابط الموقع أو الصفحة مطلوب.', 'danger')
        return redirect(url_for('index'))

    try:
        existing_report = supabase.table('reports').select('report_id, status').eq('url', m_url).execute()
        if existing_report.data:
            prior_id = existing_report.data[0].get('report_id')
            prior_status = existing_report.data[0].get('status', STATUS_PENDING)
            flash(f'⚠️ تنبيه: هذا الرابط مرصود ومُبلغ عنه مسبقاً برقم البلاغ ({prior_id}) وحالته الحالية: [{prior_status}].', 'warning')
            return redirect(url_for('index'))
    except Exception:
        log.exception("فشل التحقق من تكرار الرابط")

    report_id = f"MSW-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"

    db_payload = {
        "report_id": report_id,
        "officer": f"{clean(request.form.get('user_rank'), 100)} {clean(request.form.get('user_full_name'), 200)}".strip(),
        "source": clean(request.form.get('m_source'), 500),
        "platform": clean(request.form.get('m_platform'), 200),
        "url": m_url,
        "account_name": clean(request.form.get('m_account_name'), 500),
        "datetime": clean(request.form.get('m_datetime'), 50),
        "description": clean(request.form.get('m_description'), 5000),
        "threat_type": clean(request.form.get('m_threat_type'), 200),
        "severity": clean(request.form.get('m_severity'), 100),
        "recommendation": clean(request.form.get('m_recommendation'), 5000),
        "status": STATUS_PENDING,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "tech_indicators": {
            "ip": clean(request.form.get('tech_ip'), 500),
            "domain": clean(request.form.get('tech_domain'), 500),
            "url": clean(request.form.get('tech_url_ind'), 1000),
            "email": clean(request.form.get('tech_email'), 500),
            "username": clean(request.form.get('tech_username'), 500),
            "hash": clean(request.form.get('tech_hash'), 500),
            "ioc": clean(request.form.get('tech_ioc'), 1000),
            "other": clean(request.form.get('tech_other'), 1000)
        }
    }

    try:
        supabase.table('reports').insert(db_payload).execute()
        flash(f'تم رفع البلاغ بنجاح برقم {report_id} وهو قيد المراجعة.', 'success')
    except Exception:
        log.exception("خطأ أثناء حفظ البلاغ")
        flash('حدث خطأ أثناء حفظ البلاغ، يرجى المحاولة مجدداً.', 'danger')

    return redirect(url_for('index'))


@app.route('/get-records')
def get_records():
    if not is_logged_in():
        return jsonify({'records': []})
    return jsonify({'records': load_reports()})


def _set_status(report_id, status):
    try:
        supabase.table('reports').update({'status': status}).eq('report_id', clean(report_id, 100)).execute()
        return jsonify({'success': True})
    except Exception:
        log.exception("خطأ في تحديث حالة البلاغ")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تنفيذ العملية.'})


@app.route('/approve-report/<report_id>', methods=['POST'])
@admin_required_json
def approve_report(report_id):
    return _set_status(report_id, STATUS_APPROVED)


@app.route('/reject-report/<report_id>', methods=['POST'])
@admin_required_json
def reject_report(report_id):
    return _set_status(report_id, STATUS_REJECTED)


@app.route('/bulk-approve', methods=['POST'])
@admin_required_json
def bulk_approve():
    try:
        data = request.get_json(silent=True) or {}
        raw_ids = data.get('report_ids', [])
        if not isinstance(raw_ids, list):
            return jsonify({'success': False, 'message': 'بيانات غير صحيحة.'})
        report_ids = [clean(str(i), 100) for i in raw_ids if i][:500]
        if not report_ids:
            return jsonify({'success': False, 'message': 'لم يتم تحديد أي بلاغ.'})
        supabase.table('reports').update({'status': STATUS_APPROVED}).in_('report_id', report_ids).execute()
        return jsonify({'success': True})
    except Exception:
        log.exception("خطأ في الموافقة الجماعية")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تنفيذ العملية.'})


@app.route('/delete-report/<report_id>', methods=['POST'])
@admin_required_json
def delete_report(report_id):
    try:
        supabase.table('reports').delete().eq('report_id', clean(report_id, 100)).execute()
        return jsonify({'success': True})
    except Exception:
        log.exception("خطأ في حذف البلاغ")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تنفيذ العملية.'})


@app.route('/delete-approved-bulk', methods=['POST'])
@admin_required_json
def delete_approved_bulk():
    try:
        supabase.table('reports').delete().eq('status', STATUS_APPROVED).execute()
        return jsonify({'success': True})
    except Exception:
        log.exception("خطأ في حذف البلاغات الموافق عليها")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تنفيذ العملية.'})


@app.route('/delete-monthly-approved', methods=['POST'])
@admin_required_json
def delete_monthly_approved():
    try:
        current_month = datetime.now().strftime('%Y-%m')
        reports = supabase.table('reports').select('report_id, timestamp, status').eq('status', STATUS_APPROVED).execute().data or []
        ids = [r['report_id'] for r in reports if str(r.get('timestamp', '')).startswith(current_month)]
        for i in range(0, len(ids), 100):
            supabase.table('reports').delete().in_('report_id', ids[i:i + 100]).execute()
        return jsonify({'success': True})
    except Exception:
        log.exception("خطأ في تصفية بلاغات الشهر")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تنفيذ العملية.'})


MONTH_NAMES = {
    '01': 'كانون الثاني (يناير)', '02': 'شباط (فبراير)', '03': 'آذار (مارس)',
    '04': 'نيسان (أبريل)', '05': 'أيار (مايو)', '06': 'حزيران (يونيو)',
    '07': 'تموز (يوليو)', '08': 'آب (أغسطس)', '09': 'أيلول (سبتمبر)',
    '10': 'تشرين الأول (أكتوبر)', '11': 'تشرين الثاني (نوفمبر)', '12': 'كانون الأول (ديسمبر)'
}


@app.route('/monthly-log')
@require(is_admin_session, _deny_json(monthly_data=[]))
def monthly_log():
    try:
        months_dict = {}
        for r in load_reports():
            ts = str(r.get('timestamp', ''))
            parts = ts[:7].split('-')
            if len(ts) >= 7 and len(parts) == 2:
                y, m = parts
                key = f"{y}-{m}"
                if key not in months_dict:
                    months_dict[key] = {'month_key': key, 'month_name': f"{MONTH_NAMES.get(m, m)} {y}", 'count': 0, 'reports': []}
                months_dict[key]['count'] += 1
                months_dict[key]['reports'].append(r)

        sorted_months = sorted(months_dict.values(), key=lambda x: x['month_key'], reverse=True)
        return jsonify({'monthly_data': sorted_months})
    except Exception:
        log.exception("خطأ في السجل الشهري")
        return jsonify({'monthly_data': []})


@app.route('/get-officers-activity')
@require(is_admin_session, _deny_json(officers=[]))
def get_officers_activity():
    try:
        res = supabase.table('reports').select('report_id, officer, platform, url, status, timestamp').execute()
        officers_dict = {}
        for r in (res.data or []):
            off = (r.get('officer') or '').strip() or 'غير محدد'
            entry = officers_dict.setdefault(off, {
                'name': off, 'uploaded_count': 0, 'approved_count': 0,
                'rejected_count': 0, 'pending_count': 0, 'reports': []
            })
            status = r.get("status") or STATUS_PENDING
            entry['reports'].append({
                "report_id": r.get("report_id"),
                "platform": r.get("platform"),
                "url": r.get("url"),
                "status": status,
                "timestamp": r.get("timestamp")
            })
            entry['uploaded_count'] += 1
            if status == STATUS_APPROVED:
                entry['approved_count'] += 1
            elif status == STATUS_REJECTED:
                entry['rejected_count'] += 1
            else:
                entry['pending_count'] += 1

        return jsonify({'success': True, 'officers': list(officers_dict.values())})
    except Exception:
        log.exception("خطأ في نشاط الأفراد")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تحميل البيانات.', 'officers': []})


@app.route('/change-password', methods=['POST'])
@login_required_page
def change_password():
    current_pass = request.form.get('current_password') or ''
    new_pass = request.form.get('new_password') or ''
    confirm_pass = request.form.get('confirm_password') or ''

    if new_pass != confirm_pass:
        flash('كلمتا المرور الجديدتان غير متطابقتين.', 'danger')
        return redirect(url_for('index'))

    if len(new_pass) < MIN_PASSWORD_LENGTH:
        flash(f'كلمة المرور الجديدة يجب ألا تقل عن {MIN_PASSWORD_LENGTH} أحرف.', 'danger')
        return redirect(url_for('index'))

    username = session['user']
    user = get_user(username)
    try:
        valid = bool(user) and check_password_hash(user.get('password', ''), current_pass)
    except Exception:
        valid = False

    if valid:
        try:
            supabase.table('users').update({'password': generate_password_hash(new_pass)}).eq('username', username).execute()
            flash('تم تغيير كلمة المرور بنجاح.', 'success')
        except Exception:
            log.exception("خطأ في تغيير كلمة المرور")
            flash('حدث خطأ أثناء تغيير كلمة المرور.', 'danger')
    else:
        flash('كلمة المرور الحالية غير صحيحة.', 'danger')
    return redirect(url_for('index'))


@app.route('/add-user', methods=['POST'])
@admin_required_page
def add_user():
    username = clean(request.form.get('new_username'), 50)
    password = (request.form.get('new_password') or '').strip()
    fullname = clean(request.form.get('new_fullname'), 200)
    rank = clean(request.form.get('new_rank'), 100)

    if not username or not password:
        flash('يرجى تعبئة اسم المستخدم وكلمة المرور بشكل صحيح.', 'danger')
        return redirect(url_for('index'))

    if len(password) < MIN_PASSWORD_LENGTH:
        flash(f'كلمة المرور يجب ألا تقل عن {MIN_PASSWORD_LENGTH} أحرف.', 'danger')
        return redirect(url_for('index'))

    if get_user(username):
        flash('اسم المستخدم موجود مسبقاً.', 'danger')
        return redirect(url_for('index'))

    try:
        supabase.table('users').insert({
            "username": username,
            "password": generate_password_hash(password),
            "is_admin": False,
            "fullname": fullname,
            "rank": rank
        }).execute()
        flash(f'تم إضافة المستخدم {username} بنجاح.', 'success')
    except Exception:
        log.exception("خطأ أثناء إضافة المستخدم")
        flash('حدث خطأ أثناء إضافة المستخدم.', 'danger')
    return redirect(url_for('index'))


@app.route('/update-user/<username>', methods=['POST'])
@admin_required_page
def update_user(username):
    new_fullname = clean(request.form.get('fullname'), 200)
    new_pass = (request.form.get('password') or '').strip()

    update_data = {}
    if new_fullname:
        update_data["fullname"] = new_fullname
    if new_pass:
        if len(new_pass) < MIN_PASSWORD_LENGTH:
            flash(f'كلمة المرور يجب ألا تقل عن {MIN_PASSWORD_LENGTH} أحرف.', 'danger')
            return redirect(url_for('index'))
        update_data["password"] = generate_password_hash(new_pass)

    if not update_data:
        flash('لم يتم إدخال أي تعديل.', 'warning')
        return redirect(url_for('index'))

    try:
        supabase.table('users').update(update_data).eq('username', username).execute()
        flash(f'تم تحديث بيانات المستخدم {username} بنجاح.', 'success')
    except Exception:
        log.exception("خطأ أثناء تحديث المستخدم")
        flash('حدث خطأ أثناء التحديث.', 'danger')
    return redirect(url_for('index'))


@app.route('/delete-user/<username>', methods=['POST'])
@admin_required_page
def delete_user(username):
    if username == 'admin':
        flash('لا يمكن حذف حساب المشرف الرئيسي.', 'danger')
        return redirect(url_for('index'))
    if username == session.get('user'):
        flash('لا يمكنك حذف حسابك الحالي.', 'danger')
        return redirect(url_for('index'))
    try:
        supabase.table('users').delete().eq('username', username).execute()
        flash(f'تم حذف المستخدم {username} بنجاح.', 'success')
    except Exception:
        log.exception("خطأ أثناء حذف المستخدم")
        flash('حدث خطأ أثناء الحذف.', 'danger')
    return redirect(url_for('index'))


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
