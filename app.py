import os
import re
import hmac
import time
import calendar
import secrets
import logging
import threading
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit, parse_qsl, unquote

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash, check_password_hash
from supabase import create_client, Client

import whatsapp_sender as wa

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
# بعد الموافقة: تُرسل تلقائياً على واتساب فتصبح "تمت الموافقة وتم إرسالها"
STATUS_SENDING = 'جاري الإرسال'          # حالة مؤقتة أثناء الإرسال (تمنع الإرسال المزدوج)
STATUS_SENT = 'تمت الموافقة وتم إرسالها'
APPROVED_STATES = (STATUS_APPROVED, STATUS_SENDING, STATUS_SENT)

RANKS = ('مفوض', 'شرطي', 'منتسب / مرتب')


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
    """الأدمن الكامل: وحده يوافق ويرفض ويحذف ويعدّل البلاغات ويدير الأدوار."""
    return session.get('user') == 'admin' or bool(session.get('is_admin', False))


def is_supervisor_session():
    return bool(session.get('is_supervisor', False)) and not is_admin_session()


def can_view_all():
    """يرى كل البلاغات والسجل الشهري ونشاط الأفراد: الأدمن والمشرف."""
    return is_logged_in() and (is_admin_session() or is_supervisor_session())


def role_name():
    if is_admin_session():
        return 'admin'
    return 'supervisor' if is_supervisor_session() else 'user'


@app.context_processor
def inject_roles():
    return {
        'ROLE_ADMIN': is_admin_session(),
        'ROLE_SUPERVISOR': is_supervisor_session(),
        'CAN_VIEW_ALL': can_view_all(),
        'USER_RANK': session.get('rank', '') or '',
        'RANKS': RANKS,
    }


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
viewer_required_page = require(can_view_all, _deny_page)


def _escape_like(text):
    return text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


def fetch_all(build_query, page_size=1000, max_rows=200000):
    """Supabase يرجع 1000 صف كحد أقصى في الطلب الواحد، لذلك نقرأ على صفحات حتى لا نفقد بيانات."""
    rows = []
    start = 0
    while True:
        chunk = build_query().range(start, start + page_size - 1).execute().data or []
        rows.extend(chunk)
        if len(chunk) < page_size or len(rows) >= max_rows:
            return rows
        start += page_size


# ---------------------------------------------------------------------------
# فحص الروابط وتطبيعها (لكشف الرابط المكرر حتى لو كُتب بشكل مختلف)
# ---------------------------------------------------------------------------
_SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://')
_HOST_RE = re.compile(r'^[a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9_])?)*$')
_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

# نفس الموقع بأسماء مختلفة
_HOST_ALIASES = {
    'twitter.com': 'x.com',
    'telegram.me': 't.me', 'telegram.dog': 't.me',
    'fb.com': 'facebook.com', 'fb.me': 'facebook.com',
    'instagr.am': 'instagram.com',
}
_SOCIAL_BASES = {'facebook.com', 'instagram.com', 'x.com', 'tiktok.com', 'youtube.com', 't.me', 'linkedin.com', 'snapchat.com'}
_MOBILE_PREFIXES = ('m.', 'mobile.', 'web.', 'mbasic.', 'touch.')

# معاملات تتبّع لا تغيّر الصفحة
_TRACKING_PARAMS = {
    'fbclid', 'gclid', 'dclid', 'gbraid', 'wbraid', 'msclkid', 'yclid', 'igshid', 'igsh',
    'mc_cid', 'mc_eid', 'mibextid', 'fref', 'ref_src', 'ref_url', '_ga', '__tn__', '__cft__',
}
_HOST_TRACKING = {
    'x.com': {'s', 't'},
    'youtube.com': {'si', 'feature'},
    'facebook.com': {'ref', '_rdr', 'refsrc'},
    'tiktok.com': {'is_copy_url', 'is_from_webapp', 'sender_device', 'sender_web_id', '_r', '_t'},
}


def _canonical_host(host):
    if host.startswith('www.'):
        host = host[4:]
    for prefix in _MOBILE_PREFIXES:
        if host.startswith(prefix) and (host[len(prefix):] in _SOCIAL_BASES or host[len(prefix):] in _HOST_ALIASES):
            host = host[len(prefix):]
            break
    return _HOST_ALIASES.get(host, host)


def normalize_url(raw):
    """يرجع (مفتاح المقارنة, الرابط للعرض والحفظ). يرفع ValueError برسالة عربية إذا كان الرابط غير صالح."""
    text = (raw or '').strip()
    if not text:
        raise ValueError('رابط الموقع أو الصفحة مطلوب.')
    if len(text) > 1000:
        raise ValueError('الرابط طويل جداً.')
    if re.search(r'\s', text):
        raise ValueError('الرابط يحتوي على مسافات أو أسطر، يرجى التأكد منه.')

    if _SCHEME_RE.match(text):
        if text.split('://', 1)[0].lower() not in ('http', 'https'):
            raise ValueError('يُسمح بروابط http أو https فقط.')
        display = text
    else:
        first = text.split('/', 1)[0]
        # "javascript:..." أو "mailto:..." وما شابه: النقطتان بدون رقم منفذ بعدها
        if ':' in first and not re.fullmatch(r'[^:/]+:\d{1,5}', first):
            raise ValueError('يُسمح بروابط http أو https فقط.')
        default_scheme = 'http' if first.lower().split(':')[0].endswith('.onion') else 'https'
        display = f'{default_scheme}://{text}'

    try:
        parts = urlsplit(display)
        host = (parts.hostname or '').lower().rstrip('.')
        port = parts.port
    except ValueError:
        raise ValueError('صيغة الرابط غير صحيحة.')
    if not host:
        raise ValueError('صيغة الرابط غير صحيحة: لم يُعثر على اسم النطاق.')
    try:
        host = host.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValueError('اسم النطاق غير صحيح.')

    if _IPV4_RE.match(host):
        if any(int(o) > 255 for o in host.split('.')):
            raise ValueError('عنوان IP غير صحيح.')
    elif ':' not in host:  # غير IPv6
        if not _HOST_RE.match(host) or '.' not in host or host.rsplit('.', 1)[1].isdigit():
            raise ValueError('اسم النطاق غير صحيح (مثال: example.com).')

    host = _canonical_host(host)

    path = re.sub(r'/{2,}', '/', unquote(parts.path or '')).rstrip('/')
    if host in _SOCIAL_BASES:
        invite = host == 't.me' and (path.startswith('/+') or path.lower().startswith('/joinchat'))
        if host == 't.me' and path.lower().startswith('/s/'):
            path = path[2:]  # معاينة القناة على الويب = نفس القناة
        if not invite:
            path = path.lower()

    drop = _HOST_TRACKING.get(host, set())
    query_items = []
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        base = k.split('[')[0].lower()
        if base.startswith('utm_') or base in _TRACKING_PARAMS or base in drop:
            continue
        query_items.append((k, v))
    query = '&'.join(f'{k}={v}' for k, v in sorted(query_items))

    port_part = f':{port}' if port and port not in (80, 443) else ''
    key = f'{host}{port_part}{path}' + (f'?{query}' if query else '')
    return key, display


def find_duplicate_report(key, exclude_id=None):
    """يبحث في كل البلاغات عن نفس الرابط بعد التطبيع. يرجع صف البلاغ أو None."""
    rows = fetch_all(lambda: supabase.table('reports').select('report_id, url, status').order('report_id'))
    for r in rows:
        if exclude_id and r.get('report_id') == exclude_id:
            continue
        existing = r.get('url') or ''
        try:
            other_key = normalize_url(existing)[0]
        except ValueError:
            other_key = existing.strip().lower()
        if other_key == key:
            return r
    return None


def duplicate_message(row):
    return f"⚠️ هذا الرابط مرصود ومُبلغ عنه مسبقاً برقم البلاغ ({row.get('report_id')}) وحالته الحالية: [{row.get('status') or STATUS_PENDING}]."


def load_users():
    try:
        # نسقط كلمة السر (الهاش) فوراً: تُستخدم فقط عند تسجيل الدخول وتغيير كلمة السر
        res = supabase.table('users').select('*').execute()
        return {
            u['username']: {
                'fullname': u.get('fullname') or '',
                'rank': u.get('rank') or '',
                'is_admin': u['username'] == 'admin' or bool(u.get('is_admin')),
                'is_supervisor': bool(u.get('is_supervisor')),
            }
            for u in (res.data or [])
        }
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


def _is_owner(row):
    """صاحب البلاغ: من رفعه (يُحفظ اسم المستخدم داخل tech_indicators)، وللبلاغات القديمة نطابق الاسم الكامل."""
    ti = row.get('tech_indicators') if isinstance(row.get('tech_indicators'), dict) else {}
    submitted_by = ti.get('submitted_by')
    if submitted_by:
        return submitted_by == session.get('user')
    fullname = str(session.get('fullname', '')).strip().lower()
    return bool(fullname) and fullname in str(row.get('officer') or '').lower()


def _can_edit(row):
    """التعديل مسموح فقط لصاحب البلاغ (أو الأدمن) وطالما البلاغ قيد المراجعة."""
    return row.get('status') == STATUS_PENDING and (is_admin_session() or _is_owner(row))


def extract_report_fields(src):
    """يقرأ حقول الاستمارة من form أو JSON (نفس أسماء الحقول) ويرجع (أعمدة, مؤشرات فنية)."""
    columns = {
        "source": clean(src.get('m_source'), 500),
        "platform": clean(src.get('m_platform'), 200),
        "account_name": clean(src.get('m_account_name'), 500),
        "datetime": clean(src.get('m_datetime'), 50),
        "description": clean(src.get('m_description'), 5000),
        "threat_type": clean(src.get('m_threat_type'), 200),
        "severity": clean(src.get('m_severity'), 100),
        "recommendation": clean(src.get('m_recommendation'), 5000),
    }
    tech = {
        "ip": clean(src.get('tech_ip'), 500),
        "domain": clean(src.get('tech_domain'), 500),
        "url": clean(src.get('tech_url_ind'), 1000),
        "email": clean(src.get('tech_email'), 500),
        "username": clean(src.get('tech_username'), 500),
        "hash": clean(src.get('tech_hash'), 500),
        "ioc": clean(src.get('tech_ioc'), 1000),
        "other": clean(src.get('tech_other'), 1000),
    }
    return columns, tech


def _reports_query(columns='*'):
    """يبني استعلام البلاغات مع تطبيق صلاحيات المستخدم. يرجع None إذا لا يحق له رؤية شيء."""
    query = supabase.table('reports').select(columns)
    if not can_view_all():
        current_fullname = str(session.get('fullname', '')).strip()
        if not current_fullname:
            # مستخدم بلا اسم كامل لا يرى شيئاً (بدل أن يرى كل البلاغات)
            return None
        query = query.ilike('officer', f"%{_escape_like(current_fullname)}%")
    return query


def load_report_stats():
    """إحصائيات الصفحة الرئيسية: تجلب 3 أعمدة فقط بدل كل بيانات البلاغات."""
    stats = {'total': 0, 'critical': 0, 'monthly': 0, 'approved': 0, 'rejected': 0, 'pending': 0}
    try:
        query = _reports_query('severity, timestamp, status')
        if query is None:
            return stats
        rows = query.execute().data or []
    except Exception:
        log.exception("خطأ في تحميل إحصائيات البلاغات")
        return stats

    month_prefix = wa.now_iraq().strftime('%Y-%m')
    for r in rows:
        status = r.get('status') or STATUS_PENDING
        stats['total'] += 1
        if 'حرج' in str(r.get('severity') or ''):
            stats['critical'] += 1
        if str(r.get('timestamp') or '').startswith(month_prefix):
            stats['monthly'] += 1
        if status in APPROVED_STATES:
            stats['approved'] += 1
        elif status == STATUS_REJECTED:
            stats['rejected'] += 1
        else:
            stats['pending'] += 1
    return stats


def load_reports():
    try:
        query = _reports_query()
        if query is None:
            return []

        res = query.order('timestamp', desc=True).execute()
        reports = []

        for r in (res.data or []):
            reports.append({
                "editable": _can_edit(r),
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

ROLE_REFRESH_SECONDS = 60


def _apply_user_to_session(user_record, username):
    session['is_admin'] = True if username == 'admin' else bool(user_record.get('is_admin', False))
    session['is_supervisor'] = bool(user_record.get('is_supervisor', False))
    session['fullname'] = user_record.get('fullname') or username
    session['rank'] = (user_record.get('rank') or '').strip()
    session['_role_at'] = time.time()


@app.before_request
def refresh_role():
    """يعيد قراءة صلاحيات المستخدم من قاعدة البيانات كل دقيقة: سحب صلاحية المشرف أو حذف مستخدم
    يسري خلال دقيقة وليس بعد 8 ساعات (عمر الجلسة)."""
    if request.endpoint in ('healthz', 'static', 'login', 'logout', 'cron_send_pending') or not is_logged_in():
        return None
    if time.time() - float(session.get('_role_at', 0) or 0) < ROLE_REFRESH_SECONDS:
        return None
    username = session['user']
    try:
        res = supabase.table('users').select('*').eq('username', username).limit(1).execute()
    except Exception:
        log.exception("تعذر تحديث صلاحيات المستخدم، نبقي الجلسة كما هي مؤقتاً")
        return None
    if not res.data:
        session.clear()
        if request.is_json or request.path.startswith(('/get-', '/check-', '/monthly', '/whatsapp')):
            return jsonify({'success': False, 'message': 'انتهت الجلسة.'}), 401
        return redirect(url_for('login'))
    _apply_user_to_session(res.data[0], username)
    return None


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
@app.route('/healthz')
def healthz():
    """بدون تسجيل دخول وبدون قاعدة بيانات: لخدمات المراقبة (UptimeRobot) حتى لا ينام الموقع."""
    return 'ok', 200


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
                _apply_user_to_session(user_record, username)
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
        stats = load_report_stats()

        users = load_users() if can_view_all() else {}   # بدون كلمات السر
        return render_template('index.html', stats=stats, users=users)
    except Exception:
        log.exception("خطأ في الصفحة الرئيسية")
        stats = {'total': 0, 'critical': 0, 'monthly': 0, 'approved': 0, 'rejected': 0, 'pending': 0}
        return render_template('index.html', stats=stats, users={})


@app.route('/submit-report', methods=['POST'])
@login_required_page
def submit_report():
    try:
        url_key, m_url = normalize_url(request.form.get('m_url'))
    except ValueError as e:
        flash(str(e), 'danger')
        return redirect(url_for('index'))

    try:
        duplicate = find_duplicate_report(url_key)
    except Exception:
        log.exception("فشل التحقق من تكرار الرابط")
        flash('تعذر التحقق من تكرار الرابط حالياً، يرجى المحاولة مجدداً.', 'danger')
        return redirect(url_for('index'))
    if duplicate:
        flash(duplicate_message(duplicate), 'warning')
        return redirect(url_for('index'))

    # الرتبة تُحدَّد مرة وحدة: إن كانت محفوظة نستعملها، وإلا نحفظ ما اختاره الآن (ولا تتغير بعدها)
    rank = (session.get('rank') or '').strip()
    if not rank:
        chosen = clean(request.form.get('user_rank'), 100)
        if chosen not in RANKS:
            flash('يرجى اختيار الرتبة. تُحدَّد مرة واحدة فقط ولا تُسأل عنها مجدداً.', 'danger')
            return redirect(url_for('index'))
        try:
            fresh = get_user(session['user']) or {}
            rank = (fresh.get('rank') or '').strip() or chosen
            if not (fresh.get('rank') or '').strip():
                supabase.table('users').update({'rank': rank}).eq('username', session['user']).execute()
            session['rank'] = rank
        except Exception:
            log.exception("تعذر حفظ رتبة المستخدم")
            flash('تعذر حفظ الرتبة حالياً، يرجى المحاولة مجدداً.', 'danger')
            return redirect(url_for('index'))

    # اسم القائم بالرصد يُبنى من ملف المستخدم في الخادم، وليس من حقول الاستمارة
    fullname = (session.get('fullname') or session['user']).strip()

    columns, tech = extract_report_fields(request.form)
    tech['submitted_by'] = session['user']
    report_id = f"MSW-{wa.now_iraq().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"

    db_payload = {
        "report_id": report_id,
        "officer": f"{rank} {fullname}".strip(),
        **columns,
        "url": m_url,
        "status": STATUS_PENDING,
        "timestamp": wa.now_iraq().strftime('%Y-%m-%d %H:%M:%S'),
        "tech_indicators": tech,
    }

    try:
        supabase.table('reports').insert(db_payload).execute()
        flash(f'تم رفع البلاغ بنجاح برقم {report_id} وهو قيد المراجعة.', 'success')
    except Exception:
        log.exception("خطأ أثناء حفظ البلاغ")
        flash('حدث خطأ أثناء حفظ البلاغ، يرجى المحاولة مجدداً.', 'danger')

    return redirect(url_for('index'))


@app.route('/check-url')
def check_url():
    """فحص مباشر للرابط أثناء الكتابة: صحة الصيغة + هل هو مرصود سابقاً."""
    if not is_logged_in():
        return jsonify({'valid': False, 'duplicate': False, 'message': 'غير مسموح'}), 403
    raw = clean(request.args.get('url'), 1000)
    exclude = clean(request.args.get('exclude'), 100) or None
    if not raw:
        return jsonify({'valid': False, 'duplicate': False, 'message': ''})
    try:
        key, _display = normalize_url(raw)
    except ValueError as e:
        return jsonify({'valid': False, 'duplicate': False, 'message': str(e)})
    try:
        duplicate = find_duplicate_report(key, exclude)
    except Exception:
        log.exception("فشل فحص الرابط")
        return jsonify({'valid': True, 'duplicate': False, 'message': 'تعذر فحص التكرار حالياً، سيُفحص عند الحفظ.'})
    if duplicate:
        return jsonify({'valid': True, 'duplicate': True, 'message': duplicate_message(duplicate)})
    return jsonify({'valid': True, 'duplicate': False, 'message': '✓ الرابط صالح وغير مرصود سابقاً.'})


@app.route('/edit-report/<report_id>', methods=['POST'])
@require(is_logged_in, _deny_json())
def edit_report(report_id):
    """تعديل البلاغ من صاحبه (أو الأدمن) قبل الموافقة أو الرفض فقط."""
    rid = clean(report_id, 100)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'success': False, 'message': 'بيانات غير صحيحة.'}), 400

    try:
        rows = supabase.table('reports').select('*').eq('report_id', rid).limit(1).execute().data or []
    except Exception:
        log.exception("خطأ في جلب البلاغ للتعديل")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تنفيذ العملية.'}), 500
    if not rows:
        return jsonify({'success': False, 'message': 'البلاغ غير موجود.'}), 404
    row = rows[0]

    if not (is_admin_session() or _is_owner(row)):
        return jsonify({'success': False, 'message': 'غير مسموح لك بتعديل هذا البلاغ.'}), 403
    if row.get('status') != STATUS_PENDING:
        return jsonify({'success': False, 'message': 'لا يمكن تعديل بلاغ تمت الموافقة عليه أو رفضه.'}), 409

    try:
        url_key, new_url = normalize_url(data.get('m_url'))
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    try:
        duplicate = find_duplicate_report(url_key, exclude_id=rid)
    except Exception:
        log.exception("فشل التحقق من تكرار الرابط عند التعديل")
        return jsonify({'success': False, 'message': 'تعذر التحقق من تكرار الرابط حالياً.'}), 500
    if duplicate:
        return jsonify({'success': False, 'message': duplicate_message(duplicate)}), 409

    columns, tech = extract_report_fields(data)
    old_tech = row.get('tech_indicators') if isinstance(row.get('tech_indicators'), dict) else {}
    for keep in ('submitted_by',):
        if old_tech.get(keep):
            tech[keep] = old_tech[keep]
    tech['edited_at'] = wa.now_iraq().strftime('%Y-%m-%d %H:%M:%S')

    try:
        # الشرط على الحالة داخل نفس الاستعلام: إن وافق الأدمن في هذه اللحظة لا يُطبَّق التعديل
        res = (supabase.table('reports')
               .update({**columns, "url": new_url, "tech_indicators": tech})
               .eq('report_id', rid).eq('status', STATUS_PENDING).execute())
    except Exception:
        log.exception("خطأ أثناء حفظ تعديل البلاغ")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء حفظ التعديل.'}), 500
    if not res.data:
        return jsonify({'success': False, 'message': 'تمت معالجة البلاغ (موافقة أو رفض) قبل حفظ تعديلك، فلا يمكن تعديله.'}), 409
    return jsonify({'success': True})


@app.route('/get-records')
def get_records():
    if not is_logged_in():
        return jsonify({'records': []})
    return jsonify({'records': load_reports()})


def _tech_of(row):
    return row.get('tech_indicators') if isinstance(row.get('tech_indicators'), dict) else {}


def _decide_report(report_id, new_status, extra_tech=None):
    """يبتّ في بلاغ قيد المراجعة (موافقة/رفض) مرة واحدة فقط، ويسجّل من قرر ومتى.
    الشرط على الحالة داخل نفس استعلام التحديث، فلا يمكن البتّ مرتين ولا قلب قرار سابق."""
    rid = clean(report_id, 100)
    try:
        rows = supabase.table('reports').select('*').eq('report_id', rid).limit(1).execute().data or []
        if not rows:
            return jsonify({'success': False, 'message': 'البلاغ غير موجود.'}), 404
        row = rows[0]
        if row.get('status') != STATUS_PENDING:
            return jsonify({'success': False, 'message': 'تم البتّ في هذا البلاغ مسبقاً، لا يمكن تغيير قراره.'}), 409
        tech = dict(_tech_of(row))
        tech['decided_by'] = session.get('user')
        tech['decided_at'] = wa.now_iraq().strftime('%Y-%m-%d %H:%M:%S')
        tech.update(extra_tech or {})
        res = (supabase.table('reports').update({'status': new_status, 'tech_indicators': tech})
               .eq('report_id', rid).eq('status', STATUS_PENDING).execute())
        if not res.data:
            return jsonify({'success': False, 'message': 'تم البتّ في هذا البلاغ للتو من مستخدم آخر.'}), 409
        return jsonify({'success': True})
    except Exception:
        log.exception("خطأ في تحديث حالة البلاغ")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تنفيذ العملية.'}), 500


@app.route('/approve-report/<report_id>', methods=['POST'])
@admin_required_json
def approve_report(report_id):
    resp = _decide_report(report_id, STATUS_APPROVED)
    if (resp[0] if isinstance(resp, tuple) else resp).get_json().get('success'):
        trigger_whatsapp_async()      # يُرسل فوراً إن كنا داخل وقت الإرسال، وإلا ينتظر الطابور
    return resp


@app.route('/reject-report/<report_id>', methods=['POST'])
@admin_required_json
def reject_report(report_id):
    data = request.get_json(silent=True) or {}
    reason = clean(str(data.get('reason') or ''), 1000)
    if len(reason) < 3:
        return jsonify({'success': False, 'message': 'يجب كتابة سبب الرفض قبل رفض البلاغ.'}), 400
    return _decide_report(report_id, STATUS_REJECTED, {'rejection_reason': reason})


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
        # الشرط على الحالة: لا تمسّ البلاغات المبتوت فيها (المرفوضة أو المرسلة)
        res = (supabase.table('reports').update({'status': STATUS_APPROVED})
               .in_('report_id', report_ids).eq('status', STATUS_PENDING).execute())
        trigger_whatsapp_async()
        return jsonify({'success': True, 'approved': len(res.data or [])})
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


def _deletable_statuses():
    """عند تفعيل واتساب لا نحذف إلا ما أُرسل فعلاً، حتى لا يضيع بلاغ موافق عليه لم يصل بعد."""
    return [STATUS_SENT] if wa.load_config()['enabled'] else [STATUS_APPROVED, STATUS_SENT]


def _kept_unsent_count():
    if not wa.load_config()['enabled']:
        return 0
    return len(supabase.table('reports').select('report_id').in_('status', [STATUS_APPROVED, STATUS_SENDING]).execute().data or [])


@app.route('/delete-approved-bulk', methods=['POST'])
@admin_required_json
def delete_approved_bulk():
    try:
        res = supabase.table('reports').delete().in_('status', _deletable_statuses()).execute()
        return jsonify({'success': True, 'deleted': len(res.data or []), 'kept_unsent': _kept_unsent_count()})
    except Exception:
        log.exception("خطأ في حذف البلاغات الموافق عليها")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تنفيذ العملية.'})


@app.route('/delete-monthly-approved', methods=['POST'])
@admin_required_json
def delete_monthly_approved():
    try:
        current_month = wa.now_iraq().strftime('%Y-%m')
        reports = fetch_all(lambda: supabase.table('reports').select('report_id, timestamp, status')
                            .in_('status', _deletable_statuses()).order('report_id'))
        ids = [r['report_id'] for r in reports if str(r.get('timestamp', '')).startswith(current_month)]
        for i in range(0, len(ids), 100):
            supabase.table('reports').delete().in_('report_id', ids[i:i + 100]).execute()
        return jsonify({'success': True, 'deleted': len(ids), 'kept_unsent': _kept_unsent_count()})
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
@require(can_view_all, _deny_json(monthly_data=[]))
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
@require(can_view_all, _deny_json(officers=[]))
def get_officers_activity():
    try:
        rows = fetch_all(lambda: supabase.table('reports')
                         .select('report_id, officer, platform, url, status, timestamp').order('report_id'))
        officers_dict = {}
        for r in rows:
            off = (r.get('officer') or '').strip() or 'غير محدد'
            entry = officers_dict.setdefault(off, {
                'name': off, 'uploaded_count': 0, 'approved_count': 0,
                'rejected_count': 0, 'pending_count': 0, 'reports': [], '_months': {}
            })
            status = r.get("status") or STATUS_PENDING
            ts = str(r.get("timestamp") or '')
            entry['reports'].append({
                "report_id": r.get("report_id"),
                "platform": r.get("platform"),
                "url": r.get("url"),
                "status": status,
                "timestamp": ts
            })

            bucket = [entry]
            if re.fullmatch(r'\d{4}-(0[1-9]|1[0-2])', ts[:7]):
                key = ts[:7]
                month = entry['_months'].setdefault(key, {
                    'month_key': key,
                    'month_name': f"{MONTH_NAMES.get(key[5:], key[5:])} {key[:4]}",
                    'days': calendar.monthrange(int(key[:4]), int(key[5:7]))[1],
                    'uploaded_count': 0, 'approved_count': 0, 'rejected_count': 0, 'pending_count': 0,
                })
                bucket.append(month)

            for b in bucket:
                b['uploaded_count'] += 1
                if status in APPROVED_STATES:
                    b['approved_count'] += 1
                elif status == STATUS_REJECTED:
                    b['rejected_count'] += 1
                else:
                    b['pending_count'] += 1

        officers = []
        for entry in officers_dict.values():
            months = sorted(entry.pop('_months').values(), key=lambda m: m['month_key'], reverse=True)
            for m in months:
                # معدل الرصد اليومي = عدد حالات الشهر ÷ عدد أيام الشهر الكامل
                m['daily_rate'] = round(m['uploaded_count'] / m['days'], 2)
            entry['months'] = months
            entry['reports'].sort(key=lambda x: x['timestamp'], reverse=True)
            officers.append(entry)
        officers.sort(key=lambda e: e['uploaded_count'], reverse=True)

        return jsonify({'success': True, 'officers': officers})
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


def _is_privileged_user(record):
    """حسابات لا يلمسها المشرف: الأدمن وأي مشرف آخر (منعاً لرفع الصلاحيات عبر تغيير كلمة السر)."""
    return bool(record) and (record.get('username') == 'admin' or bool(record.get('is_admin')) or bool(record.get('is_supervisor')))


@app.route('/add-user', methods=['POST'])
@viewer_required_page
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
@viewer_required_page
def update_user(username):
    target = get_user(username)
    if not target:
        flash('المستخدم غير موجود.', 'danger')
        return redirect(url_for('index'))
    if not is_admin_session() and _is_privileged_user(target):
        flash('المشرف لا يستطيع تعديل حسابات الأدمن أو المشرفين.', 'danger')
        return redirect(url_for('index'))

    new_fullname = clean(request.form.get('fullname'), 200)
    new_rank = clean(request.form.get('rank'), 100)
    new_pass = (request.form.get('password') or '').strip()

    update_data = {}
    if new_fullname:
        update_data["fullname"] = new_fullname
    if new_rank:
        update_data["rank"] = new_rank
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


@app.route('/set-supervisor/<username>', methods=['POST'])
@admin_required_page
def set_supervisor(username):
    """الأدمن فقط يعيّن المشرفين أو يسحب الإشراف."""
    make = request.form.get('value') == '1'
    target = get_user(username)
    if not target:
        flash('المستخدم غير موجود.', 'danger')
        return redirect(url_for('index'))
    if username == 'admin' or target.get('is_admin'):
        flash('حساب الأدمن لا يُحوَّل إلى مشرف.', 'danger')
        return redirect(url_for('index'))
    try:
        supabase.table('users').update({'is_supervisor': make}).eq('username', username).execute()
        flash(f'تم تعيين {username} مشرفاً.' if make else f'تم سحب صلاحية الإشراف من {username}.', 'success')
    except Exception as e:
        log.exception("خطأ أثناء تغيير دور المستخدم")
        if 'is_supervisor' in str(e):
            flash('عمود is_supervisor غير موجود في جدول users. شغّل أمر SQL المذكور في README مرة واحدة ثم أعد المحاولة.', 'danger')
        else:
            flash('حدث خطأ أثناء تغيير الدور.', 'danger')
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


# ---------------------------------------------------------------------------
# الإرسال التلقائي على واتساب بعد الموافقة (07:00 - 16:00 بتوقيت بغداد)
# ---------------------------------------------------------------------------
WA_MAX_ATTEMPTS = 6        # بعدها يتوقف التلقائي ويظهر "فشل الإرسال" مع زر إعادة المحاولة
WA_STALE_SECONDS = 600     # إرسال عالق أكثر من 10 دقائق بلا معرّف رسالة يُعاد للطابور
WA_BATCH_LIMIT = 10        # أقصى عدد رسائل في الدورة الواحدة (الدورة كل دقيقة)
WA_LOOP_SECONDS = 60
_wa_lock = threading.Lock()


def _fmt_local(dt):
    return dt.astimezone(wa.IRAQ_TZ).strftime('%Y-%m-%d %H:%M:%S')


def _parse_local(text):
    try:
        return datetime.strptime(str(text), '%Y-%m-%d %H:%M:%S').replace(tzinfo=wa.IRAQ_TZ)
    except (TypeError, ValueError):
        return None


def _wa_info(row):
    return dict(_tech_of(row).get('whatsapp') or {})


def _wa_eligible(row, now):
    info = _wa_info(row)
    if int(info.get('attempts') or 0) >= WA_MAX_ATTEMPTS:
        return False
    retry_at = _parse_local(info.get('next_retry_at'))
    return not (retry_at and retry_at > now)


def _wa_save(row, tech, info, status, only_if_status):
    tech = dict(tech)
    tech['whatsapp'] = info
    return (supabase.table('reports').update({'status': status, 'tech_indicators': tech})
            .eq('report_id', row['report_id']).eq('status', only_if_status).execute())


def _wa_claim(row, now):
    """يحجز البلاغ بتحديث شرطي واحد (موافق عليه -> جاري الإرسال). نجح الحجز لمن رجع له صف فقط،
    فلا يرسل عاملان نفس البلاغ حتى لو اشتغل أكثر من نسخة من التطبيق (مثلاً أثناء النشر)."""
    tech = dict(_tech_of(row))
    info = _wa_info(row)
    info.update({'state': 'sending', 'claimed_at': _fmt_local(now), 'attempts': int(info.get('attempts') or 0) + 1})
    info.pop('next_retry_at', None)
    res = _wa_save(row, tech, info, STATUS_SENDING, STATUS_APPROVED)
    return (tech, info) if res.data else None


def _wa_mark_sent(row, tech, info, message_id, cfg, now):
    info.update({'state': 'sent', 'sent_at': _fmt_local(now), 'message_id': message_id, 'to': wa.mask_number(cfg['to'])})
    info.pop('last_error', None)
    info.pop('next_retry_at', None)
    for attempt in range(3):
        try:
            _wa_save(row, tech, info, STATUS_SENT, STATUS_SENDING)
            return True
        except Exception:
            log.exception("تعذر تسجيل نجاح الإرسال للبلاغ %s (المحاولة %s)", row.get('report_id'), attempt + 1)
            time.sleep(0.5)
    log.error("أُرسل البلاغ %s (message_id=%s) لكن تعذر تحديث حالته؛ لن يُعاد إرساله تلقائياً قبل مرور %s ثانية",
              row.get('report_id'), message_id, WA_STALE_SECONDS)
    return False


def _wa_mark_failed(row, tech, info, error, retryable, now):
    attempts = int(info.get('attempts') or 1)
    if not retryable:
        attempts = max(attempts, WA_MAX_ATTEMPTS)     # خطأ إعداد: لا فائدة من التكرار التلقائي
    info['attempts'] = attempts
    info['last_error'] = str(error)[:300]
    info['failed_at'] = _fmt_local(now)
    if attempts >= WA_MAX_ATTEMPTS:
        info['state'] = 'failed'
        info.pop('next_retry_at', None)
    else:
        info['state'] = 'retry'
        info['next_retry_at'] = _fmt_local(now + timedelta(seconds=min(60 * 2 ** (attempts - 1), 3600)))
    try:
        _wa_save(row, tech, info, STATUS_APPROVED, STATUS_SENDING)
    except Exception:
        log.exception("تعذر تسجيل فشل الإرسال للبلاغ %s", row.get('report_id'))


def _wa_reclaim_stale(now):
    rows = supabase.table('reports').select('*').eq('status', STATUS_SENDING).limit(100).execute().data or []
    for row in rows:
        info = _wa_info(row)
        claimed = _parse_local(info.get('claimed_at'))
        if info.get('message_id') or (claimed and (now - claimed).total_seconds() < WA_STALE_SECONDS):
            continue
        info.update({'state': 'retry', 'last_error': 'انقطعت عملية الإرسال السابقة قبل اكتمالها'})
        try:
            _wa_save(row, _tech_of(row), info, STATUS_APPROVED, STATUS_SENDING)
        except Exception:
            log.exception("تعذر إعادة البلاغ العالق %s للطابور", row.get('report_id'))


def process_whatsapp_queue(limit=WA_BATCH_LIMIT, only_id=None, delay=1.0):
    """يرسل البلاغات الموافق عليها غير المرسلة (الأقدم أولاً) داخل وقت الإرسال فقط."""
    cfg = wa.load_config()
    out = {'enabled': cfg['enabled'], 'in_window': False, 'sent': 0, 'failed': 0, 'busy': False}
    if not cfg['enabled']:
        return out
    out['in_window'] = wa.in_send_window(cfg, wa.now_iraq())
    if not out['in_window']:
        return out
    if not _wa_lock.acquire(blocking=False):
        out['busy'] = True
        return out
    try:
        _wa_reclaim_stale(wa.now_iraq())
        query = supabase.table('reports').select('*').eq('status', STATUS_APPROVED)
        if only_id:
            query = query.eq('report_id', only_id)
        rows = query.order('report_id').limit(50).execute().data or []
        handled = 0
        for row in rows:
            if handled >= limit:
                break
            now = wa.now_iraq()
            if not wa.in_send_window(cfg, now):      # انتهى الوقت أثناء الدورة
                out['in_window'] = False
                break
            if not only_id and not _wa_eligible(row, now):
                continue
            claimed = _wa_claim(row, now)
            if not claimed:
                continue
            tech, info = claimed
            handled += 1
            try:
                message_id = wa.send_message(cfg, wa.build_message(row, max_len=900 if cfg['template'] else None))
            except wa.WhatsAppError as e:
                log.warning("فشل إرسال البلاغ %s: %s", row.get('report_id'), e)
                _wa_mark_failed(row, tech, info, e, e.retryable, wa.now_iraq())
                out['failed'] += 1
                continue
            except Exception as e:
                log.exception("خطأ غير متوقع أثناء إرسال البلاغ %s", row.get('report_id'))
                _wa_mark_failed(row, tech, info, f"{type(e).__name__}", True, wa.now_iraq())
                out['failed'] += 1
                continue
            _wa_mark_sent(row, tech, info, message_id, cfg, wa.now_iraq())
            out['sent'] += 1
            if delay and handled < limit:
                time.sleep(delay)
    finally:
        _wa_lock.release()
    return out


def _background_disabled():
    return bool(os.environ.get('DISABLE_BACKGROUND_JOBS'))


def _safe_process():
    try:
        process_whatsapp_queue()
    except Exception:
        log.exception("خطأ في دورة إرسال واتساب")


def trigger_whatsapp_async():
    """بعد الموافقة: دورة فورية في الخلفية (لا تُبطئ الطلب). خارج وقت الإرسال لا تفعل شيئاً."""
    if _background_disabled() or not wa.load_config()['enabled']:
        return
    threading.Thread(target=_safe_process, name='wa-trigger', daemon=True).start()


def _wa_worker_loop():
    while True:
        time.sleep(WA_LOOP_SECONDS)
        _safe_process()


def start_whatsapp_worker():
    if _background_disabled():
        return
    if not wa.load_config()['enabled']:
        log.info("الإرسال التلقائي على واتساب غير مفعّل (متغيرات WHATSAPP_* غير مضبوطة).")
        return
    threading.Thread(target=_wa_worker_loop, name='wa-worker', daemon=True).start()
    log.info("بدأ عامل الإرسال التلقائي على واتساب.")


@app.route('/whatsapp-status')
def whatsapp_status():
    if not can_view_all():
        return jsonify({'success': False, 'message': 'غير مسموح'}), 403
    cfg = wa.load_config()
    out = {'success': True, 'enabled': cfg['enabled'], 'window': wa.window_label(cfg), 'in_window': False,
           'pending': 0, 'failed': 0, 'to': wa.mask_number(cfg['to']) if cfg['enabled'] else ''}
    if not cfg['enabled']:
        return jsonify(out)
    out['in_window'] = wa.in_send_window(cfg, wa.now_iraq())
    try:
        rows = supabase.table('reports').select('report_id, tech_indicators, status').in_('status', [STATUS_APPROVED, STATUS_SENDING]).execute().data or []
        for row in rows:
            if int(_wa_info(row).get('attempts') or 0) >= WA_MAX_ATTEMPTS:
                out['failed'] += 1
            else:
                out['pending'] += 1
    except Exception:
        log.exception("خطأ في قراءة حالة الإرسال")
    return jsonify(out)


@app.route('/whatsapp-send-now/<report_id>', methods=['POST'])
@admin_required_json
def whatsapp_send_now(report_id):
    """إرسال/إعادة محاولة يدوية لبلاغ واحد (الأدمن فقط) وبنفس قيد وقت الإرسال."""
    rid = clean(report_id, 100)
    cfg = wa.load_config()
    if not cfg['enabled']:
        return jsonify({'success': False, 'message': 'الإرسال على واتساب غير مفعّل: لم تُضبط متغيرات WHATSAPP_* في Render.'}), 400
    if not wa.in_send_window(cfg, wa.now_iraq()):
        return jsonify({'success': False, 'message': f'خارج وقت الإرسال المسموح ({wa.window_label(cfg)} بتوقيت بغداد). سيُرسل تلقائياً عند بدء الوقت.'}), 409
    try:
        rows = supabase.table('reports').select('*').eq('report_id', rid).limit(1).execute().data or []
        if not rows or rows[0].get('status') != STATUS_APPROVED:
            return jsonify({'success': False, 'message': 'البلاغ غير موجود أو ليس بانتظار الإرسال.'}), 409
        row = rows[0]
        info = _wa_info(row)
        info.update({'attempts': 0, 'state': 'retry'})
        info.pop('next_retry_at', None)
        _wa_save(row, _tech_of(row), info, STATUS_APPROVED, STATUS_APPROVED)
        result = process_whatsapp_queue(limit=1, only_id=rid, delay=0)
    except Exception:
        log.exception("خطأ في الإرسال اليدوي")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء تنفيذ العملية.'}), 500
    if result.get('busy'):
        return jsonify({'success': False, 'message': 'عملية إرسال أخرى جارية الآن، حاول بعد لحظات.'}), 409
    if result['sent']:
        return jsonify({'success': True})
    fresh = supabase.table('reports').select('*').eq('report_id', rid).limit(1).execute().data or []
    error = _wa_info(fresh[0]).get('last_error') if fresh else ''
    return jsonify({'success': False, 'message': f'فشل الإرسال: {error or "سبب غير معروف"}'}), 502


@app.route('/cron/send-pending')
def cron_send_pending():
    """رابط لخدمة مراقبة خارجية (UptimeRobot / cron-job.org) كل 5 دقائق: يبقي الموقع مستيقظاً
    على الخطة المجانية ويشغّل دورة الإرسال. يعمل فقط إذا ضُبط CRON_KEY."""
    expected = _clean_env('CRON_KEY')
    sent = request.args.get('key') or request.headers.get('X-Cron-Key', '')
    if not expected:
        return 'not found', 404
    if not hmac.compare_digest(expected.encode(), str(sent).encode()):
        return jsonify({'success': False, 'message': 'مفتاح غير صحيح'}), 403
    try:
        return jsonify({'success': True, **process_whatsapp_queue()})
    except Exception:
        log.exception("خطأ في دورة الإرسال من الرابط الخارجي")
        return jsonify({'success': False, 'message': 'خطأ داخلي'}), 500


start_whatsapp_worker()


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
