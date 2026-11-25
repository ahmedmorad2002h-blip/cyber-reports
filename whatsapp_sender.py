"""إرسال البلاغات على واتساب عبر WhatsApp Business Cloud API (من Meta) + قواعد وقت الإرسال.

كل الإعدادات من متغيرات البيئة (Render > Environment) ولا يُكتب أي رقم أو مفتاح في الكود:

  WHATSAPP_TOKEN             رمز الوصول الدائم (System User Token) من Meta
  WHATSAPP_PHONE_NUMBER_ID   معرّف رقم المُرسِل في Meta (ليس الرقم نفسه)
  WHATSAPP_TO                رقم المستلم بصيغة دولية (مثال: 9647XXXXXXXXX). لعدة مستلمين افصل بينهم بفاصلة: 9647A,9647B
  WHATSAPP_TEMPLATE_NAME     اسم القالب المعتمد (مطلوب عملياً، انظر README)
  WHATSAPP_TEMPLATE_LANG     لغة القالب (الافتراضي ar)
  WHATSAPP_TEMPLATE_VARS     عدد متغيرات القالب: 1 (الافتراضي، كل النص بمتغير واحد) أو 12 (متغير لكل حقل، يحفظ الترتيب والأسطر)
  WHATSAPP_DOC_TEMPLATE      اسم قالب معتمد برأس "مستند" لإرسال ملف Excel خارج نافذة الـ 24 ساعة (متغيران في الجسم: {{1}} التاريخ {{2}} العدد)
  WHATSAPP_HOURS             ساعات الإرسال بتوقيت بغداد، الافتراضي 7-19
  WHATSAPP_API_VERSION       الافتراضي v23.0
  WHATSAPP_API_BASE          الافتراضي https://graph.facebook.com
  WHATSAPP_ENABLED           ضع 0 لإيقاف الإرسال مؤقتاً
"""
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib import error as urlerror
from urllib import request as urlrequest

# بغداد UTC+3 ثابت (العراق بلا توقيت صيفي)
IRAQ_TZ = timezone(timedelta(hours=3))

DEFAULT_HOURS = (7, 19)


class WhatsAppError(Exception):
    def __init__(self, message, retryable=True):
        super().__init__(message)
        self.retryable = retryable


def now_iraq():
    return datetime.now(IRAQ_TZ)


def _env(name, default=''):
    return os.environ.get(name, default).strip().strip('"').strip("'")


def parse_hours(value):
    m = re.fullmatch(r'\s*(\d{1,2})\s*-\s*(\d{1,2})\s*', value or '')
    if m:
        start, end = int(m.group(1)), int(m.group(2))
        if 0 <= start < end <= 24:
            return start, end
    return DEFAULT_HOURS


def parse_recipients(value):
    """أرقام المستلمين من WHATSAPP_TO: تفصل بينها فاصلة أو فاصلة منقوطة أو سطر جديد (المسافات داخل الرقم مسموحة)؛ بلا تكرار ولا أرقام غير صالحة."""
    numbers = []
    for part in re.split(r'[,;\n]+', value or ''):
        digits = re.sub(r'\D', '', part)
        if 8 <= len(digits) <= 15 and digits not in numbers:
            numbers.append(digits)
    return numbers


def recipient_key(number):
    """مفتاح مختصر للمستلم لتسجيل من وصله البلاغ دون تخزين رقمه."""
    return hashlib.sha1(re.sub(r'\D', '', number or '').encode()).hexdigest()[:10]


def load_config():
    """تُقرأ في كل مرة (وليس عند الاستيراد) حتى تُطبَّق تغييرات Render بدون تعديل الكود."""
    token = _env('WHATSAPP_TOKEN')
    phone_id = re.sub(r'\D', '', _env('WHATSAPP_PHONE_NUMBER_ID'))
    recipients = parse_recipients(_env('WHATSAPP_TO'))
    start, end = parse_hours(_env('WHATSAPP_HOURS', '7-19'))
    switched_off = _env('WHATSAPP_ENABLED', '1').lower() in ('0', 'false', 'no', 'off')
    return {
        'enabled': bool(token and phone_id and recipients) and not switched_off,
        'token': token,
        'phone_id': phone_id,
        'to': recipients[0] if recipients else '',
        'recipients': recipients,
        'api_base': _env('WHATSAPP_API_BASE', 'https://graph.facebook.com').rstrip('/'),
        'api_version': _env('WHATSAPP_API_VERSION', 'v23.0'),
        'template': _env('WHATSAPP_TEMPLATE_NAME'),
        'template_lang': _env('WHATSAPP_TEMPLATE_LANG', 'ar'),
        'template_vars': 12 if _env('WHATSAPP_TEMPLATE_VARS', '1') == '12' else 1,
        'doc_template': _env('WHATSAPP_DOC_TEMPLATE'),
        'start_hour': start,
        'end_hour': end,
    }


def in_send_window(cfg, now=None):
    """من بداية ساعة البدء (07:00:00) حتى قبل ساعة الانتهاء (19:00:00) بتوقيت بغداد."""
    now = (now or now_iraq()).astimezone(IRAQ_TZ)
    return cfg['start_hour'] <= now.hour < cfg['end_hour']


def window_label(cfg):
    return f"{cfg['start_hour']:02d}:00 - {cfg['end_hour'] % 24:02d}:00"


def mask_number(number):
    digits = re.sub(r'\D', '', number or '')
    return ('*' * max(0, len(digits) - 3)) + digits[-3:] if digits else ''


# ---------------------------------------------------------------------------
# نص الرسالة
# ---------------------------------------------------------------------------
def build_message(row, max_len=None):
    """نفس صيغة زر "مشاركة واتساب" في الموقع تماماً (ترتيب الحقول والرموز والقيم الافتراضية)."""
    tech = row.get('tech_indicators') if isinstance(row.get('tech_indicators'), dict) else {}

    def val(x, default):
        x = str(x).strip() if x not in (None, '') else ''
        return x or default

    def assemble(desc):
        return (
            "📋 *تقرير رصد سيبراني - مديرية أمن وسلامة الوزارة*\n\n"
            f"🌐 *المنصة:* {val(row.get('platform'), 'غير محدد')}\n"
            f"🔗 *الرابط:* {val(row.get('url'), 'غير محدد')}\n"
            f"🏷️ *اسم الحساب:* {val(row.get('account_name'), 'غير محدد')}\n"
            f"📅 *التاريخ:* {val(row.get('datetime') or row.get('timestamp'), 'غير محدد')}\n"
            f"⚠️ *نوع التهديد:* {val(row.get('threat_type'), 'غير محدد')}\n"
            f"🔴 *مستوى الخطورة:* {val(row.get('severity'), 'غير محدد')}\n"
            f"📝 *الوصف:* {desc}\n"
            "⚙️ *المؤشرات الفنية:*\n"
            f"- IP: {val(tech.get('ip'), 'غير متوفر')}\n"
            f"- Domain: {val(tech.get('domain'), 'غير متوفر')}\n"
            f"- Email: {val(tech.get('email'), 'غير متوفر')}\n"
            f"- Hash: {val(tech.get('hash'), 'غير متوفر')}\n"
            f"- IOC: {val(tech.get('ioc'), 'غير متوفر')}"
        )

    description = val(row.get('description'), 'لا يوجد وصف')
    text = assemble(description)
    if max_len and len(text) > max_len:
        overflow = len(text) - max_len
        if len(description) > overflow + 20:
            description = description[: len(description) - overflow - 1].rstrip() + '…'
            text = assemble(description)
        if len(text) > max_len:
            text = text[: max_len - 1].rstrip() + '…'
    return text


LRM = '\u200e'


def _param(value, default, max_len=200):
    """قيمة متغير في القالب: بلا أسطر جديدة ولا فراغات كثيرة ولا قيمة فارغة (ميتا ترفضها)."""
    text = str(value).strip() if value not in (None, '') else ''
    text = re.sub(r'[\r\n\t]+', ' ', text)
    text = re.sub(r' {2,}', ' ', text).strip()
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + '…'
    return text or default


def field_values(row):
    """12 قيمة بنفس ترتيب متغيرات القالب {{1}}..{{12}} (انظر README)."""
    tech = row.get('tech_indicators') if isinstance(row.get('tech_indicators'), dict) else {}
    when = _param(row.get('datetime') or row.get('timestamp'), 'غير محدد', 40).replace('T', ' ')
    return [
        _param(row.get('platform'), 'غير محدد', 60),
        _param(row.get('url'), 'غير محدد', 300),
        _param(row.get('account_name'), 'غير محدد', 100),
        LRM + when + LRM if when != 'غير محدد' else when,   # LRM يمنع قلب ترتيب الأرقام داخل النص العربي
        _param(row.get('threat_type'), 'غير محدد', 80),
        _param(row.get('severity'), 'غير محدد', 40),
        _param(row.get('description'), 'لا يوجد وصف', 450),
        _param(tech.get('ip'), 'غير متوفر', 100),
        _param(tech.get('domain'), 'غير متوفر', 100),
        _param(tech.get('email'), 'غير متوفر', 100),
        _param(tech.get('hash'), 'غير متوفر', 130),
        _param(tech.get('ioc'), 'غير متوفر', 100),
    ]


def flatten_for_template(text, max_len=1000):
    """متغيرات القالب في واتساب لا تقبل أسطراً جديدة ولا أكثر من 4 مسافات متتالية."""
    flat = re.sub(r'[\r\t]+', ' ', text or '')
    flat = re.sub(r'\n+', ' | ', flat)
    flat = re.sub(r' {2,}', ' ', flat).strip()
    if len(flat) > max_len:
        flat = flat[: max_len - 1].rstrip() + '…'
    return flat


# ---------------------------------------------------------------------------
# الإرسال
# ---------------------------------------------------------------------------
_HINTS = {
    131047: 'الرسالة النصية الحرة لا تُقبل إلا خلال 24 ساعة من آخر رسالة من المستلم: استخدم قالباً معتمداً (WHATSAPP_TEMPLATE_NAME).',
    131030: 'رقم المستلم غير مسموح له في وضع الاختبار: أضفه إلى قائمة المستلمين في Meta.',
    132000: 'عدد متغيرات القالب لا يطابق القالب المعتمد: يجب أن يحوي متغيراً واحداً في الجسم {{1}}.',
    132001: 'اسم القالب أو لغته غير موجودين أو غير معتمدين بعد.',
    190: 'رمز الوصول (WHATSAPP_TOKEN) منتهٍ أو غير صحيح.',
    100: 'معرّف الرقم (WHATSAPP_PHONE_NUMBER_ID) أو صيغة الطلب غير صحيحة.',
}


_DOC_HINTS = {
    131047: 'إرسال ملف بدون قالب لا يُقبل إلا خلال 24 ساعة من آخر رسالة من المستلم: أرسل أي رسالة من رقم المستلم إلى رقم الحساب، أو أنشئ قالب مستند معتمداً وضع اسمه في WHATSAPP_DOC_TEMPLATE.',
    132001: 'قالب المستند (WHATSAPP_DOC_TEMPLATE) غير موجود أو غير معتمد بهذه اللغة.',
    132012: 'متغيرات قالب المستند لا تطابق القالب: يجب أن يكون في رأسه مستند وفي جسمه متغيران {{1}} و{{2}}.',
}


def _error_detail(http_error, hints=None):
    try:
        body = json.loads(http_error.read().decode('utf-8', 'replace') or '{}')
    except Exception:
        return ''
    err = body.get('error') if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return ''
    code = err.get('code')
    sub = err.get('error_subcode')
    merged = {**_HINTS, **(hints or {})}
    hint = merged.get(sub) or merged.get(code)
    text = ''
    data = err.get('error_data')
    if isinstance(data, dict) and data.get('details'):
        text = str(data['details'])
    elif err.get('message'):
        text = str(err['message'])
    text = text[:250]
    return f"{text} {('— ' + hint) if hint else ''}".strip()


def send_message(cfg, text, timeout=20, fields=None, to=None):
    """يرسل الرسالة إلى مستلم واحد (to أو أول مستلم) ويرجع معرّف الرسالة. يرفع WhatsAppError عند الفشل (مع retryable)."""
    target = re.sub(r'\D', '', to or cfg['to'])
    if cfg.get('template') and cfg.get('template_vars') == 12 and fields:
        payload = {
            "messaging_product": "whatsapp",
            "to": target,
            "type": "template",
            "template": {
                "name": cfg['template'],
                "language": {"code": cfg['template_lang']},
                "components": [{"type": "body", "parameters": [{"type": "text", "text": v} for v in fields]}],
            },
        }
    elif cfg.get('template'):
        payload = {
            "messaging_product": "whatsapp",
            "to": target,
            "type": "template",
            "template": {
                "name": cfg['template'],
                "language": {"code": cfg['template_lang']},
                "components": [{"type": "body", "parameters": [{"type": "text", "text": flatten_for_template(text)}]}],
            },
        }
    else:
        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": target,
            "type": "text",
            "text": {"preview_url": False, "body": (text or '')[:4000]},
        }

    url = f"{cfg['api_base']}/{cfg['api_version']}/{cfg['phone_id']}/messages"
    req = urlrequest.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
        headers={'Authorization': f"Bearer {cfg['token']}", 'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode('utf-8', 'replace') or '{}')
    except urlerror.HTTPError as e:
        detail = _error_detail(e)
        # 5xx و429 مؤقتة؛ باقي 4xx أخطاء إعداد لا يفيد تكرارها تلقائياً
        raise WhatsAppError(f"HTTP {e.code}" + (f": {detail}" if detail else ''), retryable=(e.code >= 500 or e.code == 429))
    except (urlerror.URLError, TimeoutError, OSError) as e:
        raise WhatsAppError(f"تعذر الاتصال بخادم واتساب: {type(e).__name__}", retryable=True)
    except ValueError:
        raise WhatsAppError("ردّ غير مفهوم من خادم واتساب", retryable=True)

    messages = body.get('messages') if isinstance(body, dict) else None
    if not messages or not isinstance(messages[0], dict) or not messages[0].get('id'):
        raise WhatsAppError("لم يرجع خادم واتساب معرّف الرسالة", retryable=True)
    return str(messages[0]['id'])


# ---------------------------------------------------------------------------
# إرسال ملف (Excel) : رفع الملف إلى ميتا مرة واحدة ثم إرسال معرّفه لكل مستلم
# ---------------------------------------------------------------------------
def _http_json(req, timeout, hints=None):
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8', 'replace') or '{}')
    except urlerror.HTTPError as e:
        detail = _error_detail(e, hints)
        raise WhatsAppError(f"HTTP {e.code}" + (f": {detail}" if detail else ''), retryable=(e.code >= 500 or e.code == 429))
    except (urlerror.URLError, TimeoutError, OSError) as e:
        raise WhatsAppError(f"تعذر الاتصال بخادم واتساب: {type(e).__name__}", retryable=True)
    except ValueError:
        raise WhatsAppError("ردّ غير مفهوم من خادم واتساب", retryable=True)


def upload_media(cfg, content, filename, mime, timeout=60):
    """يرفع الملف إلى ميتا ويرجع معرّفه (صالح 30 يوماً ويمكن إرساله لعدة مستلمين)."""
    boundary = '----cyberreports' + hashlib.sha1(os.urandom(16)).hexdigest()
    safe_name = re.sub(r'[^A-Za-z0-9._-]', '_', filename) or 'report.xlsx'
    parts = [
        f'--{boundary}\r\nContent-Disposition: form-data; name="messaging_product"\r\n\r\nwhatsapp\r\n'.encode(),
        f'--{boundary}\r\nContent-Disposition: form-data; name="type"\r\n\r\n{mime}\r\n'.encode(),
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{safe_name}"\r\nContent-Type: {mime}\r\n\r\n'.encode(),
        content,
        f'\r\n--{boundary}--\r\n'.encode(),
    ]
    req = urlrequest.Request(
        f"{cfg['api_base']}/{cfg['api_version']}/{cfg['phone_id']}/media",
        data=b''.join(parts),
        headers={'Authorization': f"Bearer {cfg['token']}", 'Content-Type': f'multipart/form-data; boundary={boundary}'},
        method='POST',
    )
    body = _http_json(req, timeout, _DOC_HINTS)
    media_id = body.get('id') if isinstance(body, dict) else None
    if not media_id:
        raise WhatsAppError("لم يرجع خادم واتساب معرّف الملف بعد الرفع", retryable=True)
    return str(media_id)


def send_document(cfg, media_id, filename, caption, to, template_params=None, timeout=30):
    """يرسل ملفاً مرفوعاً إلى مستلم واحد ويرجع معرّف الرسالة.
    مع WHATSAPP_DOC_TEMPLATE: رسالة قالب برأس مستند (تعمل في أي وقت). بدونه: مستند حر يعمل ضمن نافذة 24 ساعة فقط."""
    target = re.sub(r'\D', '', to or cfg['to'])
    if cfg.get('doc_template'):
        payload = {
            "messaging_product": "whatsapp",
            "to": target,
            "type": "template",
            "template": {
                "name": cfg['doc_template'],
                "language": {"code": cfg['template_lang']},
                "components": [
                    {"type": "header", "parameters": [{"type": "document", "document": {"id": media_id, "filename": filename}}]},
                    {"type": "body", "parameters": [{"type": "text", "text": _param(v, '-', 100)} for v in (template_params or [])]},
                ],
            },
        }
    else:
        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": target,
            "type": "document",
            "document": {"id": media_id, "filename": filename, "caption": (caption or '')[:1000]},
        }
    req = urlrequest.Request(
        f"{cfg['api_base']}/{cfg['api_version']}/{cfg['phone_id']}/messages",
        data=json.dumps(payload, ensure_ascii=False).encode('utf-8'),
        headers={'Authorization': f"Bearer {cfg['token']}", 'Content-Type': 'application/json'},
        method='POST',
    )
    body = _http_json(req, timeout, _DOC_HINTS)
    messages = body.get('messages') if isinstance(body, dict) else None
    if not messages or not isinstance(messages[0], dict) or not messages[0].get('id'):
        raise WhatsAppError("لم يرجع خادم واتساب معرّف الرسالة", retryable=True)
    return str(messages[0]['id'])
