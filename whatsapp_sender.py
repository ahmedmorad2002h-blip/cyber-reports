"""إرسال البلاغات على واتساب عبر WhatsApp Business Cloud API (من Meta) + قواعد وقت الإرسال.

كل الإعدادات من متغيرات البيئة (Render > Environment) ولا يُكتب أي رقم أو مفتاح في الكود:

  WHATSAPP_TOKEN             رمز الوصول الدائم (System User Token) من Meta
  WHATSAPP_PHONE_NUMBER_ID   معرّف رقم المُرسِل في Meta (ليس الرقم نفسه)
  WHATSAPP_TO                رقم المستلم بصيغة دولية (مثال: 9647XXXXXXXXX)
  WHATSAPP_TEMPLATE_NAME     اسم القالب المعتمد (مطلوب عملياً، انظر README)
  WHATSAPP_TEMPLATE_LANG     لغة القالب (الافتراضي ar)
  WHATSAPP_HOURS             ساعات الإرسال بتوقيت بغداد، الافتراضي 7-16
  WHATSAPP_API_VERSION       الافتراضي v23.0
  WHATSAPP_API_BASE          الافتراضي https://graph.facebook.com
  WHATSAPP_ENABLED           ضع 0 لإيقاف الإرسال مؤقتاً
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib import error as urlerror
from urllib import request as urlrequest

# بغداد UTC+3 ثابت (العراق بلا توقيت صيفي)
IRAQ_TZ = timezone(timedelta(hours=3))

DEFAULT_HOURS = (7, 16)


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


def load_config():
    """تُقرأ في كل مرة (وليس عند الاستيراد) حتى تُطبَّق تغييرات Render بدون تعديل الكود."""
    token = _env('WHATSAPP_TOKEN')
    phone_id = re.sub(r'\D', '', _env('WHATSAPP_PHONE_NUMBER_ID'))
    to = re.sub(r'\D', '', _env('WHATSAPP_TO'))
    start, end = parse_hours(_env('WHATSAPP_HOURS', '7-16'))
    switched_off = _env('WHATSAPP_ENABLED', '1').lower() in ('0', 'false', 'no', 'off')
    return {
        'enabled': bool(token and phone_id and 8 <= len(to) <= 15) and not switched_off,
        'token': token,
        'phone_id': phone_id,
        'to': to,
        'api_base': _env('WHATSAPP_API_BASE', 'https://graph.facebook.com').rstrip('/'),
        'api_version': _env('WHATSAPP_API_VERSION', 'v23.0'),
        'template': _env('WHATSAPP_TEMPLATE_NAME'),
        'template_lang': _env('WHATSAPP_TEMPLATE_LANG', 'ar'),
        'start_hour': start,
        'end_hour': end,
    }


def in_send_window(cfg, now=None):
    """من بداية ساعة البدء (07:00:00) حتى قبل ساعة الانتهاء (16:00:00) بتوقيت بغداد."""
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
    tech = row.get('tech_indicators') if isinstance(row.get('tech_indicators'), dict) else {}

    def val(x):
        return str(x).strip() if x not in (None, '') else ''

    def line(icon, label, value):
        value = val(value)
        return f"{icon} *{label}:* {value}" if value else None

    head = [x for x in (
        "📋 *تقرير رصد سيبراني - مديرية أمن وسلامة الوزارة*",
        line("🆔", "رقم البلاغ", row.get('report_id')),
        line("👤", "القائم بالرصد", row.get('officer')),
        line("🌐", "المنصة", row.get('platform')),
        line("🔗", "الرابط", row.get('url')),
        line("🏷️", "اسم الحساب", row.get('account_name')),
        line("📅", "تاريخ الرصد", row.get('datetime') or row.get('timestamp')),
        line("⚠️", "نوع التهديد", row.get('threat_type')),
        line("🔴", "مستوى الخطورة", row.get('severity')),
    ) if x]

    indicators = [x for x in (
        line("•", "IP", tech.get('ip')),
        line("•", "Domain", tech.get('domain')),
        line("•", "URL فرعي", tech.get('url')),
        line("•", "Email", tech.get('email')),
        line("•", "Username", tech.get('username')),
        line("•", "Hash", tech.get('hash')),
        line("•", "IOC", tech.get('ioc')),
        line("•", "أخرى", tech.get('other')),
    ) if x]
    tail = []
    if indicators:
        tail.append("⚙️ *المؤشرات الفنية:*")
        tail.extend(indicators)
    recommendation = val(row.get('recommendation'))
    if recommendation:
        tail.append(f"✅ *التوصية:* {recommendation[:400]}")
    decided_at = val(tech.get('decided_at'))
    if decided_at:
        tail.append(f"🗓️ *تمت الموافقة:* {decided_at}")

    description = val(row.get('description'))

    def assemble(desc):
        parts = list(head)
        if desc:
            parts.append(f"📝 *الوصف:* {desc}")
        parts.extend(tail)
        return "\n".join(parts)

    text = assemble(description)
    if max_len and len(text) > max_len:
        overflow = len(text) - max_len
        if description and len(description) > overflow + 20:
            description = description[: len(description) - overflow - 1].rstrip() + '…'
            text = assemble(description)
        if len(text) > max_len:
            text = text[: max_len - 1].rstrip() + '…'
    return text


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


def _error_detail(http_error):
    try:
        body = json.loads(http_error.read().decode('utf-8', 'replace') or '{}')
    except Exception:
        return ''
    err = body.get('error') if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return ''
    code = err.get('code')
    sub = err.get('error_subcode')
    hint = _HINTS.get(sub) or _HINTS.get(code)
    text = ''
    data = err.get('error_data')
    if isinstance(data, dict) and data.get('details'):
        text = str(data['details'])
    elif err.get('message'):
        text = str(err['message'])
    text = text[:250]
    return f"{text} {('— ' + hint) if hint else ''}".strip()


def send_message(cfg, text, timeout=20):
    """يرسل الرسالة ويرجع معرّف الرسالة. يرفع WhatsAppError عند الفشل (مع retryable)."""
    if cfg.get('template'):
        payload = {
            "messaging_product": "whatsapp",
            "to": cfg['to'],
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
            "to": cfg['to'],
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
