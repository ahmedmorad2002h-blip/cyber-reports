"""ملف Excel لبلاغات المنظومة: نفس معلومات رسالة الواتساب (المنصة، الرابط، اسم الحساب، التاريخ، نوع التهديد،
مستوى الخطورة، الوصف، والمؤشرات الفنية)، بلاغ في كل صف، لسحبه أو مشاركته على واتساب."""
import io
import re

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

XLSX_MIME = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'

# (عنوان العمود، عرضه، دالة القيمة) بنفس ترتيب ومسميات رسالة الواتساب
COLUMNS = [
    ('ت', 6, None),
    ('رقم البلاغ', 24, lambda r, t: r.get('report_id')),
    ('المنصة', 16, lambda r, t: r.get('platform')),
    ('الرابط', 46, lambda r, t: r.get('url')),
    ('اسم الحساب', 24, lambda r, t: r.get('account_name')),
    ('التاريخ', 20, lambda r, t: r.get('datetime') or r.get('timestamp')),
    ('نوع التهديد', 22, lambda r, t: r.get('threat_type')),
    ('مستوى الخطورة', 14, lambda r, t: r.get('severity')),
    ('الوصف', 60, lambda r, t: r.get('description')),
    ('IP', 18, lambda r, t: t.get('ip')),
    ('Domain', 24, lambda r, t: t.get('domain')),
    ('Email', 26, lambda r, t: t.get('email')),
    ('Hash', 34, lambda r, t: t.get('hash')),
    ('IOC', 24, lambda r, t: t.get('ioc')),
]

_DEFAULTS = {'الوصف': 'لا يوجد وصف', 'IP': 'غير متوفر', 'Domain': 'غير متوفر', 'Email': 'غير متوفر', 'Hash': 'غير متوفر', 'IOC': 'غير متوفر'}
_ILLEGAL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')


def _text(value, default):
    text = str(value).strip() if value not in (None, '') else ''
    text = _ILLEGAL.sub('', text)
    return text or default


def build_workbook(rows, title='بلاغات الرصد السيبراني'):
    """يرجع ملف xlsx (bytes). الصفوف مرتبة كما وصلت. النصوص تُكتب كنص دائماً فلا تُنفَّذ كصيغ في Excel."""
    wb = Workbook()
    ws = wb.active
    ws.title = 'البلاغات'
    ws.sheet_view.rightToLeft = True
    header_font = Font(bold=True, color='FFFFFF', name='Arial', size=11)
    header_fill = PatternFill('solid', fgColor='1F3A5F')
    thin = Side(style='thin', color='B0B7C3')
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    center = Alignment(horizontal='center', vertical='center', wrap_text=True)
    right = Alignment(horizontal='right', vertical='top', wrap_text=True)

    for col, (label, width, _) in enumerate(COLUMNS, start=1):
        cell = ws.cell(row=1, column=col, value=label)
        cell.font, cell.fill, cell.alignment, cell.border = header_font, header_fill, center, border
        ws.column_dimensions[get_column_letter(col)].width = width
    ws.row_dimensions[1].height = 26

    for n, row in enumerate(rows, start=1):
        tech = row.get('tech_indicators') if isinstance(row.get('tech_indicators'), dict) else {}
        for col, (label, _, getter) in enumerate(COLUMNS, start=1):
            if getter is None:
                value = n
            else:
                value = _text(getter(row, tech), _DEFAULTS.get(label, 'غير محدد'))
            cell = ws.cell(row=n + 1, column=col, value=value)
            if isinstance(value, str):
                cell.data_type = 's'            # حتى لو بدأ النص بـ = أو + لا يُعامل كصيغة
            cell.alignment = center if col == 1 else right
            cell.border = border
            cell.font = Font(name='Arial', size=10)

    ws.freeze_panes = 'A2'
    ws.auto_filter.ref = f"A1:{get_column_letter(len(COLUMNS))}{max(len(rows), 1) + 1}"
    ws.page_setup.orientation = 'landscape'
    ws.page_setup.fitToWidth = 1
    ws.page_setup.fitToHeight = 0
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.print_title_rows = '1:1'
    wb.properties.title = title
    wb.properties.creator = 'منظومة الرصد السيبراني'

    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()
