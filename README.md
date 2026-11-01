# cyber-reports

منصة الرصد والتحقيقات السيبرانية (Flask + Supabase)، تعمل على Render.

## متغيرات البيئة (Render > Environment)

لا تضع أي أسرار داخل الكود أبداً. هذه المتغيرات تُضبط في Render فقط:

| المتغير | مطلوب؟ | الوصف |
|---|---|---|
| `SUPABASE_URL` | نعم | رابط مشروع Supabase |
| `SUPABASE_KEY` | نعم | مفتاح Supabase (ويُفضّل تفعيل RLS على الجداول) |
| `SECRET_KEY` | نعم | نص عشوائي طويل لتوقيع الجلسات. بدونه يُولَّد مفتاح مؤقت ويخرج الجميع عند كل إعادة تشغيل |
| `ADMIN_PASSWORD` | اختياري | إن ضُبط يصبح هو كلمة سر حساب `admin` عند كل تشغيل (8 أحرف على الأقل). أنشئه لتدوير كلمة السر ثم احذفه لتديرها من الموقع |

لتوليد `SECRET_KEY`:

```
python -c "import secrets; print(secrets.token_hex(32))"
```

## التشغيل محلياً

```
pip install -r requirements.txt
export SUPABASE_URL=... SUPABASE_KEY=... SECRET_KEY=...
python app.py
```

## ملاحظات أمنية

- كلمات المرور 8 أحرف على الأقل.
- حماية CSRF مفعّلة على كل الطلبات من نوع POST.
- 5 محاولات دخول فاشلة تقفل المحاولة 5 دقائق.
- ملفات البلاغات الحقيقية (`cases/` وملفات `*.json`) ممنوعة بـ `.gitignore`.
