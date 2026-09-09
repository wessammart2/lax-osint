# LAX OSINT

محرك بحث استخباراتي (OSINT) يبحث في البصمة الرقمية عبر 4 أنواع بحث.
ثنائي اللغة (عربي RTL / إنجليزي LTR)، تصميم أحمر داكن، نتائج تدريجية، ونظام اشتراك (مجاني / برو 30 يومًا).

## البنية

```
lax-osint/
├── frontend/                 → واجهة المستخدم (تُرفع على Vercel)
│   ├── index.html            ← الصفحة الرئيسية
│   ├── admin.html            ← لوحة الأدمن
│   ├── config.js             ← إعدادات البيئة (API_URL / SUPABASE_URL / ANON_KEY)
│   ├── css/style.css
│   ├── js/{app,auth,search,i18n}.js
│   └── assets/
└── backend/                  → الباك إند (يُرفع على Railway)
    ├── main.py               ← FastAPI — يخدم الواجهة ثابتة على /
    ├── config.py             ← متغيرات البيئة
    ├── db.py                 ← طبقة الوصول (LocalDB SQLite / SupabaseDatabase)
    ├── database.py           ← طبقة Supabase (supabase-py)
    ├── utils.py              ← JWT / SSE / rate limit / make_code
    ├── routers/              ← auth / admin / pro / search (username, email, phone, name)
    ├── schema.sql            ← مخطط Supabase (RLS + trigger + pgcrypto)
    ├── requirements.txt
    ├── Dockerfile
    └── railway.json
```

## التشغيل محليًا

### ١. الباك إند

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate             # Windows PowerShell
# source .venv/bin/activate        # macOS/Linux
pip install -r requirements.txt
# pip install maigret holehe       # اختياري: أدوات البحث الفعلية
uvicorn main:app --port 8000
```

> **وضع SQLite (الافتراضي):** يعمل بدون أي حسابات خارجية.
> **وضع Supabase:** اضبط `DB_MODE=supabase` + `SUPABASE_URL` + `SUPABASE_ANON_KEY` + `SUPABASE_SERVICE_KEY` في `.env`، وشغّل `schema.sql` في Supabase SQL Editor.

### ٢. الواجهة محليًا

الباك إند يخدم الواجهة تلقائيًا:
- **الصفحة الرئيسية:** `http://127.0.0.1:8000/`
- **لوحة الأدمن:** `http://127.0.0.1:8000/admin.html`

### ٣. بيانات الدخول الافتراضية

| | اسم المستخدم | كلمة المرور |
|---|---|---|
| **أدمن اللوحة** | `kalilax` | `kalilax122313` |

> غيّر كلمة المرور في `.env` (المتغيرين `ADMIN_USERNAME` / `ADMIN_PASSWORD`) قبل النشر.

---

## النشر إلى الإنتاج

### الخطوة ١: إعداد Supabase (قاعدة البيانات)

1. أنشئ حسابًا مجانيًا على [supabase.com](https://supabase.com) وأنشئ مشروعًا جديدًا.
2. من **Project Settings → API**، انسخ:
   - `Project URL`
   - `anon` (public) key
   - `service_role` key
3. افتح **SQL Editor → New query**، الصق محتوى `backend/schema.sql` بالكامل واضغط **Run**.
4. تحقق من إنشاء الجداول: **Table Editor** يجب أن يظهر `users`، `codes`، `search_logs`، `admins`.

### الخطوة ٢: نشر الباك إند على Railway

1. ارفع الكود إلى GitHub.
2. سجّل الدخول إلى [railway.app](https://railway.app) و **New Project → Deploy from GitHub Repo**.
3. اختر المستودع، ثم حدد **Root Directory** كـ `backend/`.
4. Railway سيكتشف `Dockerfile` تلقائيًا ويبني الصورة.
5. أضف متغيرات البيئة من **Settings → Variables**:

| المتغير | القيمة |
|---|---|
| `DB_MODE` | `supabase` |
| `SUPABASE_URL` | `https://xxxx.supabase.co` |
| `SUPABASE_ANON_KEY` | `eyJhbG...` |
| `SUPABASE_SERVICE_KEY` | `eyJhbG...` |
| `TOKEN_SECRET` | `(مفتاح عشوائي طويل 64+ حرف)` |
| `ADMIN_USERNAME` | `kalilax` |
| `ADMIN_PASSWORD` | `( كلمة مرور قوية جديدة — غير الافتراضية! )` |
| `RATE_LIMIT_PER_IP` | `20` |
| `PORT` | `8000` *(Railway يمرره تلقائيًا — لا تُضفه إلا إذا لزم)* |

6. اضغط **Deploy**. ستحصل على رابط مثل `https://laxosint-production.up.railway.app`.
7. تحقق: `https://your-url.up.railway.app/api/health` يجب أن يُرجع `{"status": "ok"}`.

### الخطوة ٣: نشر الواجهة على Vercel

1. سجّل الدخول إلى [vercel.com](https://vercel.com) و **New Project → Import Git Repository**.
2. اختر المستودع، ثم اضبط:
   - **Root Directory:** `frontend/`
   - **Framework Preset:** `Other`
   - **Build Command:** *(اتركه فارغًا)*
   - **Output Directory:** `.` *(نقطة فقط)*
3. أضف متغيرات البيئة (اختياري لـ `config.js`، لكنه يتغير يدويًا):

| المتغير | القيمة |
|---|---|
| `NEXT_PUBLIC_API_URL` | *(لا تحتاج — config.js ثابت)* |

4. اضغط **Deploy**. ستحصل على رابط مثل `https://laxosint.vercel.app`.
5. **مهم:** حدّث `frontend/config.js` قبل الرفع:

```javascript
window.LAX_CONFIG = {
  API_URL: "https://laxosint-production.up.railway.app",   // ← رابط Railway
  SUPABASE_URL: "https://xxxx.supabase.co",
  SUPABASE_ANON_KEY: "eyJhbG...",
};
```

### الخطوة ٤: ربط دومين مخصص

**طريقة 1 — Doman مسجل مسبقًا (Namecheap / GoDaddy / Cloudflare):**

1. من Vercel: **Settings → Domains → Add** → اكتب الدومين (مثلاً `laxosint.com`).
2. Vercel يُعطيك سجل DNS:通常是 CNAME أو A record. انسخ القيمة.
3. اذهب إلى مزود الدومين (Namecheap / GoDaddy / Cloudflare DNS) وأضف السجل:
   - **Type:** `CNAME`
   - **Host:** `@` أو `www`
   - **Value:** `cname.vercel-dns.com`
   - **TTL:** Auto
4. انتظر من دقيقة إلى 48 ساعة حتى ينتشر الـ DNS.

**طريقة 2 — شراء دومين من Vercel ( أسهل ):**
1. **Settings → Domains → Buy Domain** → ابحث عن الدومين المتاح.
2. Vercel يُنشئ السجلات تلقائيًا — لا حاجة لأي تعديل يدوي.

**خطوة إضافية (SSL مجاني):** Vercel يُصدر شهادة SSL تلقائيًا بعد انتشار DNS — لا حاجة لأي إعداد.

### الخطوة ٥: التحقق الكامل بعد النشر

```bash
# ١) صحة الباك إند
curl https://your-backend.up.railway.app/api/health
# → {"status":"ok","db":"supabase",...}

# ٢) تسجيل مستخدم
curl -X POST https://your-backend.up.railway.app/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"Test1234!"}'

# ٣) تسجيل دخول الأدمن
curl -X POST https://your-backend.up.railway.app/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username":"kalilax","password":"PASSWORD_YOU_SET"}'

# ٤) إنشاء كود تفعيل
curl -X POST "https://your-backend.up.railway.app/api/admin/codes?token=ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"count":1,"days":30}'

# ٥) تفعيل البرو
curl -X POST https://your-backend.up.railway.app/api/pro/activate \
  -H "Content-Type: application/json" \
  -d '{"token":"USER_TOKEN","code":"XXXX-XXXX-XXXXX-XXX"}'

# ٦) التحقق من البرو
curl "https://your-backend.up.railway.app/api/auth/me?token=USER_TOKEN"
```

### الخطوة ٦: قائمة التحقق النهائية

- [ ] `schema.sql` شُغّل في Supabase (الجداول الأربعة موجودة)
- [ ] Railway: `api/health` يُرجع `{"status":"ok"}`
- [ ] Vercel: `config.js` يحتوي رابط Railway الصحيح
- [ ] تسجيل مستخدم جديد يعمل
- [ ] تسجيل دخول المستخدم يعمل
- [ ] تسجيل دخول الأدمن يعمل (بكلمة المرور الجديدة)
- [ ] إنشاء أكواد تفعيل يعمل
- [ ] تفعيل البرو يعمل (الكود يُستخدم مرة واحدة فقط)
- [ ] إعادة استخدام الكود تُرفض بـ 409
- [ ] البحث مقطوع بعد 4 بحوث للمستخدم المجاني
- [ ] المستخدم البرو يمكنه البحث بلا حدود
- [ ] الدومين المخصص يعمل مع SSL

---

## أدوات البحث

| الأداة | الاستخدام | الحالة |
|---|---|---|
| **Maigret** | يوزر نيم في 3000+ موقع | تتطلب `pip install maigret` |
| **holehe** | إيميل في 120+ موقع | تتطلب `pip install holehe` |
| **Gravatar** | صورة البروفايل بالإيميل | تعمل بدون تثبيت (HTTP) |
| **PhoneInfoga** | رقم الهاتف | تتطلب ملف binary `phoneinfoga` |
| **DDGS + Playwright** | الاسم الكامل (Deep Search) | اختيارية — تتجاوز إن غابت |

> أي أداة غير مثبتة تُرجع نتيجة «الأداة غير متوفرة محليًا» مع تعليمات التثبيت.

## نقاط الاتصال (API Endpoints)

| Method | المسار | الوصف |
|---|---|---|
| GET | `/api/health` | فحص صحة الخادم |
| POST | `/api/auth/register` | تسجيل حساب جديد |
| POST | `/api/auth/login` | تسجيل دخول |
| GET | `/api/auth/me` | بيانات المستخدم الحالي |
| GET | `/api/search/username?q=&token=` | بحث يوزر نيم |
| GET | `/api/search/email?q=&token=` | بحث إيميل |
| GET | `/api/search/phone?q=&token=` | بحث هاتف |
| GET | `/api/search/name?q=&token=` | بحث اسم |
| POST | `/api/pro/activate` | تفعيل كود برو |
| POST | `/api/admin/login` | تسجيل دخول الأدمن |
| GET | `/api/admin/stats` | إحصائيات لوحة الأدمن |
| POST | `/api/admin/codes` | إنشاء أكواد تفعيل |
| GET | `/api/admin/codes` | قائمة الأكواد |
| GET | `/api/admin/users` | قائمة المستخدمين |
| POST | `/api/admin/users/{id}/disable` | تعطيل حساب مستخدم |
| GET | `/api/admin/logs` | سجل نشاط الأدمن |

## الخصوصية

- لا نخزن نتائج البحث⚰️ — نُسجّل فقط: نوع البحث + عدد النتائج + معرّف المستخدم.
- كلمات مرور المستخدمين تُشفَّر بـ bcrypt تلقائيًا من Supabase GoTrue.
- كلمة مرور الأدمن تُخزَّن كـ bcrypt في جدول `admins` (JSON Web Tokens للمصادقة).
- لا ملفات تعريف ارتباط — الجلسات عبر `Authorization` header فقط.

## الاختبارات

```bash
# اختبار الاستيراد
cd backend && .\.venv\Scripts\python.exe -c "import main; print('OK')"

# اختبار تكامل شامل (21 اختبار — يشتغل محليًا فقط)
cd backend && .\.venv\Scripts\python.exe test_integration.py

# تشغيل يدوي واختبار صحة
uvicorn main:app --port 8000
curl http://127.0.0.1:8000/api/health
```