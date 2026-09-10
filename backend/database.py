"""LAX OSINT — طبقة الاتصال بـ Supabase (الوضع الإنتاجي)
يستخدم مكتبة supabase-py + مصادقة GoTrue:
- الحسابات الجديدة: كلمة المرور تُشفر تلقائيًا بـ bcrypt من GoTrue.
- أدمن اللوحة: كلمة المرور تُخزَّن كـ bcrypt في جدول admins وتُتحقق بـ bcrypt.
- البحث: 4 بحوث مجانية يوميًا، وبرو 30 يومًا عبر code التفعيل.

الدوال العامية حسب المتطلبات:
  connect(), check_daily_limit(), increment_searches(),
  activate_pro(), log_search(), verify_admin()
"""
import datetime as dt

import bcrypt

import config
from utils import make_code

PRO_COLUMNS_USERS = ("id", "email", "searches_today", "last_search_date",
                     "is_pro", "pro_until", "disabled", "created_at")


def _now():
    return dt.datetime.now(dt.timezone.utc)


class SupabaseDatabase:
    mode = "supabase"

    def __init__(self, url, anon_key, service_key):
        self.url = url.rstrip("/")
        self.anon_key = anon_key or ""
        self.service_key = service_key or ""
        self._client = None      # عميل anon (للمصادقة/sign_up/sign_in)
        self._admin = None       # عميل service_role (للعمليات الإدارية)
        self.connect()

    # ----------------------------------------------------------
    #  ١) الاتصال بقاعدة البيانات
    # ----------------------------------------------------------
    def connect(self):
        """إنشاء عميلَي Supabase (anon و service_role) وتخزينهما."""
        if self._client is None:
            from supabase import create_client
            self._client = create_client(self.url, self.anon_key)
            self._admin = create_client(self.url, self.service_key)
        return self._admin

    def client(self):
        return self._client

    # ----------------------------------------------------------
    #  أدوات مساعدة
    # ----------------------------------------------------------
    def _fmt_user(self, row):
        if not row:
            return None
        today = dt.date.today().isoformat()
        searches = row.get("searches_today") or 0
        if row.get("last_search_date") != today:
            searches = 0
        return {
            "id": row.get("id"),
            "email": row.get("email"),
            "searches_today": searches,
            "last_search_date": today,
            "is_pro": bool(row.get("is_pro")) and is_pro_active(row.get("pro_until")),
            "pro_until": row.get("pro_until"),
            "disabled": bool(row.get("disabled")),
            "created_at": row.get("created_at"),
        }

    def _select(self, table, filters=None, order=None, limit=None):
        q = self._admin.table(table).select("*")
        for col, val in (filters or {}).items():
            q = q.eq(col, val)
        if order:
            q = q.order(order, desc=True)
        if limit:
            q = q.limit(limit)
        res = q.execute()
        return list(res.data or [])

    def _insert(self, table, payload):
        res = self._admin.table(table).insert(payload).execute()
        return list(res.data or [])

    def _update(self, table, payload, filters):
        q = self._admin.table(table).update(payload)
        for col, val in (filters or {}).items():
            q = q.eq(col, val)
        res = q.execute()
        return list(res.data or [])

    # ----------------------------------------------------------
    #  المستخدمون
    # ----------------------------------------------------------
    def create_user(self, email, password):
        """إنشاء حساب: تُشفَّر كلمة المرور بـ bcrypt تلقائيًا من GoTrue."""
        email = email.strip().lower()
        try:
            res = self._admin.auth.admin.create_user(
                {"email": email, "password": password, "email_confirm": True}
            )
        except Exception:
            return None  # (إيميل مكرر أو فشل)
        uid = res.user.id
        # trigger handle_new_user يُضيف الصف تلقائيًا؛ upsert يضمن عدم تكراره
        try:
            self._admin.table("users").upsert({"id": uid, "email": email},
                                              on_conflict="id").execute()
        except Exception:
            pass
        return self.get_user_by_id(uid)

    def login(self, email, password):
        """تسجيل الدخول عبر GoTrue (يتحقق من كلمة المرور المشفرة بـ bcrypt)."""
        try:
            res = self._client.auth.sign_in_with_password({"email": email, "password": password})
        except Exception:
            return None
        return {"id": res.user.id, "email": res.user.email,
                "access_token": res.session.access_token if res.session else ""}

    def get_user_by_id(self, uid):
        rows = self._select("users", {"id": str(uid)})
        return self._fmt_user(rows[0]) if rows else None

    def get_user_by_email(self, email):
        rows = self._select("users", {"email": email.strip().lower()})
        return self._fmt_user(rows[0]) if rows else None

    def get_password_hash(self, email):
        # كلمة المرور محفوظة مشفرة في GoTrue وليست ضمن جدول users العام
        return None

    def list_users(self):
        rows = self._select("users", order="created_at")
        return [self._fmt_user(r) for r in rows]

    def set_disabled(self, uid, disabled):
        self._update("users", {"disabled": bool(disabled)}, {"id": str(uid)})

    # ----------------------------------------------------------
    #  ٢) فحص الحد اليومي  ٣) زيادة عداد البحوث
    # ----------------------------------------------------------
    def check_daily_limit(self, user):
        """تحديد ما إذا بقي للمستخدم بحث اليوم (4 مجانيًا / ∞ للأبرو)."""
        if not user:
            return {"ok": False, "searches_today": 0, "limit": config.SEARCH_LIMIT_DAILY,
                    "is_pro": False}
        used = user.get("searches_today", 0)
        if user.get("is_pro"):
            return {"ok": True, "searches_today": used,
                    "limit": config.SEARCH_LIMIT_DAILY, "is_pro": True}
        return {"ok": used < config.SEARCH_LIMIT_DAILY, "searches_today": used,
                "limit": config.SEARCH_LIMIT_DAILY, "is_pro": False}

    def increment_searches(self, uid):
        """زيادة عداد البحوث اليومية (يستدعي دالة SQL increment_searches أولًا)."""
        try:
            # دالة SQL security definer: تعيد تصفير العداد عند تغيّر اليوم
            self._admin.rpc("increment_searches", {"p_uid": str(uid)}).execute()
            return True
        except Exception:
            pass
        # بديل محلي (لو فشل RPC): قراءة ثم تحديث
        rows = self._select("users", {"id": str(uid)})
        if not rows:
            return False
        today = dt.date.today().isoformat()
        row = rows[0]
        count = (row.get("searches_today") or 0) + 1
        if row.get("last_search_date") != today:
            count = 1
        self._update("users", {"searches_today": count, "last_search_date": today},
                     {"id": str(uid)})
        return True

    def set_pro(self, uid, pro_until_iso):
        self._update("users", {"is_pro": True, "pro_until": pro_until_iso}, {"id": str(uid)})

    # ----------------------------------------------------------
    #  ٤) التحقق من كود التفعيل وتفعيل البرو (30 يومًا)
    # ----------------------------------------------------------
    def activate_pro(self, user_id, code):
        """يتحقق من الكود (موجود + غير مستخدم + غير منتهي) ويفعّل البرو."""
        import re
        code = (code or "").strip().upper()
        if not re.match(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{5}-[A-Z0-9]{3}$", code):
            return {"ok": False, "error": "bad_format"}
        rows = self._select("activation_codes", {"code": code})
        if not rows:
            return {"ok": False, "error": "not_found"}
        rec = rows[0]
        if rec.get("used"):
            return {"ok": False, "error": "used"}
        expires = rec.get("expires_at")
        if expires and _parse_dt(expires) <= _now():
            return {"ok": False, "error": "expired"}
        self._update("activation_codes", {"used": True, "used_by": str(user_id),
                               "activated_at": _now().isoformat()}, {"id": rec["id"]})
        base = _parse_dt(expires) if expires else None
        pro_until = base if base and base > _now() else _now() + dt.timedelta(
            days=config.PRO_DURATION_DAYS)
        self.set_pro(user_id, pro_until.isoformat())
        return {"ok": True, "pro_until": pro_until.isoformat()}

    # ----------------------------------------------------------
    #  أكواد التفعيل (إدارة)
    # ----------------------------------------------------------
    def create_codes(self, count, duration_days):
        now = _now()
        expires = (now + dt.timedelta(days=duration_days)).isoformat()
        payload = [{"code": make_code(), "expires_at": expires,
                    "created_at": now.isoformat()} for _ in range(count)]
        try:
            ins = self._insert("activation_codes", payload)
        except Exception:
            return []
        out = []
        for r in ins:
            out.append(self._decorate_code(r))
        return out

    def list_codes(self, admin_id=None):
        rows = self._select("activation_codes", order="created_at")
        return [self._decorate_code(r) for r in rows]

    def _decorate_code(self, r):
        used = bool(r.get("used"))
        exp = r.get("expires_at")
        status = "used" if used else ("expired" if exp and _parse_dt(exp) <= _now() else "active")
        return {"id": r.get("id"), "code": r.get("code"), "used": used, "used_by": r.get("used_by"),
                "activated_at": r.get("activated_at"), "expires_at": exp,
                "created_at": r.get("created_at"), "status": status}

    def get_code(self, code):
        rows = self._select("activation_codes", {"code": code.upper()})
        return self._decorate_code(rows[0]) if rows else None

    def use_code(self, code_id, user_id):
        """استخدام الكود (واجهة قديمة) — الأفضل activate_pro()."""
        rows = self._select("activation_codes", {"id": str(code_id)})
        if not rows or rows[0].get("used"):
            return None
        self._update("activation_codes", {"used": True, "used_by": str(user_id),
                               "activated_at": _now().isoformat()}, {"id": str(code_id)})
        return {"activated_at": _now().isoformat(), "expires_at": rows[0].get("expires_at")}

    def delete_code(self, code_id):
        self._admin.table("activation_codes").delete().eq("id", str(code_id)).execute()

    # ----------------------------------------------------------
    #  ٥) تسجيل البحث
    # ----------------------------------------------------------
    def log_search(self, user_id, search_type, query, results_count):
        try:
            self._insert("search_logs", {"user_id": str(user_id), "search_type": search_type,
                                         "query": (query or "")[:500],
                                         "results_count": int(results_count or 0)})
        except Exception:
            pass

    # ----------------------------------------------------------
    #  كاش البحث (جدول search_cache — صلاحية 24 ساعة افتراضيًا)
    #  يقلّل الطلبات المتكررة لنفس الاسم، فيتجنّب الحجب.
    # ----------------------------------------------------------
    def search_cache_get(self, key):
        """يرجع الـ payload المحفوظ إن وُجد ولم تتجاوز صلاحيته CACHE_TTL_HOURS."""
        import json
        try:
            rows = self._select("search_cache", {"name": str(key)})
            if not rows:
                return None
            row = rows[0]
            created = _parse_dt(row.get("created_at"))
            if not created or (_now() - created).total_seconds() > config.CACHE_TTL_HOURS * 3600:
                return None
            return json.loads(row.get("result_json") or "null")
        except Exception:
            return None

    def search_cache_set(self, key, payload):
        """يحفظ/يحدّث النتيجة في الجدول (upsert على name)."""
        try:
            import json
            self._admin.table("search_cache").upsert(
                {"name": str(key),
                 "result_json": json.dumps(payload, ensure_ascii=False),
                 "created_at": _now().isoformat()},
                on_conflict="name").execute()
            return True
        except Exception:
            return False

    # ----------------------------------------------------------
    #  الأدمن
    # ----------------------------------------------------------
    def get_admin(self, username):
        rows = self._select("admins", {"username": username.strip()})
        return dict(rows[0]) if rows else None

    def _seed_admin(self):
        """إنشاء أدمن افتراضي بـ bcrypt إن لم يُنشأ بعد. (للتشغيل الأول فقط)."""
        existing = self._select("admins")
        if existing:
            return False
        hashed = bcrypt.hashpw(config.ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode()
        self._insert("admins", {"username": config.ADMIN_USERNAME, "password_hash": hashed})
        return True

    #  ٦) التحقق من بيانات الأدمن (bcrypt)
    def verify_admin(self, username, password):
        admin = self.get_admin(username)
        if not admin:
            if self._seed_admin():
                admin = self.get_admin(username)
        if not admin:
            return False
        try:
            return bcrypt.checkpw(password.encode(), admin.get("password_hash", "").encode())
        except Exception:
            return False

    def log_admin(self, admin_id, action, detail, ip):
        try:
            import json
            self._insert("admin_logs", {"admin_id": str(admin_id), "action": action,
                                        "detail": json.dumps(detail, ensure_ascii=False) if detail else None,
                                        "ip": ip})
        except Exception:
            pass

    def list_admin_logs(self, limit=100):
        rows = self._select("admin_logs", order="created_at", limit=limit)
        return list(rows)

    # ----------------------------------------------------------
    #  الإحصائيات
    # ----------------------------------------------------------
    def stats(self):
        def cnt(table):
            try:
                res = self._admin.table(table).select("id", count="exact").limit(1).execute()
                return res.count or 0
            except Exception:
                return 0
        return {"total_searches": cnt("search_logs"), "searches_count": cnt("search_logs"),
                "users": cnt("users"), "codes": cnt("activation_codes"),
                "active_codes": cnt("activation_codes")}


def _parse_dt(value):
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def is_pro_active(pro_until):
    exp = _parse_dt(pro_until) if pro_until else None
    if not exp:
        return False
    return exp > _now()