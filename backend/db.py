"""LAX OSINT — طبقة قاعدة البيانات (طبقة موحّدة)
- وضع local  : SQLite محلي (تجريبي بدون حسابات خارجية)
- وضع supabase: Supabase عبر مكتبة supabase-py + مصادقة GoTrue (bcrypt تلقائي)

يتم اختيار الواجهة تلقائيًا حسب إعدادات config:
  DB_MODE=supabase + وجود المفاتيح  →  SupabaseDatabase (من database.py)
  غير ذلك                             →  LocalDB (SQLite)
"""
import os
import sqlite3
import hashlib
import secrets
import datetime as dt

import config
from utils import make_code  # noqa: F401  (إعادة تصدير للتوافق)

DB_FILE = os.path.join(os.path.dirname(__file__), "lax_local.db")


# ----------------------------------------------------------
#  تشفير/تحقق كلمات المرور (local mode)
#  ملاحظة: في وضع supabase تُدار كلمة المرور بـ bcrypt عبر GoTrue
#  (للمستخدمين) وبـ bcrypt عبر table admins (للأدمن). هنا PBKDF2 للعرض المحلي.
# ----------------------------------------------------------
def hash_password(password: str, password_hash: str = None) -> str:
    if password_hash is None:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
        return f"pbkdf2${salt}${digest}"
    try:
        _alg, salt, expected = password_hash.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
        return "ok" if secrets.compare_digest(digest, expected) else "no"
    except Exception:
        return "no"


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password, password_hash) == "ok"


def _now():
    return dt.datetime.now(dt.timezone.utc)


def is_pro_active(pro_until):
    if not pro_until:
        return False
    try:
        exp = dt.datetime.fromisoformat(str(pro_until).replace("Z", "+00:00"))
        return exp > _now()
    except Exception:
        return False


def _today():
    return dt.date.today().isoformat()


# ----------------------------------------------------------
#  Local (SQLite)
# ----------------------------------------------------------
def _conn():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    _init_local(conn)
    return conn


def _init_local(conn):
    conn.executescript(
        """
        create table if not exists users (
          id text primary key,
          email text unique not null,
          password_hash text not null,
          searches_today integer not null default 0,
          last_search_date text,
          is_pro integer not null default 0,
          pro_until text,
          disabled integer not null default 0,
          created_at text not null
        );
        create table if not exists codes (
          id text primary key,
          code text unique not null,
          used integer not null default 0,
          used_by text,
          activated_at text,
          expires_at text,
          created_at text not null
        );
        create table if not exists admins (
          id text primary key,
          username text unique not null,
          password_hash text not null,
          created_at text not null
        );
        create table if not exists admin_logs (
          id integer primary key autoincrement,
          admin_id text,
          action text not null,
          detail text,
          ip text,
          created_at text not null
        );
        create table if not exists search_logs (
          id integer primary key autoincrement,
          user_id text,
          search_type text not null,
          query text not null,
          results_count integer not null default 0,
          created_at text not null
        );
        """
    )
    conn.commit()
    row = conn.execute("select id from admins where username = ?", (config.ADMIN_USERNAME,)).fetchone()
    if not row:
        conn.execute(
            "insert into admins (id, username, password_hash, created_at) values (?,?,?,?)",
            (secrets.token_hex(16), config.ADMIN_USERNAME, hash_password(config.ADMIN_PASSWORD), _now().isoformat()),
        )
        conn.commit()


def _user_from_row(row):
    if row is None:
        return None
    last = row["last_search_date"]
    today = _today()
    searches = row["searches_today"]
    if last and last != today:
        searches = 0
    return {
        "id": row["id"],
        "email": row["email"],
        "searches_today": searches,
        "last_search_date": today,
        "is_pro": bool(row["is_pro"]) and is_pro_active(row["pro_until"]),
        "pro_until": row["pro_until"],
        "disabled": bool(row["disabled"]),
        "created_at": row["created_at"],
    }


class LocalDB:
    mode = "local"

    # ---------- مستخدمون ----------
    def create_user(self, email, password):
        uid = secrets.token_hex(16)
        conn = _conn()
        try:
            conn.execute(
                "insert into users (id,email,password_hash,created_at) values (?,?,?,?)",
                (uid, email.lower(), hash_password(password), _now().isoformat()),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return None
        finally:
            conn.close()
        return self.get_user_by_id(uid)

    def get_user_by_email(self, email):
        conn = _conn()
        row = conn.execute("select * from users where email = ?", (email.lower(),)).fetchone()
        conn.close()
        return _user_from_row(row)

    def get_user_by_id(self, uid):
        conn = _conn()
        row = conn.execute("select * from users where id = ?", (uid,)).fetchone()
        conn.close()
        return _user_from_row(row)

    def get_password_hash(self, email):
        conn = _conn()
        row = conn.execute("select password_hash from users where email = ?", (email.lower(),)).fetchone()
        conn.close()
        return row["password_hash"] if row else None

    def increment_searches(self, uid):
        conn = _conn()
        conn.execute(
            "update users set searches_today = searches_today + 1, last_search_date = ? where id = ?",
            (_today(), uid),
        )
        conn.commit()
        conn.close()

    def set_pro(self, uid, pro_until_iso):
        conn = _conn()
        conn.execute("update users set is_pro = 1, pro_until = ? where id = ?", (pro_until_iso, uid))
        conn.commit()
        conn.close()

    def list_users(self):
        conn = _conn()
        rows = conn.execute("select * from users order by created_at desc").fetchall()
        conn.close()
        return [_user_from_row(r) for r in rows]

    def set_disabled(self, uid, disabled):
        conn = _conn()
        conn.execute("update users set disabled = ? where id = ?", (1 if disabled else 0, uid))
        conn.commit()
        conn.close()

    # ---------- أكواد التفعيل ----------
    def create_codes(self, count, duration_days):
        conn = _conn()
        codes = []
        created = _now()
        expires = created + dt.timedelta(days=duration_days)
        for _ in range(count):
            code = make_code()
            cid = secrets.token_hex(16)
            conn.execute(
                "insert into codes (id,code,expires_at,created_at) values (?,?,?,?)",
                (cid, code, expires.isoformat(), created.isoformat()),
            )
            codes.append({"id": cid, "code": code, "used": False, "used_by": None,
                          "activated_at": None, "expires_at": expires.isoformat(),
                          "created_at": created.isoformat()})
        conn.commit()
        conn.close()
        return codes

    def list_codes(self, admin_id=None):
        conn = _conn()
        rows = conn.execute("select * from codes order by created_at desc").fetchall()
        conn.close()
        out = []
        for r in rows:
            used = bool(r["used"])
            exp = r["expires_at"]
            status = "used" if used else ("expired" if exp and dt.datetime.fromisoformat(exp) <= _now() else "active")
            out.append({"id": r["id"], "code": r["code"], "used": used, "used_by": r["used_by"],
                        "activated_at": r["activated_at"], "expires_at": exp,
                        "created_at": r["created_at"], "status": status})
        return out

    def get_code(self, code):
        conn = _conn()
        row = conn.execute("select * from codes where code = ?", (code.upper(),)).fetchone()
        conn.close()
        return dict(row) if row else None

    def activate_pro(self, user_id, code):
        """يتحقق من الكود ويفعّل البرو لمدة 30 يومًا (واجهة موحّدة مع Supabase)."""
        import re
        code = (code or "").strip().upper()
        if not re.match(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{5}-[A-Z0-9]{3}$", code):
            return {"ok": False, "error": "bad_format"}
        found = self.get_code(code)
        if not found:
            return {"ok": False, "error": "not_found"}
        if found.get("used"):
            return {"ok": False, "error": "used"}
        exp = found.get("expires_at")
        if exp and dt.datetime.fromisoformat(exp) <= _now():
            return {"ok": False, "error": "expired"}
        used = self.use_code(found["id"], user_id)
        if not used:
            return {"ok": False, "error": "used"}
        try:
            base = dt.datetime.fromisoformat(used["expires_at"])
            if base <= _now():
                raise ValueError()
        except Exception:
            base = _now() + dt.timedelta(days=config.PRO_DURATION_DAYS)
        self.set_pro(user_id, base.isoformat())
        return {"ok": True, "pro_until": base.isoformat()}

    def use_code(self, code_id, user_id):
        conn = _conn()
        row = conn.execute("select * from codes where id = ? and used = 0", (code_id,)).fetchone()
        if not row:
            conn.close()
            return None
        used_at = _now()
        conn.execute(
            "update codes set used = 1, used_by = ?, activated_at = ? where id = ?",
            (user_id, used_at.isoformat(), code_id),
        )
        conn.commit()
        conn.close()
        return {"activated_at": used_at, "expires_at": row["expires_at"]}

    def delete_code(self, code_id):
        conn = _conn()
        conn.execute("delete from codes where id = ?", (code_id,))
        conn.commit()
        conn.close()

    # ---------- أدمن ----------
    def get_admin(self, username):
        conn = _conn()
        row = conn.execute("select * from admins where username = ?", (username,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def verify_admin(self, username, password):
        admin = self.get_admin(username)
        if not admin:
            return False
        return verify_password(password, admin["password_hash"])

    def log_admin(self, admin_id, action, detail, ip):
        import json
        conn = _conn()
        conn.execute(
            "insert into admin_logs (admin_id,action,detail,ip,created_at) values (?,?,?,?,?)",
            (admin_id, action, json.dumps(detail, ensure_ascii=False) if detail else None,
             ip, _now().isoformat()),
        )
        conn.commit()
        conn.close()

    def list_admin_logs(self, limit=100):
        conn = _conn()
        rows = conn.execute(
            "select admin_id,action,detail,ip,created_at from admin_logs order by id desc limit ?",
            (limit,),
        ).fetchall()
        conn.close()
        return [{"admin_id": r["admin_id"], "action": r["action"], "detail": r["detail"],
                 "ip": r["ip"], "created_at": r["created_at"]} for r in rows]

    # ---------- سجل البحث ----------
    def log_search(self, user_id, search_type, query, results_count):
        conn = _conn()
        conn.execute(
            "insert into search_logs (user_id,search_type,query,results_count,created_at) values (?,?,?,?,?)",
            (user_id, search_type, query, results_count, _now().isoformat()),
        )
        conn.commit()
        conn.close()

    def stats(self):
        conn = _conn()
        searches = conn.execute("select count(*) c, coalesce(sum(results_count),0) s from search_logs").fetchone()
        users = conn.execute("select count(*) c from users").fetchone()
        codes = conn.execute("select count(*) c from codes").fetchone()
        active_codes = conn.execute("select count(*) c from codes where used = 0").fetchone()
        conn.close()
        return {"total_searches": searches["s"], "searches_count": searches["c"],
                "users": users["c"], "codes": codes["c"], "active_codes": active_codes["c"]}


# ----------------------------------------------------------
#  اختيار الواجهة العاملة
# ----------------------------------------------------------
if config.DB_MODE == "supabase" and config.SUPABASE_READY:
    from database import SupabaseDatabase
    db = SupabaseDatabase(config.SUPABASE_URL, config.SUPABASE_ANON_KEY, config.SUPABASE_SERVICE_KEY)
else:
    db = LocalDB()

DB_MODE_ACTIVE = db.mode