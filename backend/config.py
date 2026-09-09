"""LAX OSINT — الإعدادات العامة
يقرأ متغيرات البيئة من ملف .env (عبر python-dotenv إن وجد) مع قيم افتراضية آمنة.
"""
import os
import hashlib

# تحميل .env بدون الحاجة لتعطيل الحزمة إذا غابت
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
except Exception:
    pass


def _bool(v, default=False):
    if isinstance(v, bool):
        return v
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


DB_MODE = os.getenv("DB_MODE", "local").strip().lower()          # local | supabase
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "").strip()
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "").strip()
SUPABASE_READY = bool(SUPABASE_URL.startswith("http") and SUPABASE_SERVICE_KEY)

SEARCH_LIMIT_DAILY = int(os.getenv("SEARCH_LIMIT_DAILY", "4"))
PRO_DURATION_DAYS = int(os.getenv("PRO_DURATION_DAYS", "30"))

# مفاتيح محلية لتوقيع JWTs (local mode). في الإنتاج استبدلها بقيمة طويلة عشوائية.
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "change-me-please")
if len(TOKEN_SECRET) < 16:
    TOKEN_SECRET = hashlib.sha256(("lax-osint-" + TOKEN_SECRET).encode()).hexdigest()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "kalilax")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "kalilax122313")

MAIGRET_BIN = os.getenv("MAIGRET_BIN", "maigret")
HOLEHE_BIN = os.getenv("HOLEHE_BIN", "holehe")
PHONEINFOGA_BIN = os.getenv("PHONEINFOGA_BIN", "phoneinfoga")

# إعدادات البحث بالاسم الكامل
SEARCH_DELAY = int(os.getenv("SEARCH_DELAY", "2"))          # ثانية بين الطلبات/المحاولات
USER_AGENT_ROTATION = _bool(os.getenv("USER_AGENT_ROTATION", "true"))
SEARCH_PROXY = (os.getenv("SEARCH_PROXY") or os.getenv("HTTP_PROXY") or "").strip()

RATE_LIMIT_PER_IP = int(os.getenv("RATE_LIMIT_PER_IP", "20"))  # طلبًا/ساعة/IP
RATE_LIMIT_WINDOW = 3600      # ثانية

ADMIN_SESSION_HOURS = 24      # صلاحية جلسة الأدمن
SEARCH_TIMEOUT = 180          # مهلة كل بحث بالثواني