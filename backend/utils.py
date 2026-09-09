"""LAX OSINT — أدوات مساعدة: JWT خفيف، بث SSE، ترتيب النتائج، سجل الطلبات."""
import hmac
import hashlib
import base64
import json
import time
import uuid
import threading
from datetime import datetime, timedelta, timezone

import config

# ----------------------------------------------------------
#  JWT بسيط (HS256) بدون اعتماديات خارجية
# ----------------------------------------------------------
def _b64(o):
    return base64.urlsafe_b64encode(json.dumps(o, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_token(payload: dict, expires_seconds: int) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(payload)
    body["iat"] = int(time.time())
    body["exp"] = int(time.time()) + expires_seconds
    signing_input = f"{_b64(header)}.{_b64(body)}"
    sig = hmac.new(config.TOKEN_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def verify_token(token: str):
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}"
        sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        expected = hmac.new(config.TOKEN_SECRET.encode(), signing_input.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expected):
            return None
        body = json.loads(_b64u(parts[1]))
        if body.get("exp", 0) < time.time():
            return None
        return body
    except Exception:
        return None


# ----------------------------------------------------------
#  دالة قراءة المستخدم من التوكن
# ----------------------------------------------------------
def user_from_token(token):
    payload = verify_token(token)
    if not payload or payload.get("type") != "user":
        return None
    return db_get_user(payload["uid"])


# استيراد مؤجل لتفادي التدوير
def db_get_user(uid):
    from db import db
    return db.get_user_by_id(uid)


# ----------------------------------------------------------
#  بث الأحداث (Server-Sent Events)
# ----------------------------------------------------------
def sse_event(name: str, data: dict) -> str:
    return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


def sse_data(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


# ----------------------------------------------------------
#  ترتيب النتائج: الأشهر أولاً ثم باقي المنصات
# ----------------------------------------------------------
POPULAR_ORDER = [
    "facebook", "instagram", "tiktok", "youtube", "twitter", "x.com", "x(",
    "whatsapp", "snapchat", "telegram", "discord", "linkedin", "steam",
    "github", "reddit",
]
FALLBACK_ORDER = 100


def _norm(name: str) -> str:
    return (name or "").strip().lower()


def popularity_key(name: str) -> int:
    n = _norm(name)
    for i, tag in enumerate(POPULAR_ORDER):
        if n == tag or n.startswith(tag) or tag in n:
            return i
    return FALLBACK_ORDER


def sort_results(items) -> list:
    """ترتيب النتائج من الأشهر للأقل شهرة، مع استقرار الترتيب داخليًا."""
    return sorted(items, key=lambda it: (popularity_key(it.get("site") or it.get("name") or ""),
                                         _norm(it.get("site") or it.get("name") or "")))


# ----------------------------------------------------------
#  Rate Limiting: 20 طلبًا في الساعة لكل IP
# ----------------------------------------------------------
_ratelock = threading.Lock()
_ratetable: dict = {}


def rate_check(ip: str) -> bool:
    """تسجيل طلب؛ تُرجع True إن تجاوز الحد."""
    now = time.time()
    with _ratelock:
        key = str(ip)
        entry = _ratetable.get(key)
        if not entry or entry["start"] < now - config.RATE_LIMIT_WINDOW:
            _ratetable[key] = {"count": 1, "start": now}
            return False
        entry["count"] += 1
        return entry["count"] > config.RATE_LIMIT_PER_IP


def rate_remaining(ip: str) -> int:
    now = time.time()
    with _ratelock:
        entry = _ratetable.get(str(ip))
        if not entry or entry["start"] < now - config.RATE_LIMIT_WINDOW:
            return config.RATE_LIMIT_PER_IP
        return max(0, config.RATE_LIMIT_PER_IP - entry["count"])


# ----------------------------------------------------------
#  أدوات متنوعة
# ----------------------------------------------------------
def new_id() -> str:
    return str(uuid.uuid4())


def make_code():
    """توليد كود بالشكل XXXX-XXXX-XXXXX-XXX (مثال: HSDFN-DSLF-84357-FFJ)."""
    import random
    import string
    alphabet = string.ascii_uppercase + string.digits
    return "-".join(
        ["".join(random.choices(alphabet, k=4)),
         "".join(random.choices(alphabet, k=4)),
         "".join(random.choices(alphabet, k=5)),
         "".join(random.choices(alphabet, k=3))]
    )


def parse_number(number: str) -> list:
    """تطبيع رقم الهاتف إلى الصيغ المدعومة: "+رمز الدولة" وصيغته المحلية."""
    digits = "".join(ch for ch in number if ch.isdigit())
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    return digits


def clamp(value, low, high):
    return max(low, min(high, value))