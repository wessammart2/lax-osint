"""LAX OSINT — اعتماديات مشتركة بين راوترات البحث:
- تحقق المستخدم (JWT) ومعاقبة رفضه لو معطّل
- فحص الحصة اليومية (مجاني: حد يومي / برو: غير محدود)
- بدء بحث: زيادة العداد والتسجيل في السجل
"""
import config


class SearchBlocked(Exception):
    def __init__(self, status: int, payload: dict):
        self.status = status
        self.payload = payload


def require_user(token: str):
    from db import db
    if not token:
        raise SearchBlocked(401, {"error": "unauthorized", "message": "يجب تسجيل الدخول أولًا"})
    payload = verify_user_token(token)
    if not payload:
        raise SearchBlocked(401, {"error": "unauthorized", "message": "الجلسة منتهية أو غير صالحة"})
    user = db.get_user_by_id(payload["uid"])
    if not user:
        raise SearchBlocked(401, {"error": "unauthorized", "message": "الحساب غير موجود"})
    if user.get("disabled"):
        raise SearchBlocked(403, {"error": "disabled", "message": "تم تعطيل حسابك"})
    return user


def verify_user_token(token: str):
    from utils import verify_token
    payload = verify_token(token)
    if payload and payload.get("type") == "user":
        return payload
    return None


def check_and_begin(user, search_type: str, query: str):
    """فحص الحصة ثم (في حالة السماح) زيادة العد والتسجيل."""
    from db import db
    is_pro = bool(user.get("is_pro"))
    if not is_pro and user.get("searches_today", 0) >= config.SEARCH_LIMIT_DAILY:
        raise SearchBlocked(402, {
            "error": "limit",
            "message": "وصلت لحد 4 بحوث مجانية اليوم",
            "searches_today": user.get("searches_today", 0),
            "limit": config.SEARCH_LIMIT_DAILY,
        })
    db.increment_searches(user["id"])
    return {"searches_today": user.get("searches_today", 0) + 1,
            "limit": config.SEARCH_LIMIT_DAILY,
            "is_pro": is_pro,
            "quota_used": min(user.get("searches_today", 0) + 1, config.SEARCH_LIMIT_DAILY),
            "quota_max": config.SEARCH_LIMIT_DAILY}


def finalize_search(user_id, search_type: str, query: str, results_count: int):
    from db import db
    db.log_search(user_id, search_type, query[:500], results_count)