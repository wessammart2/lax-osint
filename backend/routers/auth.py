"""LAX OSINT — راوتر المصادقة
register / login / me — تصدر JWT موقّعًا، وتدعم وضعي local و supabase.
"""
from fastapi import APIRouter, Request
from pydantic import BaseModel, EmailStr  # type: ignore

from db import db
from utils import make_token
import config

router = APIRouter(tags=["auth"])

SESSION_SECONDS = 60 * 60 * 24 * 7  # 7 أيام


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = ""  # تُستخدم في وضع supabase (GoTrue) أو محليًا


class LoginIn(BaseModel):
    email: str
    password: str


@router.post("/auth/register")
def register(body: RegisterIn, request: Request):
    password = body.password.strip()
    if not password or len(password) < 6:
        return {"error": "weak_password", "message": "كلمة المرور يجب ألا تقل عن 6 أحرف"}
    user = db.create_user(str(body.email).lower(), password)
    if not user:
        return {"error": "exists", "message": "هذا الإيميل مسجل بالفعل"}
    return {"ok": True, "token": make_token({"type": "user", "uid": user["id"]}, SESSION_SECONDS),
            "user": sanitize(user)}


@router.post("/auth/login")
def login(body: LoginIn):
    user = db.get_user_by_email(body.email.strip())
    if not user:
        return {"error": "not_found", "message": "لا يوجد حساب بهذا الإيميل"}
    if db.mode == "supabase":
        # في وضع supabase نستخدم GoTrue لمصادقة كلمة المرور
        result = db.login(user["email"], body.password)
        if not result:
            return {"error": "bad_password", "message": "كلمة المرور غير صحيحة"}
        return {"ok": True, "token": make_token({"type": "user", "uid": result["id"]}, SESSION_SECONDS),
                "user": sanitize(db.get_user_by_id(result["id"])), "access_token": result.get("access_token")}
    else:
        from db import verify_password
        if not verify_password(body.password, db.get_password_hash(user["email"])):
            return {"error": "bad_password", "message": "كلمة المرور غير صحيحة"}
        return {"ok": True, "token": make_token({"type": "user", "uid": user["id"]}, SESSION_SECONDS),
                "user": sanitize(user)}


@router.get("/auth/me")
def me(token: str = ""):
    from routers.deps import require_user
    try:
        user = require_user(token)
    except Exception as e:
        return {"error": "unauthorized", "message": str(e)}
    return {"user": sanitize(user), "db_mode": db.mode}


def sanitize(user: dict) -> dict:
    return {
        "id": user.get("id"),
        "email": user.get("email"),
        "searches_today": user.get("searches_today", 0),
        "last_search_date": user.get("last_search_date"),
        "is_pro": bool(user.get("is_pro")),
        "pro_until": user.get("pro_until"),
        "created_at": user.get("created_at"),
    }