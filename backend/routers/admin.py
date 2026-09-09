"""LAX OSINT — راوتر لوحة الأدمن (معزول، بجلسة 24 ساعة).
تسجيل دخول: /api/admin/login → JWT بنوع admin.
استعراض إحصائيات/أكواد/مستخدمين/سجلات + إنشاء/حذف أكواد + تعطيل مستخدم.
"""
import datetime as dt

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel  # type: ignore

from db import db
from utils import make_token, verify_token, rate_check
import config

router = APIRouter(tags=["admin"])

ADMIN_SESSION = 60 * 60 * 24  # 24 ساعة


class AdminLogin(BaseModel):
    username: str
    password: str


class CodeCreate(BaseModel):
    count: int = 5
    duration_days: int = 30


def _resolve_token(token: str, authorization: str | None) -> str:
    if token:
        return token
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:].strip()
    return authorization or ""


def _require_admin(token: str, authorization: str | None = None) -> dict | None:
    t = _resolve_token(token, authorization)
    payload = verify_token(t)
    if not payload or payload.get("type") != "admin":
        return None
    return payload


def _admin_or_401(token: str, authorization: str | None = None):
    info = _require_admin(token, authorization)
    if not info:
        raise HTTPException(status_code=401, detail="unauthorized")
    return info


def _ip(request):
    return request.client.host if request and request.client else None


@router.post("/admin/login")
def admin_login(body: AdminLogin, request: Request):
    if rate_check(f"admin:{_ip(request)}"):
        return JSONResponse(status_code=429, content={"error": "slowdown",
                             "message": "محاولات كثيرة — جرّب لاحقًا"})
    admin = db.get_admin(body.username.strip())
    if not admin or not db.verify_admin(body.username.strip(), body.password):
        return JSONResponse(status_code=401, content={"error": "bad_creds",
                             "message": "اسم المستخدم أو كلمة المرور غير صحيحة"})
    token = make_token({"type": "admin", "aid": admin["id"], "user": config.ADMIN_USERNAME},
                       ADMIN_SESSION)
    db.log_admin(admin["id"], "login", {"ip": _ip(request)}, _ip(request))
    return {"ok": True, "token": token, "expires_in": ADMIN_SESSION}


@router.get("/admin/stats")
def admin_stats(token: str = "", authorization: str | None = Header(default=None),
                request: Request = None):
    info = _admin_or_401(token, authorization)
    db.log_admin(info["aid"], "view_stats", None, _ip(request))
    return db.stats()


@router.post("/admin/codes")
def admin_create_codes(body: CodeCreate, token: str = "",
                       authorization: str | None = Header(default=None), request: Request = None):
    info = _admin_or_401(token, authorization)
    count = max(1, min(body.count, 100))
    duration = max(1, min(body.duration_days, 365))
    codes = db.create_codes(count, duration)
    db.log_admin(info["aid"], "create_codes", {"count": count, "duration": duration}, _ip(request))
    return {"ok": True, "codes": codes}


@router.get("/admin/codes")
def admin_list_codes(token: str = "", authorization: str | None = Header(default=None),
                     request: Request = None):
    info = _admin_or_401(token, authorization)
    return {"codes": db.list_codes()}


@router.delete("/admin/codes/{code_id}")
def admin_delete_code(code_id: str, token: str = "",
                      authorization: str | None = Header(default=None), request: Request = None):
    info = _admin_or_401(token, authorization)
    db.delete_code(code_id)
    db.log_admin(info["aid"], "delete_code", {"id": code_id}, _ip(request))
    return {"ok": True}


@router.get("/admin/users")
def admin_list_users(token: str = "", authorization: str | None = Header(default=None),
                     request: Request = None):
    info = _admin_or_401(token, authorization)
    return {"users": db.list_users()}


@router.post("/admin/users/{user_id}/disable")
def admin_disable_user(user_id: str, disable: bool = True, token: str = "",
                       authorization: str | None = Header(default=None), request: Request = None):
    info = _admin_or_401(token, authorization)
    db.set_disabled(user_id, disable)
    db.log_admin(info["aid"], "disable_user" if disable else "enable_user", {"id": user_id},
                 _ip(request))
    return {"ok": True}


@router.get("/admin/logs")
def admin_logs(token: str = "", authorization: str | None = Header(default=None),
               request: Request = None):
    info = _admin_or_401(token, authorization)
    return {"logs": db.list_admin_logs(150)}