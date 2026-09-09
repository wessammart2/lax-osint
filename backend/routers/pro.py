"""LAX OSINT — راوتر تفعيل الكود البرو (Pro Code activation).

الكود بصيغة XXXX-XXXX-XXXXX-XXX، يُستخدم مرة واحدة،
ويمنح برو لمدة PRO_DURATION_DAYS (30 يومًا) من لحظة التفعيل.
"""
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel  # type: ignore

from db import db
from routers.deps import require_user

router = APIRouter(tags=["pro"])


class ActivateIn(BaseModel):
    token: str
    code: str


@router.post("/pro/activate")
def activate(body: ActivateIn):
    from routers.auth import sanitize
    try:
        user = require_user(body.token.strip())
    except Exception as e:
        return JSONResponse(status_code=401, content={"error": "unauthorized", "message": str(e)})

    result = db.activate_pro(user["id"], body.code)
    if not result.get("ok"):
        msg_map = {
            "bad_format": "صيغة الكود غير صحيحة — التنسيق: XXXX-XXXX-XXXXX-XXX",
            "not_found": "الكود غير موجود",
            "used": "هذا الكود مستخدم بالفعل",
            "expired": "انتهت صلاحية هذا الكود",
        }
        codes = {
            "bad_format": 400, "not_found": 404, "used": 409, "expired": 410,
        }
        return JSONResponse(status_code=codes.get(result["error"], 400),
                            content={"error": result["error"], "message": msg_map[result["error"]]})

    return {"ok": True, "message": "تم تفعيل الحساب البرو بنجاح",
            "pro_until": result["pro_until"],
            "user": sanitize(db.get_user_by_id(user["id"]))}