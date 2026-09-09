"""LAX OSINT — راوتر البحث بالإيميل (holehe + Gravatar) عبر SSE."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from services import gravatar_service, holehe_service
from routers.search_common import authorize, stream_response
from utils import sort_results

router = APIRouter(tags=["search"])


@router.get("/search/email")
def email_search(q: str, token: str = "", request: Request = None):
    query = (q or "").strip().lower()
    if not query or "@" not in query:
        return {"error": "empty", "message": "أدخل إيميلًا صحيحًا (مثال: name@domain.com)"}
    if len(query) > 120:
        return {"error": "too_long", "message": "الإيميل طويل جدًا"}

    auth = authorize(token, "email", query)
    if auth.get("blocked"):
        return JSONResponse(status_code=auth["status"], content=auth["payload"])

    async def runner():
        notes = []
        def progress(level, msg):
            notes.append(("progress" if level != "warn" else "warn", {"message": msg}))

        # 1) صورة Gravatar إن وُجدت
        avatar = gravatar_service.avatar_available(query)
        if avatar.get("available"):
            yield ("result", {"type": "avatar", "data": avatar})
        elif avatar.get("available") is None and avatar.get("error"):
            notes.append(("warn", {"message": f"تعذّر التحقق من Gravatar: {avatar['error']}"}))

        # 2) ملخص حساب الجاذبية إن وُجدت
        if avatar.get("available"):
            notes.append(("progress", {"message": "تم العثور على صورة Gravatar ✓"}))

        # 3) holehe: التحقق من المنصات
        results = await holehe_service.search_email(query, progress)
        results = sort_results(results)
        for level, msg in notes:
            yield (level, msg)
        for r in results:
            yield ("result", {"type": "site", "data": r})

    return stream_response(auth["user"], query, "email", runner, auth["quota"])