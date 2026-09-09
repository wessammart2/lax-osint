"""LAX OSINT — راوتر البحث برقم الهاتف (PhoneInfoga) عبر SSE."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from services import phoneinfoga_service
from routers.search_common import authorize, stream_response
from utils import parse_number

router = APIRouter(tags=["search"])


@router.get("/search/phone")
def phone_search(q: str, token: str = "", request: Request = None):
    raw = (q or "").strip()
    number = parse_number(raw)
    # المحافظة على صيغة "+" الدولية إن وردت؛ وإلا نمرر الأرقام كما هي
    if raw.startswith("+") and not number.startswith("+"):
        number = "+" + number
    if not number:
        return {"error": "bad_number",
                "message": "أدخل رقمًا بصيغة دولية (مثال: +15551234567)"}

    auth = authorize(token, "phone", raw)
    if auth.get("blocked"):
        return JSONResponse(status_code=auth["status"], content=auth["payload"])

    async def runner():
        notes = []
        def progress(level, msg):
            notes.append(("progress" if level != "warn" else "warn", {"message": msg}))

        info = await phoneinfoga_service.search_phone(number, progress)
        for level, msg in notes:
            yield (level, msg)
        if info.get("tech"):
            yield ("result", {"type": "phone_tech", "data": info})
        else:
            yield ("warn", {"message": info.get("note") or "لا توجد تقنيات لعرضها"})

    return stream_response(auth["user"], raw, "phone", runner, auth["quota"])