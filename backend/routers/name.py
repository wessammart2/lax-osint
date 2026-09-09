"""LAX OSINT — راوتر البحث بالاسم الكامل (Deep Search / Dossier) عبر SSE."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from services import deep_search_service
from routers.search_common import authorize, stream_response

router = APIRouter(tags=["search"])


@router.get("/search/name")
def name_search(q: str, token: str = "", request: Request = None):
    query = (q or "").strip()
    if not query:
        return {"error": "empty", "message": "أدخل الاسم الكامل (مثال: أحمد محمد علي)"}
    if len(query) > 100:
        return {"error": "too_long", "message": "الاسم طويل جدًا"}

    auth = authorize(token, "name", query)
    if auth.get("blocked"):
        return JSONResponse(status_code=auth["status"], content=auth["payload"])

    async def runner():
        notes = []
        def progress(level, msg):
            notes.append(("progress" if level != "warn" else "warn", {"message": msg}))

        payload = await deep_search_service.deep_search(query, progress)

        recipe_sites = await deep_search_service.search_facebook(query, progress)

        for level, msg in notes:
            yield (level, msg)

        if payload.get("dossier", {}).get("details"):
            yield ("result", {"type": "dossier", "data": payload["dossier"]})
        for r in payload.get("results", []):
            yield ("result", {"type": "link", "data": r})
        if recipe_sites:
            yield ("result", {"type": "facebook", "data": recipe_sites})

    return stream_response(auth["user"], query, "name", runner, auth["quota"])