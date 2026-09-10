"""LAX OSINT — راوتر البحث باليوزر نيم (Maigret) عبر SSE."""
from fastapi import APIRouter, Request

from services import maigret_service, profile_image_service
from routers.search_common import authorize, stream_response
from utils import sort_results

router = APIRouter(tags=["search"])


@router.get("/search/username")
def username_search(q: str, token: str = "", request: Request = None):
    query = (q or "").strip()
    if not query:
        return {"error": "empty", "message": "يجب إدخال يوزر نيم"}
    if len(query) > 60:
        return {"error": "too_long", "message": "اليوزر نيم طويل جدًا"}

    auth = authorize(token, "username", query)
    if auth.get("blocked"):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=auth["status"], content=auth["payload"])

    async def runner():
        notes = []
        def progress(level, msg):
            notes.append(("progress" if level != "warn" else "warn", {"message": msg}))

        results = await maigret_service.search_username(query, progress)
        results = sort_results(results)
        results = await profile_image_service.enrich(results)
        for level, msg in notes:
            yield (level, msg)
        for r in results:
            yield ("result", {"type": "site", "data": r})

    return stream_response(auth["user"], query, "username", runner, auth["quota"])