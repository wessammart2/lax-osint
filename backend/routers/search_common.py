"""LAX OSINT — أدوات مشتركة لبث نتائج البحث عبر SSE.

تدفق الأحداث:
  event: meta      {query, search_type, quota}
  event: progress  {step}
  event: warn      {message}
  event: result    {type, data}
  event: done      {count, duration}
"""
import asyncio
import time

from fastapi.responses import StreamingResponse

from routers.deps import SearchBlocked, check_and_begin, finalize_search, require_user
from utils import sse_event


def authorize(token: str, search_type: str, query: str):
    """تحقق من المستخدم والحصة قبل فتح تدفق الأحداث.

    تُرجع {blocked: True, status, payload} أو {blocked: False, user, quota}.
    """
    try:
        user = require_user(token)
        quota = check_and_begin(user, search_type, query)
    except SearchBlocked as e:
        return {"blocked": True, "status": e.status, "payload": e.payload}
    return {"blocked": False, "user": user, "quota": quota}


def stream_response(user, query, search_type, runner, quota, timeout_sec=180):
    """يبني StreamingResponse من مولّد أحداث غير متزامن.

    runner: دالة غير متزامنة تُرجع مولّد أحداث تُصدِر tuples:
      ("progress"/"warn", msg) أو ("result", {"type", "data"})
    """
    started = time.time()

    async def gen():
        count = 0
        try:
            yield sse_event("meta", {"query": query, "search_type": search_type,
                                     "quota": quota})
            async for name, data in keepalive(lambda: _each(runner())):
                if name == "result":
                    count += 1
                elif name == "done":
                    continue  # لا نسمح للمخدم الخارجي بـ done الخاصة
                yield sse_event(name, data)
            yield sse_event("done", {"count": count, "search_type": search_type,
                                     "duration": round(time.time() - started, 2)})
        finally:
            finalize_search(user["id"], search_type, query, count)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive",
                 "X-Accel-Buffering": "no"},
    )


async def _each(async_gen):
    try:
        async for item in async_gen:
            yield item
    except Exception as e:  # noqa: BLE001
        yield ("warn", {"message": f"خطأ أثناء تنفيذ البحث: {e}"})


_DONE = object()


async def keepalive(agen, interval: int = 4):
    """يحافظ على حيوية بث SSE أثناء المعالجات الطويلة.

    يرسل حدث heartbeat حقيقي (event: heartbeat) كل بضع ثوانٍ حتى لا تقطع
    نفق Railway/Traefik الاتصال؛ بعض الوكالات لا تعيد توجيه أسطر التعليق
    ("...") بينما تعيد توجيه أحداث SSE الحقيقية بموثوقية.
    """
    q: asyncio.Queue = asyncio.Queue()
    inner = agen()

    async def _fill():
        try:
            async for item in inner:
                await q.put(item)
        finally:
            await q.put(_DONE)

    task = asyncio.create_task(_fill())
    last = time.monotonic()
    try:
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=interval)
            except asyncio.TimeoutError:
                if time.monotonic() - last >= interval:
                    yield sse_event("heartbeat", {"t": int(time.time())})
                    last = time.monotonic()
                continue
            if item is _DONE:
                break
            last = time.monotonic()
            yield item
    finally:
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass