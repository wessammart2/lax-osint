"""LAX OSINT — نقطة دخول الباك إند (FastAPI)
يتضمن: CORS، Rate Limiting، وكل راوترات البحث والمصادقة والاشتراك والأدمن.
التشغيل: uvicorn main:app --port 8000
"""
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import config
import utils

app = FastAPI(title="LAX OSINT API", version="1.0.0")

# CORS: الواجهة قد تُستضاف على منفذ/نطاق مختلف عن الباك إند
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api"):
        ip = request.client.host if request.client else "?"
        if utils.rate_check(ip):
            remaining = utils.rate_remaining(ip)
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limited",
                         "message": f"تم تجاوز حد الطلبات ({config.RATE_LIMIT_PER_IP}/ساعة)",
                         "retry_in": config.RATE_LIMIT_WINDOW},
                headers={"Retry-After": str(config.RATE_LIMIT_WINDOW), "X-RateLimit-Remaining": str(remaining)},
            )
    return await call_next(request)


# ---------- راوترات ----------
from routers import auth, pro, admin, username, email, phone, comprehensive  # noqa: E402

app.include_router(auth.router, prefix="/api")
app.include_router(pro.router, prefix="/api")
app.include_router(admin.router, prefix="/api")
app.include_router(username.router, prefix="/api")
app.include_router(email.router, prefix="/api")
app.include_router(phone.router, prefix="/api")
app.include_router(comprehensive.router, prefix="/api")


@app.get("/api/health")
def health():
    from db import DB_MODE_ACTIVE
    return {"status": "ok", "db": DB_MODE_ACTIVE, "time": time.time(),
            "search_limit_daily": config.SEARCH_LIMIT_DAILY}


# ---------- الواجهة الأمامية (فردية للتطوير المحلي) ----------
import os
from fastapi.staticfiles import StaticFiles

_FRONTEND = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.isdir(_FRONTEND):
    app.mount("/", StaticFiles(directory=_FRONTEND, html=True), name="static")