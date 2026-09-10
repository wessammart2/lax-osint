"""LAX OSINT — راوتر التحليل الشامل (جمع المعلومات الكاملة).

يتيح زر "تحليل شامل" على كل نوع بحث:
  GET /api/comprehensive/{kind}?q=...&token=...

يجمع البيانات من المصادر الكاملة ثم يمررها لخدمة الذكاء الاصطناعي
(OpenRouter) ليُنتج تقريرًا منظمًا: اسم/عمر/جنس/موقع/اهتمامات/حسابات/
علاقات/خط زمني/تقييم مخاطر — مع الثقة والمصدر لكل معلومة.

kind: username | email | phone
البيانات تُبث عبر SSE (progress + result واحد بنوع comprehensive).
"""
import time

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from services import ai_analysis, email_verification, phone_analysis
from services import profile_image_service
from routers.search_common import authorize, stream_response
from utils import parse_number

router = APIRouter(tags=["search"])

KINDS = ("username", "email", "phone")


@router.get("/comprehensive/{kind}")
def comprehensive(kind: str, q: str = "", token: str = "", request: Request = None):
    kind = (kind or "").strip().lower()
    raw = (q or "").strip()

    if kind not in KINDS:
        return {"error": "bad_kind", "message": "النوع يجب أن يكون: username | email | phone"}

    if kind == "phone":
        number = parse_number(raw)
        if raw.startswith("+") and not number.startswith("+"):
            number = "+" + number
        if not number:
            return {"error": "bad_number",
                    "message": "أدخل رقمًا بصيغة دولية (مثال: +9665xxxxxxxx)"}
    elif kind == "email" and ("@" not in raw):
        return {"error": "bad_email", "message": "صيغة الإيميل غير صحيحة"}

    auth = authorize(token, kind, raw)
    if auth.get("blocked"):
        return JSONResponse(status_code=auth["status"], content=auth["payload"])

    started = time.time()

    async def runner():
        notes = []

        def progress(level, msg):
            notes.append(("progress" if level != "warn" else "warn", {"message": msg}))

        # 1) جمع المعلومات الكاملة من المصادر
        if kind == "username":
            from services import maigret_service
            results = await maigret_service.search_username(raw, progress)
            await profile_image_service.enrich(results)
            data = {"query": raw, "kind": kind, "accounts": results}
        elif kind == "email":
            data = await email_verification.verify_email(raw, progress)
        else:
            data = await phone_analysis.analyze_phone(raw, progress)

        data["kind"] = kind  # رسم القسم الصحيح في الواجهة (email/phone ليسا افتراضيًا)

        for level, msg in notes:
            yield (level, msg)

        if data.get("error"):
            yield ("warn", {"message": data.get("message") or "بيانات غير صالحة"})
            yield ("result", {"type": "comprehensive", "data": data})
            return

        # 2) التحليل الذكي عبر OpenRouter
        if progress:
            progress("info", "الذكاء الاصطناعي يبني التقرير الشامل… (قد يستغرق دقيقة)")
        try:
            report = await ai_analysis.generate_report(kind, raw, data,
                                                       user_id=str(auth["user"]["id"]))
        except Exception as e:  # noqa: BLE001
            report = {"status": "error", "message": f"فشل التحليل الذكي: {e}"}

        data["ai"] = report
        data["duration_sec"] = round(time.time() - started, 2)
        yield ("result", {"type": "comprehensive", "data": data})

    return stream_response(auth["user"], raw, "comprehensive:" + kind,
                           runner, auth["quota"], timeout_sec=300)