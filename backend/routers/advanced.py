"""LAX OSINT — البحث المتقدم (Deep Research + فحص ثغرات + ديب ويب + Qwen).

GET /api/advanced?kind=username|email|phone&q=...&token=...
مراحل بث SSE:
  1) research  — Wayback + Google Dorks + PGP + Shodan + Censys (متوازية)
  2) vuln      — فحص أمني سلبي لأهم أهداف الهدف (حد 3) بدون أي هجوم
  3) deepweb   — مؤشرات التسريبات (عبر Tor إن وُجد / بدائل آمنة)
  4) ai_deep   — تقرير Qwen العميق الذي يراكب كل البيانات (يتطلب Pro)
  نتيجة أخيرة: result {research, vuln, deepweb, ai_deep, csv, graph}
"""
import asyncio
import csv
import io
import logging

import config
from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from routers.deps import SearchBlocked, require_user
from services import advanced_research as AR
from services import ai_analysis
from services import deep_web_search as DW
from services import qwen_analysis as QW
from services import vulnerability_scanner as VS
from utils import sse_event

LOG = logging.getLogger("advanced")
router = APIRouter(prefix="/api/advanced", tags=["advanced"])

KINDS = ("username", "email", "phone")


def _to_csv(section: str, rows: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([section, "LAX OSINT"])
    if not rows:
        w.writerow(["no results"])
        return buf.getvalue()
    keys = sorted({k for r in rows for k in (r.keys() if isinstance(r, dict) else ())})
    w.writerow(keys)
    for r in rows:
        w.writerow([r.get(k, "") for k in keys]) if isinstance(r, dict) else None
    return buf.getvalue()


def _simple_graph(base: dict, research: dict) -> dict:
    nodes, edges, seen = [], [], set()

    def add(nid, label, ntype):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "label": label, "type": ntype})

    add("target", base.get("query", ""), "target")
    for a in (base.get("accounts") or [])[:25]:
        nid = a.get("site") or a.get("username") or ""
        if nid:
            add("a:" + nid, nid, "account")
            edges.append({"source": "target", "target": "a:" + nid})
    for r in (research.get("wayback") or {}).get("items", [])[:10]:
        nid = r.get("url") or ""
        if nid:
            add("wb:" + nid, nid[:40], "archive")
            edges.append({"source": "target", "target": "wb:" + nid})
    return {"nodes": nodes, "edges": edges}


async def _targets_from(base: dict) -> list:
    urls = set()
    for acc in (base.get("accounts") or [])[:8]:
        u = (acc.get("url") or "").strip()
        if u and "http" in u:
            urls.add(u)
    return [u for u in urls][:5]


def _run(kind: str, query: str, base: dict, user_id: str, is_pro: bool):
    async def gen():
        progress = []  # (name, data) tuples

        def note(level, msg):
            progress.append((("warn" if level == "warn" else "progress"), {"type": "info", "message": msg}))

        # 1) البحث العميق
        research = await AR.research_target(kind, query, note)
        progress.append(("stage", {"id": 1, "title": "البحث العميق", "ok": True}))

        # 2) فحص الثغرات (سلبي)
        targets = await _targets_from(base)
        vuln = {"scanned": 0, "targets": targets, "results": {}}
        if targets:
            vuln = await VS.scan_many(targets, limit=3, progress=note)
        progress.append(("stage", {"id": 2, "title": "فحص الثغرات", "ok": True,
                                   "target_count": len(vuln.get("targets") or [])}))

        # 3) الديب ويب
        deepweb = await DW.deepweb_search(kind, query, note)
        progress.append(("stage", {"id": 3, "title": "مؤشرات الديب ويب", "ok": True}))

        # 4) التقرير العميق Qwen (Pro فقط)
        ai_deep = {"status": "pro_required", "note": "التقرير العميق متاح فقط للحسابات البرو"}
        if is_pro:
            ai_deep = await QW.deep_report(
                kind, query, base, user_id=user_id,
                extra={"research": research, "vuln": vuln, "deepweb": deepweb})
            if ai_deep.get("cached"):
                ai_deep.pop("cached", None)
            progress.append(("stage", {"id": 4, "title": "التقرير العميق (Qwen)", "ok": True}))

        csv_parts = [_to_csv("accounts_" + query, base.get("accounts") or [])]
        wb = (research.get("wayback") or {})
        if wb.get("items"):
            csv_parts.append(_to_csv("wayback", wb["items"]))

        for name, data in progress:
            yield sse_event(name, data)
        yield sse_event("result", {
            "query": query, "kind": kind, "research": research, "vuln": vuln,
            "deepweb": deepweb, "ai_deep": ai_deep,
            "csv": "\n".join(csv_parts), "graph": _simple_graph(base, research),
            "pro": is_pro,
        })

    return gen()


@router.get("")
async def advanced_search(request: Request, kind: str = Query(...),
                          q: str = Query(...), token: str = Query(...)):
    kind = (kind or "").strip().lower()
    query = (q or "").strip()
    if kind not in KINDS:
        return JSONResponse({"error": "bad_kind", "message": "نوع البحث غير صالح"})
    if len(query) < 2:
        return JSONResponse({"error": "bad_query", "message": "استعلام قصير جدًا"})

    try:
        user = require_user(token)
    except SearchBlocked as e:
        return JSONResponse(status_code=e.status, content=e.payload)

    is_pro = bool(user.get("is_pro"))
    base = ai_analysis.get_base_data(kind, query)
    if not base:
        base = {"query": query, "accounts": [], "summary": {},
                "note": "أجرِ البحث الأساسي (تحليل شامل) لهذا الهدف أولًا؛ سيكتمل هنا التحليل المتقدم بعد ذلك."}

    return StreamingResponse(
        _run(kind, query, base, str(user["id"]), is_pro),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive",
                 "X-Accel-Buffering": "no"})