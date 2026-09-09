"""LAX OSINT — خدمة البحث باليوزر نيم عبر Maigret (3000+ موقع)
تنفيذ التعليق الرسمي من Maiгret كـ Python library
(maigret_search في maigret.checking.maigret) — لا يشغّل CLI خارجي.
"""
import asyncio
import logging
from pathlib import Path

MAIGRET_TOP_SITES = 500   # نفس عدد المواقع الافتراضي للـ CLI (أعلى حركة مرور)
MAIGRET_TIMEOUT = 20      # ثانية لكل طلب


def _logger():
    lg = logging.getLogger("maigret")
    lg.setLevel(logging.WARNING)
    lg.propagate = False
    if not lg.handlers:
        lg.addHandler(logging.NullHandler())
    return lg


def _load_database():
    import maigret
    from maigret.sites import MaigretDatabase

    db_path = Path(maigret.__file__).resolve().parent / "resources" / "data.json"
    if not db_path.exists():
        db_path = Path("maigret/resources/data.json")
    return MaigretDatabase().load_from_path(str(db_path))


def available() -> tuple:
    """تُرجع (متاح, رسالة)."""
    try:
        import maigret  # noqa: F401
        return True, ""
    except Exception:
        return False, (
            "Maigret غير مثبت — أعد بناء الصورة: pip install maigret"
        )


def _ids_summary(ids_data) -> str:
    """تحويل بيانات socid_extractor (حسابات/معرّفات مرتبطة) إلى سطر مختصر."""
    if not ids_data or not isinstance(ids_data, dict):
        return ""
    fields = []
    for key in ("usernames", "ids", "emails", "phones", "full_name"):
        v = ids_data.get(key)
        if v:
            vals = ", ".join(str(x) for x in v)[:120]
            fields.append(f"{key}: {vals}")
    return " | ".join(fields)


async def search_username(username: str, progress=None) -> list:
    """
    البحث عن اليوزر عبر مكتبة Maigret.
    progress: دالة (msg) تُستدعى مع كل رسالة إعلامية.
    تُرجع قائمة نتائج بصيغة موحّدة.
    """
    ok, msg = available()
    if not ok:
        if progress:
            progress("warn", msg)
        return [{"site": "Maigret", "username": username, "url": "",
                 "status": "warning", "note": msg}]

    if progress:
        progress("info", f"جارٍ فحص يوزر النيم عبر Maigret ({MAIGRET_TOP_SITES} موقع)…")
    try:
        from maigret import search as maigret_search

        try:
            db = _load_database()
            sites = db.ranked_sites_dict(top=MAIGRET_TOP_SITES)
        except Exception:
            sites = None

        if not sites:
            if progress:
                progress("warn", "تعذّر تحميل قاعدة مواقع Maigret")
            return [{"site": "Maigret", "username": username, "url": "",
                     "status": "warning", "note": "تعذّر تحميل قاعدة مواقع Maigret"}]

        if progress:
            progress("info", f"فُحص {len(sites)} موقع… (قد يستغرق دقيقة)")
        results = await asyncio.wait_for(
            maigret_search(
                username=username,
                site_dict=sites,
                logger=_logger(),
                timeout=MAIGRET_TIMEOUT,
                is_parsing_enabled=True,
                max_connections=50,
                no_progressbar=True,
            ),
            timeout=160,
        )
    except asyncio.TimeoutError:
        if progress:
            progress("warn", "انتهت مهلة Maigret")
        return [{"site": "Maigret", "username": username, "url": "",
                 "status": "warning", "note": "انتهت مهلة Maigret (160 ثانية)"}]
    except Exception as e:
        if progress:
            progress("warn", f"Maigret فشل: {e}")
        return [{"site": "Maigret", "username": username, "url": "",
                 "status": "error", "note": f"Maigret فشل: {e}"}]

    sites_found = 0
    out = []
    for site_name, res in (results or {}).items():
        if not isinstance(res, dict):
            continue
        status_obj = res.get("status")
        found = bool(getattr(status_obj, "is_found", lambda: False)())
        if not found:
            continue
        sites_found += 1
        url = res.get("url_user") or res.get("url_auto") or ""
        ids = _ids_summary(res.get("ids_data"))
        item = {"site": site_name, "username": username, "url": url,
                "status": "registered"}
        tags = res.get("tags")
        if tags:
            item["tags"] = tags
        if ids:
            item["note"] = ids
        out.append(item)

    if not out:
        if progress:
            progress("warn", "لم يُعثر على حسابات لهذا اليوزر")
        return [{"site": "Maigret", "username": username, "url": "",
                 "status": "warning", "note": "لم يُعثر على حسابات مسجَّلة"}]
    if progress:
        progress("info", f"عُثر على {sites_found} حسابات مقترنة باليوزر")
    return out


def parse_report(report, username) -> list:
    """توافق قديم — تحويل تقرير Maigret JSON إلى النموذج الموحّد."""
    sites = []
    if isinstance(report, dict):
        if "results" in report:
            data = report.get("results", {})
            if isinstance(data, dict):
                for name, info in data.items():
                    if not info:
                        continue
                    url = info.get("url_site") or info.get("url_main") or ""
                    tags = info.get("tags", []) or []
                    sites.append({"site": name, "username": username, "url": url,
                                  "status": "registered", "tags": tags})
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        sites.append({"site": item.get("site", item.get("name", "")),
                                      "username": username,
                                      "url": item.get("url", ""),
                                      "status": "registered"})
        else:
            for name, info in report.items():
                if isinstance(info, dict) and "url_site" in info:
                    sites.append({"site": name, "username": username,
                                  "url": info.get("url_site", ""), "status": "registered",
                                  "tags": info.get("tags", [])})
    return sites