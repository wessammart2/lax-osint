"""LAX OSINT — خدمة البحث باليوزر نيم عبر Maigret (3000+ موقع)
التشغيل: subprocess على CLI، مع تفسير مخرجاتها في صيغ متعددة.
"""
import asyncio
import json
import os
import shutil
import tempfile

import config


def available() -> tuple:
    """تُرجع (متاح, رسالة)."""
    if shutil.which(config.MAIGRET_BIN):
        return True, ""
    try:
        import maigret  # noqa: F401
        return True, ""
    except Exception:
        return False, (
            "Maigret غير مثبت محليًا — شغّل: pip install maigret "
            "(أو ضع مسار الـ binary في MAIGRET_BIN)"
        )


async def _run_cli(username: str, timeout: int = 120) -> tuple:
    """تشغيل maigret CLI وحفظ التقرير JSON مؤقتًا إن أمكن."""
    import subprocess

    fd, tmp = tempfile.mkstemp(suffix=".json", prefix="maigret_")
    os.close(fd)
    try:
        # حفظ الخرجJSON في ملف مؤقت (الصيغة المعتمدة: maigret username -o file.json)
        proc = await asyncio.create_subprocess_exec(
            config.MAIGRET_BIN, username, "-o", tmp,
            "-T", "6", "--db", "all",
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return None, "انتهت المهلة أثناء تشغيل Maigret", []
        if os.path.exists(tmp) and os.path.getsize(tmp) > 0:
            try:
                with open(tmp, encoding="utf-8") as f:
                    report = json.load(f)
                return report, "", []
            except Exception:
                pass
        # فشل التقرير: نحاول تفسير السطر الأخير من stderr كملخص
        tail = (stderr or b"").decode("utf-8", "ignore").strip().splitlines()
        return None, (tail[-1] if tail else "لم يُنتج Maigret أي نتائج"), []
    finally:
        try:
            os.remove(tmp)
        except Exception:
            pass


async def _run_library(username: str, timeout: int = 120) -> tuple:
    """الاستخدام البرمجي لحزمة maigret (fallback إن لم يوجد CLI)."""
    try:
        import maigret  # noqa: F401
    except Exception:
        return None, "", []

    import maigret.api as api

    try:
        loop = asyncio.get_running_loop()
        result = await asyncio.wait_for(
            api.search_username(username, loop=loop), timeout=timeout
        )
        # api.search_username تُرجع (found_sites, stars, buckets, errors...)
        found_sites = result[0] if isinstance(result, tuple) else {}
        sites = []
        for name, info in (found_sites or {}).items():
            if isinstance(info, dict):
                url = info.get("url_site") or info.get("pretty_site")
                sites.append({"site": name, "username": username, "url": url or "",
                              "status": "registered", "tags": info.get("tags", [])})
        return None, "", sites
    except Exception as e:
        return None, str(e), []


async def search_username(username: str, progress=None) -> list:
    """
    البحث عن اليوزر.
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
        progress("info", "جارٍ فحص يوزر النيم عبر Maigret…")
    report, err, library_sites = await _run_cli(username)
    if report is None:
        if library_sites:
            return library_sites
        if progress:
            progress("warn", err or "Maigret لم يُنتج نتائج")
        return [{"site": "Maigret", "username": username, "url": "",
                 "status": "warning", "note": err or "لا نتائج"}]

    return parse_report(report, username)


def parse_report(report, username) -> list:
    """تحويل تقرير Maigret (بصيغته JSON المعروفة) إلى النموذج الموحّد."""
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
            # صيغة { name: {url_site:..., tags:...} }
            for name, info in report.items():
                if isinstance(info, dict) and "url_site" in info:
                    sites.append({"site": name, "username": username,
                                  "url": info.get("url_site", ""), "status": "registered",
                                  "tags": info.get("tags", [])})
    return sites