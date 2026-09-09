"""LAX OSINT — خدمة رقم الهاتف عبر PhoneInfoga (معلومات فنية)
تُعطي التقنيات عن الرقم: البلد، شركة الاتصالات، صيغة الرقم، ثم ترجمة النتائج.
"""
import asyncio
import json
import re
import shutil

import config


def available() -> tuple:
    if shutil.which(config.PHONEINFOGA_BIN):
        return True, ""
    return False, (
        "PhoneInfoga غير مثبت محليًا — حمّل الثنائي من "
        "github.com/sundowndev/phoneinfoga أو ضع مساره في PHONEINFOGA_BIN"
    )


async def _run(args: list, timeout: int = 60) -> str:
    import subprocess

    proc = await asyncio.create_subprocess_exec(
        config.PHONEINFOGA_BIN, *args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return ""
    return out.decode("utf-8", "ignore")


async def search_phone(number: str, progress=None) -> dict:
    """معلومات فنية عن الرقم + قائمة المنصات (عبر holehe في راوتر الرقم)."""
    ok, msg = available()
    if not ok:
        if progress:
            progress("warn", msg)
        return {"number": number, "tech": None, "note": msg}

    if progress:
        progress("info", "جارٍ تحليل رقم الهاتف عبر PhoneInfoga…")

    tech = {}
    out = await _run(["scan", "-n", number])
    tech["scan"] = parse_scan(out)

    if progress:
        progress("info", "جارٍ استخراج الموقع الجغرافي للرقم…")
    loc = await _run(["locate", "-n", number])
    tech["location"] = parse_location(loc)

    return {"number": number, "tech": tech, "note": ""}


def parse_scan(text: str) -> dict:
    """قراءة معلومات الفحص: رمز الدولة، شركة الاتصالات، الصيغة…"""
    out = {}
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        m = re.search(r'"([A-Za-z_ ]+)":\s*"?([^",}]+)"?', ln)
        if m:
            out[m.group(1).strip()] = m.group(2).strip()
    if not out:
        # صيغة النص: key: value
        for ln in lines:
            m = re.search(r"^([A-Za-z_ ]+):\s*(.+)$", ln)
            if m:
                out[m.group(1).strip()] = m.group(2).strip()
    return out


def parse_location(text: str) -> dict:
    out = {}
    for ln in text.splitlines():
        ln = ln.strip()
        if "|" in ln:
            parts = [p.strip() for p in ln.split("|")]
            if len(parts) >= 4:
                out = {"country": parts[0], "region": parts[1],
                       "city": parts[2], "coordinates": parts[3]}
                break
    return out if out else {"raw": text[:500]}