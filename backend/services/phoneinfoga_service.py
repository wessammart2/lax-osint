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
    """معلومات فنية عن الرقم (فقط فحص — PhoneInfoga v2 لم يعد يحتوي أمر locate)."""
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

    # PhoneInfoga v2.11 أزال أمر locate — نستخرج البلد من نتائج الفحص مباشرة
    country = (tech["scan"].get("Country") or "").strip()
    if country:
        tech["location"] = {
            "country": country,
            "region": tech["scan"].get("region", ""),
            "city": tech["scan"].get("city", ""),
            "note": "مستخرج من فحص PhoneInfoga",
        }
    else:
        tech["location"] = {"raw": out[:300] if out else "لا توجد معلومات"}

    links = tech["scan"].get("links") or []
    if links:
        tech["links"] = links

    return {"number": number, "tech": tech, "note": ""}


def parse_scan(text: str) -> dict:
    """قراءة معلومات الفحص: رمز الدولة، شركة الاتصالات، الصيغة…
    صيغة PhoneInfoga v2 (scan): سطور "key: value" + أقسام بها "URL: ..."
    """
    out = {}
    links = []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    for ln in lines:
        m = re.search(r'"([A-Za-z_ ]+)":\s*"?([^",}]+)"?', ln)
        if m:
            out[m.group(1).strip()] = m.group(2).strip()
            continue
        m = re.search(r"^([A-Za-z_ ]+):\s*(.+)$", ln)
        if m:
            key, val = m.group(1).strip(), m.group(2).strip()
            if key.lower() == "url":
                links.append(val)
            else:
                out[key] = val
    if links:
        out["links"] = links
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