"""LAX OSINT — خدمة البحث بالإيميل عبر holehe (120+ موقع)
تحقق الإيميل في المنصات المدعومة وتُخرِج حالة التسجيل في كل موقع.
"""
import asyncio
import re
import shutil

import config


def available() -> tuple:
    if shutil.which(config.HOLEHE_BIN):
        return True, ""
    try:
        import holehe  # noqa: F401
        return True, ""
    except Exception:
        return False, (
            "holehe غير مثبت محليًا — شغّل: pip install holehe "
            "(أو ضع مسار الـ binary في HOLEHE_BIN)"
        )


async def search_email(email: str, progress=None) -> list:
    ok, msg = available()
    if not ok:
        if progress:
            progress("warn", msg)
        return [{"site": "holehe", "email": email, "status": "warning", "note": msg}]

    if progress:
        progress("info", "جارٍ فحص الإيميل عبر holehe…")
    try:
        import holehe.cli  # noqa: F401
        # holehe يوفر main يمكن معالجته عبر arguments
        from holehe import main
    except Exception:
        pass

    # الأسلوب الأكثر استقرارًا: استدعاء برنامج holehe كعملية تفاعلية مع تفسير المخرجات
    try:
        text = await _run_cli(email)
    except Exception as e:
        return [{"site": "holehe", "email": email, "status": "error", "note": str(e)}]

    return parse_output(text, email)


async def _run_cli(email: str, timeout: int = 120) -> str:
    import subprocess

    proc = await asyncio.create_subprocess_exec(
        config.HOLEHE_BIN, email, "--no-color", "--no-clear", "-T", "20",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return ""
    return out.decode("utf-8", "ignore")


# أنماط لقراءة مخرجات holehe CLI — صيغة التقرير:
#   [+] site.com      -> الإيميل مستخدم (مسجل)
#   [-] site.com      -> غير مستخدم
#   [x] site.com      -> Rate limit
RESULT_LINE = re.compile(r"^\[(.)\]\s+(\S+?)\s*$")
MARK_TO_STATUS = {"+": "registered", "-": "not_registered", "x": "rate_limited"}
RE_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_output(text: str, email: str) -> list:
    """حول نص إخراج holehe إلى نتائج (موقع، حالة)."""
    results = []
    seen = set()
    for ln in text.splitlines():
        ln = RE_ANSI.sub("", ln).strip()
        # نتجاوز سطور شريط التقدم "12%|...|"
        if not ln or ln[0].isdigit() or "|" in ln[:3]:
            continue
        m = RESULT_LINE.match(ln)
        if not m:
            continue
        site = m.group(2)
        key = site.lower()
        if key in seen:
            continue
        seen.add(key)
        results.append({"site": site, "email": email, "status": MARK_TO_STATUS.get(m.group(1), "unknown")})
    return results