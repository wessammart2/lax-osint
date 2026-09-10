"""LAX OSINT — خدمة البحث بالإيميل عبر holehe (120+ موقع)

التحقق الصارم (strict):
  نفحص الإيميل في المنصات المدعومة عبر مكتبة holehe الرسمية (trio + httpx)
  بنفس منطق التحقق لكل موقع (صفحة التسجيل / استرداد كلمة المرور / البروفايل)،
  ونُبقي فقط النتائج المؤكَّدة 100% (exists=True وليست Rate limit).
  يُستبعد: غير المسجّل، محدود الطلبات، وكل ما ليس مؤكدًا.

الأداء:
  - طلبات متوازية (حد أقصى MAX_CONCURRENCY في آنٍ واحد).
  - مهلة REQUEST_TIMEOUT ثانية لكل طلب HTTP.
  - كاش بالذاكرة لمدة 24 ساعة لنفس الإيميل.

الأخطاء:
  - فشل موقع واحد لا يوقف البحث (سجل واستمر).
  - إن تعذّرت المكتبة، نتراجع إلى holehe CLI مع نفس الفلترة الصارمة.
"""
import asyncio
import logging
import re
import shutil
import threading
import time

import config

LOG = logging.getLogger("holehe")

CACHE_TTL = 24 * 3600        # نحتفظ بنتائج الإيميل لمدة 24 ساعة
REQUEST_TIMEOUT = 10         # مهلة كل طلب HTTP بالثواني
MAX_CONCURRENCY = 60         # أقصى عدد طلبات موازية

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_CACHE = {}
_CACHE_LOCK = threading.Lock()


def available() -> tuple:
    """هل holehe جاهز للاستخدام؟"""
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


_MODULE_COUNT = None


def platform_count() -> int:
    """عدد كل منصات holehe المدعومة فعليًا (≈121) — بدون تشغيل الفحص."""
    global _MODULE_COUNT
    if _MODULE_COUNT is None:
        try:
            from holehe.core import get_functions, import_submodules
            _MODULE_COUNT = len(get_functions(import_submodules("holehe.modules")))
        except Exception:
            _MODULE_COUNT = 0
    return _MODULE_COUNT


# ---------------------------------------------------------------------------
# كاش 24 ساعة
# ---------------------------------------------------------------------------
def _copy(x: dict) -> dict:
    return dict(x)


def _cache_get(email) -> list:
    key = email.strip().lower()
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and time.time() - hit[0] < CACHE_TTL:
            return [_copy(x) for x in hit[1]]
    return None


def _cache_set(email, results: list):
    key = email.strip().lower()
    with _CACHE_LOCK:
        _CACHE[key] = (time.time(), [_copy(x) for x in results])


# ---------------------------------------------------------------------------
# الفلترة الصارمة: نتائج مؤكدة فقط
# ---------------------------------------------------------------------------
def _strict(raw: list, email: str) -> list:
    """نُبقي فقط المواقع التي أكّدت تسجيل الإيميل (exists=True، status=registered)."""
    items, seen = [], set()
    for it in raw or []:
        if not isinstance(it, dict):
            continue
        if it.get("exists") is True and not it.get("rateLimit"):
            site = it.get("domain") or it.get("name") or ""
            username = it.get("username") or ""
            recovery = it.get("emailrecovery")
        elif it.get("status") == "registered":
            site = it.get("site") or it.get("name") or ""
            username = it.get("username") or ""
            recovery = it.get("note") or it.get("emailrecovery")
        else:
            continue  # غير مؤكد، غير مسجّل، Rate limit، مجهول → استبعاد

        key = site.lower()
        if not key or key in seen:
            continue
        seen.add(key)

        item = {
            "site": site,
            "name": it.get("name") or site,
            "email": email,
            "status": "registered",
            "url": _site_url(site),
        }
        if username:
            item["username"] = username
        if recovery:
            item["note"] = "استرداد: %s" % recovery
        items.append(item)
    return items


def _site_url(domain: str) -> str:
    d = (domain or "").strip()
    if not d or "." not in d:
        return ""
    return "https://" + d


# ---------------------------------------------------------------------------
# البحث عبر مكتبة holehe (trio) — التوازي والتجاوز عن الأخطاء
# ---------------------------------------------------------------------------
def _search_library(email: str) -> list:
    import httpx
    import trio
    from holehe.core import get_functions, import_submodules, launch_module

    modules = import_submodules("holehe.modules")
    funcs = get_functions(modules)
    if not funcs:
        raise RuntimeError("لا توجد وحدات holehe متاحة")

    out = []

    async def _main():
        client = httpx.AsyncClient(timeout=REQUEST_TIMEOUT,
                                   headers={"User-Agent": _UA},
                                   follow_redirects=True)
        sem = trio.Semaphore(MAX_CONCURRENCY)
        try:
            async with trio.open_nursery() as nursery:
                async def guarded(mod):
                    async with sem:
                        try:
                            await launch_module(mod, email, client, out)
                        except Exception:
                            # فشل الموقع لا يوقف البحث
                            LOG.warning("holehe module failed: %s",
                                        getattr(mod, "__name__", mod))
                for mod in funcs:
                    nursery.start_soon(guarded, mod)
        finally:
            await client.aclose()

    trio.run(_main)
    return out


# ---------------------------------------------------------------------------
# احتياطي: holehe CLI (نفس الفلترة الصارمة في التحليل)
# ---------------------------------------------------------------------------
async def _run_cli(email: str, timeout: int = 120) -> str:
    proc = await asyncio.create_subprocess_exec(
        config.HOLEHE_BIN, email, "--no-color", "--no-clear", "-T", "10",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return ""
    return out.decode("utf-8", "ignore")


# أنماط مخرجات holehe CLI:
#   [+] site.com -> مستخدم (مسجّل) | [-] -> غير مستخدم | [x] -> Rate limit
RESULT_LINE = re.compile(r"^\[(.)\]\s+(\S+?)\s*$")
RE_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def parse_output(text: str, email: str) -> list:
    """تحويل نص CLI إلى نتائج ثم الفلترة الصارمة (مسجّل فقط)."""
    raw, seen = [], set()
    for ln in text.splitlines():
        ln = RE_ANSI.sub("", ln).strip()
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
        status = {"+": "registered", "-": "not_registered",
                  "x": "rate_limited"}.get(m.group(1), "unknown")
        raw.append({"site": site, "email": email, "status": status})
    return _strict(raw, email)


# ---------------------------------------------------------------------------
# الواجهة
# ---------------------------------------------------------------------------
async def search_email(email: str, progress=None) -> list:
    """فحص الإيميل وإرجاع النتائج المؤكدة فقط (مع كاش 24 ساعة)."""
    ok, msg = available()
    if not ok:
        if progress:
            progress("warn", msg)
        return [{"site": "holehe", "email": email, "status": "warning",
                 "note": msg, "url": ""}]

    cached = _cache_get(email)
    if cached is not None:
        if progress:
            progress("info", "نتائج من الفحص السابق (مخزنة 24 ساعة)")
        return cached

    if progress:
        progress("info", f"جارٍ فحص الإيميل في {platform_count() or 120} منصة (طلبات متوازية)…")

    results = None
    try:
        # المحرك الأساسي: مكتبة holehe داخل thread (تريو له حلقة خاصة)
        raw = await asyncio.to_thread(_search_library, email)
        results = _strict(raw, email)
    except Exception as e:
        LOG.warning("holehe library failed (%s) — fallback to CLI", e)
        if progress:
            progress("warn", "محاولة عبر holehe CLI…")

    if results is None:
        try:
            text = await _run_cli(email)
            results = parse_output(text, email)
        except Exception as e:
            LOG.error("holehe search failed entirely: %s", e)
            return [{"site": "holehe", "email": email, "status": "error",
                     "note": str(e), "url": ""}]

    _cache_set(email, results)
    return results