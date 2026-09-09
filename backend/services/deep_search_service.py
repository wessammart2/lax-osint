"""LAX OSINT — خدمة البحث بالاسم الكامل (Deep Search)
يستخرج ملفًا استخباراتيًا (Dossier) من:
- DuckDuckGo Search مع تناوب User-Agent وإعادة محاولة (backoff مع SEARCH_DELAY)
- بديل تلقائي: Google عبر googlesearch-python عند فشل DuckDuckGo
- دعم Proxy اختياري عبر متغير البيئة SEARCH_PROXY
- تفسير مبسط (إيميل/رقم/عمر) من نصوص النتائج
"""
import asyncio
import inspect
import random
import re
import warnings

import config

warnings.filterwarnings("ignore", message="This package .duckduckgo_search. has been renamed")

# محاولة استيراد محركات البحث
try:
    from duckduckgo_search import DDGS
    DDGS_OK = True
except Exception:
    DDGS_OK = False

try:
    from googlesearch import search as _google_text
    GOOGLE_OK = True
except Exception:
    GOOGLE_OK = False


def _tool_status():
    tools = []
    tools.append("DuckDuckGo (DDGS)" if DDGS_OK else "duckduckgo-search غير مثبت")
    tools.append("Google (googlesearch-python)" if GOOGLE_OK else "googlesearch-python غير مثبت")
    try:
        __import__("bs4")
        tools.append("BeautifulSoup")
    except Exception:
        tools.append("BeautifulSoup غير مثبت")
    return tools


# قائمة User-Agent للتبديل العشوائي لتجنّب حجب محركات البحث
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]


def _headers() -> dict:
    hd = {"Accept": "*/*", "Accept-Language": "en-US,en;q=0.9,*;q=0.8"}
    if config.USER_AGENT_ROTATION:
        hd["User-Agent"] = random.choice(_USER_AGENTS)
    else:
        hd["User-Agent"] = _USER_AGENTS[0]
    return hd


def _proxy_value():
    return config.SEARCH_PROXY or None


def _make_ddgs():
    """ينشئ DDGS متوافقًا مع نسخ المكتبة المختلفة (headers/proxies/proxy/timeout)."""
    params = inspect.signature(DDGS.__init__).parameters
    kw = {}
    if "headers" in params:
        kw["headers"] = _headers()
    if "proxies" in params:
        kw["proxies"] = _proxy_value()
    elif "proxy" in params:
        kw["proxy"] = _proxy_value()
    if "timeout" in params:
        kw["timeout"] = 15
    return DDGS(**kw)


async def _ddg_search(full_name: str, progress=None) -> list:
    """بحث DuckDuckGo مع 3 محاولات (auto → lite → html) وتأجيل بينها."""
    backends = []
    try:
        params = inspect.signature(DDGS.text).parameters
        if "backend" in params:
            backends = ["auto", "lite", "html"]
        else:
            backends = [None]
    except Exception:
        backends = [None]

    last_err = None
    for attempt, backend in enumerate(backends):
        await asyncio.sleep(config.SEARCH_DELAY * attempt)  # 0، 2، 4 ثانية
        try:
            def _run():
                with _make_ddgs() as ddgs:
                    if backend:
                        return list(ddgs.text(full_name, max_results=12, backend=backend))
                    return list(ddgs.text(full_name, max_results=12))
            hits = await asyncio.to_thread(_run)
            if hits:
                return hits
        except Exception as e:  # noqa: BLE001
            last_err = e
    if last_err and progress:
        progress("warn", f"DuckDuckGo فشل في كل المحاولات: {last_err}")
    return []


def _google_kwargs():
    params = inspect.signature(_google_text).parameters
    kw = {"num_results": 12}
    if "advanced" in params:
        kw["advanced"] = True
    proxy = _proxy_value()
    if proxy and "proxy" in params:
        kw["proxy"] = proxy
    return kw


async def _google_search(full_name: str, progress=None) -> list:
    """بحث Google عبر googlesearch-python (يعمل في المعالجات حيث Google غير محجوب)."""
    def _run():
        kw = _google_kwargs()
        out = []
        try:
            items = list(_google_text(full_name, **kw))
        except TypeError:
            # نسخ أقدم بلا معامل advanced
            base = {k: v for k, v in kw.items() if k != "advanced"}
            items = list(_google_text(full_name, **base))
        for it in items:
            if it is None:
                continue
            if hasattr(it, "url"):               # SearchResult (advanced=True)
                out.append({"title": getattr(it, "title", "") or "",
                            "url": it.url or "",
                            "body": getattr(it, "description", "") or ""})
            elif isinstance(it, dict):           # سجلات قاموس
                out.append({"title": it.get("title", "") or "",
                            "url": it.get("url", "") or "",
                            "body": it.get("description", it.get("body", "")) or ""})
            elif isinstance(it, str):            # روابط خام
                out.append({"title": "", "url": it, "body": ""})
        return out

    return await asyncio.to_thread(_run)


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(\+?\d[\d\s().-]{7,}\d)")
AGE_RE = re.compile(r"\b(\d{1,3})\s*(سنة|عام|سنوات|years old|yo)\b", re.I)
CITY_HINTS = ["يعيش في", "المدينة", "معروف من", "ساكن في", "lives in", "based in", "city:"]


def _extract(text: str) -> dict:
    info = {}
    emails = set(EMAIL_RE.findall(text))
    phones = set(m.strip() for m in PHONE_RE.findall(text))
    if emails:
        info["emails"] = list(emails)[:5]
    if phones:
        info["phones"] = list(phones)[:5]
    am = AGE_RE.search(text)
    if am:
        info["age"] = am.group(1)
    return info


def _build_row(row: dict) -> dict:
    snippet = " ".join([row["title"], row["body"]])
    info = _extract(snippet)
    return {"title": row["title"], "url": row["url"], "body": row["body"][:400], "info": info}


async def deep_search(full_name: str, progress=None) -> dict:
    results = []
    dossier = {"full_name": full_name, "details": {}, "sources": []}

    if not DDGS_OK and not GOOGLE_OK:
        if progress:
            progress("warn", "مكتبات البحث غير مثبتة — شغّل: pip install duckduckgo-search googlesearch-python")
        dossier["details"]["tools"] = _tool_status()
        return {"results": results, "dossier": dossier}

    raw = []
    if DDGS_OK:
        if progress:
            progress("info", "جارٍ البحث بالاسم الكامل عبر DuckDuckGo…")
        ddg_hits = await _ddg_search(full_name, progress)
        for hit in ddg_hits:
            if isinstance(hit, dict):
                raw.append({"title": hit.get("title", ""), "url": hit.get("href", ""),
                            "body": hit.get("body", "")})

    if not raw and GOOGLE_OK:
        if progress:
            progress("info", "الاستعانة بمحرك Google الاحتياطي…")
        try:
            raw = await _google_search(full_name, progress)
        except Exception as e:  # noqa: BLE001
            if progress:
                progress("warn", f"Google فشل: {e}")

    if not raw:
        if progress:
            progress("warn", "محركات البحث لم تُرجع نتائج (حجب/حصص مؤقت من IP الخادم) — جرّب لاحقًا أو استخدم اسمًا أكثر تخصصًا")
        dossier["details"] = {"tools": _tool_status()}
        return {"results": results, "dossier": dossier}

    for row in raw:
        item = _build_row(row)
        results.append(item)
        dossier["sources"].append(row.get("url", ""))

    detail = {
        "name_found": results[0]["title"] if results else None,
        "emails": sorted({e for r in results for e in (r["info"].get("emails") or [])}),
        "phones": sorted({p for r in results for p in (r["info"].get("phones") or [])}),
        "age": next((r["info"]["age"] for r in results if r["info"].get("age")), None),
        "tools": _tool_status(),
    }
    dossier["details"] = detail
    return {"results": results, "dossier": dossier}


async def search_facebook(full_name: str, progress=None) -> dict:
    """محاولة اختيارية لجلب صورة/بيانات فيسبوك (إن نُصّب facebook-scraper)."""
    try:
        from facebook_scraper import get_profile
    except Exception:
        return {}
    try:
        pf = dict(get_profile(full_name))
        return {"url": pf.get("url", ""), "picture": pf.get("profile_picture", ""),
                "name": pf.get("name", ""), "about": pf.get("about", "") or pf.get("bio", "")}
    except Exception:
        return {}


async def search_playwright(full_name: str, progress=None) -> list:
    """خيار ثقيل (اختياري): فتح صفحات النتائج واستخراج معلومات عبر Playwright+BS4."""
    try:
        from bs4 import BeautifulSoup
        from playwright.async_api import async_playwright
    except Exception:
        return []
    found = []
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto("https://www.google.com/search?q=" + full_name.replace(" ", "+"),
                            timeout=20000)
            content = await page.content()
            soup = BeautifulSoup(content, "html.parser")
            for a in soup.select("a[href^='http']")[:15]:
                href = a.get("href", "")
                txt = a.get_text(" ", strip=True)
                if txt and len(txt) > 12:
                    found.append({"title": txt[:120], "url": href})
            await browser.close()
    except Exception:
        pass
    return found