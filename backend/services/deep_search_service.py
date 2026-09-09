"""LAX OSINT — خدمة البحث بالاسم الكامل (Deep Search)
يستخرج ملفًا استخباراتيًا (Dossier) من:
- DuckDuckGo Search (بحث عام)
- اختبار وجود إيميل/رقم/عمر/مدينة/مهنة من صفحات النتائج (تفسير مبسط)
- Gravatar/فيسبوك اختياري (facebook-scraper / playwright) إن ثُبّتت
"""
import re

# محاولة استيراد مكتبات اختيارية
try:
    from duckduckgo_search import DDGS  # pip install duckduckgo-search
    DDGS_OK = True
except Exception:
    DDGS_OK = False


def _tool_status():
    tools = []
    tools.append("DDGS" if DDGS_OK else "duckduckgo-search غير مثبت")
    try:
        __import__("facebook_scraper")
        tools.append("facebook_scraper")
    except Exception:
        tools.append("facebook_scraper غير مثبت")
    try:
        __import__("bs4")
        tools.append("BeautifulSoup")
    except Exception:
        tools.append("BeautifulSoup غير مثبت")
    return tools


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


async def deep_search(full_name: str, progress=None) -> dict:
    results = []
    dossier = {"full_name": full_name, "details": {}, "sources": []}

    if not DDGS_OK:
        if progress:
            progress("warn", "مكتبة duckduckgo-search غير مثبتة — شغّل: pip install duckduckgo-search")
        dossier["details"]["tools"] = _tool_status()
        return {"results": results, "dossier": dossier}

    if progress:
        progress("info", "جارٍ البحث بالاسم الكامل عبر الإنترنت…")

    try:
        with DDGS() as ddgs:
            hits = list(ddgs.text(full_name, max_results=12))
    except Exception as e:
        if progress:
            progress("warn", f"بحث DuckDuckGo فشل: {e}")
        return {"results": results, "dossier": dossier}

    for hit in hits:
        title = hit.get("title", "")
        url = hit.get("href", "")
        body = hit.get("body", "")
        snippet = " ".join([title, body])
        info = _extract(snippet)
        results.append({"title": title, "url": url, "body": body[:400], "info": info})
        dossier["sources"].append(url)

    # تجميع "الملف الاستخباراتي"
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