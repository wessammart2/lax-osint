"""LAX OSINT — خدمة البحث بالاسم الكامل (Deep Search)
مصمّمة لتجنّب حجب Google/DuckDuckGo من IP الخادم (Error 429):
- تناوب 30 User-Agent مختلف مع كل طلب
- delays عشوائية بين الطلبات (SEARCH_DELAY_MIN … SEARCH_DELAY_MAX) عبر _smart_delay
- retry مع exponential backoff عند الخطأ أو الحجب
- كاش في قاعدة البيانات (جدول search_cache، صلاحية CACHE_TTL_HOURS=24 ساعة)
  عبر ENABLE_CACHE — يمنع تكرار نفس الطلب
- محركات احتياطية: Google (googlesearch-python) ← Wikipedia API ← LinkedIn ← Twitter API
- تقليل النتائج إلى SEARCH_MAX_RESULTS (افتراضي 5) لتقليل الضغط
- دعم Proxy اختياري عبر SEARCH_PROXY / HTTP_PROXY
"""
import asyncio
import hashlib
import inspect
import json
import os
import pathlib
import random
import re
import tempfile
import time as _time
import urllib.parse
import warnings

import config

warnings.filterwarnings("ignore", message=".*duckduckgo_search.*renamed.*")
warnings.filterwarnings("ignore", message=".*has been renamed.*")

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

# ملاحظة: تُسجَّل الفلاتر هنا وليس قبل الاستيراد، لأن حزمة duckduckgo_search
# تُدرج `simplefilter("always")` في مقدمة قائمة الفلاتر لحظة استيرادها،
# فتُلغي أي فلتر ignore مُسجَّل قبلها. بعد الاستيراد يصبح فلترنا في المقدمة.
warnings.filterwarnings("ignore", message=".*duckduckgo_search.*renamed.*")
warnings.filterwarnings("ignore", message=".*has been renamed.*")


def _tool_status():
    tools = []
    tools.append("DuckDuckGo (DDGS)" if DDGS_OK else "duckduckgo-search غير مثبت")
    tools.append("Google (googlesearch-python)" if GOOGLE_OK else "googlesearch-python غير مثبت")
    try:
        import httpx  # noqa: F401
        tools.append("Wikipedia API (httpx)")
    except Exception:
        tools.append("httpx غير مثبت")
    try:
        __import__("bs4")
        tools.append("BeautifulSoup")
    except Exception:
        pass
    return tools


# قائمة 28 User-Agent للتناوب العشوائي لتجنّب حجب محركات البحث
_USER_AGENTS = [
    # Chrome — Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # Chrome — macOS / Linux
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Chrome — Android / iPhone
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.80 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.105 Mobile/15E148 Safari/604.1",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Android 14; Mobile; rv:126.0) Gecko/126.0 Firefox/126.0",
    # Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    # Opera / Brave
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Brave/1.66.110",
]


def _headers() -> dict:
    ua = random.choice(_USER_AGENTS)
    if not config.USER_AGENT_ROTATION:
        ua = _USER_AGENTS[0]
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice([
            "en-US,en;q=0.9,ar;q=0.8",
            "ar,en-US;q=0.9,en;q=0.8",
            "en-US,en;q=0.9;q=0.8,fr;q=0.7",
        ]),
        "Cache-Control": "no-cache",
        "DNT": "1",
    }


def _proxy_value():
    return config.SEARCH_PROXY or None


# ---------------------------------------------------------------
#  كاش ملفي محلي (يعمل فورًا بدون الحاجة لجدول Supabase)
#  الهدف: عدم تكرار نفس الطلب لنفس الاسم خلال CACHE_TTL_HOURS.
#  عند وجود جدول public.search_cache في Supabase يُستخدم أيضًا ككاش
#  مشترك/دائم (يعبر إعادة النشر) — هنا طبقة سريعة وموثوقة في /tmp.
# ---------------------------------------------------------------
_CACHE_ROOT = pathlib.Path(
    os.getenv("SEARCH_CACHE_DIR") or os.path.join(tempfile.gettempdir(), "lax_search_cache")
)


def _file_cache_path(key):
    safe = re.sub(r"[^a-z0-9]+", "_", key.lower())[:60].strip("_")
    digest = hashlib.md5(key.encode("utf-8")).hexdigest()[:10]
    return _CACHE_ROOT / f"{safe}_{digest}.json"


def _file_cache_get(key):
    try:
        p = _file_cache_path(key)
        if not p.exists():
            return None
        raw = json.loads(p.read_text(encoding="utf-8"))
        if _time.time() - (raw.get("saved_at") or 0) > config.CACHE_TTL_HOURS * 3600:
            return None
        return raw.get("payload")
    except Exception:
        return None


def _file_cache_set(key, payload):
    try:
        _CACHE_ROOT.mkdir(parents=True, exist_ok=True)
        p = _file_cache_path(key)
        p.write_text(
            json.dumps({"saved_at": _time.time(), "payload": payload}, ensure_ascii=False),
            encoding="utf-8",
        )
        return True
    except Exception:
        return False


async def _smart_delay(backoff=0, progress=None):
    """تأجيل عشوائي بين الطلبات؛ مع exponential backoff عند إعادة المحاولة."""
    base = random.uniform(config.SEARCH_DELAY_MIN, config.SEARCH_DELAY_MAX)
    delay = min((base * (2 ** backoff)) + random.uniform(0, base), 120)
    await asyncio.sleep(delay)
    return delay


def _make_ddgs():
    """ينشئ DDGS مع منع الحزمة من فرض إظهار تحذير إعادة التسمية.

    duckduckgo_search 8.x يستدعي `warnings.simplefilter("always")` داخل
    DDGS.__init__ عند كل إنشاء، فيتجاوز فلاترنا. نعطّل function مؤقتًا ثم نعيدها.
    """
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
    _orig_simplefilter = warnings.simplefilter

    def _noop(*_a, **_k):
        pass

    warnings.simplefilter = _noop
    try:
        return DDGS(**kw)
    finally:
        warnings.simplefilter = _orig_simplefilter


async def _ddg_search(full_name: str, progress=None) -> list:
    """بحث DuckDuckGo: auto → lite → html مع exponential backoff وتأجيل عشوائي."""
    backends = []
    try:
        params = inspect.signature(DDGS.text).parameters
        backends = ["auto", "lite", "html"] if "backend" in params else [None]
    except Exception:
        backends = [None]

    last_err = None
    for attempt, backend in enumerate(backends):
        if attempt:
            delay = await _smart_delay(backoff=attempt - 1, progress=progress)
            if progress:
                progress("info", f"إعادة محاولة DuckDuckGo ({backend}) بعد {round(delay, 1)} ث…")

        def _run():
            with _make_ddgs() as ddgs:
                kw = {"max_results": config.SEARCH_MAX_RESULTS}
                if backend:
                    kw["backend"] = backend
                return list(ddgs.text(full_name, **kw))

        try:
            hits = await asyncio.wait_for(asyncio.to_thread(_run), timeout=30)
            if hits:
                return hits
        except Exception as e:  # noqa: BLE001
            last_err = e
    if last_err and progress:
        progress("warn", f"DuckDuckGo فشل في كل المحاولات: {last_err}")
    return []


def _google_kwargs():
    params = inspect.signature(_google_text).parameters
    kw = {"num_results": config.SEARCH_MAX_RESULTS}
    if "advanced" in params:
        kw["advanced"] = True
    proxy = _proxy_value()
    if proxy and "proxy" in params:
        kw["proxy"] = proxy
    return kw


async def _google_search(full_name: str, progress=None) -> list:
    """بحث Google عبر googlesearch-python مع إعادة محاولة واحدة بعد تأجيل عشوائي."""

    def _run():
        kw = _google_kwargs()
        out = []
        for allow_old in (False, True):
            try:
                k = {kk: vv for kk, vv in kw.items() if not (allow_old and kk == "advanced")}
                items = list(_google_text(full_name, **k))
                break
            except TypeError:
                items = []
                continue
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

    out = await asyncio.to_thread(_run)
    if not out:
        delay = await _smart_delay(progress=progress)
        if progress:
            progress("info", f"إعادة محاولة Google بعد {round(delay, 1)} ث…")
        out = await asyncio.to_thread(_run)
    return out


# مواقع ويكيبيديا المدعومة بالعربية والإنجليزية وغيرها (بديل موثوق بدون مفاتيح)
WIKI_LANGS = ["ar", "en", "fa", "fr", "de", "es", "tr", "ur"]


async def _wikipedia_search(full_name: str, progress=None) -> list:
    """بحث Wikipedia API (مجاني، لا يحجب IP الخوادم) — محرك احتياطي أساسي."""
    import httpx

    rows = []
    try:
        async with httpx.AsyncClient(headers=_headers(), timeout=12) as client:
            for lang in WIKI_LANGS:
                if len(rows) >= config.SEARCH_MAX_RESULTS:
                    break
                await asyncio.sleep(random.uniform(0.4, 1.2))  # ليسرع الموقع لا يُحجب
                try:
                    r = await client.get(f"https://{lang}.wikipedia.org/w/api.php", params={
                        "action": "query", "list": "search",
                        "srsearch": full_name, "srlimit": 3,
                        "format": "json", "utf8": "1",
                    })
                    r.raise_for_status()
                    for it in (r.json().get("query", {}).get("search", []) or []):
                        title = (it.get("title") or "").strip()
                        if not title:
                            continue
                        snippet = (it.get("snippet") or "")
                        snippet = re.sub(r"<[^>]+>", "", snippet)
                        rows.append({
                            "title": f"{title} — ويكيبيديا ({lang})",
                            "url": "https://" + lang + ".wikipedia.org/wiki/" +
                                   urllib.parse.quote(title.replace(" ", "_")),
                            "body": snippet[:400],
                        })
                except Exception:
                    continue
    except Exception:
        pass
    rows = rows[:config.SEARCH_MAX_RESULTS]
    if progress and rows:
        progress("info", f"Wikipedia API أعاد {len(rows)} نتيجة")
    return rows


async def _linkedin_search(full_name: str, progress=None) -> list:
    """بحث LinkedIn العام: في الغالب يتطلب تسجيل دخول، محاولة مرة واحدة فقط وبأمان."""
    import httpx

    parts = full_name.strip().split()
    if len(parts) < 2:
        return []
    first = urllib.parse.quote(parts[0])
    last = urllib.parse.quote(" ".join(parts[1:]))
    url = f"https://www.linkedin.com/pub/dir/?firstName={first}&lastName={last}"
    rows = []
    try:
        async with httpx.AsyncClient(headers=_headers(), timeout=8, follow_redirects=False) as c:
            r = await c.get(url)
            if r.status_code == 200:
                seen = set()
                for m in re.findall(r'href="([^"]*/in/[A-Za-z0-9_-]+)"', r.text):
                    href = m if m.startswith("http") else "https://www.linkedin.com" + m
                    href = href.split("?")[0]
                    if href in seen:
                        continue
                    seen.add(href)
                    rows.append({"title": "LinkedIn profile", "url": href, "body": ""})
    except Exception:
        pass
    if progress and rows:
        progress("info", f"LinkedIn أعاد {len(rows)} نتيجة")
    return rows


async def _twitter_search(full_name: str, progress=None) -> list:
    """بحث Twitter/X API: نسخة مجانية محدودة — يعمل فقط عند ضبط TWITTER_BEARER_TOKEN."""
    if not config.TWITTER_BEARER_TOKEN:
        return []
    import httpx

    rows = []
    headers = {"Authorization": f"Bearer {config.TWITTER_BEARER_TOKEN}",
               "User-Agent": "lax-osint/1.0"}
    for base in ("https://api.twitter.com/2/users/search",
                 "https://api.x.com/2/users/search"):
        try:
            async with httpx.AsyncClient(headers=headers, timeout=10) as c:
                r = await c.get(base, params={
                    "query": full_name, "max_results": config.SEARCH_MAX_RESULTS,
                    "user.fields": "name,username,description,location"})
                r.raise_for_status()
                for u in (r.json().get("data") or []):
                    uname = u.get("username", "")
                    rows.append({
                        "title": f"{u.get('name') or uname} (@{uname})",
                        "url": f"https://twitter.com/{uname}",
                        "body": (u.get("description") or "")[:400],
                    })
                break
        except Exception as e:  # noqa: BLE001
            if progress:
                progress("warn", f"Twitter API فشل: {e}")
            continue
    return rows


EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(\+?\d[\d\s().-]{7,}\d)")
AGE_RE = re.compile(r"\b(\d{1,3})\s*(سنة|عام|سنوات|years old|yo)\b", re.I)
DATE_RE = re.compile(r"^\d{1,4}[-/.]\d{1,2}[-/.]\d{1,4}$")  # استبعاد تواريخ شبيهة بالأرقام


def _extract(text: str) -> dict:
    info = {}
    emails = set(EMAIL_RE.findall(text))
    phones = {m.strip() for m in PHONE_RE.findall(text) if not DATE_RE.match(m.strip())}
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
    engine_used = None

    from db import db

    cache_key = full_name.strip().lower()

    # ١) الكاش: إن وُجدت نتيجة حديثة (24 ساعة) فلا حاجة لأي طلب خارجي
    cached = None
    if config.ENABLE_CACHE:
        if hasattr(db, "search_cache_get"):
            try:
                cached = await asyncio.to_thread(db.search_cache_get, cache_key)
            except Exception:
                cached = None
        if cached is None:
            cached = await asyncio.to_thread(_file_cache_get, cache_key)  # كاش /tmp فوري
    if cached and cached.get("dossier"):
        if progress:
            progress("info", "النتائج من الكاش المحفوظ (أقل من 24 ساعة) — بدون طلب جديد")
        cached["dossier"].setdefault("details", {})["cache"] = "hit"
        return {"results": cached.get("results", []), "dossier": cached["dossier"]}

    if not DDGS_OK and not GOOGLE_OK:
        if progress:
            progress("warn", "مكتبات البحث غير مثبتة — شغّل: pip install duckduckgo-search googlesearch-python")
        dossier["details"]["tools"] = _tool_status()
        return {"results": results, "dossier": dossier}

    raw = []

    # ٢) DuckDuckGo مع تناوب UA وbackoff
    if DDGS_OK:
        if progress:
            progress("info", "البحث بالاسم الكامل عبر DuckDuckGo…")
        hits = await _ddg_search(full_name, progress)
        raw = [{"title": h.get("title", ""), "url": h.get("href", ""),
                "body": h.get("body", "")} for h in hits if isinstance(h, dict)]
        if raw:
            engine_used = "DuckDuckGo (DDGS)"

    # ٣) بديل Google
    if not raw and GOOGLE_OK:
        await _smart_delay(progress=progress)
        if progress:
            progress("info", "الاستعانة بمحرك Google الاحتياطي…")
        engine_used = "Google (googlesearch-python)"
        try:
            raw = await _google_search(full_name, progress) or raw
        except Exception as e:  # noqa: BLE001
            if progress:
                progress("warn", f"Google فشل: {e}")

    # ٤) بديل Wikipedia API (لا يُحجب IP الخوادم)
    if not raw:
        await _smart_delay(progress=progress)
        if progress:
            progress("info", "الاستعانة بـ Wikipedia API…")
        engine_used = "Wikipedia API"
        raw = await _wikipedia_search(full_name, progress)

    # ٥) بديل LinkedIn (إن وُجدت نتائج عامة)
    if not raw:
        await _smart_delay(progress=progress)
        engine_used = "LinkedIn"
        raw = await _linkedin_search(full_name, progress)

    # ٦) بديل Twitter API (يعمل عند ضبط TWITTER_BEARER_TOKEN فقط)
    if not raw and config.TWITTER_BEARER_TOKEN:
        await _smart_delay(progress=progress)
        engine_used = "Twitter API"
        raw = await _twitter_search(full_name, progress)

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
        "engine_used": engine_used,
        "tools": _tool_status(),
    }
    dossier["details"] = detail
    payload = {"results": results, "dossier": dossier}

    # ٧) حفظ الكاش للنتائج غير الفارغة (يقلّل الطلبات المتكررة لنفس الاسم)
    if config.ENABLE_CACHE:
        try:
            await asyncio.to_thread(_file_cache_set, cache_key, payload)
        except Exception:
            pass
        if hasattr(db, "search_cache_set"):   # إن وُجد جدول search_cache في Supabase
            try:
                await asyncio.to_thread(db.search_cache_set, cache_key, payload)
            except Exception:
                pass
    return payload


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
            page = await browser.new_page(user_agent="")
            await page.goto("https://www.google.com/search?q=" + urllib.parse.quote(full_name),
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