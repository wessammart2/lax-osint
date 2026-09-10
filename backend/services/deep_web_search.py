"""LAX OSINT — بحث الديب ويب (Deep Web / Dark Web) عبر Tor — آمن واختياري.

المبدأ الواضح:
  - بدون خادم Tor تكوينه (TOR_PROXY) لا نجري أي اتصال بمخفي (onion):
    تُرجع حالة needs_tor صريحة مع بدائل آمنة (بحث في منصات نسخ التسريبات
    العامة + Google) — لا نصل لأي سوق أو شبكة بدون ترخيص/إعدادات.
  - مع TOR_PROXY مفعّل (مثال: socks5h://127.0.0.1:9050):
    نبحث فقط عبر محرك بحث Tor العام (DuckDuckGo .onion) عن وجود الهدف في
    مؤشرات التسريبات والمنتديات، ونعرض النتائج كروابط للفتح اليدوي.
    أي بحث عن أسواق الممنوعات/الأسلحة/الجرائم لا يدعمه الموقع إطلاقًا — قوانين
    وآمان واضحة: استخدم المنصة فقط لأهدافك المصرح بها.

لا نقوم بأي فحص نشط ولا نجمع بيانات شخصية من طرف ثالث.
"""
import asyncio
import base64
import logging
import re

import config

LOG = logging.getLogger("deepweb")

_TIMEOUT = 15
_ONION_DDG = ("https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
              "html/?q=")

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# نصوص عربية توضح للواجهة حدود الاستخدام المسموح
_SAFE_NOTE = (
    "البحث الآمن: تُراجع التسريبات والمنصات العامة فقط. "
    "استخدم المنصة حصرًا على أهداف تملك الإذن بفحصها."
)


def _tor_available() -> bool:
    return bool(config.TOR_PROXY and config.TOR_PROXY.lower().startswith(("socks", "http")))


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s or "", safe="")


def _decode_ddg_redirect(url: str) -> str:
    m = re.search(r"uddg=([^&]+)", url)
    if m:
        try:
            return base64.urlsafe_b64decode(m.group(1) + "==").decode("utf-8", "ignore")
        except Exception:
            return url
    return url


async def _tor_search(query: str) -> list:
    """بحث عبر محرك Tor العام (DuckDuckGo onion) عن نص الهدف."""
    if not _tor_available():
        return []
    try:
        import requests  # عبر PySocks (socks5h) لتمرير ترافيك Tor
        r = requests.get(_ONION_DDG + _quote(query),
                         proxies={"http": config.TOR_PROXY, "https": config.TOR_PROXY},
                         headers={"User-Agent": _UA}, timeout=_TIMEOUT)
        rows = [] if r.status_code == 200 else []
        if not rows:
            results = []
            for raw, title in re.findall(r'<a rel="nofollow" class="result__a" href="([^"]+)">([^<]+)</a>', r.text):
                results.append({"title": _clean_html(title), "url": _decode_ddg_redirect(raw)})
            snips = re.findall(r'class="result__snippet"[^>]*>(.*?)</a>', r.text or "", re.S)
            for i, sn in enumerate(snips[: len(results)]):
                results[i]["snippet"] = _clean_html(sn)
            limit = 15
            results = results[:limit]
            # filter out trading/market/criminal keywords? نتائج المحرك عامة —
            # نُبعد أي نتيجة تبيع أسلحة/مخدرات بشكل صريح كضمان أمني
            banned = ("guns", "weapons", "firearm", "drug", "cocaine",
                      "heroin", "counterfeit", "credit-card-dumps", "hack-for-hire")
            results = [r for r in results if not any(b in (r.get("url") or "").lower() or b in (r.get("title") or "").lower() for b in banned)]
            return results
    except Exception as e:
        LOG.info("tor search unavailable: %s", e)
        return []


def _clean_html(s: str) -> str:
    s = re.sub(r"<[^>]+>", "", s or "")
    return (s or "").strip()


def _public_leak_links(kind: str, query: str) -> list:
    """روابط عامة آمنة للتحقق من التسريبات (بدون أي اتصال بـ Tor)."""
    quoted = _quote(query)
    links = [
        {"label": "VirusTotal (الإيميل/الرقم في تسريبات)", "url":
         f"https://www.virustotal.com/gui/search/{quoted}", "safe": True},
        {"label": "Google — تسريبات ومنتديات", "url":
         f"https://www.google.com/search?q=%22{quoted}%22+(breach+OR+leak+OR+dump+OR+paste)", "safe": True},
        {"label": "Pastebin بحث", "url":
         f"https://pastebin.com/search?q={quoted}", "safe": True},
        {"label": "HIBP (الإيميل)", "url":
         f"https://haveibeenpwned.com/account/{quoted}", "safe": True},
    ]
    if kind == "phone":
        links.append({"label": "بحث الرقم في منصات العناوين العامة", "url":
                      f"https://www.bing.com/search?q=%22{quoted}%22", "safe": True})
    return links


async def deepweb_search(kind: str, query: str, progress=None) -> dict:
    """واجهة البحث الآمن في الديب ويب — تُرجع {status, note, items, links}."""
    if progress:
        progress("info", "فحص مؤشرات الديب ويب (آمن، Tor اختياري)…")

    leak_hits = []
    tor_ready = _tor_available()
    if tor_ready:
        try:
            leak_hits = await asyncio.to_thread(_tor_search, query)
        except Exception as e:
            LOG.warning("deepweb search failed: %s", e)

    public_links = _public_leak_links(kind, query)

    if tor_ready:
        status = "ok" if leak_hits else "empty"
        note = (f"بحث عبر Tor اكتمل (نتائج {len(leak_hits)}). " + _SAFE_NOTE
                if leak_hits else "بحث Tor لا نتائج مطابقة. تحقق يدويًا عبر الروابط الآمنة.")
        return {"status": status, "tor": True, "note": note,
                "items": leak_hits, "links": public_links}
    return {"status": "needs_tor", "tor": False,
            "note": ("تشغيل أعمق يتطلب خادم Tor محليًا (TOR_PROXY=socks5h://127.0.0.1:9050). "
                     "إلى ذلك، إليك فحوص التسريبات العامة الآمنة: " + _SAFE_NOTE),
            "items": [], "links": public_links}