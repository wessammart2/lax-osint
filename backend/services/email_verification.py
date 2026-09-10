"""LAX OSINT — التحقق الصارم من الإيميل (نسبة تأكيد 100%).

يجمع كل ما يتعلق بالإيميل في كيان واحد:
  1) Gravatar: صورة + اسم الشخص (display_name) وإن وجد حساب عام.
  2) holehe (فحص شامل 121 منصة): النتائج المؤكدة فقط (registered=True).
  3) HaveIBeenPwned: التسريبات (يتطلب HIBP_API_KEY — يمرر كتحذير بدونه).
  4) RDAP WHOIS لنطاق الإيميل (سجل الموقع، تاريخ الإنشاء، المسجل).
  5) كشف مزوّد الإيميل (MX Records): Gmail / Outlook / Yahoo / iCloud …
     + منصات غير مدعومة في holehe (Steam, Netflix, PayPal) عبر روابط بحث موجهة.
  6) صورة لكل منصة مؤكدة: بروفايل المنصة إن وُجد، وإلا unavatar بالإيميل.
  7) روابط بحث إضافية: Google (نصي/صور) + Bing + DuckDuckGo + Pastebin + منتديات.

الاستخدام الأساسي:
  data = await verify_email("name@domain.com", progress)
"""
import asyncio
import hashlib
import logging
from urllib.parse import quote

import config

LOG = logging.getLogger("email_verification")

_TIMEOUT = 10
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

# أولوية العرض: من الأهم إلى الأقل (تظهَر أولا المنصات الكبرى)
_IMPORTANCE = [
    "google", "microsoft", "office365", "outlook", "facebook", "whatsapp",
    "instagram", "twitter", "telegram", "linkedin", "amazon", "paypal",
    "netflix", "spotify", "steam", "discord", "snapchat", "tiktok",
    "reddit", "github", "youtube", "wordpress", "gravatar",
]


def _importance(site: str) -> int:
    s = (site or "").lower()
    for i, key in enumerate(_IMPORTANCE):
        if key in s:
            return i
    return len(_IMPORTANCE)


def md5(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def _gravatar_url(email: str) -> str:
    return f"https://www.gravatar.com/avatar/{md5(email)}?s=200&d=404"


# ---------------------------------------------------------------------------
# مزوّد الإيميل: مطابقة معروفة + استعلام MX (dnspython)
# ---------------------------------------------------------------------------
_PROVIDERS_BY_DOMAIN = {
    "gmail.com": "Gmail (Google)", "googlemail.com": "Gmail (Google)",
    "outlook.com": "Outlook (Microsoft)", "hotmail.com": "Outlook (Microsoft)",
    "live.com": "Outlook (Microsoft)", "msn.com": "Outlook (Microsoft)",
    "yahoo.com": "Yahoo Mail", "ymail.com": "Yahoo Mail",
    "icloud.com": "iCloud (Apple)", "me.com": "iCloud (Apple)",
    "protonmail.com": "Proton Mail", "proton.me": "Proton Mail",
    "mail.ru": "Mail.ru", "yandex.com": "Yandex Mail", "yandex.ru": "Yandex Mail",
    "zoho.com": "Zoho Mail", "aol.com": "AOL Mail", "gmx.com": "GMX",
    "seznam.cz": "Seznam", "tutanota.com": "Tuta Mail",
}

_MX_PROVIDERS = {
    "google.com": "Gmail (Google)",
    "googlemail.com": "Gmail (Google)",
    "microsoft.com": "Outlook (Microsoft)",
    "outlook.com": "Outlook (Microsoft)",
    "yahoodns.net": "Yahoo Mail",
    "apple.com": "iCloud (Apple)",
    "icloudmail.net": "iCloud (Apple)",
    "protonmail.ch": "Proton Mail", "protonmail.com": "Proton Mail",
    "proton.me": "Proton Mail",
    "mail.ru": "Mail.ru",
    "yandex.net": "Yandex Mail", "yandex.ru": "Yandex Mail",
    "zoho.eu": "Zoho Mail", "zoho.com": "Zoho Mail",
    "aol.com": "AOL Mail",
    "gmx.com": "GMX", "gmx.net": "GMX",
}


def _detect_provider(domain: str) -> dict:
    """مزوّد الإيميل: من النطاق أولًا (سريع) ثم من سجلات MX."""
    d = (domain or "").strip().lower()
    if not d or "." not in d:
        return {"name": "", "mx": []}
    name = _PROVIDERS_BY_DOMAIN.get(d, "")
    mx = []
    try:
        import dns.resolver
        for r in dns.resolver.resolve(d, "MX"):
            host = r.exchange.to_text().rstrip(".").lower()
            mx.append(host)
            if not name:
                for key, val in _MX_PROVIDERS.items():
                    if key in host:
                        name = val
                        break
    except Exception:
        pass
    return {"name": name, "mx": mx[:5]}


# ---------------------------------------------------------------------------
# Gravatar
# ---------------------------------------------------------------------------
async def _gravatar_profile(email: str) -> dict:
    """قيمة الحساب في Gravatar: الاسم + النبذة + الروابط (إن وُجد حساب عام)."""
    h = md5(email)
    hosts = (f"https://www.gravatar.com/{h}.json", f"https://en.gravatar.com/{h}.json")
    import httpx
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True,
                                 headers={"User-Agent": _UA}) as client:
        for url in hosts:
            try:
                r = await client.get(url)
                if r.status_code != 200:
                    continue
                entry = r.json()[0] if isinstance(r.json(), list) else r.json()
                profile = {
                    "hash": h,
                    "url": _gravatar_url(email),
                    "name": (entry.get("displayName") or "").strip(),
                    "about": (entry.get("aboutMe") or "").strip(),
                    "urls": [u.get("value") for u in entry.get("urls", []) if u.get("value")],
                    "accounts": [a.get("url") for a in entry.get("accounts", []) if a.get("url")],
                }
                return {"available": True, **profile}
            except Exception:
                continue
    return {"available": False, "hash": h, "url": _gravatar_url(email),
            "name": "", "about": "", "urls": [], "accounts": []}


async def _hibp(email: str) -> dict:
    """فحص التسريبات عبر HaveIBeenPwned (يتطلب مفتاح HIBP_API_KEY)."""
    if not config.HIBP_API_KEY:
        return {"status": "skipped", "note": "HIBP_API_KEY غير مضبوط في البيئة",
                "items": []}
    import httpx
    url = (f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
           "?truncateResponse=false")
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            r = await client.get(url, headers={
                "hibp-api-key": config.HIBP_API_KEY, "User-Agent": _UA})
        if r.status_code == 404:
            return {"status": "clean", "items": [], "note": "لا تسريبات معروفة"}
        if r.status_code == 200:
            items = [{"name": b.get("Name"), "date": (b.get("BreachDate") or b.get("DataClasses")) and
                      b.get("BreachDate"), "classes": b.get("DataClasses", []),
                      "pwned": b.get("PwnCount")} for b in r.json()]
            return {"status": "breached", "count": len(items), "items": items,
                    "note": "الإيميل ظهر في تسريبات عامة"}
        return {"status": "error", "code": r.status_code,
                "note": "تعذر الاستعلام عن HaveIBeenPwned", "items": []}
    except Exception as e:
        return {"status": "error", "note": f"فشل الاتصال: {e}", "items": []}


async def _rdap_whois(domain: str) -> dict:
    """WHOIS عبر RDAP (بدون مفاتيح): المسجل + تواريخ + حالة النطاق."""
    domain = (domain or "").strip().lower()
    if not domain or "." not in domain:
        return {"available": False}
    import httpx
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            r = await client.get(f"https://rdap.org/domain/{domain}")
        if r.status_code != 200:
            return {"available": False}
        data = r.json()
        events = {}
        for ev in data.get("events", []):
            kind = (ev.get("eventAction") or "").replace("event ", "")
            events[kind] = (ev.get("eventDate") or "")[:10]
        registrar = ""
        for ent in data.get("entities", []):
            roles = ent.get("roles", [])
            if "registrar" in roles or "registrant" in roles:
                vcards = ent.get("vcardArray", [])
                if len(vcards) > 1:
                    for item in vcards[1]:
                        if item and item[0] == "fn":
                            registrar = str(item[3] or "")
                            break
                if registrar:
                    break
        return {"available": True, "domain": domain, "registrar": registrar,
                "created": events.get("registration"),
                "updated": events.get("last changed") or events.get("last update"),
                "expires": events.get("expiration"),
                "statuses": [s for s in data.get("status", [])][:6]}
    except Exception:
        return {"available": False}


# ---------------------------------------------------------------------------
# روابط البحث الإضافية (Google/Bing/DDG/Pastebin/منتديات + منصات غير مدعومة)
# ---------------------------------------------------------------------------
def _google_links(email: str) -> list:
    quoted = "%22" + email.replace("@", "%40") + "%22"
    links = [
        {"label": "Google — بحث نصي", "url": f"https://www.google.com/search?q={quoted}",
         "icon": "google"},
        {"label": "Google — بحث صور", "url": f"https://www.google.com/search?tbm=isch&q={quoted}",
         "icon": "google"},
        {"label": "Bing", "url": f"https://www.bing.com/search?q={quoted}",
         "icon": "google"},
        {"label": "DuckDuckGo", "url": f"https://duckduckgo.com/?q={quoted}",
         "icon": "duckduckgo"},
        {"label": "Pastebin", "url": f"https://pastebin.com/search?q={quoted}",
         "icon": "google"},
        {"label": "منتديات ومجتمعات", "url": (f"https://www.google.com/search?q={quoted}+"
                                               "(%22forum%22+OR+%22board%22+OR+%22community%22)"),
         "icon": "google"},
    ]
    # منصات غير مُدرجة داخل holehe → بحث موجه (مفتوح الاتصال أو Google)
    for plat, site in (("Steam", "steamcommunity.com"),
                       ("Netflix", "netflix.com"),
                       ("PayPal", "paypal.com"),
                       ("Gmail (بحث داخل جوجل)", "google.com")):
        links.append({"label": f"{plat} — بحث موجه",
                      "url": f"https://www.google.com/search?q={quoted}+site%3A{site}",
                      "icon": "google"})
    return links


async def verify_email(email: str, progress=None) -> dict:
    """التنفيذ الكامل: Gravatar + holehe الشامل + HIBP + WHOIS + مزوّد + صور."""
    email = (email or "").strip().lower()
    if "@" not in email:
        return {"error": "bad_email", "message": "صيغة الإيميل غير صحيحة",
                "email": email}
    domain = email.rsplit("@", 1)[-1]

    if progress:
        progress("info", "جارٍ التحقق الشامل من الإيميل…")

    gravatar, breaches, whois = await asyncio.gather(
        _gravatar_profile(email),
        _hibp(email),
        _rdap_whois(domain),
    )

    # holehe الشامل (كل المنصات، نتائج مؤكدة فقط)
    from services import holehe_service
    accounts = await holehe_service.search_email(email, progress)

    # مزوّد الإيميل (Gmail/Outlook/Yahoo/iCloud…) عبر MX
    provider = _detect_provider(domain)

    if accounts:
        # صورة لكل منصة: بروفايل المنصة إن وُجد، وإلا unavatar بالإيميل
        from services import profile_image_service
        try:
            await profile_image_service.enrich(accounts)
        except Exception:
            LOG.warning("profile image enrich failed", exc_info=True)
        for a in accounts:
            if not a.get("avatar_url"):
                a["avatar_url"] = f"https://unavatar.io/email/{quote(email, safe='')}"

    # ترتيب النتائج من الأهم إلى الأقل (المنصات الكبرى أولًا)
    accounts.sort(key=lambda a: (_importance(a.get("site") or a.get("name") or ""),
                                 str(a.get("site") or a.get("name") or "").lower()))
    platform_names = sorted({a.get("name") or a.get("site") for a in accounts
                             if (a.get("name") or a.get("site"))},
                            key=lambda x: (_importance(x), x.lower()))

    summary = {
        "email": email,
        "domain": domain,
        "provider_name": provider["name"],
        "provider_mx": provider["mx"],
        "accounts_count": len(accounts),
        "platforms_checked": holehe_service.platform_count(),
        "platforms_found": platform_names,
    }
    return {
        "summary": summary,
        "gravatar": gravatar,
        "accounts": accounts,
        "breaches": breaches,
        "whois": whois,
        "provider": provider,
        "links": _google_links(email),
        "person": {"name": gravatar.get("name", ""),
                   "about": gravatar.get("about", ""),
                   "urls": gravatar.get("urls", []) + gravatar.get("accounts", [])}
                    if gravatar.get("available") else {"name": "", "about": ""},
    }