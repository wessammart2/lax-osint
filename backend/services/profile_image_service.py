"""LAX OSINT — جلب صورة البروفايل لكل منصة من أدواتها الرسمية/البديلة.

تُضاف الصورة كحقل avatar_url لكل نتيجة من نوع site في بحث اليوزر نيم:
  - JSON: Instagram (profile_pic_url)، TikTok (avatarLarger) — يُجلب ويُستخرج الرابط.
  - img : روابط مباشرة (GitHub .png، Snapcode SVG، unavatar للبقية) — تُمرَّر دون انتظار،
           وتتولى الواجهة إظهار صورة بديلة (placeholder) عند فشل التحميل.
"""
import asyncio
from urllib.parse import quote

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

TIMEOUT = 6        # ثانية لكل الطلبات
MAX_ENRICH = 25    # حد أقصى للمنصات التي تُنجَز في البحث الواحد

# خطط الصور: type=json يُجلب ويُستخرج، type=img رابط مباشر
IMAGE_PLANS = {
    "instagram": {"type": "json",
                  "url": "https://www.instagram.com/{u}/?__a=1&__d=dis",
                  "keys": ("profile_pic_url_hd", "profile_pic_url"),
                  "fallback": "https://unavatar.io/instagram/{u}"},
    "tiktok": {"type": "json",
               "url": "https://www.tiktok.com/api/user/detail/?uniqueId={u}",
               "keys": ("avatarLarger", "avatarMedium", "avatarThumb"),
               "fallback": "https://unavatar.io/tiktok/{u}"},
    "snapchat": {"type": "img",
                 "url": "https://feelinsonice.appspot.com/web/deeplink/snapcode?username={u}&type=SVG"},
    "twitter": {"type": "img", "url": "https://unavatar.io/twitter/{u}"},
    "facebook": {"type": "img", "url": "https://unavatar.io/facebook/{u}"},
    "github": {"type": "img", "url": "https://github.com/{u}.png"},
    "linkedin": {"type": "img", "url": "https://unavatar.io/linkedin/{u}"},
    "youtube": {"type": "img", "url": "https://unavatar.io/youtube/{u}"},
    "reddit": {"type": "img", "url": "https://unavatar.io/reddit/{u}"},
    "telegram": {"type": "img", "url": "https://unavatar.io/telegram/{u}"},
    "twitch": {"type": "img", "url": "https://unavatar.io/twitch/{u}"},
    "pinterest": {"type": "img", "url": "https://unavatar.io/pinterest/{u}"},
    "discord": {"type": "img", "url": "https://unavatar.io/discord/{u}"},
    "steam": {"type": "img", "url": "https://unavatar.io/steam/{u}"},
}

_ALIASES = {
    "instagram": "instagram", "insta": "instagram",
    "tiktok": "tiktok", "ticktock": "tiktok",
    "snapchat": "snapchat", "snap": "snapchat",
    "twitter": "twitter", "x.com": "twitter", "x": "twitter",
    "facebook": "facebook", "fb": "facebook",
    "github": "github", "gitlab": "github",
    "linkedin": "linkedin",
    "youtube": "youtube",
    "reddit": "reddit",
    "telegram": "telegram",
    "twitch": "twitch",
    "pinterest": "pinterest",
    "discord": "discord",
    "steam": "steam",
}

_TLDS = (".com", ".org", ".net", ".io", ".co", ".app", ".xyz", ".me",
         ".tv", ".in", ".ru", ".de", ".fr")


def _norm(name: str) -> str:
    s = (name or "").lower().strip()
    for tld in _TLDS:
        if s.endswith(tld):
            s = s[: -len(tld)]
    s = "".join(ch for ch in s if ch.isalnum())
    return s


def _platform(site: str):
    s = _norm(site)
    if s in _ALIASES:
        return _ALIASES[s]
    for plat in IMAGE_PLANS:
        if plat and plat in s:
            return plat
    return None


def platform_key(name: str) -> str:
    """الاسم القياسي للمنصة (instagram/twitter/…) أو '' إن لم تُعرف."""
    return _platform(name) or ""


def _extract(obj, keys) -> str:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and isinstance(v, str) and v.startswith("http"):
                return v
        for v in obj.values():
            r = _extract(v, keys)
            if r:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _extract(v, keys)
            if r:
                return r
    return ""


async def _fetch(client, plan: dict, username: str) -> str:
    u = quote(username, safe="")
    if plan["type"] == "img":
        return plan["url"].format(u=u)
    try:
        resp = await client.get(plan["url"].format(u=u))
        url = _extract(resp.json(), plan.get("keys", ()))
    except Exception:
        url = ""
    if not url and plan.get("fallback"):
        return plan["fallback"].format(u=u)
    return url


async def enrich(results: list) -> list:
    """تُلصق avatar_url للنتائج المعروفة دون كسر سرعة البحث."""
    todo = []
    for it in results:
        if len(todo) >= MAX_ENRICH:
            break
        if not it.get("username"):
            continue
        plat = _platform(it.get("site") or it.get("name") or "")
        plan = plat and IMAGE_PLANS.get(plat)
        if plan and not it.get("avatar_url"):
            todo.append((it, plan))
    if not todo:
        return results
    try:
        import httpx
        headers = {"User-Agent": _UA, "Accept": "application/json, */*"}
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=headers,
                                     follow_redirects=True) as client:
            tasks = [asyncio.wait_for(_fetch(client, plan, it.get("username") or ""),
                                      timeout=TIMEOUT + 3)
                     for it, plan in todo]
            urls = await asyncio.gather(*tasks, return_exceptions=True)
        for (it, _plan), url in zip(todo, urls):
            if isinstance(url, str) and url.startswith("http"):
                it["avatar_url"] = url
    except Exception:
        pass
    return results