"""LAX OSINT — خدمة صور Gravatar
تأخذ إيميلًا وتُرجع صورة البروفايل إذا وُجدت حساب Gravatar له.
https://www.gravatar.com/avatar/{MD5}
"""
import hashlib


def md5(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()


def avatar_url(email: str, size: int = 200) -> str:
    h = md5(email)
    return f"https://www.gravatar.com/avatar/{h}?d=404&s={size}"


def avatar_available(email: str, size: int = 200) -> dict:
    """يفحص وجود الصورة عبر طلب HEAD/GET مع d=404: تُرجِع 200 إن وُجدت."""
    import urllib.request

    url = avatar_url(email, size)
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0"})
    try:
        import base64 as _b64
        r = urllib.request.urlopen(req, timeout=10)
        if r.status == 200:
            data = r.read()
            image = _b64.b64encode(data).decode()
            return {"available": True, "url": url, "hash": md5(email),
                    "image_base64": f"data:image/png;base64,{image}"}
    except Exception as e:
        code = getattr(e, "code", None)
        if code in (404, 403):
            return {"available": False, "url": url, "hash": md5(email), "code": code, "image_base64": ""}
        return {"available": None, "url": url, "hash": md5(email), "error": str(e), "image_base64": ""}
    return {"available": False, "url": url, "hash": md5(email), "image_base64": ""}