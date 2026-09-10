"""LAX OSINT — التحليل الشامل لرقم الهاتف.

ثلاث طبقات:
  1) معلومات تقنية دقيقة عبر مكتبة phonenumbers (مستقلة تمامًا عن الخارج):
       الرقم، الدولة + العلم (كود ISO2)، شركة الاتصالات، نوع الخط، المنطقة/المدينة،
       Timezone، الصيغ الدولية/المحلية/E164 — مع دمج بيانات PhoneInfoga إن وُجد الثنائي.
  2) فحوص منصات الويب (best-effort عبر endpoints عامة):
       WhatsApp (كشف حضور تقريبي)، Telegram (رابط/جلسة اختيارية عبر Telethon)،
       Snapchat/Discord/Facebook/Google — روابط بحث مباشرة.
  3) مواقع عربية: Haraj، OpenSooq، LinkedIn، وروابط بحث عامة.

ملاحظة أمان/دقة صريحة:
  التحقق من ربط رقم بهاتف في منصات مثل Insta/Tele عند الطرف الآخر يتطلب جلسة
  مصادقة للخدمة (App session) — لذلك هذه الخطوة تنتج "روابط" موثقة لا "تأكيدات"
  ما لم تتوفر مفاتيح TELEGRAM_* في البيئة. كل نتيجة تحمل status:
  confirmed | possible | link.
"""
import asyncio
import logging
import threading
import time

import config

LOG = logging.getLogger("phone_analysis")

_PLATFORM_TIMEOUT = 8   # ثانية لكل فحص ويب
_CACHE_TTL = 1800       # كاش 30 دقيقة لنفس الرقم (تجنب إعادة الفحص)
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

_CACHE = {}
_CACHE_LOCK = threading.Lock()


def _country_name(country_code: str, lang: str = "ara") -> str:
    """اسم الدولة بالعربية — من خريطة الرموز الشائعة، مع fallback على الرمز نفسه."""
    return _CC_NAMES.get(country_code.upper(), country_code)


_CC_NAMES = {
    "SA": "السعودية", "AE": "الإمارات", "EG": "مصر", "JO": "الأردن",
    "KW": "الكويت", "QA": "قطر", "BH": "البحرين", "OM": "عُمان",
    "IQ": "العراق", "YE": "اليمن", "LB": "لبنان", "SY": "سوريا",
    "LY": "ليبيا", "TN": "تونس", "DZ": "الجزائر", "MA": "المغرب", "SD": "السودان",
    "PS": "فلسطين", "US": "الولايات المتحدة", "GB": "المملكة المتحدة",
    "CA": "كندا", "FR": "فرنسا", "DE": "ألمانيا", "IN": "الهند",
    "PK": "باكستان", "BD": "بنغلاديش", "TR": "تركيا", "IR": "إيران",
    "RU": "روسيا", "CN": "الصين", "AU": "أستراليا",
}


def _line_type(num) -> str:
    try:
        import phonenumbers
        t = phonenumbers.number_type(num)
    except Exception:
        return "unknown"
    types = {
        phonenumbers.PhoneNumberType.MOBILE: "mobile",
        phonenumbers.PhoneNumberType.FIXED_LINE: "fixed",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
        phonenumbers.PhoneNumberType.VOIP: "voip",
        phonenumbers.PhoneNumberType.PAGER: "pager",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal",
        phonenumbers.PhoneNumberType.UAN: "uan",
        phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
    }
    return types.get(t, "unknown")


def _label(kind: str) -> str:
    return {
        "mobile": "موبايل", "fixed": "أرضي", "fixed_or_mobile": "موبايل/أرضي",
        "toll_free": "مجاني", "premium_rate": "مدفوع", "voip": "VoIP",
        "pager": "بيجر", "personal": "شخصي", "uan": "UAN",
        "shared_cost": "تقاسم", "unknown": "غير معروف",
    }.get(kind, "غير معروف")


def _timezones_for_number(num) -> list:
    """مناطق زمنية للرقم — تعمل مع مختلف نسخ مكتبة phonenumbers."""
    try:
        from phonenumbers import time_zones as _tz  # old API
        return sorted(_tz.time_zones_for_number(num))
    except Exception:
        pass
    try:
        import phonenumbers
        from phonenumbers import tzdata  # v9: جدول {prefix: (tz…)}
        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        digits = e164.lstrip("+")
        for i in range(len(digits), 0, -1):
            region = digits[:i]
            if region in tzdata.TIMEZONE_DATA:
                vals = tzdata.TIMEZONE_DATA[region]
                tzs = [v for v in vals if isinstance(v, str)]
                if tzs:
                    return sorted(set(tzs))
    except Exception:
        pass
    return []


def parse_phone(raw: str) -> dict:
    """تحليل الرقم إلى معلومات تقنية (بدون أي اتصال شبكي)."""
    import phonenumbers
    from phonenumbers import geocoder

    text = (raw or "").strip()
    if not text.startswith("+"):
        text = "+" + text
    try:
        num = phonenumbers.parse(text, None)
    except Exception:
        return {"error": "bad_number",
                "message": "رقم غير صالح — استخدم الصيغة الدولية مثال: +9665xxxxxxxx"}

    if not phonenumbers.is_possible_number(num):
        return {"error": "bad_number", "message": "الرقم ليس واقعيًا وفق الكود الدولي"}

    valid = phonenumbers.is_valid_number(num)
    cc = phonenumbers.region_code_for_number(num) or ""
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    tech = {
        "number": text,
        "e164": e164,
        "country_code": num.country_code,
        "country_iso2": cc.lower(),
        "country": _country_name(cc),
        "country_en": phonenumbers.region_code_for_number(num) or "",
        "line_type": _line_type(num),
        "line_type_label": _label(_line_type(num)),
        "formats": {
            "e164": e164,
            "international": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL),
        },
        "timezones": _timezones_for_number(num),
        "valid": valid,
    }
    # شركة الاتصالات (حيث تدعم البيانات)
    try:
        from phonenumbers import carrier
        name = carrier.name_for_number(num, "en")
        if name:
            tech["carrier"] = name
    except Exception:
        pass
    # المنطقة/المدينة (حيث تتوفر، وتعمل جيدًا لبعض الدول)
    try:
        area = geocoder.description_for_number(num, "ar")
        if area and area not in (tech.get("country"), ""):
            tech["region_city"] = area
    except Exception:
        pass
    return {"tech": tech, "number": tech["e164"]}


def _whatsapp_marker(e164: str) -> str:
    """حضور تقريبي لـ WhatsApp: لا يمكن الجزم 100% بدون جلسة.
    العلامة السلبية تعني غالبًا أن الرقم غير مسجل؛ غيابها = possible."""
    return ("none",
            f"https://wa.me/{e164}",
            "التحقق النهائي من وجود حساب WhatsApp يتطلب فتح الرابط أو تطبيق المحمول")


async def _check_whatsapp(e164: str) -> dict:
    try:
        import httpx
        async with httpx.AsyncClient(timeout=_PLATFORM_TIMEOUT, follow_redirects=True,
                                     headers={"User-Agent": _UA}) as client:
            r = await client.get(f"https://wa.me/{e164}")
        txt = (r.text or "").lower()
        negative = any(m in txt for m in
                       ("isn't on whatsapp", "not on whatsapp", "we couldn't find",
                        "invalid phone number", "doesn't use whatsapp"))
        status = "not_registered" if negative else ("possible" if r.status_code == 200 else "link")
        return {"platform": "whatsapp", "label": "WhatsApp", "status": status,
                "url": f"https://wa.me/{e164}", "icon": "whatsapp",
                "note": "تأكيد نهائي يتطلب فتح الرابط" if status != "not_registered" else "يبدو غير مسجل"}
    except Exception:
        return {"platform": "whatsapp", "label": "WhatsApp", "status": "link",
                "url": f"https://wa.me/{e164}", "icon": "whatsapp",
                "note": "تعذر الاتصال — الرابط للتحقق اليدوي"}


def _telegram_entry(e164: str) -> dict:
    return {"platform": "telegram", "label": "Telegram", "status": "link",
            "url": f"https://t.me/{e164.replace('+', '')}", "icon": "telegram",
            "note": "يتطلب جلسة (TELEGRAM_SESSION) للتأكيد التلقائي"}


def _telegram_verify(e164: str, timeout: int = 20) -> dict:
    """فحص حقيقي عبر Telethon (يتطلب TELEGRAM_API_ID/HASH/SESSION في البيئة)."""
    try:
        from telethon import TelegramClient
        import telethon as _tl
    except Exception as e:
        return {"platform": "telegram", "label": "Telegram", "status": "link",
                "url": f"https://t.me/{e164.replace('+', '')}", "icon": "telegram",
                "note": f"Telethon غير مثبت: {e}"}

    async def _run():
        client = TelegramClient(
            config.TELEGRAM_SESSION,
            int(config.TELEGRAM_API_ID),
            config.TELEGRAM_API_HASH,
        )
        await client.connect()
        try:
            await client.get_entity(e164)
            return "registered"
        except ValueError:
            return "not_registered"
        except _tl.errors.rpcerrorlist.UsernameNotOccupiedError:
            return "not_registered"
        except _tl.errors.rpcerrorlist.PhoneNumberInvalidError:
            return "not_registered"
        except Exception:
            return "possible"
        finally:
            try:
                await client.disconnect()
            except Exception:
                pass

    try:
        status = asyncio.run(_run())
    except Exception as e:
        return {"platform": "telegram", "label": "Telegram", "status": "possible",
                "url": f"https://t.me/{e164.replace('+', '')}", "icon": "telegram",
                "note": f"فحص الجلسة تعثر: {e}"}
    if status == "registered":
        note = "الرقم مرتبط بحساب نشِط (تحقق Telethon)"
    elif status == "not_registered":
        note = "لا يوجد حساب Telegram بهذا الرقم"
    else:
        note = "حالة غير مؤكدة من الجلسة — تحقق يدويًا"
    return {"platform": "telegram", "label": "Telegram", "status": status,
            "url": f"https://t.me/{e164.replace('+', '')}", "icon": "telegram",
            "note": note}


def _search_links(e164: str) -> list:
    """روابط بحث موجهة لكل منصة (من الأهم للأقل) — بحث بالرقم داخل كل موقع."""
    q = e164.replace("+", "")          # 966555123456
    qq = q if q.startswith("0") else "+" + q   # +966555123456
    search = f"https://www.google.com/search?q=%22{qq}%22"
    site = lambda s: f"{search}+site%3A{s}"
    return [
        # منصات التواصل الكبرى — بحث موجه بالرقم
        {"platform": "facebook", "label": "Facebook", "status": "link",
         "url": f"https://www.facebook.com/search/top/?q=%22{qq}%22",
         "icon": "facebook", "note": "البحث في الملفات العامة"},
        {"platform": "instagram", "label": "Instagram — استرداد كلمة المرور", "status": "link",
         "url": "https://www.instagram.com/accounts/password_reset/",
         "icon": "instagram", "note": "تحقق يدوي: أدخل الرقم ليرى الموقع هل له حساب"},
        {"platform": "instagram", "label": "Instagram — بحث بالرقم", "status": "link",
         "url": site("instagram.com"),
         "icon": "instagram", "note": "بحث في الملفات العامة المفهرسة"},
        {"platform": "tiktok", "label": "TikTok", "status": "link",
         "url": site("tiktok.com"),
         "icon": "tiktok", "note": "بحث بالرقم داخل حسابات TikTok"},
        {"platform": "snapchat", "label": "Snapchat", "status": "link",
         "url": site("snapchat.com"),
         "icon": "snapchat", "note": "بحث في الملفات العامة المفهرسة"},
        {"platform": "twitter", "label": "X (Twitter)", "status": "link",
         "url": f"{search}+(site%3Atwitter.com+OR+site%3Ax.com)",
         "icon": "twitter", "note": "بحث بالرقم في تغريدات وحسابات"},
        {"platform": "discord", "label": "Discord", "status": "link",
         "url": site("discord.com"),
         "icon": "discord", "note": "بحث في السيرفرات والأعضاء المفهرسة"},
        {"platform": "telegram", "label": "Telegram — بحث بالرقم", "status": "link",
         "url": site("t.me"),
         "icon": "telegram", "note": "بحث بالرقم في الروابط العامة"},
        # مواقع عربية
        {"platform": "haraj", "label": "Haraj (حراج)", "status": "link",
         "url": f"https://haraj.com.sa/search?q={q}",
         "icon": "haraj", "note": "حراج السعودية"},
        {"platform": "opensooq", "label": "OpenSooq (السوق المفتوح)", "status": "link",
         "url": f"https://www.opensooq.com/ar/find?q={q}",
         "icon": "opensooq", "note": "إعلانات السوق المفتوح العربية"},
        {"platform": "linkedin", "label": "LinkedIn", "status": "link",
         "url": f"https://www.linkedin.com/search/results/all/?keywords=%22{qq}%22",
         "icon": "linkedin", "note": "البحث في الملفات العامة"},
        # محركات بحث عامة
        {"platform": "google", "label": "Google", "status": "link",
         "url": f"https://www.google.com/search?q=%22{q}%22",
         "icon": "google", "note": "أي نص عام يعرض الرقم"},
        {"platform": "google", "label": "Bing", "status": "link",
         "url": f"https://www.bing.com/search?q=%22{q}%22",
         "icon": "google", "note": "بحث منافس"},
        {"platform": "duckduckgo", "label": "DuckDuckGo", "status": "link",
         "url": f"https://duckduckgo.com/?q=%22{q}%22",
         "icon": "duckduckgo", "note": "محرك شامل"},
    ]


async def analyze_phone(raw: str, progress=None) -> dict:
    """التحليل الشامل لرقم الهاتف: تقنيات + منصات + مواقع عربية (مع كاش 30 دقيقة)."""
    if progress:
        progress("info", "جارٍ التحليل التقني الشامل للرقم…")

    parsed = parse_phone(raw)
    if parsed.get("error"):
        return {"number": raw, "tech": None, "platforms": [], "error": parsed["error"]}

    tech = parsed["tech"]
    e164 = tech["e164"]

    # كاش 30 دقيقة لنفس الرقم
    with _CACHE_LOCK:
        hit = _CACHE.get(e164)
        if hit and time.time() - hit[0] < _CACHE_TTL:
            if progress:
                progress("info", "نتائج من فحص سابق (مخزنة 30 دقيقة)")
            return hit[1]

    # دمج بيانات PhoneInfoga إن توفر (carrier/region/city إضافية)
    try:
        from services import phoneinfoga_service
        ok, _ = phoneinfoga_service.available()
        if ok:
            info = await phoneinfoga_service.search_phone(e164)
            scan = (info.get("tech") or {}).get("scan") or {}
            extra = {}
            for k in ("Carrier", "region", "city"):
                if scan.get(k):
                    extra[k] = scan[k]
            if extra:
                tech["phoneinfoga"] = extra
            elif info.get("tech") and info["tech"].get("location"):
                tech["phoneinfoga_location"] = info["tech"]["location"]
    except Exception as e:
        LOG.warning("phoneinfoga merge failed: %s", e)

    # فحوص ويب متوازية (Telegram عبر Telethon إن توفرت الجلسة في البيئة)
    if config.TELEGRAM_API_ID and config.TELEGRAM_API_HASH and config.TELEGRAM_SESSION:
        telegram = asyncio.to_thread(_telegram_verify, e164)
    else:
        telegram = asyncio.to_thread(lambda: _telegram_entry(e164))
    whatsapp, telegram = await asyncio.gather(
        _check_whatsapp(e164),
        telegram,
        return_exceptions=True,
    )
    if isinstance(whatsapp, Exception):
        whatsapp = {"platform": "whatsapp", "label": "WhatsApp", "status": "link",
                    "url": f"https://wa.me/{e164}", "icon": "whatsapp",
                    "note": "تعذر الاتصال — الرابط للتحقق اليدوي"}
    if isinstance(telegram, Exception):
        telegram = _telegram_entry(e164)

    # الترتيب من الأهم للأقل: زيادة واتساب/تيليجرام أولًا ثم بقية المنصات
    platforms = [whatsapp, telegram] + _search_links(e164)

    result = {"number": e164, "tech": tech, "platforms": platforms, "error": None}
    with _CACHE_LOCK:
        _CACHE[e164] = (time.time(), result)
    return result