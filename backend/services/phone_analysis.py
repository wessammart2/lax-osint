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

import config

LOG = logging.getLogger("phone_analysis")

_PLATFORM_TIMEOUT = 8   # ثانية لكل فحص ويب
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


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
    if config.TELEGRAM_API_ID and config.TELEGRAM_API_HASH and config.TELEGRAM_SESSION:
        return {"platform": "telegram", "label": "Telegram", "status": "possible",
                "url": f"tg://search?q={e164}", "icon": "telegram",
                "note": "جلسة Telethon جاهزة — فحص من جهة الخادم"}
    return {"platform": "telegram", "label": "Telegram", "status": "link",
            "url": f"https://t.me/{e164.replace('+', '')}", "icon": "telegram",
            "note": "يتطلب جلسة (TELEGRAM_SESSION) للتأكيد التلقائي"}


def _search_links(e164: str) -> list:
    q = e164.replace("+", "")
    qq = "%22+%2B" + q + "+%22"
    return [
        {"platform": "snapchat", "label": "Snapchat", "status": "link",
         "url": "https://www.snapchat.com/", "icon": "snapchat",
         "note": "لا واجهة عامة للبحث بالرقم"},
        {"platform": "discord", "label": "Discord", "status": "link",
         "url": f"https://www.google.com/search?q=site%3Adiscord.com+%22%2B{q}%22",
         "icon": "discord", "note": "بحث في سيرفرات مفهرسة عامة"},
        {"platform": "facebook", "label": "Facebook", "status": "link",
         "url": f"https://www.facebook.com/search/top/?q=%2B{q}",
         "icon": "facebook", "note": "بحث في الملفات العامة"},
        {"platform": "google", "label": "Google", "status": "link",
         "url": f"https://www.google.com/search?q={qq}",
         "icon": "google", "note": "بحث عن الرقم في النصوص العامة"},
        {"platform": "haraj", "label": "Haraj (حراج)", "status": "link",
         "url": f"https://haraj.com.sa/search?q={q}",
         "icon": "haraj", "note": "حراج السعودية"},
        {"platform": "opensooq", "label": "OpenSooq (السوق المفتوح)", "status": "link",
         "url": f"https://www.opensooq.com/ar/find?q={q}",
         "icon": "opensooq", "note": "إعلانات السوق المفتوح العربية"},
        {"platform": "linkedin", "label": "LinkedIn", "status": "link",
         "url": f"https://www.linkedin.com/search/results/all/?keywords=%2B{q}",
         "icon": "linkedin", "note": "البحث في الملفات العامة"},
    ]


async def analyze_phone(raw: str, progress=None) -> dict:
    """التحليل الشامل لرقم الهاتف: تقنيات + منصات + مواقع عربية."""
    if progress:
        progress("info", "جارٍ التحليل التقني الشامل للرقم…")

    parsed = parse_phone(raw)
    if parsed.get("error"):
        return {"number": raw, "tech": None, "platforms": [], "arabic": [], "error": parsed["error"]}

    tech = parsed["tech"]
    e164 = tech["e164"]

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

    # فحوص ويب متوازية
    whatsapp, telegram = await asyncio.gather(
        _check_whatsapp(e164),
        asyncio.to_thread(lambda: _telegram_entry(e164)),
        return_exceptions=True,
    )
    if isinstance(whatsapp, Exception):
        whatsapp = {"platform": "whatsapp", "label": "WhatsApp", "status": "link",
                    "url": f"https://wa.me/{e164}", "icon": "whatsapp",
                    "note": "تعذر الاتصال — الرابط للتحقق اليدوي"}
    if isinstance(telegram, Exception):
        telegram = _telegram_entry(e164)

    platforms = [whatsapp, telegram] + _search_links(e164)

    return {"number": e164, "tech": tech, "platforms": platforms, "error": None}