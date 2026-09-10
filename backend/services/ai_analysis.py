"""LAX OSINT — التحليل الشامل بالذكاء الاصطناعي عبر OpenRouter.

النقاط:
  - المفتاح يُقرأ من البيئة فقط (OPENROUTER_API_KEY) — لا يظهر للعميل أبدًا.
  - نماذج مجانية/قوية مع fallback تلقائي عند فشل/غياب أحد النماذج.
  - retry مع backoff بسيط + معالجة أخطاء حازمة.
  - كاش ذاكرة 24 ساعة لنفس (kind:query) لتقليل الاستهلاك.
  - حد زمني لكل مستخدم (AI_PER_USER_HOUR_LIMIT/ساعة) لمنع إساءة الاستخدام.
  - يطلب من النموذج إرجاع JSON منظم: حقول + ثقة (confidence) + مصدر (source)
    + تقييم مخاطر + خط زمني + علاقات — ثم نتأكد من البنية.
"""
import asyncio
import hashlib
import json
import logging
import threading
import time

import config

LOG = logging.getLogger("ai_analysis")

_REFERER = "https://lax-osint.app"
_TITLE = "LAX OSINT Analysis"

_CACHE = {}
_CACHE_LOCK = threading.Lock()
_USAGE = {}
_USAGE_LOCK = threading.Lock()
# كاش البيانات الأساسية (accounts/tech...) بحيث يقرأها بحث المتقدم من نفس الكاش
_BASE_CACHE = {}
_BASE_MAX = 300

MAX_CONTEXT = 16000      # سياق البيانات المُرسلة للنموذج
MAX_OUTPUT_TOKENS = 2600
RETRIES = 2               # عدد إعادة المحاولة لكل نموذج


class AIError(Exception):
    pass


def available() -> tuple:
    if config.OPENROUTER_API_KEY:
        return True, ""
    return False, "OPENROUTER_API_KEY غير مضبوط في بيئة الخادم — لن يعمل التحليل الشامل"


# ---------------------------------------------------------------------------
# كاش + حد الاستخدام
# ---------------------------------------------------------------------------
def _cache_key(kind: str, query: str) -> str:
    return hashlib.sha256(f"{kind}:{query}".strip().lower().encode("utf-8")).hexdigest()


def _cache_get(key):
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
        if hit and hit[0] > time.time():
            return hit[1]
    return None


def _cache_set(key, value):
    with _CACHE_LOCK:
        _CACHE[key] = (time.time() + config.AI_CACHE_HOURS * 3600, value)


def store_base(kind: str, query: str, data: dict):
    """نسخ البيانات الأساسية للبحث (ليربطها البحث المتقدم بنفس الهدف)."""
    if not data or not isinstance(data, dict):
        return
    with _CACHE_LOCK:
        _BASE_CACHE[_cache_key(kind, query)] = data
        while len(_BASE_CACHE) > _BASE_MAX:
            _BASE_CACHE.pop(next(iter(_BASE_CACHE)), None)


def get_base_data(kind: str, query: str) -> dict:
    with _CACHE_LOCK:
        return _BASE_CACHE.get(_cache_key(kind, query))


def _usage_allowed(uid: str) -> tuple:
    """تسجيل محاولة استخدام؛ تُرجع (allowed, remaining_in_window)."""
    now = time.time()
    with _USAGE_LOCK:
        user = [_t for _t in _USAGE.get(uid, []) if _t > now - 3600]
        if len(user) >= config.AI_PER_USER_HOUR_LIMIT:
            _USAGE[uid] = user
            return False, 0
        user.append(now)
        _USAGE[uid] = user
        return True, config.AI_PER_USER_HOUR_LIMIT - len(user)


# ---------------------------------------------------------------------------
# استدعاء OpenRouter (requests — متزامن، يُشغَّل في thread)
# ---------------------------------------------------------------------------
def _openrouter_chat(messages: list, models: list = None) -> tuple:
    """محاولة عبر نماذج fallback مع retry لكل نموذج. تُرجع (content, model).

    يفرض response_format json_object عند دعم النموذج (استدلال تلقائي: إن رد
    الخادم 400 يشير لعدم دعم json ردّد الطلب بدونه). الاستجابة لا تُقبل إلا
    إذا احتوت JSON قابل للتحليل — وإلا نموذج التالي.
    """
    import requests

    last_err = None
    for model in (models or config.AI_MODELS):
        for attempt in range(RETRIES + 1):
            payload = {"model": model, "messages": messages,
                       "temperature": 0.2, "max_tokens": MAX_OUTPUT_TOKENS}
            if attempt == 0:
                payload["response_format"] = {"type": "json_object"}
            try:
                resp = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": _REFERER,
                        "X-Title": _TITLE,
                    },
                    json=payload,
                    timeout=config.AI_REQUEST_TIMEOUT,
                )
                body = (resp.text or "")
                # نموذج لا يدعم json_object → أعد المحاولة بدونه
                if (resp.status_code == 400 and "json" in body.lower()
                        and payload.get("response_format")):
                    payload["response_format"] = None
                    last_err = f"{model}: json_object unsupported"
                    time.sleep(0.4)
                    continue
                if resp.status_code == 429 or resp.status_code >= 500:
                    last_err = f"{model}: HTTP {resp.status_code}"
                    time.sleep(1.5 * (attempt + 1))
                    continue
                if resp.status_code != 200:
                    # نموذج غير متاح/صلاحية محدودة → جرب النموذج التالي فورًا
                    last_err = f"{model}: HTTP {resp.status_code} {resp.text[:160]}"
                    break
                data = resp.json()
                content = (((data.get("choices") or [{}])[0] or {})
                           .get("message") or {}).get("content") or ""
                if content.strip():
                    # مطلوب JSON قابل للتحليل قبل اعتماد الاستجابة.
                    if _extract_json(content):
                        return content.strip(), model
                    last_err = f"{model}: non-JSON response"
                    time.sleep(0.4 * (attempt + 1))
                    continue
                last_err = f"{model}: empty response"
            except Exception as e:  # noqa: BLE001 — شبكة/مهلة
                last_err = f"{model}: {e}"
                time.sleep(0.5 * (attempt + 1))
    raise AIError(f"فشل كل النماذج: {last_err}")


# ---------------------------------------------------------------------------
# بناء السياق وإرسال الطلب
# ---------------------------------------------------------------------------
def _json_subset(data: dict, keys: tuple) -> dict:
    out = {}
    for k in keys:
        if data.get(k) is not None:
            out[k] = data[k]
    return out


def _compact(value, limit: int) -> str:
    s = json.dumps(value, ensure_ascii=False)[:limit]
    return s if not value else s + ("…" if len(json.dumps(value, ensure_ascii=False)) > limit else "")


def _build_context(kind: str, query: str, data: dict) -> str:
    ctx = {"kind": kind, "query": query}
    if kind == "email":
        ctx["summary"] = _json_subset(data.get("summary", {}),
                                      ("email", "domain", "accounts_count", "platforms_found"))
        ctx["person"] = data.get("person") or {}
        ctx["gravatar"] = _json_subset(data.get("gravatar") or {},
                                       ("available", "name", "about"))
        ctx["accounts"] = [
            _json_subset(a, ("site", "name", "status", "url", "username", "note",
                             "aliases", "profile_name"))
            for a in (data.get("accounts") or [])][:80]
        breaches_raw = data.get("breaches") or []
        if not isinstance(breaches_raw, list):
            breaches_raw = (breaches_raw or {}).get("items") or []
        ctx["breaches"] = [{"name": b.get("name"), "date": b.get("date"),
                            "pwned": b.get("pwned")} for b in breaches_raw][:25]
        ctx["whois"] = _json_subset(data.get("whois") or {},
                                    ("domain", "registrar", "created", "expires", "statuses"))
    elif kind == "phone":
        tech = data.get("tech") or {}
        ctx["tech"] = _json_subset(tech,
                                   ("number", "e164", "country", "country_iso2", "carrier",
                                    "line_type_label", "region_city", "timezones", "formats",
                                    "phoneinfoga"))
        ctx["platforms"] = [{"platform": p.get("platform"), "label": p.get("label"),
                             "url": p.get("url"), "status": p.get("status"),
                             "note": p.get("note")} for p in (data.get("platforms") or [])]
    elif kind == "username":
        ctx["accounts"] = [
            {"site": a.get("site"), "name": a.get("name"), "status": a.get("status"),
             "url": a.get("url"), "username": a.get("username"),
             "note": a.get("note"), "avatar": bool(a.get("avatar_url"))}
            for a in (data.get("accounts") or [])][:80]
        if data.get("relations"):
            ctx["relations"] = [r for r in data.get("relations") or []][:20]
    for extra_key in ("research", "vuln", "deepweb"):
        if data.get(extra_key):
            ctx[extra_key] = data[extra_key]
    return _compact(ctx, MAX_CONTEXT)


_SYSTEM_PROMPT = (
    "You are a professional Open-Source Intelligence (OSINT) analyst. "
    "Analyze the provided intelligence data (extracted from  Datos such as "
    "Maigret/ holehe / PhoneInfoga / searches) and extract every available "
    "personal detail about the target person.\n"
    "Return STRICTLY one JSON object (no text, no markdown, no comments) "
    "matching this EXACT schema:\n"
    "{\n"
    "  \"full_name\": {\"value\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"birth_date\": {\"value\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"age_estimate\": {\"value\": null, \"confidence\": 0, \"source\": \"\"},\n"
    "  \"gender\": {\"value\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"location\": {\"value\": \"\", \"city\": \"\", \"country\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"phone_numbers\": [],\n"
    "  \"emails\": [],\n"
    "  \"aliases\": [],\n"
    "  \"social_accounts\": [{\"platform\": \"\", \"username\": \"\", \"url\": \"\"}],\n"
    "  \"profession\": {\"value\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"languages\": [],\n"
    "  \"interests\": [],\n"
    "  \"relationships\": [{\"related_to\": \"\", \"how\": \"\"}],\n"
    "  \"extra_info\": \"\",\n"
    "  \"timeline\": [{\"date\": \"\", \"event\": \"\"}],\n"
    "  \"risk_score\": 0,\n"
    "  \"risk_level\": \"low\"\n"
    "}\n"
    "Rules:\n"
    "- confidence: 0 to 100. source: where the fact was found "
    "(platform name / breach / PhoneInfoga / logical inference).\n"
    "- phone_numbers and emails: extract ALL numbers and emails found "
    "(including ones inside 'note', 'ids_data', registrations, breaches).\n"
    "- aliases: every username / nickname found.\n"
    "- social_accounts: one entry per platform found.\n"
    "- risk_score 0-100, risk_level one of: low | medium | high.\n"
    "- If a value is not present in the data, output an empty value with "
    "confidence 0 — NEVER invent information.\n"
    "- Write every free text (extra_info, summary-style values, event, how) "
    "in Arabic. Platform names in English.\n"
    "- The final JSON must be valid — no trailing commas.\n"
)


async def generate_report(kind: str, query: str, data: dict, user_id: str = None,
                          models: list = None, system_prompt: str = None) -> dict:
    """توليد التقرير الشامل. تُرجع dict منظمًا دائمًا (حتى عند الفشل).
    models / system_prompt اختياريتان لتغطية تحليلات خاصة (مثل Qwen العميق)."""
    key = _cache_key(kind, query)
    cached = _cache_get(key)
    if cached:
        return {**cached, "cached": True}

    store_base(kind, query, data)
    ok, msg = available()
    if not ok:
        return {"status": "unavailable", "message": msg}

    if user_id:
        allowed, remaining = _usage_allowed(str(user_id))
        if not allowed:
            return {"status": "limit",
                    "message": f"وصلت لحد {config.AI_PER_USER_HOUR_LIMIT} تحليلات ذكية في الساعة",
                    "retry_in": 3600}

    context = _build_context(kind, query, data)
    messages = [
        {"role": "system", "content": system_prompt or _SYSTEM_PROMPT},
        {"role": "user", "content": "البيانات:\n" + context},
    ]

    try:
        content, used_model = await asyncio.to_thread(
            _openrouter_chat, messages, models)
        report = _extract_json(content)
        if not isinstance(report, dict):
            raise AIError("النموذج لم يُرجع JSON صالحًا")
        report = _normalize_report(report)
        report["status"] = "ok"
    except Exception as e:
        LOG.warning("ai analysis failed: %s", e)
        used_model = ""
        report = {"status": "error", "message": f"تعذر التحليل: {e}"}

    report["used_model"] = used_model if isinstance(report, dict) else ""
    report["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    # لا نخزّن الفشل في الكاش (يُعاد تم التحليل في المرة القادمة)
    if isinstance(report, dict) and report.get("status") in ("ok", "limit"):
        _cache_set(key, report)
    return report


def _empty_field():
    return {"value": "", "confidence": 0, "source": ""}


def _normalize_report(report: dict) -> dict:
    """تُوحّد البنية وتضمن كل الحقول النهائية (مع توافق مفاتيح قديمة)."""
    r = dict(report or {})

    def field_val(f):
        if isinstance(f, dict):
            return (f.get("value") or ""), (f.get("confidence") or 0), (f.get("source") or "")
        return str(f or ""), 100, ""

    name = r.get("full_name")
    if not name and r.get("name"):
        v, c, s = field_val(r["name"])
        r["full_name"] = {"value": v, "confidence": c, "source": s}
    age = r.get("age_estimate")
    if not age and r.get("age"):
        v, c, s = field_val(r["age"])
        try:
            r["age_estimate"] = {"value": int(v), "confidence": c, "source": s}
        except (TypeError, ValueError):
            r["age_estimate"] = {"value": v, "confidence": c, "source": s}
    prof = r.get("profession")
    if not prof and r.get("occupation"):
        v, c, s = field_val(r["occupation"])
        r["profession"] = {"value": v, "confidence": c, "source": s}
    for key in ("full_name", "birth_date", "gender", "profession"):
        if not r.get(key):
            r[key] = _empty_field()
    loc = r.get("location")
    if not isinstance(loc, dict):
        r["location"] = {"value": str(loc or ""), "city": "", "country": "",
                         "confidence": 0, "source": ""}
    else:
        loc.setdefault("city", "")
        loc.setdefault("country", "")
        loc.setdefault("confidence", 0)
        loc.setdefault("source", "")
        loc.setdefault("value", "")
    for key in ("phone_numbers", "emails", "aliases", "languages", "interests", "timeline"):
        if not isinstance(r.get(key), list):
            r[key] = []
    accounts = r.get("social_accounts")
    if not isinstance(accounts, list) and isinstance(r.get("accounts"), list):
        accounts = r["accounts"]
    if not isinstance(accounts, list):
        accounts = []
    r["social_accounts"] = [
        {"platform": a.get("platform") or a.get("site") or "",
         "username": a.get("username") or "",
         "url": a.get("url") or ""}
        for a in accounts[:60]
    ]
    if not isinstance(r.get("relationships"), list):
        r["relationships"] = []
    if not isinstance(r.get("summary"), str):
        r["summary"] = ""
    if not isinstance(r.get("extra_info"), str):
        r["extra_info"] = ""
    if not isinstance(r.get("risk_score"), (int, float)) or isinstance(r.get("risk_score"), bool):
        r["risk_score"] = 0
    r.setdefault("risk_level", "low")
    return r


def _repair_json(t: str):
    """محاولة إصلاح أخطاء JSON الشائعة من النماذج (فواصل زائدة، نمودج مفقود محتوى)."""
    import re as _re
    t = _re.sub(r",\s*([}\]])", r"\1", t)          # فواصل زائدة قبل ] أو }
    t = _re.sub(r"([{,])\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", r'\1"\2":', t)  # مفاتيح بلا اقتباس
    t = _re.sub(r"'", '"', t)                       # اقتباسات مفردة → مزدوجة (خام)
    return t


def _extract_json(text: str):
    if not text:
        return None
    t = text.strip()
    if t.startswith("```") or t.startswith("```json"):
        t = t.strip("`")
        t = t.replace("json", "", 1).strip() if t.startswith("json") else t
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    frag = t[start:end + 1]
    for candidate in (frag, _repair_json(frag)):
        try:
            return json.loads(candidate)
        except Exception:
            continue
    return None