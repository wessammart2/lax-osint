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

MAX_CONTEXT = 6000        # نحصر سياق البيانات المُرسلة للنموذج
MAX_OUTPUT_TOKENS = 1800
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
def _openrouter_chat(messages: list) -> tuple:
    """محاولة عبر نماذج fallback مع retry لكل نموذج. تُرجع (content, model)."""
    import requests

    last_err = None
    for model in config.AI_MODELS:
        for attempt in range(RETRIES + 1):
            try:
                resp = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {config.OPENROUTER_API_KEY}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": _REFERER,
                        "X-Title": _TITLE,
                    },
                    json={"model": model, "messages": messages,
                          "temperature": 0.2, "max_tokens": MAX_OUTPUT_TOKENS},
                    timeout=config.AI_REQUEST_TIMEOUT,
                )
                if resp.status_code == 429 or resp.status_code >= 500:
                    last_err = f"{model}: HTTP {resp.status_code}"
                    time.sleep(0.8 * (attempt + 1))
                    continue
                if resp.status_code != 200:
                    # نموذج غير متاح/صلاحية محدودة → جرب النموذج التالي فورًا
                    last_err = f"{model}: HTTP {resp.status_code} {resp.text[:160]}"
                    break
                data = resp.json()
                content = (((data.get("choices") or [{}])[0] or {})
                           .get("message") or {}).get("content") or ""
                if content.strip():
                    return content.strip(), model
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
            _json_subset(a, ("site", "name", "status", "url", "username", "note"))
            for a in (data.get("accounts") or [])][:40]
        breaches_raw = data.get("breaches") or []
        if not isinstance(breaches_raw, list):
            breaches_raw = (breaches_raw or {}).get("items") or []
        ctx["breaches"] = [{"name": b.get("name"), "date": b.get("date"),
                            "pwned": b.get("pwned")} for b in breaches_raw][:15]
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
             "url": a.get("url"), "username": a.get("username"), "avatar": bool(a.get("avatar_url"))}
            for a in (data.get("accounts") or [])][:60]
    return _compact(ctx, MAX_CONTEXT)


_SYSTEM_PROMPT = (
    "أنت محلل استخبارات مصادر مفتوحة (OSINT) محترف. حللّ البيانات الواردة وأخرج "
    "تقريرًا منظمًا بـ JSON فقط (بدون أي نص خارج JSON). المخطط المطلوب حرفيًا:\n"
    "{\n"
    "  \"summary\": \"ملخص عربي قصير عن الهدف\",\n"
    "  \"name\": {\"value\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"age\": {\"value\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"gender\": {\"value\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"location\": {\"value\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"languages\": [],\n"
    "  \"interests\": [],\n"
    "  \"occupation\": {\"value\": \"\", \"confidence\": 0, \"source\": \"\"},\n"
    "  \"accounts\": [{\"platform\": \"\", \"username\": \"\", \"url\": \"\"}],\n"
    "  \"relationships\": [{\"related_to\": \"\", \"how\": \"\"}],\n"
    "  \"personal_note\": \"ملاحظات شخصية متبقية\",\n"
    "  \"timeline\": [{\"date\": \"\", \"event\": \"\"}],\n"
    "  \"risk_score\": 0,\n"
    "  \"risk_level\": \"low\"\n"
    "}\n"
    "قواعد: confidence بين 0 و100. source = من أين استُنتجت (منصة/تسريب/تخمين منطقي).\n"
    "risk_score بين 0 و100، وrisk_level أحد: low|medium|high.\n"
    "إن لم توجد معلومة في البيانات ضع قيمة فارغة وثقة 0 — لا تخترع أبدًا.\n"
    "مهم جدًا: كل كتابة النص الحر (summary, personal_note, event, how) بالعربية الفصحى —\n"
    "أسماء المنصات والتطبيقات بالإنجليزية. summary جملة عربية واحدة موجزة.\n"
)


async def generate_report(kind: str, query: str, data: dict, user_id: str = None) -> dict:
    """توليد التقرير الشامل. تُرجع dict منظمًا دائمًا (حتى عند الفشل)."""
    key = _cache_key(kind, query)
    cached = _cache_get(key)
    if cached:
        return {**cached, "cached": True}

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
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user", "content": "البيانات:\n" + context},
    ]

    try:
        content, used_model = await asyncio.to_thread(_openrouter_chat, messages)
        report = _extract_json(content)
        if not isinstance(report, dict):
            raise AIError("النموذج لم يُرجع JSON صالحًا")
    except Exception as e:
        LOG.warning("ai analysis failed: %s", e)
        used_model = ""
        report = {"status": "error", "message": f"تعذر التحليل: {e}"}

    report["used_model"] = used_model if isinstance(report, dict) else ""
    report["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _cache_set(key, report)
    return report


def _extract_json(text: str):
    if not text:
        return None
    t = text.strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.startswith("json"):
            t = t[4:].strip()
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(t[start:end + 1])
    except Exception:
        return None