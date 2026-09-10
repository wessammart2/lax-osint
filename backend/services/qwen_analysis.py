"""LAX OSINT — التحليل العميق المتقدم (Deep Analysis) عبر Qwen.

نموذج فرعي من ai_analysis مع:
  - نماذج OpenRouter المخصصة (Qwen 72B ثم Qwen Coder 32B ثم احتياط Llama).
  - Prompt معمّق: استخراج الأنماط، العلاقات، المخاطر، اتجاهات بحث جديدة،
    كشف التناقضات، تقرير احترافي — كلها في JSON منظم بالثقة والمصدر.
  - يكمل بيانات Mayo (ربط)، وربما تمرر له roadmap/وصلة البيانات العميقة
    (Wayback / PGP / Shodan / فاحص الثغرات / الديب ويب) للاستفادة منها.

الاستخدام:
  report = await qwen_analysis.deep_report(kind, query, deep_data, user_id)
"""
import logging

import config
from services import ai_analysis

LOG = logging.getLogger("qwen_analysis")

DEEP_PROMPT = (
    "You are Qwen, a professional OSINT analyst. "
    "Analyze the provided intelligence data of the target thoroughly:\n"
    "- Target: the query (username / email / phone)\n"
    "- Platforms found: all accounts / registrations / pages\n"
    "- Associated data: notes, aliases, dates, locations, breaches, WHOIS\n"
    "- Historical data: archived pages (Wayback), PGP keys, exposed technical info\n"
    "Perform the following:\n"
    " 1. Extract all personal information (full name, birth date, age, gender, "
    "location city+country, phones, emails, aliases).\n"
    " 2. Identify relationships and connections between accounts and entities.\n"
    " 3. Detect patterns in behavior and habits (posting times, platforms, topics).\n"
    " 4. Assess risk level (low/medium/high) with risk_score 0-100.\n"
    " 5. Suggest additional search vectors (new dorks, platforms, angles).\n"
    " 6. Detect contradictions/inconsistencies in the collected data.\n"
    " 7. Generate a comprehensive professional report.\n"
    " 8. Rate confidence 0-100 and cite the source for every finding.\n"
    "Return STRICTLY one valid JSON object (no text, no markdown) with EXACTLY this schema:\n"
    "{\n"
    "  \"summary\": \"\",\n"
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
    "  \"relationships\": [{\"related_to\": \"\", \"how\": \"\"}],\n"
    "  \"patterns\": [],\n"
    "  \"contradictions\": [{\"finding\": \"\", \"why\": \"\"}],\n"
    "  \"next_vectors\": [],\n"
    "  \"timeline\": [{\"date\": \"\", \"event\": \"\"}],\n"
    "  \"critical_assets\": [],\n"
    "  \"risk_score\": 0,\n"
    "  \"risk_level\": \"low\"\n"
    "}\n"
    "Rules: confidence 0-100 and always a source per finding. Never invent data "
    "that is not present in the input (empty value + confidence 0 instead). "
    "Free text in Arabic. Platform names in English. Valid JSON, no trailing commas.\n"
)


def _enrich_context(kind: str, query: str, base: dict, extra: dict = None) -> dict:
    """تعيد نسخة البيئة التي يراها النموذج (البيانات الأساسية + البحث العميق)."""
    data = dict(base or {})
    if extra:
        data["research"] = {k: v for k, v in (extra.get("research") or {}).items()
                            if v} if extra.get("research") else None
        data["vuln"] = (extra.get("vuln") or {}).get("summary") if extra.get("vuln") else None
        data["deepweb"] = extra.get("deepweb") or None
    data["query"] = query
    data.setdefault("kind", kind)
    return data


async def deep_report(kind: str, query: str, base: dict, user_id: str = None,
                      extra: dict = None) -> dict:
    """التقرير العميق عبر Qwen — يعيد dict منظم + used_model + status.

    extra كاختياري يحتوي research / vuln / deepweb من المرحلة المتقدمة.
    """
    data = _enrich_context(kind, query, base, extra)
    try:
        report = await ai_analysis.generate_report(
            kind, query, data, user_id=user_id,
            models=config.AI_DEEP_MODELS, system_prompt=DEEP_PROMPT)
    except Exception as e:
        LOG.warning("deep report failed: %s", e)
        report = {"status": "error", "message": f"تعذر التقرير العميق: {e}"}
    if isinstance(report, dict):
        report.pop("cached", None)
    return report