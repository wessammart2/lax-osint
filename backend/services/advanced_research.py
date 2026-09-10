"""LAX OSINT — البحث العميق المتقدم (Deep Research).

طبقات إضافية فوق البحث الأساسي:
  1) Wayback Machine (CDX API): النسخ المؤرشفة التي تذكر الهدف (يميل/يوزر/إيميل/رقم).
  2) Google Dorks موجهة (حسب النوع) + محاولة نتيجة فعلية عبر DuckDuckGo (best-effort)
     مع روابط جاهزة للفتح يدويًا كـ fallback.
  3) PGP Key Servers (pgp.mit.edu ثم keys.openpgp.org): مفاتيح مرتبطة بالبريد/الاسم.
  4) Shodan (اختياري: SHODAN_API_KEY): اسم النطاق → نطاقات فرعية/أجهزة.
  5) Censys (اختياري: CENSYS_API_ID+SECRET): شهادات TSL مرتبطة بالنطاق.
  6) unshort? لا — نلخص كل نتيجة بعنوان + تاريخ + رابط.

كل خدمة خارجية تعمل تلقائيًا إن توفر مفتاحها؛ وإلا تُرجع حالة needs_key صريحة
(لا نتائج مزيفة أبدًا).
"""
import asyncio
import logging
import re

import config

LOG = logging.getLogger("advanced_research")

_TIMEOUT = 12
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
_MAX_WAYBACK = 30
_MAX_DDG = 12


# ---------------------------------------------------------------------------
# 1) Wayback Machine
# ---------------------------------------------------------------------------
def _wb_candidates(kind: str, q: str) -> list:
    """(matchType, url) مرشّحات Wayback حسب النوع."""
    q = (q or "").strip().lower().lstrip("+")
    if "@" in q:
        local, domain = q.split("@", 1)
    if kind == "username":
        return [("domain", f"{q}.com"), ("domain", f"www.{q}.com"),
                ("exact", f"https://{q}/"), ("exact", f"{q}/")]
    if kind == "email":
        return [("domain", domain), ("exact", f"{q}"), ("exact", local)]
    return [("exact", f"{q}")]


async def _wayback(kind: str, query: str) -> dict:
    """بحث أرشيف Wayback حسب المرشحات المناسبة للاستعلام."""
    import httpx
    q = (query or "").strip().lower().lstrip("+")
    if not q:
        return {"type": "wayback", "items": [], "count": 0}
    if "@" in q:
        domain = q.split("@", 1)[1]
    items, seen = [], set()
    async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                 headers={"User-Agent": _UA}) as client:
        for mt, u in _wb_candidates(kind, q):
            url = ("https://web.archive.org/cdx/search/cdx"
                   f"?url={quote(u)}&matchType={mt}&output=json"
                   "&fl=timestamp,original,statuscode&filter=statuscode:200"
                   "&limit=80&from=2005")
            try:
                r = await client.get(url)
            except Exception as e:  # noqa: BLE001
                LOG.info("wayback %s: %s", mt, e)
                continue
            if r.status_code in (429, 503):
                await asyncio.sleep(1.4)
                continue
            if r.status_code != 200:
                continue
            try:
                rows = r.json()
            except Exception:  # noqa: BLE001
                continue
            for row in rows[1:]:
                if len(row) < 3 or row[1] in seen:
                    continue
                seen.add(row[1])
                ts, orig, code = row[0], row[1], row[2]
                items.append({
                    "date": f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts,
                    "url": orig,
                    "saved": f"https://web.archive.org/web/{ts}/{orig}",
                    "code": code,
                })
            if len(items) >= _MAX_WAYBACK:
                break
    return {"type": "wayback", "count": len(items[: _MAX_WAYBACK]),
            "items": items[:_MAX_WAYBACK]}


# ---------------------------------------------------------------------------
# 2) Google Dorks + نتيجة فعلية (DDG)
# ---------------------------------------------------------------------------
def _dorks_for(kind: str, q: str) -> list:
    quoted = f'"{q}"'
    domain = q.split("@")[-1] if kind == "email" else q
    dorks = [
        f'{quoted}',                                        # عام نصي
        f'intitle:"{q}"',                                   # عنوان
        f'"{q}" intext:"phone" OR intext:"email"',          # بيانات اتصال
        f'"{q}" filetype:pdf OR filetype:docx',             # مستندات
        f'"{q}" site:linkedin.com',                         # لينكد إن
        f'"{q}" site:facebook.com',                         # فيسبوك
        f'"{q}" site:x.com OR site:twitter.com',            # تويتر
        f'"{q}" site:instagram.com',                        # إنستغرام
        f'"{q}" site:reddit.com',                           # ريديت
        f'"{q}" site:pastebin.com',                         # بينستبين
    ]
    if kind == "email":
        dorks += [f'"{q}" site:github.com', f'"{q}" site:*.gov', f'"{q}" site:*.edu']
    if kind == "phone":
        dorks += [f'"{q}" site:haraj.com.sa', f'"{q}" site:opensooq.com']
    if kind == "username":
        dorks += [f'"{q}" site:github.com', f'"{q}" site:*.forum']
    # استعلام Google واحد مباشر للفتح اليدوي
    return list(dict.fromkeys(dorks))


def _ddg(query: str, max_results: int = _MAX_DDG) -> list:
    try:
        from duckduckgo_search import DDGS
        with DDGS() as s:
            return [{"title": r.get("title", ""), "url": r.get("href", ""),
                     "snippet": r.get("body", "")}
                    for r in s.text(query, max_results=max_results)]
    except Exception as e:
        LOG.info("ddg unavailable: %s", e)
        return []


async def _dorks(kind: str, q: str) -> dict:
    dorks = _dorks_for(kind, q)
    # ملاحظة: نسخة duckduckgo-search المثبتة تُرجع صفرًا داخل threads هنا؛ استدعاء
    # متزامن مباشر أضمن (النتيجة best-effort وسريعة نسبيًا).
    results = []
    try:
        results = _ddg(f'"{q}"')
    except Exception:
        pass
    results = [r for r in results if r.get("url") or r.get("title")]
    return {"type": "dorks", "count": len(results[: _MAX_DDG]),
            "items": results[: _MAX_DDG],
            "dorks": dorks,
            "search_url": f"https://www.google.com/search?q=%22{quote(q)}%22"}


# ---------------------------------------------------------------------------
# 3) PGP Key Servers
# ---------------------------------------------------------------------------
async def _pgp(q: str) -> dict:
    """مفاتيح PGP عامة: keys.openpgp.org (by-email دقيق) ثم pgp.mit.edu index."""
    import httpx
    items = []
    is_email = "@" in (q or "")
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True,
                                     headers={"User-Agent": _UA}) as client:
            # 1) by-email دقيق (يدعم مفاتيح مثبتة عند openpgp.org)
            if is_email:
                try:
                    r = await client.get(
                        f"https://keys.openpgp.org/vks/v1/by-email/{quote(q)}")
                    if r.status_code == 200 and "PGP PUBLIC KEY BLOCK" in (r.text or ""):
                        items.extend(_parse_pgp_armor(r.text, q))
                except Exception as e:  # noqa: BLE001
                    LOG.info("openpgp by-email: %s", e)
            # 2) pgp.mit.edu index (بطيء لكن نصي صريح)
            if not items:
                try:
                    r = await client.get(
                        f"https://pgp.mit.edu/pks/lookup?op=index&options=mr&search={quote(q)}")
                    if (r.status_code == 200
                            and "Sorry" not in r.text[:400]
                            and not r.text.startswith("<!DOCTYPE html><html><head><title>Sorry")):
                        items.extend(_parse_pgp_mit(r.text))
                except Exception as e:  # noqa: BLE001
                    LOG.info("pgp.mit: %s", e)
    except Exception as e:  # noqa: BLE001
        LOG.warning("pgp failed: %s", e)
    return {"type": "pgp", "count": len(items), "items": items[:20]}


def _parse_pgp_armor(text: str, q: str) -> list:
    import re as _re
    out = []
    kid = ""
    m = _re.search(r"KeyID\s*:\s*([0-9A-Fa-f ]+)", text)
    if not m:
        m = _re.search(r"sub\s+\d+\s+\w+\s+\[[^\]]*\]?\[\S+\]\s+([0-9A-Fa-f]{8,40})", text)
    if m:
        kid = m.group(1).replace(" ", "").upper()
    uid = _re.search(r"uid\s+(.+)", text)
    ident = uid.group(1).strip() if uid else q
    out.append({"key_id": kid, "identity": ident, "keyserver": "keys.openpgp.org",
                "url": f"https://keys.openpgp.org/search?q={quote(q)}"})
    return out


def _parse_openpgp_html(text: str) -> list:
    import urllib.parse
    ids = set()
    for m in re.finditer(r"search\?search=0x([0-9A-Fa-f]{16})", text or ""):
        ids.add(m.group(1).upper())
    # العناوين grid: عنوان الاسم في h4 > a
    names = re.findall(r'<h4[^>]*>\s*<a[^>]*>(.*?)</a>', text or "", re.S)
    return [{"key_id": kid, "identity": (re.sub(r"<[^>]+>", "", n).strip() if i < len(names) else ""),
             "keyserver": "keys.openpgp.org",
             "url": "https://keys.openpgp.org/search?search=0x" + kid}
            for i, kid in enumerate(ids)]


def _parse_pgp_mit(text: str) -> list:
    from urllib.parse import quote as _q
    out, cur = [], None
    for ln in (text or "").splitlines():
        if ln.startswith("pub"):
            m = re.search(r"pub\s+\d+[RrDdsgS]?(?:/\s*)?([0-9A-Fa-f]{8,16})", ln)
            kid = (m.group(1) if m else "").upper()
            cur = {"key_id": kid, "identity": "", "keyserver": "pgp.mit.edu",
                   "url": f"https://pgp.mit.edu/pks/lookup?search=0x{kid}" if kid else ""}
            if kid:
                out.append(cur)
        elif ln.startswith("uid") and cur is not None:
            uid = re.sub(r"^uid\s+", "", ln).strip()
            if not cur["identity"]:
                cur["identity"] = uid
    return out


# ---------------------------------------------------------------------------
# 4) Shodan (اختياري)
# ---------------------------------------------------------------------------
async def _shodan(q: str, kind: str) -> dict:
    if not config.SHODAN_API_KEY:
        return {"type": "shodan", "status": "needs_key",
                "note": "يتطلب SHODAN_API_KEY في البيئة"}
    import httpx
    target = q.split("@")[-1] if kind == "email" else q
    url = f"https://api.shodan.io/dns/domain/{quote(target)}?key={config.SHODAN_API_KEY}"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.get(url)
        if r.status_code != 200:
            return {"type": "shodan", "status": "error",
                    "note": r.json().get("detail", r.text[:80])}
        data = r.json()
        return {"type": "shodan", "status": "ok",
                "domain": target,
                "subdomains": (data.get("data") or [])[:50],
                "total": len(data.get("data") or [])}
    except Exception as e:
        return {"type": "shodan", "status": "error", "note": str(e)}


# ---------------------------------------------------------------------------
# 5) Censys (اختياري)
# ---------------------------------------------------------------------------
async def _censys(q: str, kind: str) -> dict:
    if not (config.CENSYS_API_ID and config.CENSYS_API_SECRET):
        return {"type": "censys", "status": "needs_key",
                "note": "يتطلب CENSYS_API_ID + CENSYS_API_SECRET"}
    import base64
    import httpx
    domain = q.split("@")[-1] if kind == "email" else q
    auth = base64.b64encode(
        f"{config.CENSYS_API_ID}:{config.CENSYS_API_SECRET}".encode()).decode()
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            r = await client.post(
                "https://search.censys.io/api/v2/certificates/search",
                headers={"Authorization": f"Basic {auth}"},
                json={"q": f"names:{domain}", "per_page": 20})
        if r.status_code != 200:
            return {"type": "censys", "status": "error", "note": r.text[:120]}
        hits = r.json().get("result", {}).get("hits", [])
        return {"type": "censys", "status": "ok",
                "certs": [{"fingerprint": c.get("fingerprint", ""),
                           "names": (c.get("names") or [])[:4],
                           "first_seen": (c.get("first_seen") or "")[:10]}
                          for c in hits][:20]}
    except Exception as e:
        return {"type": "censys", "status": "error", "note": str(e)}


# ---------------------------------------------------------------------------
# الواجهة
# ---------------------------------------------------------------------------
async def research_target(kind: str, query: str, progress=None) -> dict:
    """بحث عميق متوازي: Wayback + Dorks + PGP + Shodan + Censys."""
    if progress:
        progress("info", "بحث عميق: الأرشيف + المفاتيح + الأجهزة…")

    wayback, dorks, pgp, shodan, censys = await asyncio.gather(
        _wayback(kind, query),
        _dorks(kind, query),
        _pgp(query),
        _shodan(query, kind),
        _censys(query, kind),
        return_exceptions=True,
    )
    out = {}
    for name, val in (("wayback", wayback), ("dorks", dorks), ("pgp", pgp),
                      ("shodan", shodan), ("censys", censys)):
        out[name] = val if not isinstance(val, Exception) else {
            "type": name, "count": 0, "items": [], "error": str(val)}
    return out


def quote(s: str) -> str:
    from urllib.parse import quote as _q
    return _q(s or "", safe="")