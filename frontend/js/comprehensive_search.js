/* LAX OSINT — التحليل الشامل (زر "تحليل شامل")
   ===============================================
   يبث من /api/comprehensive/{kind} عبر SSE ثم يرسم:
     · لوحة تقرير الذكاء الاصطناعي (ثقة + مصادر + خط زمني + علاقات + مخاطر)
     · قسم البيانات الكاملة حسب النوع (username | email | phone)
     · أدوات تصدير: JSON (تنزيل فعلي) وPDF (عبر الطباعة)
*/
(function () {
  "use strict";

  const API = (window.LAX_CONFIG && window.LAX_CONFIG.API_URL) || "http://127.0.0.1:8000";
  const t = (k) => window.laxI18n.t(k);

  const L = {
    ar: { possible: "محتمل", link: "رابط", clean: "سليم", count: "عدد الحسابات",
      breaches: "تسريبات", fresh: "لا تسريبات معروفة", domains: "المنصة" },
    en: { possible: "Possible", link: "Link", clean: "Clean", count: "Accounts",
      breaches: "Breaches", fresh: "No known breaches", domains: "Platform" },
  };
  const lng = () => window.laxI18n.state.lang || "ar";
  const Lx = (k) => L[lng()][k] || k;

  let compData = null;
  let busy = false;

  const els = {
    get status() { return document.getElementById("status"); },
    get statusText() { return document.getElementById("statusText"); },
    get analyzeBar() { return document.getElementById("analyzeBar"); },
    get log() { return document.getElementById("log"); },
    get list() { return document.getElementById("resultList"); },
    get resWrap() { return document.getElementById("resWrap"); },
    get resCounter() { return document.getElementById("resCounter"); },
    get resCount() { return document.getElementById("resCount"); },
    get toolbar() { return document.getElementById("compToolbar"); },
  };

  function setAnalyzing(on) {
    if (!els.analyzeBar) return;
    els.analyzeBar.classList.toggle("hidden", !on);
  }

  /* ---------- أدوات ---------- */
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function faIcon(platform) {
    const B = {
      instagram: "fa-brands fa-instagram", tiktok: "fa-brands fa-tiktok",
      snapchat: "fa-brands fa-snapchat", x: "fa-brands fa-x-twitter",
      twitter: "fa-brands fa-x-twitter", facebook: "fa-brands fa-facebook",
      github: "fa-brands fa-github", linkedin: "fa-brands fa-linkedin",
      youtube: "fa-brands fa-youtube", reddit: "fa-brands fa-reddit-alien",
      telegram: "fa-brands fa-telegram", twitch: "fa-brands fa-twitch",
      pinterest: "fa-brands fa-pinterest", discord: "fa-brands fa-discord",
      whatsapp: "fa-brands fa-whatsapp", steam: "fa-brands fa-steam",
      spotify: "fa-brands fa-spotify", soundcloud: "fa-brands fa-soundcloud",
      google: "fa-brands fa-google", duckduckgo: "fa-solid fa-magnifying-glass",
      haraj: "fa-solid fa-store", opensooq: "fa-solid fa-store-alt",
    };
    return B[platform] || B[platformOf(platform)] || "";
  }

  function platformOf(site) {
    const s = (site || "").toLowerCase();
    if (s.includes("instagram")) return "instagram";
    if (s.includes("tiktok")) return "tiktok";
    if (s.includes("snapchat")) return "snapchat";
    if (s.includes("twitter")) return "x";
    if (s === "x" || s.includes("x.com")) return "x";
    if (s.includes("facebook") || s === "fb" || s.includes("fb.")) return "facebook";
    if (s.includes("github")) return "github";
    if (s.includes("linkedin")) return "linkedin";
    if (s.includes("youtube")) return "youtube";
    if (s.includes("reddit")) return "reddit";
    if (s.includes("telegram") || s.includes("t.me")) return "telegram";
    if (s.includes("twitch")) return "twitch";
    if (s.includes("pinterest")) return "pinterest";
    if (s.includes("discord")) return "discord";
    if (s.includes("whatsapp") || s.includes("wa.me")) return "whatsapp";
    if (s.includes("steam")) return "steam";
    if (s.includes("spotify")) return "spotify";
    if (s.includes("soundcloud")) return "soundcloud";
    if (s.includes("google")) return "google";
    if (s.includes("haraj")) return "haraj";
    if (s.includes("opensooq")) return "opensooq";
    return "";
  }

  function letterFor(site) {
    const s = esc((site || "").replace(/[.-]/g, " ").trim());
    return s ? s[0].toUpperCase() : "?";
  }

  function icHtml(site) {
    const fa = faIcon(site);
    if (fa) return `<i class="${fa}" aria-hidden="true"></i>`;
    return `<span class="plat-letter">${letterFor(site)}</span>`;
  }

  function avatarHtml(item) {
    const p = item.platform || platformOf(item.site || item.name || "");
    const pcls = p ? " p-" + p : "";
    const letter = letterFor(item.site || item.name || p || "?");
    if (!item.avatar_url) return `<div class="site-avatar fall${pcls}"><div class="fb">${letter}</div></div>`;
    return `<div class="site-avatar${pcls}"><img src="${esc(item.avatar_url)}" alt="" loading="lazy" onerror="laxFbAvatar(this,'${letter}')"></div>`;
  }

  function statusChip(status) {
    const map = {
      registered: ["ok", t("status_registered"), "fa-solid fa-circle-check"],
      not_registered: ["no", t("status_not_registered"), "fa-solid fa-circle-xmark"],
      possible: ["warn", Lx("possible"), "fa-solid fa-question"],
      link: ["no", Lx("link"), "fa-solid fa-arrow-up-right-from-square"],
      warning: ["warn", t("status_warning"), "fa-solid fa-triangle-exclamation"],
      clean: ["ok", Lx("clean"), "fa-solid fa-shield-heart"],
    };
    const c = map[status] || ["err", t("status_error"), "fa-solid fa-triangle-exclamation"];
    return `<span class="chip ${c[0]}"><i class="${c[2]}" aria-hidden="true"></i> ${esc(c[1])}</span>`;
  }

  function riskMeta(level) {
    const m = {
      low: [t("riskLow"), "risk-low", "22"],
      medium: [t("riskMedium"), "risk-medium", "55"],
      high: [t("riskHigh"), "risk-high", "88"],
    }[level] || [t("riskMedium"), "risk-medium", "50"];
    return m;
  }

  /* ---------- لوحة التقرير الذكي ---------- */
  function aiPanel(ai) {
    if (!ai) return "";
    if (ai.status === "error" || ai.status === "unavailable") {
      return `<div class="note-msg"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i> ${esc(ai.message || "AI Error")}</div>`;
    }
    if (ai.status === "limit") {
      return `<div class="note-msg"><i class="fa-solid fa-hourglass-half" aria-hidden="true"></i> ${esc(ai.message || "Rate limit")}</div>`;
    }
    if (!ai.summary && !ai.name) return "";

    const [riskLbl, riskCls, riskPct] = riskMeta(ai.risk_level);
    const pct = Math.max(0, Math.min(100, ai.risk_score || 0));

    const field = (label, obj, key) => {
      const v = key && obj && typeof obj === "object" ? obj.value : obj;
      if (key ? !obj || !obj.value : v == null || v === "") return "";
      const cn = key ? (obj.confidence || 0) : 0;
      return `<div class="ai-field">
          <div class="lbl">${esc(label)} ${key ? `<span class="conf">${t("confidence")} ${cn}%</span>` : ""}</div>
          <div class="val">${esc(v)}${key ? `<span class="sub-note">${esc((obj.source || "") !== "" ? t("source") + ": " + obj.source : "")}</span>` : ""}</div>
          ${key ? `<div class="conf-bar"><span style="width:${cn}%"></span></div>` : ""}
        </div>`;
    };

    let langs = "";
    if (ai.languages && ai.languages.length) {
      langs += `<li><i class="fa-solid fa-language" aria-hidden="true"></i> ${t("languages")}: ${esc(ai.languages.join("، "))}</li>`;
    }
    if (ai.interests && ai.interests.length) {
      langs += `<li><i class="fa-solid fa-wand-magic-sparkles" aria-hidden="true"></i> ${t("interests")}: ${esc(ai.interests.join("، "))}</li>`;
    }

    const accounts = (ai.social_accounts || ai.accounts || []).map((a) =>
      `<li class="acc"><a href="${esc(a.url || "#")}" target="_blank" rel="noopener noreferrer">${icHtml(a.platform || a.username)} ${esc(a.platform || a.username || "")}${a.username && a.username !== a.platform ? " — " + esc(a.username) : ""}</a></li>`).join("");

    const chipList = (items) => !items || !items.length ? ""
      : `<div class="detail-chips">${items.filter(Boolean).map((x) => `<span class="chip ok">${esc(String(x))}</span>`).join("")}</div>`;

    const rels = (ai.relationships || []).length
      ? `<div class="section-title"><i class="fa-solid fa-diagram-project" aria-hidden="true"></i> ${t("relationsLbl")}</div>
         <ul class="tag-list">${(ai.relationships || []).map((r) => `<li>${esc(r.related_to || "")} <i class="fa-solid fa-right-left" aria-hidden="true"></i> ${esc(r.how || "")}</li>`).join("")}</ul>` : "";

    const timeline = (ai.timeline || []).length
      ? `<div class="section-title"><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i> ${t("timelineLbl")}</div>
         <div class="dossier"><div class="d-body">${(ai.timeline || []).map((ev2) =>
           `<div class="kv"><dt>${esc(ev2.date || "—")}</dt><dd>${esc(ev2.event || "")}</dd></div>`).join("")}</div></div>` : "";

    return `<div class="ai-panel" id="printArea">
      <div class="ai-head">
        <div class="ai-ic"><i class="fa-solid fa-brain" aria-hidden="true"></i></div>
        <div><h3>${t("aiTitle")}</h3><div class="sub">${t("aiSubtitle")}</div></div>
        ${ai.used_model ? `<div class="ai-model" title="${esc(ai.used_model)}">${esc(ai.used_model)}</div>` : ""}
      </div>
      <div class="ai-body">
        ${ai.summary ? `<div class="ai-summary">${esc(ai.summary)}</div>` : ""}
        ${rels}
        <div class="ai-grid">
          ${field(t("fullName"), ai.full_name && ai.full_name.value) || field(t("fullName"), ai.full_name) || field(t("name"), ai.name && ai.name.value) || field(t("name"), ai.name)}
          ${field(t("birthDate"), ai.birth_date && ai.birth_date.value) || field(t("birthDate"), ai.birth_date)}
          ${(ai.age_estimate && ai.age_estimate.value) ? field(t("ageEstimate"), ai.age_estimate) : field(t("age"), ai.age && ai.age.value) || field(t("age"), ai.age)}
          ${field(t("gender"), ai.gender && ai.gender.value) || field(t("gender"), ai.gender)}
          ${field(t("location"), ai.location && ai.location.value) || field(t("location"), ai.location)}
          ${(ai.location && (ai.location.city || ai.location.country)) ? `<div class="ai-field"><div class="lbl">${t("cityCountry")}</div><div class="val">${esc([ai.location.city, ai.location.country].filter(Boolean).join(" ، "))}<span class="sub-note">${esc(ai.location.source ? t("source") + ": " + ai.location.source : "")}</span></div></div>` : ""}
          ${field(t("profession"), ai.profession && ai.profession.value) || field(t("profession"), ai.profession) || field(t("occupation"), ai.occupation && ai.occupation.value) || field(t("occupation"), ai.occupation)}
        </div>
        ${ai.phone_numbers && ai.phone_numbers.length ? `<div class="section-title"><i class="fa-solid fa-phone" aria-hidden="true"></i> ${t("phoneNumbers")}</div>${chipList(ai.phone_numbers)}` : ""}
        ${ai.emails && ai.emails.length ? `<div class="section-title"><i class="fa-solid fa-envelope" aria-hidden="true"></i> ${t("emails")}</div>${chipList(ai.emails)}` : ""}
        ${ai.aliases && ai.aliases.length ? `<div class="section-title"><i class="fa-solid fa-fingerprint" aria-hidden="true"></i> ${t("aliases")}</div>${chipList(ai.aliases)}` : ""}
        ${langs ? `<ul class="tag-list">${langs}</ul>` : ""}
        ${accounts ? `<div class="section-title"><i class="fa-solid fa-user-tie" aria-hidden="true"></i> ${t("accountsLbl")}</div><ul class="tag-list">${accounts}</ul>` : ""}
        ${ai.extra_info ? `<div class="note-msg"><i class="fa-solid fa-circle-info" aria-hidden="true"></i> ${esc(ai.extra_info)}</div>` : ""}
        ${ai.personal_note ? `<div class="note-msg"><i class="fa-solid fa-note-sticky" aria-hidden="true"></i> ${esc(ai.personal_note)}</div>` : ""}
        ${timeline}
        <div class="risk-wrap ${riskCls}">
          <div class="risk-row"><span>${t("riskScore")}</span><b>${pct}% — ${riskLbl}</b></div>
          <div class="risk-bar"><span style="width:${pct}%"></span></div>
        </div>
      </div>
    </div>`;
  }

  /* ---------- حسابات (username / email accounts / phone platforms) ---------- */
  function accountGrid(list, opts) {
    if (!list || !list.length) return "";
    const cards = list.map((it) => {
      const site = it.label || it.site || it.name || it.platform || t("unknown");
      const key = it.platform || platformOf(site);
      const url = it.url || "";
      const st = it.status || "registered";
      return `<div class="card site-card ok-comp">
        ${avatarHtml(it)}
        <div style="display:flex;align-items:center;">
          ${faIcon(key) ? `<i class="${faIcon(key)} plat-ic" aria-hidden="true"></i>` : `<div class="plat-icon letter">${letterFor(site)}</div>`}
        </div>
        <div class="meta">
          <div class="site">${esc(site)}</div>
          ${url ? `<div class="url"><a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a></div>` : ""}
          ${it.note ? `<div class="note-txt">${esc(it.note)}</div>` : ""}
        </div>
        ${statusChip(st)}
      </div>`;
    }).join("");
    const title = (opts && opts.title) || t("platformResults");
    return `<div class="section-title"><i class="fa-solid fa-globe" aria-hidden="true"></i> ${esc(title)} (${list.length})</div><div class="grid-cards">${cards}</div>`;
  }

  /* ---------- البيانات حسب النوع ---------- */
  function renderUsername(d) {
    return accountGrid(d.accounts, { title: t("accountsLbl") });
  }

  function renderEmail(d) {
    const s = d.summary || {};
    let html = "";
    html += `<div class="card dossier gv">
      <div class="meta">
        <div class="site"><i class="fa-solid fa-envelope" aria-hidden="true"></i> ${esc(d.email)}</div>
        <div class="d-body">
          <div class="kv"><dt>${t("domainLbl")}</dt><dd>${esc(d.domain || "")}</dd></div>
          ${(d.provider && d.provider.name) ? `<div class="kv"><dt>${t("emailProvider")}</dt><dd><i class="fa-solid fa-server" aria-hidden="true"></i> ${esc(d.provider.name)}</dd></div>` : ""}
          <div class="kv"><dt>${t("platformsChecked")}</dt><dd><span class="chip ok" style="margin:0">${esc(String(s.platforms_checked || 121))} ${t("platformsCheckedUnit")}</span></dd></div>
          <div class="kv"><dt>${Lx("count")}</dt><dd>${esc(String(s.accounts_count))}</dd></div>
          <div class="kv"><dt>${t("platformsFoundLbl")}</dt><dd>${(s.platforms_found || []).slice(0, 10).map((x) => `<span class="chip ok" style="margin:2px">${esc(x)}</span>`).join(" ") || "—"}</dd></div>
        </div>
      </div>
      ${(d.gravatar && d.gravatar.available) ? `
        <div class="gv-avatar">
          ${avatarHtml({ avatar_url: d.gravatar.url, site: "gravatar", platform: "" })}
          ${d.gravatar.name ? `<div class="gv-name">${esc(d.gravatar.name)}</div>` : ""}
        </div>` : ""}
      ${statusChip(s.accounts_count ? "registered" : "link")}
    </div>`;

    html += accountGrid(d.accounts, { title: t("accountsLbl") });

    const br = d.breaches || {};
    if (br.items && br.items.length) {
      html += `<div class="section-title"><i class="fa-solid fa-shield-halved" aria-hidden="true"></i> ${t("breachesLbl")} (${br.items.length})</div>
        <div class="dossier"><div class="d-body">${br.items.map((b) => `
          <div class="kv"><dt>${esc(b.date || "—")}</dt><dd>${esc(b.name || "")} ${b.pwned ? `<span class="chip warn" style="margin-inline-start:8px">${esc(String(b.pwned))} accounts</span>` : ""}${(b.classes || []).length ? `<div class="note-txt">${esc(b.classes.join("، "))}</div>` : ""}</dd></div>`).join("")}</div></div>`;
    } else if (br.status === "clean") {
      html += `<div class="section-title"><i class="fa-solid fa-shield-heart" aria-hidden="true"></i> ${t("breachesLbl")}</div><div class="note-msg"><i class="fa-solid fa-circle-check" aria-hidden="true"></i> ${Lx("fresh")}</div>`;
    } else if (br.note) {
      html += `<div class="note-msg"><i class="fa-solid fa-info-circle" aria-hidden="true"></i> ${esc(br.note)}</div>`;
    }

    if (d.whois && d.whois.available) {
      html += `<div class="section-title"><i class="fa-solid fa-sitemap" aria-hidden="true"></i> ${t("whoisLbl")}</div>
        <div class="dossier"><div class="d-body">
          <div class="kv"><dt>${t("domainLbl")}</dt><dd>${esc(d.whois.domain)}</dd></div>
          ${d.whois.registrar ? `<div class="kv"><dt>Registrar</dt><dd>${esc(d.whois.registrar)}</dd></div>` : ""}
          ${d.whois.created ? `<div class="kv"><dt>Created</dt><dd>${esc(d.whois.created)}</dd></div>` : ""}
          ${d.whois.expires ? `<div class="kv"><dt>Expires</dt><dd>${esc(d.whois.expires)}</dd></div>` : ""}
          ${(d.whois.statuses || []).length ? `<div class="kv"><dt>Status</dt><dd>${esc(d.whois.statuses.join("، "))}</dd></div>` : ""}
        </div></div>`;
    }
    return html;
  }

  function renderPhone(d) {
    const tc = d.tech || {};
    let html = `<div class="card dossier">
      <div class="meta">
        <div class="site"><i class="fa-solid fa-phone" aria-hidden="true"></i> ${esc(d.number || "")}</div>
        <div class="d-body">`;
    const addRow = (k, v) => { if (v != null && v !== "") html += `<div class="kv"><dt>${esc(k)}</dt><dd>${v}</dd></div>`; };
    addRow(t("countryLbl"), `${tc.country_iso2 ? `<span class="fi fi-${esc(tc.country_iso2)} flag" aria-hidden="true"></span>` : ""} ${esc(tc.country || "")}`);
    addRow(t("carrierLbl"), tc.carrier);
    addRow(t("lineTypeLbl"), tc.line_type_label);
    addRow(t("regionLbl"), tc.region_city);
    addRow(t("tzLbl"), (tc.timezones || []).join(", "));
    const fm = tc.formats || {};
    addRow(t("formatsLbl"),
      `<span style="direction:ltr;unicode-bidi:embed">${esc(fm.e164 || "")}<br><span class="muted">${esc(fm.international || "")}</span></span>`);
    if (tc.phoneinfoga) {
      const pi = tc.phoneinfoga;
      addRow("PhoneInfoga", `${esc(pi.Carrier || "")} ${esc(pi.region || "")} ${esc(pi.city || "")}`.trim());
    }
    html += `</div></div><div class="chip ok"><i class="fa-solid fa-circle-check" aria-hidden="true"></i> ${tc.valid === false ? t("status_not_registered") : t("status_registered")}</div></div>`;

    html += accountGrid(d.platforms, { title: t("platformResults") });
    return html;
  }

  /* ---------- التصدير ---------- */
  function exportJSON() {
    if (!compData) return;
    const out = {
      tool: "LAX OSINT",
      kind: compData.kind,
      query: compData.query,
      generated_at: new Date().toISOString(),
      data: compData,
    };
    const blob = new Blob([JSON.stringify(out, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `lax-osint-${compData.kind}-${(compData.query || "report").replace(/[^a-zA-Z0-9]/g, "_")}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }

  function exportPDF() {
    const pa = document.getElementById("printArea");
    if (!pa) { window.print(); return; }
    const backup = document.title;
    document.title = `LAX OSINT — ${compData ? compData.kind : "report"} ${compData ? compData.query : ""}`.trim();
    window.print();
    document.title = backup;
  }

  /* ---------- بث SSE ---------- */
  async function runComprehensive(type, query) {
    busy = true;
    const btn = document.getElementById("btnComprehensive");
    if (btn) btn.disabled = true;
    compData = null;
    els.list.innerHTML = "";
    if (els.resCount) els.resCount.textContent = "0";
    if (els.resCounter) els.resCounter.classList.remove("done");
    if (els.resWrap) els.resWrap.classList.remove("hidden");
    if (els.toolbar) els.toolbar.classList.add("hidden");
    els.log.classList.remove("hidden");
    els.status.classList.add("show");
    els.statusText.textContent = t("searching");
    setAnalyzing(true);

    const store = window.laxAuth.store;
    const url = `${API}/api/comprehensive/${type}?q=${encodeURIComponent(query)}&token=${encodeURIComponent(store.token)}`;

    let resp;
    try { resp = await fetch(url); }
    catch (e) { fail(t("searchFailed")); return; }

    if (!resp.ok || !resp.headers.get("content-type") || !resp.headers.get("content-type").includes("event-stream")) {
      let j = {};
      try { j = await resp.json(); } catch (e) { /* ignore */ }
      if (resp.status === 402) { fail(t("limitReached")); if (window.laxUI) laxUI.openPro(); }
      else if (resp.status === 401) fail(j.message || t("loginRequired"));
      else if (resp.status === 429) fail(j.message || "Rate limited");
      else fail(j.message || t("searchFailed"));
      return;
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let rendered = false;

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) !== -1) {
          const block = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          handleBlock(formatBlock(block), (d) => { if (!rendered && d) { rendered = true; } });
        }
      }
    } catch (e) { /* انقطاع */ }
    finally {
      els.status.classList.remove("show");
      setAnalyzing(false);
      if (els.resCounter) els.resCounter.classList.add("done");
      if (btn) btn.disabled = false;
      busy = false;
    }
  }

  function formatBlock(block) {
    const ev = { name: "", data: "" };
    block.split("\n").forEach((line) => {
      if (line.startsWith("event:")) ev.name = line.slice(6).trim();
      else if (line.startsWith("data:")) ev.data += line.slice(5).trim();
    });
    return ev;
  }

  function handleBlock(ev) {
    if (!ev.data) return;
    let d = {};
    try { d = JSON.parse(ev.data); } catch (e) { return; }

    switch (ev.name) {
      case "meta":
        if (d.quota && window.laxUI) laxUI.setQuota(d.quota);
        if (d.search_type) els.statusText.textContent = `${t("comprehensive")} — ${d.search_type}`;
        break;
      case "progress":
        els.statusText.textContent = d.message || t("searching");
        break;
      case "warn":
        els.list.insertAdjacentHTML("beforeend", `<div class="note-msg"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i> ${esc(d.message || "")}</div>`);
        break;
      case "result":
        if (d.type === "comprehensive") render(d.data);
        break;
      case "done":
        els.statusText.textContent = `${t("done")}: ${d.count} (${d.duration} ${t("seconds")})`;
        if (els.toolbar && compData) els.toolbar.classList.remove("hidden");
        break;
    }
  }

  function render(data) {
    compData = data;
    els.list.innerHTML = "";
    let html = "";

    if (data.error) {
      html += `<div class="note-msg"><i class="fa-solid fa-circle-xmark" aria-hidden="true"></i> ${esc(data.message || data.error)}</div>`;
    } else {
      if (data.ai) {
        if (data.ai.summary || data.ai.name || data.ai.full_name || data.ai.email ||
            data.ai.phone_numbers || data.ai.social_accounts || data.ai.aliases ||
            data.ai.extra_info || data.ai.status) html += aiPanel(data.ai);
      }
      if (data.kind === "username") html += renderUsername(data);
      else if (data.kind === "email") html += renderEmail(data);
      else if (data.kind === "phone") html += renderPhone(data);

      if (data.links && data.links.length) {
        html += `<div class="section-title"><i class="fa-solid fa-arrow-up-right-from-square" aria-hidden="true"></i> ${t("searchLinks")}</div>
          <div class="links-row">${data.links.map((l) => `<a href="${esc(l.url)}" target="_blank" rel="noopener noreferrer">${icHtml(l.icon || l.label)} ${esc(l.label)}</a>`).join("")}</div>`;
      }
    }
    els.list.insertAdjacentHTML("beforeend", html);
    if (els.toolbar) els.toolbar.classList.remove("hidden");
  }

  function fail(msg) {
    els.status.classList.remove("show");
    setAnalyzing(false);
    if (els.resCounter) els.resCounter.classList.add("done");
    els.list.insertAdjacentHTML("beforeend", `<div class="note-msg"><i class="fa-solid fa-circle-xmark" aria-hidden="true"></i> ${esc(msg)}</div>`);
  }

  /* ---------- الربط ---------- */
  function bind() {
    const btn = document.getElementById("btnComprehensive");
    const input = document.getElementById("query");
    if (btn) btn.addEventListener("click", () => {
      if (busy) return;
      const type = (document.querySelector(".tab.active") || {}).getAttribute?.("data-type") || "username";
      const q = (input && input.value.trim()) || "";
      if (!q) { if (window.laxUI) laxUI.toast(t("resultsFor") + "?", "err"); return; }
      if (!window.laxAuth.isLoggedIn()) {
        if (window.laxUI) { laxUI.toast(t("loginRequired"), "err"); laxUI.openModal("login"); }
        return;
      }
      runComprehensive(type, q).then(() => { if (window.laxUI) window.laxUI.refreshQuota(); });
    });

    const eJ = document.getElementById("btnExportJson");
    if (eJ) eJ.addEventListener("click", exportJSON);
    const eP = document.getElementById("btnExportPdf");
    if (eP) eP.addEventListener("click", exportPDF);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bind);
  else bind();

  window.laxComp = { runComprehensive };
})();