/* LAX OSINT — البحث المتقدم (زر "بحث متقدم")
   =============================================
   يبث من /api/advanced?kind=..&q=..&token=.. ثم يرسم:
     · مراحل التنفيذ (بحث عميق / فحص ثغرات / ديب ويب / Qwen)
     · نتائج Deep Research: Wayback + Dorks + PGP + Shodan + Censys
     · خلاصة فحص الثغرات + تحديد الأهداف المفحوصة
     · مؤشرات الديب ويب (توتر/بدائل آمنة)
     · التقرير العميق Qwen (برو) مع الأنماط/التناقضات/الاتجاهات
     · تصدير CSV
   أمان الواجهة: كل القيم تُهرب HTML (esc). لم يُنفَّذ أي هجوم فحص سلبي فقط.
*/
(function () {
  "use strict";

  const API = (window.LAX_CONFIG && window.LAX_CONFIG.API_URL) || "http://127.0.0.1:8000";
  const t = (k) => window.laxI18n.t(k);

  let advResult = null;

  const els = {
    get status() { return document.getElementById("status"); },
    get statusText() { return document.getElementById("statusText"); },
    get analyzeBar() { return document.getElementById("analyzeBar"); },
    get list() { return document.getElementById("resultList"); },
    get resWrap() { return document.getElementById("resWrap"); },
    get resCounter() { return document.getElementById("resCounter"); },
    get resCount() { return document.getElementById("resCount"); },
    get toolbar() { return document.getElementById("compToolbar"); },
    get csvBtn() { return document.getElementById("btnExportCsv"); },
  };

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function sevMeta(s) {
    return {
      critical: [t("sevCritical"), "s-crit"],
      high: [t("sevHigh"), "s-high"],
      medium: [t("sevMedium"), "s-med"],
      low: [t("sevLow"), "s-low"],
      info: [t("sevInfo"), "s-info"],
    }[s || "info"] || [s || "", "s-info"];
  }

  /* ---------- أقسام ---------- */
  function secTitle(icon, label) {
    return `<div class="section-title adv-sec"><i class="fa-solid ${icon}" aria-hidden="true"></i> ${esc(label)}</div>`;
  }

  function renderResearch(r) {
    if (!r) return "";
    let html = secTitle("fa-magnifying-glass-chart", t("deepResearch"));

    const wb = r.wayback || {};
    if (wb.items && wb.items.length) {
      html += `<div class="adv-sub">${esc(t("researchWayback"))} <span class="chip ok" style="margin:0">${wb.items.length}</span></div>
        <div class="adv-rows">${wb.items.map((it) => `<a class="adv-row" href="${esc(it.saved || it.url)}" target="_blank" rel="noopener noreferrer">
          <span class="adv-dt">${esc(it.date || "")}</span><span class="adv-url">${esc(it.url || "")}</span>
        </a>`).join("")}</div>`;
    }

    const dk = r.dorks || {};
    if (dk.items && dk.items.length) {
      html += `<div class="adv-sub">${esc(t("searchLinks"))} <span class="chip ok" style="margin:0">${dk.items.length}</span></div>
        <div class="adv-rows">${dk.items.map((it) => `<a class="adv-row" href="${esc(it.url)}" target="_blank" rel="noopener noreferrer">
          <span class="adv-url">${esc(it.title || it.url || "")}</span>
        </a>`).join("")}</div>`;
    }
    if (dk.dorks && dk.dorks.length) {
      html += `<div class="chip-group">${dk.dorks.slice(0, 10).map((d) => `<span class="chip info">${esc(d)}</span>`).join("")}</div>`;
    }

    const pg = r.pgp || {};
    if (pg.items && pg.items.length) {
      html += `<div class="adv-sub">${esc(t("researchPgp"))} <span class="chip ok" style="margin:0">${pg.items.length}</span></div>
        <div class="adv-rows">${pg.items.map((it) => `<a class="adv-row" href="${esc(it.url || "#")}" target="_blank" rel="noopener noreferrer">
          <span class="adv-kid">${esc(it.key_id || "")}</span><span class="adv-url">${esc(it.identity || "")}</span>
        </a>`).join("")}</div>`;
    }

    const chips = [];
    for (const name of ["shodan", "censys"]) {
      const d = r[name] || {};
      if (d.status === "ok") chips.push(`<span class="chip ok"><i class="fa-solid fa-circle-check" aria-hidden="true"></i> ${esc(name)}: ${esc(String((d.subdomains || d.certs || []).length))}</span>`);
      else if (d.status === "needs_key") chips.push(`<span class="chip warn"><i class="fa-solid fa-key" aria-hidden="true"></i> ${esc(name)}: ${esc(t("needsTor"))}</span>`);
      else if (d.status === "error") chips.push(`<span class="chip warn">${esc(name)}: ${esc(d.note || d.error || "")}</span>`);
    }
    if (chips.length) html += `<div class="chip-group">${chips.join("")}</div>`;
    return html;
  }

  function renderVuln(v) {
    if (!v) return "";
    let html = secTitle("fa-shield-halved", t("vulnScan"));
    const note = v.notes || [];
    if (note.length) {
      html += `<div class="note-msg"><i class="fa-solid fa-hand" aria-hidden="true"></i> ${esc(note[0] || t("advSafe"))}</div>`;
    }
    if (!v.targets || !v.targets.length) {
      html += `<div class="note-msg">${esc(t("noVulnTargets"))}</div>`;
      return html;
    }
    html += `<div class="adv-sub">${esc(t("advTargets"))}: ${v.targets.map((u) => `<a class="adv-url mono" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(u)}</a>`).join(" · ")}</div>`;
    const res = v.results || {};
    const rows = [];
    for (const url of v.targets) {
      const r = res[url];
      if (!r) continue;
      const pct = (r.summary && r.summary.severity_counts) || {};
      rows.push(`<div class="card site-card ok-comp">
        <div class="meta">
          <div class="site"><i class="fa-solid fa-server" aria-hidden="true"></i> ${esc(r.host || url)} <span class="chip ${r.status === 200 ? "ok" : "warn"}" style="margin:0 8px">HTTP ${esc(String(r.status || "?"))}</span></div>
          <div class="adv-kv">
            ${["critical", "high", "medium", "low", "info"].filter((s) => pct[s]).map((s) => {
              const [lbl, cls] = sevMeta(s);
              return `<span class="sev ${cls}">${lbl}: ${pct[s]}</span>`;
            }).join("")}
          </div>
        </div>
        <div class="adv-detail">
          ${(r.exposures || []).map((f) => `<div class="expo ${f.severity === "high" || f.severity === "critical" ? "expo-hi" : ""}">
            <i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i> <b>${esc(f.path || f.type || f.title || "")}</b> ${esc(f.hint || f.note || "")}</div>`).join("") || `<div class="note-txt">${esc(t("done"))} — no findings flagged</div>`}
        </div>
      </div>`);
    }
    html += rows.join("");
    return html;
  }

  function renderDeepweb(dw) {
    if (!dw) return "";
    let html = secTitle("fa-mask", t("deepWeb"));
    if (dw.status === "needs_tor" || dw.status === "empty") {
      html += `<div class="note-msg"><i class="fa-solid fa-circle-info" aria-hidden="true"></i> ${esc(dw.note || t("needsTor"))}</div>`;
    } else {
      html += `<div class="note-msg"><i class="fa-solid fa-circle-check" aria-hidden="true"></i> ${esc(dw.note || "")}</div>`;
      html += `<div class="adv-rows">${(dw.items || []).map((it) => `<a class="adv-row" href="${esc(it.url)}" target="_blank" rel="noopener noreferrer">
        <span class="adv-url">${esc(it.title || it.url || "")}</span></a>`).join("")}</div>`;
    }
    if (dw.links && dw.links.length) {
      html += `<div class="links-row">${dw.links.map((l) => `<a href="${esc(l.url)}" target="_blank" rel="noopener noreferrer"><i class="fa-solid fa-arrow-up-right-from-square" aria-hidden="true"></i> ${esc(l.label)}</a>`).join("")}</div>`;
    }
    return html;
  }

  /* ---------- تقرير Qwen العميق ---------- */
  function renderQwen(ai) {
    if (!ai) return "";
    if (ai.status === "pro_required") {
      return `<div class="note-msg"><i class="fa-solid fa-lock" aria-hidden="true"></i> ${esc(ai.note || t("proAdvOnly"))}</div>`;
    }
    if (ai.status === "error" || ai.status === "unavailable") {
      return `<div class="note-msg"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i> ${esc(ai.message || "Error")}</div>`;
    }
    if (ai.status === "limit") {
      return `<div class="note-msg"><i class="fa-solid fa-hourglass-half" aria-hidden="true"></i> ${esc(ai.message || "Rate limit")}</div>`;
    }
    if (!ai.summary) return "";

    const [riskLbl, riskCls, riskPct] = (function () {
      const m = { low: [t("riskLow"), "risk-low", "22"], medium: [t("riskMedium"), "risk-medium", "55"], high: [t("riskHigh"), "risk-high", "88"] }[ai.risk_level];
      return m || [t("riskMedium"), "risk-medium", "50"];
    })();
    const pct = Math.max(0, Math.min(100, ai.risk_score || 0));

    const list = (items, fn) => !items || !items.length ? "" : `<ul class="tag-list">${items.map(fn).join("")}</ul>`;

    let html = `<div class="ai-panel adv-qwen">
      <div class="ai-head">
        <div class="ai-ic"><i class="fa-solid fa-bolt" aria-hidden="true"></i></div>
        <div><h3>${esc(t("qwenReport"))}</h3><div class="sub">${esc(t("aiSubtitle"))}</div></div>
        ${ai.used_model ? `<div class="ai-model" title="${esc(ai.used_model)}">${esc(ai.used_model)}</div>` : ""}
      </div>
      <div class="ai-body">
        ${ai.summary ? `<div class="ai-summary">${esc(ai.summary)}</div>` : ""}
        ${list(ai.relationships, (r) => `<li><i class="fa-solid fa-right-left" aria-hidden="true"></i> ${esc(r.related_to || "")} — ${esc(r.how || "")}</li>`)}
        ${(ai.patterns || []).length ? `<div class="section-title"><i class="fa-solid fa-wave-square" aria-hidden="true"></i> ${esc(t("patternsLbl"))}</div>
          <ul class="tag-list">${ai.patterns.map((p) => `<li><b>${esc(typeof p === "string" ? p : p.pattern || "")}</b>: ${esc(typeof p === "string" ? "" : p.details || "")}</li>`).join("")}</ul>` : ""}
        ${(ai.contradictions || []).length ? `<div class="section-title"><i class="fa-solid fa-code-compare" aria-hidden="true"></i> ${esc(t("contradictionsLbl"))}</div>
          <ul class="tag-list">${ai.contradictions.map((c) => `<li><b>${esc(typeof c === "string" ? c : c.finding || c.why || "")}</b> — ${esc(typeof c === "string" ? "" : c.why || "")}</li>`).join("")}</ul>` : ""}
        ${(ai.next_vectors || []).length ? `<div class="section-title"><i class="fa-solid fa-compass" aria-hidden="true"></i> ${esc(t("vectorsLbl"))}</div>
          <div class="chip-group">${ai.next_vectors.map((v) => `<span class="chip info">${esc(typeof v === "string" ? v : v.vector || v)}</span>`).join("")}</div>` : ""}
        ${(ai.critical_assets || []).length ? `<div class="section-title"><i class="fa-solid fa-satellite-dish" aria-hidden="true"></i> ${esc(t("criticalAssetsLbl"))}</div>
          <div class="chip-group">${ai.critical_assets.map((a) => `<span class="chip warn">${esc(typeof a === "string" ? a : a.asset || a)}</span>`).join("")}</div>` : ""}
        ${(ai.timeline || []).length ? `<div class="section-title"><i class="fa-solid fa-clock-rotate-left" aria-hidden="true"></i> ${esc(t("timelineLbl"))}</div>
          <div class="dossier"><div class="d-body">${ai.timeline.map((ev) => `<div class="kv"><dt>${esc(ev.date || "")}</dt><dd>${esc(ev.event || "")}</dd></div>`).join("")}</div></div>` : ""}
        <div class="risk-wrap ${riskCls}">
          <div class="risk-row"><span>${esc(t("riskScore"))}</span><b>${pct}% — ${riskLbl}</b></div>
          <div class="risk-bar"><span style="width:${pct}%"></span></div>
        </div>
      </div>
    </div>`;
    return html;
  }

  /* ---------- الرسم ---------- */
  function render(d) {
    advResult = d;
    els.list.insertAdjacentHTML("beforeend",
      secTitle("fa-microscope", `${esc(t("advanced"))} — ${esc(d.query)}`) +
      renderResearch(d.research) +
      renderVuln(d.vuln) +
      renderDeepweb(d.deepweb) +
      renderQwen(d.ai_deep));
    if (els.csvBtn && d.csv) els.csvBtn.style.display = "inline-flex";
  }

  function exportCSV() {
    if (!advResult || !advResult.csv) return;
    const blob = new Blob([advResult.csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `lax-osint-advanced-${(advResult.query || "report").replace(/[^a-zA-Z0-9]/g, "_")}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }

  /* ---------- بث SSE ---------- */
  async function runAdvanced(type, query) {
    const store = window.laxAuth.store;
    const url = `${API}/api/advanced?kind=${type}&q=${encodeURIComponent(query)}&token=${encodeURIComponent(store.token)}`;

    els.list.innerHTML = "";
    els.resWrap.classList.remove("hidden");
    els.resCounter.classList.remove("done");
    els.resCount.textContent = "0";
    els.toolbar.classList.add("hidden");
    if (els.csvBtn) els.csvBtn.style.display = "none";
    els.log.classList.remove("hidden");
    els.status.classList.add("show");
    els.statusText.textContent = t("advanced");
    if (els.analyzeBar) els.analyzeBar.classList.remove("hidden");

    let resp;
    try { resp = await fetch(url); } catch (e) { fail(t("searchFailed")); return; }
    if (!resp.ok || !resp.headers.get("content-type") || !resp.headers.get("content-type").includes("event-stream")) {
      let j = {};
      try { j = await resp.json(); } catch (e) { /* ignore */ }
      if (resp.status === 402) { fail(t("limitReached")); if (window.laxUI) laxUI.openPro(); }
      else if (resp.status === 401) fail(j.message || t("loginRequired"));
      else fail(j.message || t("searchFailed"));
      return;
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) !== -1) {
          const block = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          handle(parseBlock(block));
        }
      }
    } catch (e) { /* انقطاع */ }
    finally {
      els.status.classList.remove("show");
      if (els.analyzeBar) els.analyzeBar.classList.add("hidden");
      els.resCounter.classList.add("done");
    }
  }

  function parseBlock(block) {
    const ev = { name: "", data: "" };
    block.split("\n").forEach((line) => {
      if (line.startsWith("event:")) ev.name = line.slice(6).trim();
      else if (line.startsWith("data:")) ev.data += line.slice(5).trim();
    });
    return ev;
  }

  function handle(ev) {
    if (!ev.data) return;
    let d = {};
    try { d = JSON.parse(ev.data); } catch (e) { return; }
    switch (ev.name) {
      case "stage":
        els.statusText.textContent = `${t("stage")} ${d.id}/4 — ${d.title || ""}`;
        break;
      case "progress":
        els.statusText.textContent = d.message || t("advanced");
        break;
      case "warn":
        els.list.insertAdjacentHTML("beforeend", `<div class="note-msg"><i class="fa-solid fa-circle-exclamation" aria-hidden="true"></i> ${esc(d.message || "")}</div>`);
        break;
      case "result":
        render(d);
        break;
      case "done":
        els.statusText.textContent = `${t("done")}: ${d.count} (${d.duration} ${t("seconds")})`;
        if (advResult) els.toolbar.classList.remove("hidden");
        break;
    }
  }

  function fail(msg) {
    els.status.classList.remove("show");
    if (els.analyzeBar) els.analyzeBar.classList.add("hidden");
    els.resCounter.classList.add("done");
    els.list.insertAdjacentHTML("beforeend", `<div class="note-msg"><i class="fa-solid fa-circle-xmark" aria-hidden="true"></i> ${esc(msg)}</div>`);
  }

  function bind() {
    const btn = document.getElementById("btnAdvanced");
    const input = document.getElementById("query");
    if (btn) btn.addEventListener("click", () => {
      const type = (document.querySelector(".tab.active") || {}).getAttribute?.("data-type") || "username";
      const q = (input && input.value.trim()) || "";
      if (!q) { if (window.laxUI) laxUI.toast(t("resultsFor") + "?", "err"); return; }
      if (!window.laxAuth.isLoggedIn()) {
        if (window.laxUI) { laxUI.toast(t("loginRequired"), "err"); laxUI.openModal("login"); }
        return;
      }
      runAdvanced(type, q).then(() => { if (window.laxUI) window.laxUI.refreshQuota(); });
    });
    const csv = document.getElementById("btnExportCsv");
    if (csv) csv.addEventListener("click", exportCSV);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", bind);
  else bind();

  window.laxAdv = { runAdvanced };
})();