/* LAX OSINT — تنفيذ البحث وبث النتائج عبر SSE + رسم البطاقات */
(function () {
  "use strict";

  const API = (window.LAX_CONFIG && window.LAX_CONFIG.API_URL) || "http://127.0.0.1:8000";
  const t = (k) => window.laxI18n.t(k);

  const els = {
    get status() { return document.getElementById("status"); },
    get statusText() { return document.getElementById("statusText"); },
    get log() { return document.getElementById("log"); },
  };

  function hostOf(url) {
    try { return new URL(url).hostname; } catch (e) { return ""; }
  }

  function letterFor(site) {
    const s = (site || "").replace(/[.-]/g, " ").trim();
    return s ? s[0].toUpperCase() : "?";
  }

  function chipFor(status) {
    const map = {
      registered: ["ok", t("status_registered")],
      not_registered: ["no", t("status_not_registered")],
      rate_limited: ["warn", t("status_rate_limited")],
      warning: ["warn", t("status_warning")],
    };
    const c = map[status] || ["err", t("status_error")];
    return `<span class="chip ${c[0]}">${c[1]}</span>`;
  }

  const Render = {
    site(item) {
      const url = item.url || "";
      const site = item.site || item.name || t("unknown");
      return `<div class="card">
        <div class="favicon">${letterFor(site)}</div>
        <div class="meta">
          <div class="site">${esc(site)}</div>
          ${url ? `<div class="url"><a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a></div>` : ""}
          ${item.note ? `<div class="note-msg">${esc(item.note)}</div>` : ""}
        </div>
        ${chipFor(item.status)}
      </div>`;
    },
    avatar(item) {
      const img = item.image_base64
        ? `<img class="avatar-img" src="${item.image_base64}" alt="avatar">`
        : `<a href="${esc(item.url)}" target="_blank" rel="noopener noreferrer"><img class="avatar-img" src="${esc(item.url)}" alt="avatar"></a>`;
      return `<div class="card avatar-card">
        ${img}
        <div class="meta">
          <div class="site">${t("avatarTitle")}</div>
          <div class="url">${item.hash || item.url || ""}</div>
        </div>
        <span class="chip ok">${t("status_registered")}</span>
      </div>`;
    },
    phone_tech(item) {
      const tech = item.tech || {};
      const scan = tech.scan || {};
      const loc = tech.location || {};
      const rows = [
        ["Number", item.number],
        ["Country", loc.country],
        ["Region", loc.region],
        ["City", loc.city],
        ["Carrier", scan.carrier || scan.operator || scan.provider],
        ["Type", scan.type || scan.line_type],
        ["Valid", scan.valid || (scan.valid === false ? "No" : "")],
      ].filter(([, v]) => v != null && v !== "");
      return `<div class="card dossier">
        <div class="meta">
          <div class="site">📞 ${esc(item.number)}</div>
          <div class="d-body">
            ${rows.map(([k, v]) => `<div class="kv"><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}
          </div>
        </div>
        <span class="chip ok">•</span>
      </div>`;
    },
    dossier(d) {
      const det = d.details || {};
      const emails = det.emails || [];
      const phones = det.phones || [];
      const tools = det.tools || [];
      return `<div class="card dossier">
        <div class="meta">
          <div class="site">🕵️ ${t("dossier")} — ${esc(d.full_name)}</div>
          <div class="d-body">
            ${det.name_found ? `<div class="kv"><dt>${t("site")}</dt><dd>${esc(det.name_found)}</dd></div>` : ""}
            ${det.age ? `<div class="kv"><dt>${t("age")}</dt><dd>${esc(det.age)}</dd></div>` : ""}
            ${emails.length ? `<div class="kv"><dt>${t("emails")}</dt><dd><ul>${emails.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></dd></div>` : ""}
            ${phones.length ? `<div class="kv"><dt>${t("phones")}</dt><dd><ul>${phones.map((p) => `<li>${esc(p)}</li>`).join("")}</ul></dd></div>` : ""}
            ${tools && tools.length ? `<div class="kv"><dt>${t("nameTools")}</dt><dd>${esc(tools.join(" · "))}</dd></div>` : ""}
          </div>
        </div>
        <span class="chip warn">${t("dossier")}</span>
      </div>`;
    },
    link(item) {
      return `<div class="card">
        <div class="favicon">🔗</div>
        <div class="meta">
          <div class="site">${esc(item.title || hostOf(item.url))}</div>
          <div class="url"><a href="${esc(item.url)}" target="_blank" rel="noopener noreferrer">${esc(item.url)}</a></div>
        </div>
        <span class="chip no">↵</span>
      </div>`;
    },
    facebook(item) {
      if (!item || !item.name) return "";
      return `<div class="card avatar-card">
        ${item.picture ? `<img class="avatar-img" src="${esc(item.picture)}" alt="fb">` : `<div class="favicon">👤</div>`}
        <div class="meta">
          <div class="site">Facebook — ${esc(item.name)}</div>
          ${item.about ? `<div class="url">${esc(item.about)}</div>` : ""}
          ${item.url ? `<div class="url"><a href="${esc(item.url)}" target="_blank" rel="noopener noreferrer">${esc(item.url)}</a></div>` : ""}
        </div>
        <span class="chip ok">${t("status_registered")}</span>
      </div>`;
    },
    warning(msg) {
      return `<div class="note-msg">⚠️ ${esc(msg)}</div>`;
    },
  };

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function renderType(type, data) {
    const fn = Render[type];
    if (!fn) return "";
    const html = fn(data);
    els.log.insertAdjacentHTML("beforeend", html);
  }

  async function runSearch(type, query) {
    els.log.innerHTML = "";
    els.log.classList.remove("hidden");
    els.status.classList.add("show");
    els.statusText.textContent = t("searching");

    const store = window.laxAuth.store;
    const url = `${API}/api/search/${type}?q=${encodeURIComponent(query)}&token=${encodeURIComponent(store.token)}`;

    let resp;
    try {
      resp = await fetch(url);
    } catch (e) {
      fail(t("searchFailed"));
      return;
    }

    if (!resp.ok || !resp.headers.get("content-type") || !resp.headers.get("content-type").includes("event-stream")) {
      let j = {};
      try { j = await resp.json(); } catch (e) { /* ignore */ }
      if (resp.status === 402) {
        fail(t("limitReached"));
        if (window.laxUI) laxUI.openPro();
      } else if (resp.status === 401) {
        fail(j.message || t("loginRequired"));
      } else if (resp.status === 429) {
        fail(j.message || "Rate limited");
      } else {
        fail(j.message || t("searchFailed"));
      }
      return;
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    let doneCount = 0;

    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf("\n\n")) !== -1) {
          const block = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          handleBlock(formatBlock(block));
        }
      }
    } catch (e) {
      /* الشبكة انقطعت أثناء البث */
    } finally {
      els.status.classList.remove("show");
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
        els.statusText.textContent = `${t("searching")} ${d.search_type ? "" : ""}`;
        break;
      case "progress":
        els.statusText.textContent = d.step || t("searching");
        break;
      case "warn":
        els.log.insertAdjacentHTML("beforeend", Render.warning(d.message || ""));
        break;
      case "result":
        renderType(d.type, d.data);
        break;
      case "done":
        doneCount = d.count || 0;
        els.statusText.textContent = `${t("done")}: ${d.count} (${d.duration} ${t("seconds")})`;
        els.log.insertAdjacentHTML("beforeend",
          `<div class="done-banner">✓ ${t("done")}: ${d.count} — ${d.duration} ${t("seconds")}</div>`);
        if (doneCount === 0) els.log.insertAdjacentHTML("beforeend", `<div class="empty">${t("noResults")}</div>`);
        break;
      default:
        renderType(ev.name, d); // fallback: أسماء أحداث تلائم أسماء البطاقات
    }
  }

  function fail(msg) {
    els.status.classList.remove("show");
    els.log.insertAdjacentHTML("beforeend", `<div class="note-msg">✖ ${esc(msg)}</div>`);
  }

  window.laxSearch = { runSearch, esc };
})();