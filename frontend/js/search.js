/* LAX OSINT — تنفيذ البحث وبث النتائج عبر SSE + رسم البطاقات الاحترافية */
(function () {
  "use strict";

  const API = (window.LAX_CONFIG && window.LAX_CONFIG.API_URL) || "http://127.0.0.1:8000";
  const t = (k) => window.laxI18n.t(k);

  const els = {
    get status() { return document.getElementById("status"); },
    get statusText() { return document.getElementById("statusText"); },
    get log() { return document.getElementById("log"); },
    get list() { return document.getElementById("resultList"); },
    get resWrap() { return document.getElementById("resWrap"); },
    get resCounter() { return document.getElementById("resCounter"); },
    get resCount() { return document.getElementById("resCount"); },
  };

  /* ---------- أدوات ---------- */
  function letterFor(site) {
    const s = (site || "").replace(/[.-]/g, " ").trim();
    return s ? s[0].toUpperCase() : "?";
  }

  function chipFor(status) {
    const map = {
      registered: ["ok", t("status_registered"), "fa-solid fa-circle-check"],
      not_registered: ["no", t("status_not_registered"), "fa-solid fa-circle-xmark"],
      rate_limited: ["warn", t("status_rate_limited"), "fa-solid fa-triangle-exclamation"],
      warning: ["warn", t("status_warning"), "fa-solid fa-triangle-exclamation"],
    };
    const c = map[status] || ["err", t("status_error"), "fa-solid fa-triangle-exclamation"];
    return `<span class="chip ${c[0]}"><i class="${c[2]}" aria-hidden="true"></i> ${esc(c[1])}</span>`;
  }

  function statusClass(status) {
    if (status === "registered") return "ok";
    if (status === "not_registered") return "no";
    if (status === "rate_limited" || status === "warning") return "warn";
    return "err";
  }

  /* ---------- أيقونات المنصات (favicon من Google) ---------- */
  const PLATFORM_DOMAINS = {
    instagram: "instagram.com",
    tiktok: "tiktok.com",
    snapchat: "snapchat.com",
    x: "x.com",
    facebook: "facebook.com",
    github: "github.com",
    linkedin: "linkedin.com",
    youtube: "youtube.com",
    reddit: "reddit.com",
    telegram: "t.me",
    twitch: "twitch.tv",
    pinterest: "pinterest.com",
    discord: "discord.com",
    whatsapp: "whatsapp.com",
    steam: "steamcommunity.com",
    spotify: "open.spotify.com",
    soundcloud: "soundcloud.com",
  };

  function platformOf(site) {
    const s = (site || "").toLowerCase().replace(/[^a-z0-9.]+/g, "");
    if (s.includes("instagram")) return "instagram";
    if (s.includes("tiktok")) return "tiktok";
    if (s.includes("snapchat")) return "snapchat";
    if (s.includes("twitter")) return "x";
    if (s === "x" || s.includes("x.com")) return "x";
    if (s.includes("facebook") || s === "fb") return "facebook";
    if (s.includes("github")) return "github";
    if (s.includes("linkedin")) return "linkedin";
    if (s.includes("youtube")) return "youtube";
    if (s.includes("reddit")) return "reddit";
    if (s.includes("telegram")) return "telegram";
    if (s.includes("twitch")) return "twitch";
    if (s.includes("pinterest")) return "pinterest";
    if (s.includes("discord")) return "discord";
    if (s.includes("whatsapp")) return "whatsapp";
    if (s.includes("steam")) return "steam";
    if (s.includes("spotify")) return "spotify";
    if (s.includes("soundcloud")) return "soundcloud";
    return "";
  }

  function iconHtml(site, url) {
    const p = platformOf(site) || (url ? hostOf(url) : "");
    const letter = esc(letterFor(site));
    if (p) {
      const dom = PLATFORM_DOMAINS[p] || p;
      return `<div class="plat-icon"><img src="https://www.google.com/s2/favicons?domain=${encodeURIComponent(dom)}&sz=64" alt="" loading="lazy" onerror="laxFbImg(this,'${letter}')"></div>`;
    }
    return `<div class="plat-icon letter">${letter}</div>`;
  }

  function hostOf(url) {
    try { return new URL(url).hostname; } catch (e) { return ""; }
  }

  /* ---------- صورة البروفايل (دائرية 64px + بديل ملون بلون المنصة) ---------- */
  function avatarHtml(item) {
    const u = item.avatar_url;
    const p = item.platform || platformOf(item.site || item.name || "") || "";
    const pcls = p ? " p-" + p : "";
    const letter = esc(letterFor(item.site || item.name || p || "?"));
    if (!u) {
      return `<div class="site-avatar fall${pcls}"><div class="fb">${letter}</div></div>`;
    }
    return `<div class="site-avatar${pcls}"><img src="${esc(u)}" alt="" loading="lazy" onerror="laxFbAvatar(this,'${letter}')"></div>`;
  }

  window.laxFbImg = function (img, letter) {
    if (img.dataset.fb) return;
    img.dataset.fb = "1";
    const d = document.createElement("div");
    d.className = "plat-icon letter";
    d.textContent = letter;
    img.replaceWith(d);
  };

  window.laxFbAvatar = function (img, letter) {
    if (img.dataset.fb) return;
    img.dataset.fb = "1";
    const d = document.createElement("div");
    d.className = "fb";
    d.textContent = letter || "?";
    img.replaceWith(d);
  };

  /* ---------- البطاقات ---------- */
  const Render = {
    site(item) {
      const url = item.url || "";
      const site = item.site || item.name || t("unknown");
      const st = statusClass(item.status);
      return `<div class="card site-card ${st}">
        ${avatarHtml(item)}
        ${iconHtml(site, url)}
        <div class="meta">
          <div class="site">${esc(site)}</div>
          ${url ? `<div class="url"><a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a></div>` : ""}
          ${item.note ? `<div class="note-txt">${esc(item.note)}</div>` : ""}
        </div>
        ${chipFor(item.status)}
      </div>`;
    },
    avatar(item) {
      const img = item.image_base64
        ? `<img class="avatar-img" src="${item.image_base64}" alt="avatar">`
        : `<a href="${esc(item.url)}" target="_blank" rel="noopener noreferrer"><img class="avatar-img" src="${esc(item.url)}" alt="avatar"></a>`;
      return `<div class="card avatar-card ok">
        <div class="plat-icon letter"><i class="fa-solid fa-image"></i></div>
        <div class="meta">
          <div class="site">${t("avatarTitle")}</div>
          <div class="url">${item.hash || item.url || ""}</div>
        </div>
        ${img}
        <span class="chip ok"><i class="fa-solid fa-circle-check" aria-hidden="true"></i> ${t("status_registered")}</span>
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
          <div class="site"><i class="fa-solid fa-phone" aria-hidden="true"></i> ${esc(item.number)}</div>
          <div class="d-body">
            ${rows.map(([k, v]) => `<div class="kv"><dt>${esc(k)}</dt><dd>${esc(v)}</dd></div>`).join("")}
          </div>
        </div>
        <span class="chip ok">•</span>
      </div>`;
    },
    warning(msg) {
      return `<div class="note-msg"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i> ${esc(msg)}</div>`;
    },
  };

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  /* تأثير الظهور المتتابع: كل بطاقة تتأخر 0.1 ثانية عن سابقتها */
  function attachDelay(html, i) {
    const d = Math.min(i, 8) * 100;
    return html.replace(/<div class="([^"]+)"/, (m, c) => `<div class="${c}" style="animation-delay:${d}ms"`);
  }

  let insertIndex = 0;
  let resultCount = 0;

  function renderType(type, data) {
    const fn = Render[type];
    if (!fn) return;
    els.list.insertAdjacentHTML("beforeend", attachDelay(fn(data), insertIndex++));
  }

  async function runSearch(type, query) {
    resultCount = 0;
    insertIndex = 0;
    els.list.innerHTML = "";
    if (els.resCount) els.resCount.textContent = "0";
    if (els.resCounter) els.resCounter.classList.remove("done");
    if (els.resWrap) els.resWrap.classList.remove("hidden");
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
      if (els.resCounter) els.resCounter.classList.add("done");
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

  function countResult() {
    resultCount += 1;
    if (els.resCount) els.resCount.textContent = resultCount;
  }

  function handleBlock(ev) {
    if (!ev.data) return;
    let d = {};
    try { d = JSON.parse(ev.data); } catch (e) { return; }

    switch (ev.name) {
      case "meta":
        if (d.quota && window.laxUI) laxUI.setQuota(d.quota);
        if (d.search_type) els.statusText.textContent = `${t("searching")} ${d.search_type}`;
        break;
      case "progress":
        els.statusText.textContent = d.step || t("searching");
        break;
      case "warn":
        els.list.insertAdjacentHTML("beforeend", Render.warning(d.message || ""));
        break;
      case "result":
        countResult();
        renderType(d.type, d.data);
        break;
      case "done":
        els.statusText.textContent = `${t("done")}: ${d.count} (${d.duration} ${t("seconds")})`;
        if (d.count) {
          els.list.insertAdjacentHTML("beforeend",
            `<div class="done-banner"><i class="fa-solid fa-circle-check" aria-hidden="true"></i> ${t("done")}: ${d.count} — ${d.duration} ${t("seconds")}</div>`);
        }
        if (resultCount === 0) els.list.insertAdjacentHTML("beforeend", `<div class="empty">${t("noResults")}</div>`);
        break;
      default:
        renderType(ev.name, d); // fallback: أسماء أحداث تلائم أسماء البطاقات
    }
  }

  function fail(msg) {
    els.status.classList.remove("show");
    if (els.resCounter) els.resCounter.classList.add("done");
    els.list.insertAdjacentHTML("beforeend", `<div class="note-msg"><i class="fa-solid fa-circle-xmark" aria-hidden="true"></i> ${esc(msg)}</div>`);
  }

  window.laxSearch = { runSearch, esc };
})();