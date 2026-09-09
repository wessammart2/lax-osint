/* LAX OSINT — منطق الواجهة: التبويبات، النوافذ، التنبيهات، الخلفية، اللغة */
(function () {
  "use strict";

  const t = (k) => window.laxI18n.t(k);

  /* ---------- الخلفية المتحركة: جزيئات + شبكة + مصفوفة خفيفة ---------- */
  function initBg() {
    const wrap = document.getElementById("bgfx");
    if (!wrap) return;
    const canvas = document.createElement("canvas");
    wrap.appendChild(canvas);
    const ctx = canvas.getContext("2d");
    let W, H;
    const RED = "255,59,59";
    let parts = [];
    let raf;

    function resize() {
      W = canvas.width = wrap.clientWidth;
      H = canvas.height = wrap.clientHeight;
      parts = [];
      const n = Math.min(70, Math.floor((W * H) / 22000));
      for (let i = 0; i < n; i++) {
        parts.push({ x: Math.random() * W, y: Math.random() * H,
          r: 1 + Math.random() * 2.2, vx: (Math.random() - 0.5) * .35, vy: (Math.random() - 0.5) * .35 });
      }
    }

    const chars = "01مرحباLAX osint101101";
    function drawMatrix() {
      ctx.fillStyle = "rgba(10,10,10,.06)";
      ctx.fillRect(0, 0, W, H);
      // شريط واحد من أعلى إلى أسفل يمين الشاشة بمحاذاة مخفوية بوضوح شديد
      if (Math.random() < 0.08) {
        ctx.font = "12px monospace";
        ctx.fillStyle = "rgba(255,59,59,.25)";
        const x = 20 + Math.random() * 60;
        for (let y = 0; y < H; y += 26) {
          ctx.fillText(chars[Math.floor(Math.random() * chars.length)], x, y);
        }
      }
    }

    function frame() {
      ctx.clearRect(0, 0, W, H);
      // الشبكة
      ctx.strokeStyle = "rgba(255,59,59,.05)";
      ctx.lineWidth = 1;
      const step = 46;
      ctx.beginPath();
      for (let x = 0; x <= W; x += step) { ctx.moveTo(x, 0); ctx.lineTo(x, H); }
      for (let y = 0; y <= H; y += step) { ctx.moveTo(0, y); ctx.lineTo(W, y); }
      ctx.stroke();
      // الجزيئات
      ctx.shadowColor = "rgba(255,59,59,.6)";
      ctx.shadowBlur = 6;
      for (const p of parts) {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
        if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
        ctx.beginPath();
        ctx.fillStyle = `rgba(${RED},${0.25 + Math.random() * 0.4})`;
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.shadowBlur = 0;
      drawMatrix();
      raf = requestAnimationFrame(frame);
    }

    resize();
    window.addEventListener("resize", resize);
    raf = requestAnimationFrame(frame);
  }

  /* ---------- التنبيهات ---------- */
  function toast(msg, kind) {
    const box = document.getElementById("toasts");
    const el = document.createElement("div");
    el.className = `toast ${kind || "info"}`;
    el.textContent = msg;
    box.appendChild(el);
    setTimeout(() => { el.style.opacity = "0"; el.style.transform = "translateX(20px)"; }, 3200);
    setTimeout(() => el.remove(), 3600);
  }

  /* ---------- عداد الحصة ---------- */
  function setQuota(q) {
    const chip = document.getElementById("quotaChip");
    if (!chip) return;
    const max = q.quota_max || q.limit || 4;
    const used = Math.min(q.quota_used ?? q.searches_today ?? 0, max);
    const isPro = !!(q.is_pro || (window.laxAuth.store.user && window.laxAuth.store.user.is_pro));
    chip.classList.toggle("pro", isPro);
    chip.innerHTML = isPro
      ? `<span>${t("pro")} ∞</span>`
      : `<span>${t("quota")}:</span> <b>${used}/${max}</b>`;
  }

  /* ---------- حالة المصادقة في الترويسة ---------- */
  function renderAuth() {
    const box = document.getElementById("authBtns");
    if (!box) return;
    const A = window.laxAuth;
    if (A.isLoggedIn()) {
      const u = A.store.user || {};
      box.innerHTML = `
        <span class="quota-chip${u.is_pro ? " pro" : ""}">${t("welcome")} ${escHtml(u.email || t("unknown"))}${u.is_pro ? " ⭐" : ""}</span>
        <button class="btn btn-gold" id="btnPro">⚡ ${t("activatePro")}</button>
        <button class="btn btn-ghost" id="btnLogout">${t("logout")}</button>`;
      document.getElementById("btnPro").onclick = () => openPro();
      document.getElementById("btnLogout").onclick = () => { A.logout(); toast(t("logout"), "info"); };
    } else {
      box.innerHTML = `
        <button class="btn btn-outline" id="btnLogin">${t("login")}</button>
        <button class="btn btn-primary" id="btnRegister">${t("register")}</button>`;
      document.getElementById("btnLogin").onclick = () => openModal("login");
      document.getElementById("btnRegister").onclick = () => openModal("register");
    }
  }

  function escHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  /* ---------- النوافذ ---------- */
  function openModal(name) {
    showOverlay();
    document.querySelectorAll(".modal").forEach((m) => (m.style.display = "none"));
    const target = document.getElementById("m-" + name);
    if (target) target.style.display = "block";
    fillModalTexts(name);
  }

  function showOverlay() {
    document.getElementById("overlay").classList.add("open");
  }
  function hideOverlay() {
    document.getElementById("overlay").classList.remove("open");
  }

  function fillModalTexts(name) {
    const locale = window.laxI18n.state.lang;
    const M = {
      login: {
        title: t("loginTitle"), sub: t("welcomeBack"), btn: t("login"),
        email: t("emailLabel"), pwd: t("passwordLabel"),
        switchQ: t("noAccount"), switchBtn: t("register"), switchTarget: "register", hideCode: true,
      },
      register: {
        title: t("registerTitle"), sub: t("search"), btn: t("register"),
        email: t("emailLabel"), pwd: t("passwordLabel"),
        switchQ: t("hasAccount"), switchBtn: t("login"), switchTarget: "login", hideCode: true,
      },
      pro: {
        title: t("proTitle"), sub: t("proSub"), btn: t("activate"),
        email: "", pwd: "", code: t("codeLabel"), codePlace: t("codePlaceholder"),
        switchQ: "", switchBtn: "", hideEmail: true, hidePwd: true,
      },
    };
    const m = M[name];
    const mod = document.getElementById("m-" + name);
    if (!mod) return;
    mod.querySelector(".m-title").textContent = m.title;
    mod.querySelector(".m-sub").textContent = m.sub || "";
    const eRow = mod.querySelector(".row-email");
    const pRow = mod.querySelector(".row-password");
    const cRow = mod.querySelector(".row-code");
    if (eRow) eRow.style.display = m.hideEmail ? "none" : "";
    if (pRow) pRow.style.display = m.hidePwd ? "none" : "";
    if (cRow) cRow.style.display = m.hideCode ? "none" : "";
    const eIn = mod.querySelector('input[name="email"]');
    const pIn = mod.querySelector('input[name="password"]');
    const cIn = mod.querySelector('input[name="code"]');
    if (eIn) eIn.placeholder = m.email;
    if (pIn) pIn.placeholder = m.pwd;
    if (cIn) { cIn.placeholder = m.codePlace || m.code; }
    const submit = mod.querySelector(".m-submit");
    submit.textContent = m.btn;
    const sw = mod.querySelector(".switch-link");
    if (sw) {
      sw.style.display = m.switchQ ? "" : "none";
      sw.innerHTML = `${m.switchQ} <a class="switch-link-a">${m.switchBtn}</a>`;
      const a = sw.querySelector(".switch-link-a");
      a.onclick = (e) => { e.preventDefault(); openModal(m.switchTarget); };
    }
  }

  /* ---------- أحداث النوافذ ---------- */
  function bindModals() {
    applyLangOnce();
    document.getElementById("btnLang").onclick = () => {
      window.laxI18n.setLang(window.laxI18n.state.lang === "ar" ? "en" : "ar");
      applyLangOnce();
      renderAuth();
    };
    document.getElementById("overlay").addEventListener("click", (e) => {
      if (e.target.id === "overlay" || e.target.classList.contains("modal-close")) hideOverlay();
    });
    document.getElementById("m-login").querySelector(".m-submit").onclick = doLogin;
    document.getElementById("m-register").querySelector(".m-submit").onclick = doRegister;
    document.getElementById("m-pro").querySelector(".m-submit").onclick = doPro;
    ["login", "register", "pro"].forEach((n) => {
      const mod = document.getElementById("m-" + n);
      mod.addEventListener("keydown", (e) => { if (e.key === "Enter") mod.querySelector(".m-submit").click(); });
    });
  }

  function applyLangOnce() {
    window.laxI18n.applyLang();
    const help = document.getElementById("searchHelp");
    if (help) {
      const type = document.querySelector(".tab.active");
      const key = (type && type.getAttribute("data-help")) || "help_username";
      help.textContent = t(key);
    }
    const tab = document.querySelector(".tab.active");
    const inp = document.getElementById("query");
    if (tab && inp) inp.placeholder = t(tab.getAttribute("data-ph") || "placeholder_username");
  }

  async function doLogin() {
    const email = document.getElementById("lg-email").value.trim();
    const pwd = document.getElementById("lg-password").value;
    const res = await window.laxAuth.login(email, pwd);
    resultOrError(res, "login");
  }

  async function doRegister() {
    const email = document.getElementById("rg-email").value.trim();
    const pwd = document.getElementById("rg-password").value;
    const res = await window.laxAuth.register(email, pwd);
    resultOrError(res, "register");
  }

  async function doPro() {
    const code = document.getElementById("pr-code").value.trim();
    const res = await window.laxAuth.activatePro(code);
    resultOrError(res, "pro");
  }

  function resultOrError(res, kind) {
    if (res.ok) {
      hideOverlay();
      renderAuth();
      const msg = kind === "login" ? t("welcomeBack") : kind === "register" ? t("registered") : t("proActivated");
      toast(res.data.user && res.data.user.pro_until && kind === "pro"
        ? `${msg}: ${res.data.pro_until || ""}` : msg, "ok");
      refreshQuota();
    } else {
      toast(res.message, "err");
    }
  }

  async function refreshQuota() {
    const u = await window.laxAuth.refresh();
    if (u) setQuota({ searches_today: u.searches_today, quota_max: 4, is_pro: u.is_pro });
    renderAuth();
  }

  function openPro() {
    openModal("pro");
  }

  /* ---------- التبويبات والبحث ---------- */
  function bindSearch() {
    document.querySelectorAll(".tab").forEach((tab) => {
      tab.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
        tab.classList.add("active");
        const inp = document.getElementById("query");
        inp.placeholder = t(tab.getAttribute("data-ph") || "placeholder_username");
        document.getElementById("searchHelp").textContent = t(tab.getAttribute("data-help") || "help_username");
      });
    });

    const input = document.getElementById("query");
    const btn = document.getElementById("btnSearch");
    const go = () => {
      const tab = document.querySelector(".tab.active");
      const type = tab.getAttribute("data-type");
      const q = input.value.trim();
      if (!q) { toast(t("resultsFor") + "؟", "err"); return; }
      if (!window.laxAuth.isLoggedIn()) {
        toast(t("loginRequired"), "err");
        openModal("login");
        return;
      }
      btn.disabled = true;
      window.laxSearch.runSearch(type, q).finally(() => { btn.disabled = false; refreshQuota(); });
    };
    btn.onclick = go;
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
  }

  /* ---------- بدء التشغيل ---------- */
  window.addEventListener("DOMContentLoaded", () => {
    initBg();
    bindModals();
    bindSearch();
    renderAuth();
    refreshQuota();
  });

  window.laxUI = { openModal, hideOverlay, openPro, setQuota, toast };
})();