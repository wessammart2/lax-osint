/* LAX OSINT — المصادقة والجلسة
   يحفظ التوكن والبيانات في localStorage، يستدعي /api/auth/* و /api/pro/activate.
   يجب أن يشغَّل بعد i18n.js.
*/
(function () {
  "use strict";

  const API = (window.LAX_CONFIG && window.LAX_CONFIG.API_URL) || "http://127.0.0.1:8000";
  const t = (k) => (window.laxI18n ? window.laxI18n.t(k) : k);

  const Auth = {
    store: {
      get token() { return localStorage.getItem("lax_token") || ""; },
      set token(v) { v ? localStorage.setItem("lax_token", v) : localStorage.removeItem("lax_token"); },
      get user() { try { return JSON.parse(localStorage.getItem("lax_user") || "null"); } catch (e) { return null; } },
      set user(v) { v ? localStorage.setItem("lax_user", JSON.stringify(v)) : localStorage.removeItem("lax_user"); },
    },

    isLoggedIn() { return !!this.store.token; },

    async register(email, password) {
      return this._post("/api/auth/register", { email, password });
    },

    async login(email, password) {
      return this._post("/api/auth/login", { email, password });
    },

    async activatePro(code) {
      return this._post("/api/pro/activate", { token: this.store.token, code });
    },

    async refresh() {
      if (!this.store.token) return null;
      try {
        const r = await fetch(`${API}/api/auth/me?token=${encodeURIComponent(this.store.token)}`);
        const j = await r.json();
        if (j && j.user) { this.store.user = j.user; return j.user; }
        return null;
      } catch (e) { return null; }
    },

    logout() { this.store.token = ""; this.store.user = null; if (window.laxUI) laxUI.renderAuth(); },

    _errorFor(j) {
      const map = {
        weak_password: t("weakPassword"), exists: t("exists"), bad_password: t("badPassword"),
        not_found: t("notFound"), bad_format: t("badFormat"), used: t("codeUsed"),
        code_not_found: t("codeNotFound"), unauthorized: t("loginRequired"),
      };
      return (j && (map[j.error] || j.message)) || t("searchFailed");
    },

    async _post(path, body) {
      const r = await fetch(`${API}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j.ok) {
        if (j.token) this.store.token = j.token;
        if (j.user) this.store.user = j.user;
        return { ok: true, data: j };
      }
      return { ok: false, message: this._errorFor(j) };
    },
  };

  window.laxAuth = Auth;
})();