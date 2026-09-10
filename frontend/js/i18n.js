/* LAX OSINT — الترجمات (عربي/إنجليزي) والتبديل RTL/LTR */
(function () {
  "use strict";

  const DICT = {
    ar: {
      tagline: "اكتشف بصمتك الرقمية",
      search: "بحث",
      searching: "جارٍ البحث…",
      resultsFor: "نتائج البحث عن",
      username: "👤 يوزرنيم",
      email: "📧 إيميل",
      phone: "📞 رقم هاتف",
      placeholder_username: "مثال: darkhacker",
      placeholder_email: "مثال: name@example.com",
      placeholder_phone: "مثال: +1 555 123 4567",
      help_username: "فحص اليوزر نيم في أكثر من 3000 موقع",
      help_email: "فحص الإيميل في أكثر من 120 منصة + صورة Gravatar",
      help_phone: "استخراج معلومات تقنية عن رقم الهاتف",
      quota: "بحوثك اليوم",
      pro: "برو",
      login: "تسجيل الدخول",
      register: "إنشاء حساب",
      logout: "خروج",
      activatePro: "تفعيل كود برو",
      welcome: "مرحبًا",
      loginTitle: "تسجيل الدخول",
      registerTitle: "إنشاء حساب جديد",
      emailLabel: "البريد الإلكتروني",
      passwordLabel: "كلمة المرور",
      noAccount: "ليس لديك حساب؟ سجّل الآن",
      hasAccount: "لديك حساب؟ تسجيل الدخول",
      proTitle: "تفعيل كود برو",
      proSub: "أدخل كود التفعيل للحصول على بحث غير محدود لمدة 30 يومًا",
      codeLabel: "الكود (XXXX-XXXX-XXXXX-XXX)",
      codePlaceholder: "مثال: HSDFN-DSLF-84357-FFJ",
      activate: "تفعيل",
      cancel: "إلغاء",
      status_registered: "مسجّل ✓",
      status_not_registered: "غير مسجّل",
      status_rate_limited: "حد الاستعلام",
      status_warning: "تنبيه",
      status_error: "خطأ",
      noResults: "لا توجد نتائج",
      done: "تم — عدد النتائج",
      seconds: "ثانية",
      searchFailed: "تعذر تنفيذ البحث",
      limitReached: "وصلت لحد البحوث المجانية لهذا اليوم — فعّل كود Pro للمتابعة",
      loginRequired: "يجب تسجيل الدخول أولًا",
      welcomeBack: "تم تسجيل الدخول بنجاح",
      registered: "تم إنشاء الحساب بنجاح",
      proActivated: "تم تفعيل البرو بنجاح — بحث غير محدود حتى",
      weakPassword: "كلمة المرور قصيرة جدًا",
      exists: "هذا الإيميل مسجل بالفعل",
      badPassword: "كلمة المرور غير صحيحة",
      notFound: "لا يوجد حساب بهذا الإيميل",
      badFormat: "صيغة الكود غير صحيحة",
      codeUsed: "هذا الكود مستخدم بالفعل",
      codeNotFound: "الكود غير موجود",
      accountDisabled: "تم تعطيل حسابك",
      privacy: "لا نخزن أي نتائج أو بيانات بحثك. نُسجّل عدد البحوث فقط لحماية الخدمة.",
      close: "إغلاق",
      avatarTitle: "صورة بروفايل Gravatar",
      loggedInAs: "أنت مسجل كمستخدم",
      emailNotFound: "لا توجد صورة Gravatar لهذا الإيميل",
      unknown: "غير معروف",
      searchType: "بحث",
    },
    en: {
      tagline: "Discover Your Digital Footprint",
      search: "Search",
      searching: "Searching...",
      resultsFor: "Results for",
      username: "👤 Username",
      email: "📧 Email",
      phone: "📞 Phone",
      placeholder_username: "e.g. darkhacker",
      placeholder_email: "e.g. name@example.com",
      placeholder_phone: "e.g. +1 555 123 4567",
      help_username: "Check a username across 3000+ sites",
      help_email: "Check an email on 120+ platforms + Gravatar image",
      help_phone: "Extract technical information about a phone number",
      quota: "Searches today",
      pro: "PRO",
      login: "Login",
      register: "Sign up",
      logout: "Logout",
      activatePro: "Activate PRO code",
      welcome: "Welcome",
      loginTitle: "Login",
      registerTitle: "Create account",
      emailLabel: "Email",
      passwordLabel: "Password",
      noAccount: "No account? Sign up now",
      hasAccount: "Have an account? Login",
      proTitle: "Activate PRO code",
      proSub: "Enter your activation code for unlimited searches for 30 days",
      codeLabel: "Code (XXXX-XXXX-XXXXX-XXX)",
      codePlaceholder: "e.g. HSDFN-DSLF-84357-FFJ",
      activate: "Activate",
      cancel: "Cancel",
      status_registered: "Registered ✓",
      status_not_registered: "Not registered",
      status_rate_limited: "Rate limited",
      status_warning: "Warning",
      status_error: "Error",
      noResults: "No results found",
      done: "Done — results count",
      seconds: "seconds",
      searchFailed: "Search failed",
      limitReached: "Free daily search limit reached — activate a PRO code to continue",
      loginRequired: "Please log in first",
      welcomeBack: "Logged in successfully",
      registered: "Account created successfully",
      proActivated: "PRO activated — unlimited searches until",
      weakPassword: "Password is too short",
      exists: "This email is already registered",
      badPassword: "Incorrect password",
      notFound: "No account with this email",
      badFormat: "Invalid code format",
      codeUsed: "This code is already used",
      codeNotFound: "Code not found",
      accountDisabled: "Your account has been disabled",
      privacy: "We do not store any search results or your data. We only record search counts to protect the service.",
      close: "Close",
      avatarTitle: "Gravatar profile picture",
      loggedInAs: "You are logged in as",
      emailNotFound: "No Gravatar image for this email",
      unknown: "Unknown",
      searchType: "Search",
    },
  };

  const state = { lang: localStorage.getItem("lax_lang") || (navigator.language || "").startsWith("ar") ? "ar" : "en" };

  function t(key) {
    return (DICT[state.lang] && DICT[state.lang][key]) || DICT.en[key] || key;
  }

  const ATTR_KEYS = ["placeholder", "data-i18n", "data-help"];
  function applyLang() {
    document.documentElement.lang = state.lang;
    document.documentElement.dir = state.lang === "ar" ? "rtl" : "ltr";
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const k = el.getAttribute("data-i18n");
      if (el.tagName === "INPUT" || el.tagName === "TEXTAREA") el.setAttribute("placeholder", t(k));
      else el.textContent = t(k);
    });
    document.querySelectorAll("[data-help]").forEach((el) => {
      el.setAttribute("data-help-label", t(el.getAttribute("data-help")));
    });
    const btn = document.getElementById("langBtn");
    if (btn) btn.textContent = state.lang === "ar" ? "EN" : "عربي";
  }

  function setLang(lang) {
    state.lang = lang;
    localStorage.setItem("lax_lang", lang);
    applyLang();
  }

  window.laxI18n = { t, state, setLang, applyLang };
})();