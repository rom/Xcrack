"use strict";
// Lightweight internationalisation for the Xcrack console.
//
// Design: every translatable node in index.html carries a key in a data-i18n*
// attribute and keeps its English text inline, so the page is fully readable
// with JS disabled and with no catalogue loaded. applyI18n() walks those nodes
// and, for the active locale, replaces the text/placeholder/title/aria-label
// with the catalogue entry; a missing key falls back to English and then to the
// inline text, so a partial translation is always safe. t(key, vars) resolves a
// string programmatically (for strings app.js builds at runtime).
//
//   <h2 data-i18n="head.history">Job history</h2>
//   <input data-i18n-ph="field.caseid" placeholder="2026-0042">
//   <button data-i18n-aria="btn.close" aria-label="Close">✕</button>
//
// Adding a language = add a catalogue below and an <option> in index.html. Only
// the chrome is instrumented today; untranslated strings stay English. English
// is the base catalogue and the source of truth for the key set.
(function () {
  const CATALOGS = {
    en: {
      "nav.crack": "Crack", "nav.history": "History", "nav.recovered": "Recovered",
      "nav.library": "Library", "nav.tools": "Tools", "nav.stats": "Statistics",
      "nav.audit": "Audit", "nav.docs": "Docs", "nav.config": "Configuration",
      "nav.fleet": "Fleet", "head.fleet": "Worker fleet",
      "crack.step1": "1 · Choose files", "crack.step2": "2 · Candidate sources",
      "btn.wizard": "✨ Wizard", "btn.estimate": "◴ Estimate", "btn.run": "▶ Run",
      "btn.cancel": "■ Cancel", "btn.refresh": "Refresh", "btn.validate": "Validate",
      "btn.format": "Format",
      "head.history": "Job history", "head.recovered": "Recovered passwords",
      "head.library": "Wordlist library", "head.stats_sys": "System & acceleration",
      "head.audit": "Audit trail", "head.docs": "Documentation",
      "head.appearance": "Appearance", "head.config": "Configuration (YAML)",
      "cfg.theme": "Theme", "cfg.language": "Language",
      "skip.main": "Skip to main content",
    },
    sv: {
      "nav.crack": "Knäck", "nav.history": "Historik", "nav.recovered": "Återvunna",
      "nav.library": "Bibliotek", "nav.tools": "Verktyg", "nav.stats": "Statistik",
      "nav.audit": "Granskning", "nav.docs": "Dokument", "nav.config": "Konfiguration",
      "nav.fleet": "Flotta", "head.fleet": "Arbetarflotta",
      "crack.step1": "1 · Välj filer", "crack.step2": "2 · Kandidatkällor",
      "btn.wizard": "✨ Guide", "btn.estimate": "◴ Uppskatta", "btn.run": "▶ Kör",
      "btn.cancel": "■ Avbryt", "btn.refresh": "Uppdatera", "btn.validate": "Validera",
      "btn.format": "Formatera",
      "head.history": "Jobbhistorik", "head.recovered": "Återvunna lösenord",
      "head.library": "Ordlistebibliotek", "head.stats_sys": "System & acceleration",
      "head.audit": "Granskningslogg", "head.docs": "Dokumentation",
      "head.appearance": "Utseende", "head.config": "Konfiguration (YAML)",
      "cfg.theme": "Tema", "cfg.language": "Språk",
      "skip.main": "Hoppa till innehållet",
    },
  };

  let locale = "en";

  // t resolves a key for the active locale, falling back to English, then to the
  // provided default (or the key). vars fills {name} placeholders.
  function t(key, vars, dflt) {
    const c = CATALOGS[locale] || {};
    let s = key in c ? c[key] : (key in CATALOGS.en ? CATALOGS.en[key] : (dflt != null ? dflt : key));
    if (vars) for (const k in vars) s = s.replace(new RegExp("\\{" + k + "\\}", "g"), vars[k]);
    return s;
  }

  // apply translates every instrumented node under root (default: document).
  function apply(root) {
    root = root || document;
    const put = (attr, set) => root.querySelectorAll("[" + attr + "]").forEach((n) => {
      const key = n.getAttribute(attr);
      const c = CATALOGS[locale] || {};
      // Only override when we have a value for this locale (or English for a
      // non-inline attribute); otherwise leave the inline English in place.
      if (key in c) set(n, c[key]);
      else if (locale !== "en" && key in CATALOGS.en) set(n, CATALOGS.en[key]);
    });
    put("data-i18n", (n, v) => { n.textContent = v; });
    put("data-i18n-ph", (n, v) => n.setAttribute("placeholder", v));
    put("data-i18n-title", (n, v) => n.setAttribute("title", v));
    put("data-i18n-aria", (n, v) => n.setAttribute("aria-label", v));
  }

  // pick chooses the best starting locale: a saved choice, else the first of the
  // browser's preferred languages we actually have, else English.
  function pick() {
    try {
      const saved = localStorage.getItem("xcrack-lang");
      if (saved && CATALOGS[saved]) return saved;
    } catch {}
    for (const l of (navigator.languages || [navigator.language || "en"])) {
      const base = String(l).toLowerCase().split("-")[0];
      if (CATALOGS[base]) return base;
    }
    return "en";
  }

  function setLocale(code) {
    if (!CATALOGS[code]) code = "en";
    locale = code;
    document.documentElement.lang = code;
    try { localStorage.setItem("xcrack-lang", code); } catch {}
    apply(document);
  }

  function init() {
    locale = pick();
    document.documentElement.lang = locale;
    apply(document);
  }

  window.XI18N = {
    init, apply, setLocale, t,
    get locale() { return locale; },
    locales: () => Object.keys(CATALOGS),
  };
  window.t = t; // convenience for app.js
})();
