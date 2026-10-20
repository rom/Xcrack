"use strict";
// Xcrack web console. Talks to the JSON/SSE API in pkg/webui. Uses the vendored
// CodeMirror / uPlot / marked when present and degrades gracefully without them.
const api = (p) => "/api/v1" + p;
const $ = (id) => document.getElementById(id);
const el = (t, props = {}, kids = []) => {
  const e = document.createElement(t);
  Object.assign(e, props);
  for (const k of [].concat(kids)) if (k !== null && k !== undefined && k !== "") e.append(k);
  return e;
};

let META = {};
let pickedSources = [];
let currentJob = null;
let evtSource = null;
let jobStart = 0;        // unix ms
let elapsedTimer = null;
let jobKeyspace = -1;

// ---- editor (CodeMirror when present) --------------------------------------
const Editor = {
  cm: null,
  init() {
    if (window.CodeMirror) {
      this.cm = window.CodeMirror.fromTextArea($("yaml"), {
        mode: "yaml", lineNumbers: true, indentUnit: 2, tabSize: 2, viewportMargin: Infinity,
      });
    }
  },
  get() { return this.cm ? this.cm.getValue() : $("yaml").value; },
  set(v) { if (this.cm) this.cm.setValue(v); else $("yaml").value = v; },
  refresh() { if (this.cm) this.cm.refresh(); },
};

const THEMES = ["", "light", "dark", "glow", "gold", "autumn", "spring"];

async function boot() {
  Editor.init();
  if (window.marked) window.XcrackMarkdown = (md) => window.marked.parse(md);
  if (window.XI18N) XI18N.init();
  initTheme();
  wireLang();
  wireTabs();
  wireAdvanced();
  wireFiles();
  wireRun();
  wireEditorButtons();
  wirePreview();
  wireTools();
  wireHistory();
  wireMaskBuilder();
  wireWizard();
  wirePhase5();
  wireImport();
  wirePalette();
  wireModalA11y();
  applyHelp();
  $("login-btn").addEventListener("click", () => { location.href = "/auth/login"; });
  try { META = await (await fetch(api("/meta"))).json(); } catch { META = {}; }
  renderBadges();
  renderBanners();
  const gated = await applyAuthGate();
  Editor.set(META.starter_spec || "");
  applySharedConfig();
  if (!gated) { loadDocs(); wireLiveUpdates(); }
}

// wireLiveUpdates subscribes to the server-wide "list changed" stream so the
// History, Statistics, Recovered and Audit lists refresh on their own when a job
// changes anywhere, instead of waiting for a manual refresh. The browser's
// EventSource reconnects automatically on a dropped connection.
function wireLiveUpdates() {
  let es;
  try { es = new EventSource(api("/events")); } catch { return; }
  es.addEventListener("changed", () => {
    const active = document.querySelector("#tabs button.active");
    switch (active && active.dataset.tab) {
      case "history": refreshHistory(); break;
      case "stats": refreshStats(); break;
      case "recovered": refreshVault(); break;
      case "audit": refreshAudit(); break;
    }
  });
  es.onerror = () => {};
}

// ---- Phase 6: trust banners -------------------------------------------------
function renderBanners() {
  const host = $("banners"); if (!host) return;
  host.textContent = "";
  if (META.tls === false) {
    host.append(banner("warn", "⚠ No TLS — serve over HTTPS (--tls-cert/--tls-key) before exposing this console beyond localhost."));
  }
  if (META.expose_secrets === false) {
    host.append(banner("info", "🔒 Password display is off on this server (--expose-secrets=false)."));
  }
}
function banner(kind, text) {
  const close = el("button", { type: "button", className: "x", textContent: "✕", onclick: () => b.remove() });
  close.setAttribute("aria-label", "Dismiss notice");
  const b = el("div", { className: "banner banner-" + kind }, [el("span", { textContent: text }), close]);
  return b;
}

// ---- auth gate --------------------------------------------------------------
// When the server runs with OIDC auth enabled and this browser is not signed in,
// cover the app with a login prompt; otherwise show the signed-in user + logout.
async function applyAuthGate() {
  let me = {};
  try { me = await (await fetch(api("/me"))).json(); } catch {}
  if (me.auth_enabled && !me.authenticated) {
    $("login-gate").hidden = false;
    return true;
  }
  $("login-gate").hidden = true;
  renderUser(me);
  return false;
}
function renderUser(me) {
  // The audit trail is admin-only; hide its tab for a non-admin signed-in user
  // (single-user mode has no auth and is implicitly admin, so it stays visible).
  const auditBtn = $("tab-btn-audit");
  if (auditBtn) auditBtn.hidden = !!(me && me.auth_enabled && me.user && !me.user.admin);
  const area = $("user-area"); area.textContent = "";
  if (!me || !me.auth_enabled || !me.user) return;
  const who = me.user.email || me.user.name || me.user.subject || "signed in";
  area.append(el("span", { className: "user-chip", textContent: "👤 " + who + (me.user.admin ? " (admin)" : "") }));
  area.append(el("button", {
    type: "button", className: "mini", textContent: "Logout",
    onclick: async () => { try { await fetch("/auth/logout", { method: "POST" }); } catch {} location.reload(); },
  }));
}

function renderBadges() {
  const b = $("meta-badges"); b.textContent = "";
  const tag = (t, on) => el("span", { className: "badge " + (on ? "on" : "off"), textContent: t });
  if (META.version) b.append(el("span", { className: "badge ver", textContent: "v" + META.version }));
  b.append(tag("GPU", META.gpu_available));
  if (META.tpm_build) b.append(tag("TPM", true));
}

// ---- theme ------------------------------------------------------------------
function initTheme() {
  let saved = "";
  try { saved = localStorage.getItem("xcrack-theme") || ""; } catch {}
  applyTheme(saved);
  const sel = $("theme");
  sel.value = saved;
  sel.addEventListener("change", () => { applyTheme(sel.value); try { localStorage.setItem("xcrack-theme", sel.value); } catch {} });
  const sw = $("swatches"); sw.textContent = "";
  for (const t of THEMES) {
    const chip = el("button", { type: "button", className: "swatch", title: t || "system", textContent: t || "system" });
    chip.dataset.theme = t;
    chip.addEventListener("click", () => { sel.value = t; applyTheme(t); try { localStorage.setItem("xcrack-theme", t); } catch {} });
    sw.append(chip);
  }
}
function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t;
  else document.documentElement.removeAttribute("data-theme");
}

// wireLang binds the Appearance → Language selector to the i18n module: the
// select shows the active locale and switching it re-translates the page and
// persists the choice. A no-op when i18n is unavailable.
function wireLang() {
  const sel = $("lang"); if (!sel || !window.XI18N) return;
  sel.value = XI18N.locale;
  sel.addEventListener("change", () => XI18N.setLocale(sel.value));
}

// ---- tabs / advanced --------------------------------------------------------
function wireTabs() {
  const tabs = [...document.querySelectorAll("#tabs button")];
  tabs.forEach((btn) => {
    // Activation (click, or a programmatic .click()): set the visual + ARIA
    // selected state, roving tabindex, and run the tab's on-open refresh.
    btn.addEventListener("click", () => {
      tabs.forEach((b) => {
        const on = b === btn;
        b.classList.toggle("active", on);
        b.setAttribute("aria-selected", on ? "true" : "false");
        b.tabIndex = on ? 0 : -1;
      });
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      $("tab-" + btn.dataset.tab).classList.add("active");
      if (btn.dataset.tab === "stats") { refreshStats(); Charts.show(); }
      if (btn.dataset.tab === "audit") refreshAudit();
      if (btn.dataset.tab === "history") refreshHistory();
      if (btn.dataset.tab === "recovered") refreshVault();
      if (btn.dataset.tab === "library") refreshLibrary();
      if (btn.dataset.tab === "config") setTimeout(() => Editor.refresh(), 0);
    });
    // Keyboard navigation per the WAI-ARIA tabs pattern: arrows move (and
    // activate) across the visible tabs, Home/End jump to the ends.
    btn.addEventListener("keydown", (e) => {
      const vis = tabs.filter((t) => !t.hidden);
      let i = vis.indexOf(btn);
      if (e.key === "ArrowRight" || e.key === "ArrowDown") i = (i + 1) % vis.length;
      else if (e.key === "ArrowLeft" || e.key === "ArrowUp") i = (i - 1 + vis.length) % vis.length;
      else if (e.key === "Home") i = 0;
      else if (e.key === "End") i = vis.length - 1;
      else return;
      e.preventDefault();
      vis[i].click();
      vis[i].focus();
    });
  });
}
function wireAdvanced() {
  $("advanced").addEventListener("change", (e) => document.body.classList.toggle("adv", e.target.checked));
}

// ---- files ------------------------------------------------------------------
function wireFiles() {
  const dz = $("dropzone");
  $("pick").addEventListener("click", () => $("files").click());
  $("files").addEventListener("change", (e) => addSources(e.target.files));
  ["dragover", "dragenter"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("over"); }));
  dz.addEventListener("drop", (e) => addSources(e.dataTransfer.files));
  $("wordlists").addEventListener("change", () => renderFilePreviewList("wordlists", "wordlist-list"));
  $("aux").addEventListener("change", () => renderFilePreviewList("aux", "auxlist"));
}

// renderFilePreviewList lists the files chosen in an <input> with a preview
// button that opens the first lines of the file (handy for .txt wordlists).
function renderFilePreviewList(inputId, ulId) {
  const ul = $(ulId); ul.textContent = "";
  for (const f of $(inputId).files) {
    ul.append(el("li", {}, [
      el("span", { textContent: `${f.name} (${fmtBytes(f.size)})` }),
      el("button", { type: "button", className: "mini", textContent: "preview", onclick: () => previewFile(f) }),
    ]));
  }
}
function fmtBytes(n) {
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MiB";
  if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + " KiB";
  return n + " B";
}

// ---- accessible modal manager ----------------------------------------------
// Every .modal dialog opens through openModal / closes through closeModal so
// that focus moves into the dialog, is trapped inside it (Tab cycles, Escape
// closes), and returns to whatever opened it — the baseline for a keyboard- or
// screen-reader-driven dialog. The dialogs carry role="dialog"/aria-modal in
// the markup; this supplies the focus behaviour a native <dialog> would.
let modalOpener = null;
function focusablesIn(root) {
  const sel = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';
  return [...root.querySelectorAll(sel)].filter((e) => e.offsetParent !== null || e === document.activeElement);
}
function openModal(modal, focusTarget) {
  modalOpener = document.activeElement;
  modal.hidden = false;
  const box = modal.querySelector(".modal-box") || modal;
  const f = focusTarget || focusablesIn(box)[0] || box;
  if (f && f.focus) f.focus();
}
function closeModal(modal) {
  if (modal.hidden) return;
  modal.hidden = true;
  const back = modalOpener;
  modalOpener = null;
  if (back && back.focus && document.contains(back)) back.focus();
}
function openDialogEl() { return [...document.querySelectorAll(".modal")].find((m) => !m.hidden) || null; }
// One global handler drives Escape-to-close and Tab-trapping for the open
// dialog, so each call site only has to open/close.
function wireModalA11y() {
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" && e.key !== "Tab") return;
    const modal = openDialogEl();
    if (!modal) return;
    if (e.key === "Escape") { e.preventDefault(); closeModal(modal); return; }
    const f = focusablesIn(modal.querySelector(".modal-box") || modal);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
    else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
  });
}

// ---- wordlist / file preview (client-side) ---------------------------------
function wirePreview() {
  const modal = $("preview-modal");
  $("preview-close").addEventListener("click", () => closeModal(modal));
  modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(modal); });
}
async function previewFile(f) {
  const CAP = 256 * 1024, MAXL = 500;
  let text = "";
  try { text = await f.slice(0, CAP).text(); } catch { text = "(could not read file)"; }
  const lines = text.split(/\r?\n/);
  const shown = lines.slice(0, MAXL);
  const truncated = f.size > CAP || lines.length > MAXL;
  $("preview-title").textContent = f.name;
  $("preview-meta").textContent = `${fmtBytes(f.size)} · showing ${shown.length} line(s)` + (truncated ? " (truncated)" : "");
  $("preview-body").textContent = shown.join("\n");
  openModal($("preview-modal"));
}

// ---- inline help (hover tooltips) ------------------------------------------
const HELP = {
  use_default: "Try Xcrack's built-in list of the most common passwords. A fast, high-yield first pass; turn off for a pure wordlist/mask run.",
  passwords: "Exact guesses to try first, one per line — e.g. a password you suspect, or hints from the file's owner.",
  wordlists: "Dictionary files (one candidate per line). Uploaded with the job and tried in order; combine with mangling rules to expand each word.",
  masks: "Brute-force templates, one per line. Each ?x is a character class: ?l lower, ?u upper, ?d digit, ?s symbol, ?a all, ?1–?4 your custom sets. '?d?d?d?d' tries 0000–9999.",
  rules: "hashcat-style mangling rules (one per line) applied to every wordlist word: e.g. 'c' capitalise, '$1' append 1, 'sa@' replace a→@.",
  markov: "Markov generator: learns letter-transition probabilities from your candidate words and emits brand-new guesses best-first (the statistically likeliest strings first). Great when a wordlist is thin.",
  markov_pos: "Position-aware (2D) Markov: models likely characters per position, so digits/symbols cluster at the end as in real passwords.",
  markov_max: "Cap on how many Markov guesses to generate. 0 = the built-in default (1,000,000).",
  markov_threshold: "Keep only the N likeliest next characters at each position (smaller = narrower, faster). 0 = default (15).",
  pcfg: "PCFG generator: learns structural patterns (e.g. Word+Digits+Symbol) from the candidates and emits guesses in probability order.",
  pcfg_max: "Cap on PCFG guesses. 0 = default (100,000).",
  prince: "PRINCE: builds guesses by concatenating wordlist words into longer length-ordered combinations (e.g. 'red'+'dragon').",
  toggle_case: "Also try case-toggle variants of each wordlist word (password, Password, pAssword, …).",
  keyboard_walk: "Also try keyboard-adjacency walks (qwerty, 1q2w3e, …).",
  context: "Derive guesses from the file's own name and any readable sibling files in the same container.",
  hint: "Use a password hint embedded in the file (e.g. an iWork hint or a ZIP comment) to seed guesses.",
  hint_rules: "Mangling rules applied to hint-derived words (one per line), to try near-misses of the hint.",
  order: "Reorder wordlist words before mangling. 'markov' tries the statistically likeliest words first; 'none' keeps file order.",
  order_max: "How many wordlist entries to buffer when reordering. 0 = default (1,000,000).",
  increment: "Expand each mask over a length range, shortest first — 'MIN:MAX', e.g. '1:8' tries lengths 1 through 8.",
  hybrid_append: "Hybrid attack: append every expansion of each mask to each wordlist word (word+mask), one mask per line, e.g. '?d?d'.",
  hybrid_prepend: "Hybrid attack: prepend every expansion of each mask before each wordlist word (mask+word), one mask per line.",
  comb_left: "Combinator attack: the left wordlist (every left word + every right word). Reference an uploaded auxiliary file by name.",
  comb_right: "Combinator attack: the right wordlist. Reference an uploaded auxiliary file by name.",
  comb_sep: "A separator inserted between the two words in a combinator attack (e.g. '-' or '.'). Leave empty for none.",
  adaptive: "Across many files, try passwords already recovered from other files first, and attack the smallest files first.",
  cost_queue: "Triage many files weakest-first: benchmark each and attack the fastest/cheapest schemes before slow, strong KDFs.",
  loopback: "Feed already-recovered (cached) passwords back through the mangling rules, to catch reused passwords with new suffixes (Summer2023 → Summer2024!).",
  spray: "Try a curated password-spraying set (common passwords + season/year patterns), tried early.",
  spray_tokens: "Org/product/user words (comma-separated) mangled into the spray set, e.g. a company or product name.",
  spray_years: "Years (comma-separated) used in spray patterns. Default: the current and previous year.",
  swedish: "Also try the built-in Swedish-targeted list (common Swedish words, names and places with typical mutations).",
  min_length: "Skip candidates shorter than this many characters. 0 = no minimum.",
  max_length: "Skip candidates longer than this many characters. 0 = no maximum.",
  encoding: "Transcode each candidate to this encoding before testing — needed for passwords typed in a legacy code page or stored as UTF-16.",
  breach: "Frequency-annotated breach/leak corpora (higher yield than a generic list). Reference uploaded auxiliary files by name, one per line.",
  password_files: "Plain password lists (one per line) tried first. Reference uploaded auxiliary files by name, one per line.",
  cc1: "Define custom mask set ?1 (used by masks / .hcmask), e.g. '?l?d' = lowercase letters and digits.",
  cc2: "Define custom mask set ?2.", cc3: "Define custom mask set ?3.", cc4: "Define custom mask set ?4.",
  hcmask: "hashcat .hcmask files (each line a mask, with optional inline ?1–?4). Reference uploaded auxiliary files by name, one per line.",
  generate_rules: "Generate N random mangling rules and add them to the rule pool. 0 = off. Reproducible via the seed.",
  generate_rules_seed: "Seed for generated rules — the same seed always produces the same rules.",
  workers: "Candidate-test threads per file. 0 = one per CPU core.",
  file_jobs: "How many files to process at the same time. 0 = one per CPU core.",
  max_procs: "Global ceiling on concurrent candidate testers across all files. 0 = one per CPU core.",
  batch_size: "Candidates handed to each worker per batch (tunes channel overhead). 0 = automatic.",
  throttle: "Approximate CPU duty cycle 1–99% to run gentler on a shared machine. 0 = full speed.",
  gpu: "Offload the heavy key-derivation sweep to an OpenCL GPU. Needs a binary built with -tags opencl on GPU hardware; otherwise it falls back to the CPU.",
  dual_pipeline: "Race the CPU search and the GPU sweep over one shared keyspace per file — first to find wins. Needs the GPU tier.",
  max_depth: "Maximum container nesting depth to decompose (zip-in-zip-in-…). 0 = the safe default (32).",
  max_nodes: "Maximum number of extracted entries. 0 = the safe default.",
  max_ratio: "Maximum decompression ratio allowed (zip-bomb guard). 0 = the safe default.",
  max_total_bytes: "Cumulative decompressed-byte budget across the whole tree. 0 = the safe default (2 GiB).",
  max_entry_size: "Largest single extracted entry allowed. 0 = the safe default (512 MiB).",
  max_candidates: "Cap how many candidates are tested per encrypted node. 0 = unlimited (try the whole configured keyspace until found or exhausted).",
  per_file: "Give up on a single file after this long with no success and move on, e.g. '30s' or '10m'. Empty = no per-file limit.",
  total: "Whole-run deadline, e.g. '1h'. Empty = no overall limit.",
  recurse: "Decompose containers (zip, archives, documents) into their entries and crack each layer. Off = treat each upload as one opaque target.",
  explode_documents: "Also split documents (e.g. Office files) into their internal parts for deeper inspection.",
  as: "Force the input to be treated as a specific scheme, bypassing auto-detection — for magic-less formats like SQLCipher.",
  format: "Output format for results: human-readable text, or machine-readable JSON / JSONL.",
  audit_log_password: "Include the recovered password in the audit-log entry for a cracked file. Off keeps the trail secrets-free.",
  cache_encryption: "Encrypt the found-password cache at rest. 'tpm' seals its key to this host's TPM so the file is useless if copied off the machine (needs a -tags tpm build).",
  servers: "xcrackd server URLs to distribute the search to, one per line. Append '@GROUP' to assign a server to a partition group (e.g. https://node:8443@gpu).",
  cluster_mode: "collective = all servers share one file's keyspace; partition = server groups take different files concurrently.",
  cluster_batch: "Candidates shipped per server request. 0 = default (20,000).",
  cluster_per_request: "Per-request deadline hint sent to each server, e.g. '30s'.",
  cluster_allow_defaults: "Let each server also try its own built-in default list, in addition to the candidates you ship.",
  tls_ca: "PEM CA bundle used to verify the servers' certificates (for a private CA or self-signed certs).",
  tls_cert: "Client certificate (PEM) presented to the servers for mutual TLS.",
  tls_key: "Private key (PEM) for the client certificate.",
  tls_server_name: "Expected server certificate name (SNI / verification override), e.g. when connecting by IP.",
  tls_insecure: "Skip server certificate verification. INSECURE — for testing only.",
  theme: "Choose the colour theme. 'System' follows your OS light/dark setting.",
  "yaml-authoritative": "When on, the next run uses the YAML document below verbatim instead of the Crack form.",
};
function applyHelp() {
  for (const [id, text] of Object.entries(HELP)) {
    const e = $(id);
    if (!e) continue;
    e.title = text;
    const host = e.closest("label") || e.closest(".field");
    if (host) { host.title = text; host.classList.add("has-help"); }
  }
}
function addSources(fileList) { for (const f of fileList) pickedSources.push(f); renderFileList(); }
function renderFileList() {
  const ul = $("filelist"); ul.textContent = "";
  pickedSources.forEach((f, i) => ul.append(el("li", {}, [
    el("span", { textContent: f.name }),
    el("button", { type: "button", className: "x", textContent: "✕", onclick: () => { pickedSources.splice(i, 1); renderFileList(); } }),
  ])));
}

// ---- spec building ----------------------------------------------------------
const linesOf = (id) => $(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
const listOf = (id) => $(id).value.split(",").map((s) => s.trim()).filter(Boolean);
const numOf = (id) => { const n = +$(id).value; return n > 0 ? n : undefined; };
const put = (o, k, v) => { if (v !== undefined && v !== "" && !(Array.isArray(v) && !v.length)) o[k] = v; };

function formToSpec() {
  const s = {};
  const con = {};
  put(con, "workers", numOf("workers")); put(con, "file_jobs", numOf("file_jobs")); put(con, "max_procs", numOf("max_procs"));
  put(con, "batch_size", numOf("batch_size")); put(con, "throttle", numOf("throttle"));
  if ($("gpu").checked) con.gpu = true; if ($("dual_pipeline").checked) con.dual_pipeline = true;

  const lim = {};
  put(lim, "max_depth", numOf("max_depth")); put(lim, "max_nodes", numOf("max_nodes")); put(lim, "max_ratio", numOf("max_ratio"));
  put(lim, "max_total_bytes", numOf("max_total_bytes")); put(lim, "max_entry_size", numOf("max_entry_size")); put(lim, "max_candidates", numOf("max_candidates"));

  const rec = {};
  if (!$("recurse").checked) rec.recurse = false;
  if ($("explode_documents").checked) rec.explode_documents = true;

  const search = {};
  for (const [id, key] of [["markov", "markov"], ["markov_pos", "markov_pos"], ["pcfg", "pcfg"], ["prince", "prince"],
    ["toggle_case", "toggle_case"], ["keyboard_walk", "keyboard_walk"], ["context", "context_candidates"], ["hint", "hint_candidates"],
    ["adaptive", "adaptive"], ["cost_queue", "cost_queue"], ["loopback", "loopback"], ["spray", "spray"]]) {
    if ($(id).checked) search[key] = true;
  }
  put(search, "markov_max", numOf("markov_max")); put(search, "markov_threshold", numOf("markov_threshold")); put(search, "pcfg_max", numOf("pcfg_max"));
  put(search, "order", $("order").value); put(search, "order_max", numOf("order_max")); put(search, "increment", $("increment").value.trim());
  put(search, "hint_rules", linesOf("hint_rules")); put(search, "hybrid_append", linesOf("hybrid_append")); put(search, "hybrid_prepend", linesOf("hybrid_prepend"));
  put(search, "spray_tokens", listOf("spray_tokens"));
  const years = listOf("spray_years").map(Number).filter((n) => n > 0); if (years.length) search.spray_years = years;
  const comb = {}; put(comb, "left", $("comb_left").value.trim()); put(comb, "right", $("comb_right").value.trim()); put(comb, "sep", $("comb_sep").value);
  if (comb.left || comb.right) search.combinator = comb;

  const cand = { use_default_list: $("use_default").checked };
  put(cand, "passwords", linesOf("passwords"));
  const wl = [...$("wordlists").files].map((f) => f.name); put(cand, "wordlists", wl);
  if ($("swedish").checked) cand.swedish = true;
  put(cand, "min_length", numOf("min_length")); put(cand, "max_length", numOf("max_length")); put(cand, "encoding", $("encoding").value);
  put(cand, "breach", linesOf("breach")); put(cand, "password_files", linesOf("password_files"));

  const pat = {};
  put(pat, "masks", linesOf("masks")); put(pat, "rules", linesOf("rules")); put(pat, "hcmask", linesOf("hcmask"));
  const cc = {}; for (const n of [1, 2, 3, 4]) { const v = $("cc" + n).value.trim(); if (v) cc[String(n)] = v; }
  if (Object.keys(cc).length) pat.custom_charsets = cc;
  put(pat, "generate_rules", numOf("generate_rules"));
  const seed = +$("generate_rules_seed").value; if (seed) pat.generate_rules_seed = seed;

  const out = {};
  put(out, "format", $("format").value); if ($("audit_log_password").checked) out.audit_log_password = true; put(out, "cache_encryption", $("cache_encryption").value);
  const budget = {}; put(budget, "per_file", $("per_file").value.trim()); put(budget, "total", $("total").value.trim());
  const input = {}; put(input, "as", $("as").value);

  const cluster = {};
  const servers = linesOf("servers").map((line) => {
    const at = line.indexOf("@");
    return at > 0 ? { url: line.slice(0, at), group: line.slice(at + 1) } : { url: line };
  });
  if (servers.length) {
    cluster.servers = servers;
    put(cluster, "mode", $("cluster_mode").value); put(cluster, "batch", numOf("cluster_batch")); put(cluster, "per_request", $("cluster_per_request").value.trim());
    if ($("cluster_allow_defaults").checked) cluster.allow_defaults = true;
    const tls = {};
    put(tls, "ca", $("tls_ca").value.trim()); put(tls, "cert", $("tls_cert").value.trim()); put(tls, "key", $("tls_key").value.trim()); put(tls, "server_name", $("tls_server_name").value.trim());
    if ($("tls_insecure").checked) tls.insecure = true;
    if (Object.keys(tls).length) cluster.tls = tls;
  }

  for (const [k, v] of [["concurrency", con], ["limits", lim], ["recursion", rec], ["search", search],
    ["candidates", cand], ["patterns", pat], ["output", out], ["budget", budget], ["input", input], ["cluster", cluster]]) {
    if (Object.keys(v).length) s[k] = v;
  }
  return s;
}

function specForRun() {
  return $("yaml-authoritative").checked ? Editor.get() : JSON.stringify(formToSpec());
}

// ---- editor buttons ---------------------------------------------------------
function wireEditorButtons() {
  $("yaml-validate").addEventListener("click", async () => {
    const r = await (await fetch(api("/config/validate"), { method: "POST", body: Editor.get() })).json();
    setYamlStatus(r.valid ? "✓ valid" : "✕ " + r.error, r.valid);
  });
  $("yaml-format").addEventListener("click", async () => {
    const res = await fetch(api("/config/format"), { method: "POST", body: Editor.get() });
    if (!res.ok) { const e = await res.json(); return setYamlStatus("✕ " + e.error, false); }
    Editor.set((await res.json()).yaml); setYamlStatus("formatted", true);
  });
  $("yaml-from-form").addEventListener("click", async () => {
    const res = await fetch(api("/config/format"), { method: "POST", body: JSON.stringify(formToSpec()) });
    if (res.ok) { Editor.set((await res.json()).yaml); setYamlStatus("from form", true); $("yaml-authoritative").checked = true; }
  });
  $("yaml-share").addEventListener("click", copyShareLink);
}

// ---- Phase 6: shareable config links + import ------------------------------
function b64urlEncode(s) { return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function b64urlDecode(s) { s = s.replace(/-/g, "+").replace(/_/g, "/"); try { return decodeURIComponent(escape(atob(s))); } catch { return ""; } }

async function copyShareLink() {
  let text = $("yaml-authoritative").checked ? Editor.get() : JSON.stringify(formToSpec());
  try { const r = await fetch(api("/config/format"), { method: "POST", body: text }); if (r.ok) text = (await r.json()).yaml; } catch {}
  const url = location.origin + location.pathname + "#cfg=" + b64urlEncode(text);
  try { await navigator.clipboard.writeText(url); toast("Shareable link copied."); }
  catch { location.hash = "cfg=" + b64urlEncode(text); toast("Link placed in the address bar."); }
}
function applySharedConfig() {
  const m = /[#&]cfg=([^&]+)/.exec(location.hash);
  if (!m) return;
  const text = b64urlDecode(m[1]);
  if (!text) return;
  Editor.set(text);
  $("yaml-authoritative").checked = true;
  toast("Loaded a shared configuration — review it in Configuration, then Run.");
}

function wireImport() {
  $("yaml-import").addEventListener("click", () => openModal($("import-modal"), $("import-text")));
  $("import-close").addEventListener("click", () => closeModal($("import-modal")));
  $("import-modal").addEventListener("click", (e) => { if (e.target === $("import-modal")) closeModal($("import-modal")); });
  $("import-do").addEventListener("click", doImport);
}
async function doImport() {
  const text = $("import-text").value.trim();
  if (!text) { toast("Paste a configuration first."); return; }
  try {
    const r = await (await fetch(api("/config/validate"), { method: "POST", body: text })).json();
    if (!r.valid) { toast("Invalid configuration: " + r.error); return; }
  } catch { toast("Could not validate the configuration."); return; }
  Editor.set(text);
  $("yaml-authoritative").checked = true;
  closeModal($("import-modal"));
  document.querySelector('#tabs button[data-tab="config"]').click();
  toast("Imported — the next run uses this configuration.");
}

// ---- Phase 6: command palette ----------------------------------------------
const PALETTE = [
  { label: "Go to Crack", run: () => gotoTab("crack") },
  { label: "Go to History", run: () => gotoTab("history") },
  { label: "Go to Recovered", run: () => gotoTab("recovered") },
  { label: "Go to Library", run: () => gotoTab("library") },
  { label: "Go to Tools", run: () => gotoTab("tools") },
  { label: "Go to Statistics", run: () => gotoTab("stats") },
  { label: "Go to Docs", run: () => gotoTab("docs") },
  { label: "Go to Configuration", run: () => gotoTab("config") },
  { label: "Run job", run: () => $("run").click() },
  { label: "Cancel job", run: () => $("cancel").click() },
  { label: "Open attack wizard", run: () => $("wizard-open").click() },
  { label: "Validate configuration", run: () => { gotoTab("config"); $("yaml-validate").click(); } },
  { label: "Copy shareable link", run: copyShareLink },
  { label: "Import configuration", run: () => $("yaml-import").click() },
  { label: "Toggle advanced options", run: () => { const c = $("advanced"); c.checked = !c.checked; document.body.classList.toggle("adv", c.checked); } },
];
function gotoTab(name) { document.querySelector(`#tabs button[data-tab="${name}"]`).click(); }

let paletteIdx = 0, paletteItems = [];
function wirePalette() {
  document.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
    else if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); $("run").click(); }
  });
  const inp = $("palette-input");
  inp.addEventListener("input", renderPalette);
  inp.addEventListener("keydown", (e) => {
    // Escape is handled by the global modal trap (which also restores focus).
    if (e.key === "ArrowDown") { e.preventDefault(); paletteIdx = Math.min(paletteItems.length - 1, paletteIdx + 1); highlightPalette(); }
    else if (e.key === "ArrowUp") { e.preventDefault(); paletteIdx = Math.max(0, paletteIdx - 1); highlightPalette(); }
    else if (e.key === "Enter") { e.preventDefault(); runPalette(paletteIdx); }
  });
  $("palette-modal").addEventListener("click", (e) => { if (e.target === $("palette-modal")) closeModal($("palette-modal")); });
}
function openPalette() { $("palette-input").value = ""; paletteIdx = 0; renderPalette(); openModal($("palette-modal"), $("palette-input")); }
function renderPalette() {
  const q = $("palette-input").value.toLowerCase();
  paletteItems = PALETTE.filter((a) => a.label.toLowerCase().includes(q));
  if (paletteIdx >= paletteItems.length) paletteIdx = 0;
  const ul = $("palette-list"); ul.textContent = "";
  paletteItems.forEach((a, i) => ul.append(el("li", { className: i === paletteIdx ? "sel" : "", textContent: a.label, onclick: () => runPalette(i) })));
}
function highlightPalette() { [...$("palette-list").children].forEach((li, i) => li.classList.toggle("sel", i === paletteIdx)); }
function runPalette(i) { closeModal($("palette-modal")); const a = paletteItems[i]; if (a) a.run(); }
function setYamlStatus(msg, ok) { const s = $("yaml-status"); s.textContent = msg; s.className = ok ? "ok" : "err"; }

// ---- run / events -----------------------------------------------------------
function wireRun() {
  $("run").addEventListener("click", runJob);
  $("estimate").addEventListener("click", inspectJob);
  $("inspect-close").addEventListener("click", () => { $("inspect-card").hidden = true; });
  $("cancel").addEventListener("click", async () => { if (currentJob) await fetch(api("/jobs/" + currentJob + "/cancel"), { method: "POST" }); });
}

async function runJob() {
  if (pickedSources.length === 0) { setRunStatus("Choose at least one file first.", true); return; }
  if (notifyEnabled()) requestNotifyPermission();
  const fd = new FormData();
  fd.append("spec", specForRun());
  for (const f of pickedSources) fd.append("source", f);
  for (const f of $("wordlists").files) fd.append("aux", f);
  for (const f of $("aux").files) fd.append("aux", f);
  if ($("lib_names").value.trim()) fd.append("library", $("lib_names").value);
  if ($("case_id").value.trim()) fd.append("case_id", $("case_id").value.trim());
  if ($("examiner").value.trim()) fd.append("examiner", $("examiner").value.trim());
  for (const f of $("recovered").files) fd.append("recovered", f);
  $("log").textContent = ""; $("results").textContent = ""; $("results-card").hidden = false;
  $("latest-term").textContent = ""; resetBar();
  Charts.reset();
  setRunStatus("Submitting…");
  let res;
  try { res = await fetch(api("/jobs"), { method: "POST", body: fd }); }
  catch (e) { return setRunStatus("Network error: " + e, true); }
  if (!res.ok) { const e = await res.json().catch(() => ({})); return setRunStatus("✕ " + (e.error || res.status), true); }
  const { id } = await res.json();
  currentJob = id;
  $("run").disabled = true; $("cancel").disabled = false;
  setRunStatus("Running…");
  // Pull the authoritative start time + keyspace, then stream events.
  try {
    const job = await (await fetch(api("/jobs/" + id))).json();
    jobStart = job.started_at || Date.now();
    jobKeyspace = job.keyspace ?? -1;
  } catch { jobStart = Date.now(); jobKeyspace = -1; }
  $("job-started").textContent = new Date(jobStart).toLocaleString();
  $("job-ended").textContent = "—";
  startElapsed();
  streamEvents(id);
}

// inspectJob posts the current candidate configuration and targets to /inspect
// and shows a feasibility estimate (per-file keyspace, verify rate, and
// time-to-exhaust) plus a preview of the exact candidate stream — the CLI's
// --keyspace/--benchmark/--estimate/--stdout — without starting a job.
async function inspectJob() {
  if (pickedSources.length === 0) { setRunStatus("Choose at least one file first.", true); return; }
  const fd = new FormData();
  fd.append("spec", specForRun());
  for (const f of pickedSources) fd.append("source", f);
  for (const f of $("wordlists").files) fd.append("aux", f);
  for (const f of $("aux").files) fd.append("aux", f);
  if ($("lib_names").value.trim()) fd.append("library", $("lib_names").value);
  const btn = $("estimate");
  btn.disabled = true; setRunStatus("Estimating…");
  let res;
  try { res = await fetch(api("/inspect"), { method: "POST", body: fd }); }
  catch (e) { btn.disabled = false; return setRunStatus("Network error: " + e, true); }
  btn.disabled = false;
  if (!res.ok) { const e = await res.json().catch(() => ({})); return setRunStatus("✕ " + (e.error || res.status), true); }
  renderInspect(await res.json());
  setRunStatus("");
}

function fmtInt(n) { return (n == null ? 0 : n).toLocaleString(); }

function renderInspect(data) {
  const host = $("inspect-files");
  host.textContent = "";
  for (const f of (data.files || [])) {
    const row = document.createElement("div");
    row.className = "inspect-row";
    const ks = f.keyspace < 0 ? "open-ended" : (f.keyspace_capped ? "≥" : "") + fmtInt(f.keyspace);
    const rate = f.encrypted ? ((f.rate_text || fmtInt(Math.round(f.rate))) + "/s") : "—";
    const time = f.time_to_exhaust
      ? ("~" + f.time_to_exhaust + " to exhaust, ~" + (f.time_expected || "?") + " expected")
      : (f.note || "—");
    row.innerHTML =
      '<div class="inspect-name">' + escapeHTML(f.name) +
        (f.scheme ? ' <span class="pill">' + escapeHTML(f.scheme) + '</span>' : '') + '</div>' +
      '<div class="inspect-metrics">' +
        '<span><span class="k">keyspace</span> ' + escapeHTML(ks) + '</span>' +
        '<span><span class="k">rate</span> ' + escapeHTML(rate) + '</span>' +
        '<span><span class="k">time</span> ' + escapeHTML(time) + '</span>' +
      '</div>';
    host.appendChild(row);
  }
  if (data.files_truncated) {
    const n = document.createElement("p"); n.className = "muted";
    n.textContent = "Only the first " + (data.files || []).length + " files were estimated.";
    host.appendChild(n);
  }
  const prev = data.candidate_preview || [];
  const wrap = $("inspect-preview-wrap");
  if (prev.length) {
    wrap.hidden = false;
    $("inspect-preview").textContent = prev.join("\n");
    $("inspect-preview-count").textContent = prev.length;
    $("inspect-preview-more").textContent = data.candidate_preview_truncated ? "+" : "";
  } else {
    wrap.hidden = true;
  }
  $("inspect-card").hidden = false;
}

function startElapsed() {
  stopElapsed();
  const tick = () => { $("job-elapsed").textContent = fmtDur(Date.now() - jobStart); };
  tick();
  elapsedTimer = setInterval(tick, 1000);
}
function stopElapsed() { if (elapsedTimer) { clearInterval(elapsedTimer); elapsedTimer = null; } }
function fmtDur(ms) {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return (h ? h + "h " : "") + (h || m ? m + "m " : "") + sec + "s";
}
// fmtETA renders a remaining-seconds estimate, collapsing very long spans to a
// coarse human phrase instead of an absurd hour count.
function fmtETA(sec) {
  const yr = 365 * 86400;
  if (!isFinite(sec) || sec < 0) return "—";
  if (sec > 100 * yr) return "centuries";
  if (sec > yr) return (sec / yr).toFixed(1) + " yr";
  if (sec > 2 * 86400) return (sec / 86400).toFixed(1) + " d";
  return fmtDur(sec * 1000);
}

function streamEvents(id) {
  if (evtSource) evtSource.close();
  evtSource = new EventSource(api("/jobs/" + id + "/events"));
  evtSource.onmessage = (m) => { let e; try { e = JSON.parse(m.data); } catch { return; } handleEvent(e); };
  evtSource.onerror = () => {};
}

function handleEvent(e) {
  switch (e.type) {
    case "log": appendLog(`[${e.level || "info"}] ${e.message}`); break;
    case "found":
      appendLog(`🔓 FOUND ${e.file} (${e.format || "?"})` + (e.password ? ` → ${e.password}` : ""));
      notify("Xcrack: password found", e.file + (e.password ? " → " + e.password : ""));
      break;
    case "progress":
      if (e.keyspace !== undefined) jobKeyspace = e.keyspace;
      updateProgress(e.candidates || 0, e.latest || "");
      Charts.point(e.candidates || 0);
      break;
    case "file_done": appendLog(`• ${e.file} done (${e.files_done}/${e.files_total})`); break;
    case "state": if (["done", "error", "canceled"].includes(e.state)) finishRun(e.state); break;
  }
  if ($("tab-stats").classList.contains("active")) refreshStats();
}

function updateProgress(candidates, latest) {
  const el_ = (ms) => (Date.now() - jobStart) / 1000;
  const secs = el_();
  const rate = secs > 0 ? Math.round(candidates / secs) : 0;
  const fill = $("bar-fill"), bar = fill.parentElement;
  if (jobKeyspace > 0) {
    const pct = Math.min(100, candidates / jobKeyspace * 100);
    bar.classList.remove("indeterminate");
    fill.style.width = pct.toFixed(1) + "%";
    let line = `${candidates.toLocaleString()} / ${jobKeyspace.toLocaleString()} (${pct.toFixed(1)}%) · ${rate.toLocaleString()}/s`;
    const remain = rate > 0 ? (jobKeyspace - candidates) / rate : -1;
    if (remain > 0) {
      line += " · ETA " + fmtETA(remain);
      if (remain > 365 * 86400) line += " — impractically long at this rate; a wordlist + rules will likely beat brute force";
    }
    $("progress-text").textContent = line;
    setBarAria(pct, line);
  } else {
    // Animate the sweep only while the event stream is live; a finished run
    // (finishRun / openHistoryJob close evtSource first) leaves a static bar.
    fill.style.width = "100%";
    bar.classList.toggle("indeterminate", evtSource != null);
    const line = `${candidates.toLocaleString()} candidates · ${rate.toLocaleString()}/s`;
    $("progress-text").textContent = line;
    setBarAria(-1, line); // indeterminate: no numeric value
  }
  if (evtSource) setTitleProgress(jobKeyspace > 0 ? Math.min(100, candidates / jobKeyspace * 100) : -1);
  if (latest) $("latest-term").innerHTML = "latest: <code>" + escapeHTML(latest) + "</code>";
  const srcLabel = $("run-source");
  srcLabel.textContent = latest ? "testing: " + latest : "";
}
function resetBar() {
  const fill = $("bar-fill"); fill.style.width = "0%"; fill.parentElement.classList.remove("indeterminate");
  $("progress-text").textContent = "—"; $("run-source").textContent = "";
  setBarAria(-1, "");
}
// setBarAria keeps the progressbar's accessible value in sync with the visual
// fill. pct < 0 marks an indeterminate bar (no known keyspace), so the numeric
// value is removed and only a text description is exposed.
function setBarAria(pct, text) {
  const bar = $("progress-bar"); if (!bar) return;
  if (pct >= 0) bar.setAttribute("aria-valuenow", Math.round(pct));
  else bar.removeAttribute("aria-valuenow");
  if (text) bar.setAttribute("aria-valuetext", text);
  else bar.removeAttribute("aria-valuetext");
}
function escapeHTML(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

function appendLog(s) {
  const log = $("log"); log.textContent += s + "\n";
  const as = $("log-autoscroll");
  if (!as || as.checked) log.scrollTop = log.scrollHeight;
}

async function finishRun(state) {
  if (evtSource) { evtSource.close(); evtSource = null; }
  stopElapsed();
  $("run").disabled = false; $("cancel").disabled = true;
  setRunStatus(state === "done" ? "✓ Done" : state === "canceled" ? "Canceled" : "Error", state !== "done");
  if (!currentJob) return;
  const job = await (await fetch(api("/jobs/" + currentJob))).json();
  if (job.ended_at && job.started_at) $("job-elapsed").textContent = fmtDur(job.ended_at - job.started_at);
  if (job.ended_at) $("job-ended").textContent = new Date(job.ended_at).toLocaleString();
  updateProgress(job.candidates || 0, "");
  renderResults(job);
  const ok = state === "done";
  notify(ok ? "Xcrack: job finished" : "Xcrack: job " + state, (job.files || []).join(", "));
  flashTitle(ok ? "✓" : "✕");
  if ($("tab-history").classList.contains("active")) refreshHistory();
}

function renderResults(job) {
  const root = $("results"); root.textContent = "";
  const total = job.files_total || (job.files || []).length;
  root.append(el("div", { className: "results-summary", textContent: `${job.decrypted || 0} of ${total} decrypted` }));
  if (job.distributed) root.append(el("div", { className: "hint", textContent: "distributed run — passwords recovered on the servers; decrypted content stays there." }));
  (job.results || []).forEach((fr) => {
    const card = el("div", { className: "result" });
    card.append(el("div", { className: "result-head" }, [el("strong", { textContent: fr.name }), fr.error ? el("span", { className: "err", textContent: " — " + fr.error }) : ""]));
    const rep = fr.report;
    if (rep) {
      const pws = rep.recovered_passwords || [];
      card.append(el("div", { className: "pw" }, pws.length ? "🔑 " + pws.join(", ") : "No password recovered"));
      card.append(renderNode(rep.root));
      if (rep.stats) card.append(el("div", { className: "stat-line", textContent: `${(rep.stats.candidates_tried || 0).toLocaleString()} candidates · ${rep.stats.elapsed_ms} ms` }));
    }
    root.append(card);
  });
  if (!job.distributed && (job.results || []).some((r) => r.report)) {
    root.append(el("a", { className: "download", href: api("/jobs/" + job.id + "/download"), textContent: "⬇ Download decrypted output (zip)" }));
  }
}
function renderNode(n) {
  const li = el("li", {}, [el("span", { className: "status s-" + n.status, textContent: n.status }), " " + (n.path || "(root)") + (n.format ? ` [${n.format}]` : "") + (n.password ? ` → ${n.password}` : "")]);
  if (n.children && n.children.length) li.append(el("ul", {}, n.children.map(renderNode)));
  return el("ul", { className: "tree" }, [li]);
}
function setRunStatus(msg, err) { const s = $("run-status"); s.textContent = msg; s.className = err ? "err" : ""; }

// ---- history ----------------------------------------------------------------
function wireHistory() {
  $("history-refresh").addEventListener("click", refreshHistory);
  $("audit-refresh").addEventListener("click", refreshAudit);
  $("vault-refresh").addEventListener("click", refreshVault);
  const nt = $("notify-toggle");
  try { nt.checked = localStorage.getItem("xcrack-notify") === "1"; } catch {}
  nt.addEventListener("change", () => {
    try { localStorage.setItem("xcrack-notify", nt.checked ? "1" : "0"); } catch {}
    if (nt.checked) requestNotifyPermission();
  });
}

// ---- audit trail ------------------------------------------------------------
async function refreshAudit() {
  const host = $("audit-body");
  let entries;
  try {
    const r = await fetch(api("/audit"));
    if (r.status === 403) { host.textContent = ""; host.append(el("p", { className: "hint", textContent: "Audit is visible to administrators only." })); return; }
    entries = (await r.json()).entries || [];
  } catch { host.textContent = ""; host.append(el("p", { className: "err", textContent: "Could not load the audit trail." })); return; }
  host.textContent = "";
  if (!entries.length) { host.append(el("p", { className: "hint", textContent: "No audited actions yet." })); return; }
  const tbl = el("table", { className: "history-table" });
  tbl.append(el("tr", {}, ["When", "Actor", "IP", "Action", "Target", "Detail"].map((h) => el("th", { textContent: h }))));
  for (const e of entries) {
    tbl.append(el("tr", {}, [
      el("td", { textContent: e.time ? new Date(e.time).toLocaleString() : "—" }),
      el("td", { textContent: e.email || e.actor || "—" }),
      el("td", { textContent: e.ip || "—" }),
      el("td", {}, [el("span", { className: "pill", textContent: e.action })]),
      el("td", { textContent: e.target || "" }),
      el("td", { textContent: e.detail || "" }),
    ]));
  }
  host.append(tbl);
}

const STATE_LABEL = { done: "done", error: "error", canceled: "canceled", interrupted: "interrupted", running: "running", queued: "queued" };

async function refreshHistory() {
  const host = $("history-list");
  let jobs;
  try { jobs = (await (await fetch(api("/jobs"))).json()).jobs || []; }
  catch { host.textContent = ""; host.append(el("p", { className: "err", textContent: "Could not load history." })); return; }
  host.textContent = "";
  if (!jobs.length) { host.append(el("p", { className: "hint", textContent: "No jobs yet — run one from the Crack tab." })); return; }
  const tbl = el("table", { className: "history-table" });
  tbl.append(el("tr", {}, ["", "Files", "State", "Decrypted", "Candidates", "Created", ""].map((h) => el("th", { textContent: h }))));
  for (const j of jobs) {
    const files = (j.files || []).join(", ") || "—";
    const hasOutput = !j.distributed && (j.results || []).some((r) => r.report);
    tbl.append(el("tr", {}, [
      el("td", {}, [el("button", { type: "button", className: "mini", textContent: "open", onclick: () => openHistoryJob(j.id) })]),
      el("td", { className: "h-files", title: files, textContent: files }),
      el("td", {}, [el("span", { className: "badge s-state-" + j.state, textContent: STATE_LABEL[j.state] || j.state })]),
      el("td", { textContent: String(j.decrypted || 0) }),
      el("td", { textContent: (j.candidates || 0).toLocaleString() }),
      el("td", { textContent: j.created_at ? new Date(j.created_at).toLocaleString() : "—" }),
      el("td", {}, [
        hasOutput ? el("a", { className: "mini", href: api("/jobs/" + j.id + "/download"), textContent: "⬇ zip" }) : "",
        hasOutput ? el("a", { className: "mini", href: api("/jobs/" + j.id + "/report"), target: "_blank", rel: "noopener", textContent: "report" }) : "",
        hasOutput ? el("a", { className: "mini", href: api("/jobs/" + j.id + "/report?format=csv"), textContent: "csv" }) : "",
        el("button", {
          type: "button", className: j.resumable ? "mini resume" : "mini",
          textContent: j.resumable ? "⟳ resume" : "re-run",
          title: j.resumable ? "Resume this interrupted run from its saved checkpoint" : "Start a fresh run from this job's spec and files",
          onclick: () => rerunJob(j.id),
        }),
        ownsJob(j) ? el("button", { type: "button", className: "mini", textContent: (j.shared && j.shared.length) ? "shared ✓" : "share", onclick: () => shareJob(j) }) : "",
        el("button", { type: "button", className: "mini danger", textContent: "delete", onclick: () => deleteHistoryJob(j.id) }),
      ]),
    ]));
  }
  host.append(tbl);
}

// ownsJob reports whether the signed-in user owns this job, so only an owner is
// offered the Share control (single-user mode has no sharing).
function ownsJob(j) {
  return me && me.auth_enabled && me.user && j.owner && j.owner === me.user.subject;
}

// shareJob prompts for the subjects to grant read access and saves the share.
async function shareJob(j) {
  const current = (j.shared || []).join(", ");
  const input = prompt("Share this job (read-only) with these user subjects, comma-separated.\nLeave empty to un-share.", current);
  if (input === null) return; // cancelled
  const subjects = input.split(",").map((s) => s.trim()).filter(Boolean);
  let res;
  try { res = await fetch(api("/jobs/" + j.id + "/share"), { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ subjects }) }); }
  catch (e) { toast("Share failed: " + e); return; }
  if (!res.ok) { const e = await res.json().catch(() => ({})); toast("Share failed: " + (e.error || res.status)); return; }
  toast(subjects.length ? ("Shared with " + subjects.length + " user(s)") : "Un-shared");
  refreshHistory();
}

// rerunJob starts a fresh job from a saved one's spec + uploads (no re-upload)
// and opens it. The GUI "resume" for an interrupted or finished run.
async function rerunJob(id) {
  let res;
  try { res = await fetch(api("/jobs/" + id + "/rerun"), { method: "POST" }); }
  catch (e) { toast("Re-run failed: " + e); return; }
  if (!res.ok) { const e = await res.json().catch(() => ({})); toast("Re-run failed: " + (e.error || res.status)); return; }
  const { id: nid } = await res.json();
  toast("Re-running…");
  openHistoryJob(nid);
}

// ---- recovered-password vault (potfile) ------------------------------------
async function refreshVault() {
  const host = $("vault-list");
  let v;
  try { v = await (await fetch(api("/vault"))).json(); }
  catch { host.textContent = ""; host.append(el("p", { className: "err", textContent: "Could not load the vault." })); return; }
  host.textContent = "";
  if (!v.enabled) {
    host.append(el("p", { className: "hint", textContent: "The vault is available only on a single-user instance with password display enabled." }));
    return;
  }
  host.append(el("p", { className: "hint", textContent: `${(v.count || 0).toLocaleString()} recovered password(s) · ${v.encrypted ? "sealed to the host TPM at rest" : "plaintext at rest"}` }));
  if (!v.count) { host.append(el("p", { className: "hint", textContent: "No passwords recovered yet." })); return; }
  const ol = el("ol", { className: "toplist" });
  for (const pw of v.passwords || []) ol.append(el("li", {}, [el("code", { textContent: pw })]));
  host.append(ol);
}

// ---- Phase 5: library, cluster health, log controls ------------------------
function wirePhase5() {
  $("lib-refresh").addEventListener("click", refreshLibrary);
  $("lib-upload").addEventListener("change", uploadLibrary);
  const cc = $("cluster-check"); if (cc) cc.addEventListener("click", clusterHealth);
  const lc = $("log-copy"); if (lc) lc.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("log").textContent); toast("Log copied."); } catch { toast("Copy failed."); }
  });
}

async function refreshLibrary() {
  const host = $("lib-list");
  let v;
  try { v = await (await fetch(api("/library"))).json(); }
  catch { host.textContent = ""; host.append(el("p", { className: "err", textContent: "Could not load the library." })); return; }
  host.textContent = "";
  const wls = v.wordlists || [];
  if (!wls.length) { host.append(el("p", { className: "hint", textContent: "No wordlists yet — upload one above." })); return; }
  const tbl = el("table", { className: "stat-table" });
  tbl.append(el("tr", {}, [el("th", { textContent: "name" }), el("th", { textContent: "size" }), el("th", { textContent: "" })]));
  for (const e of wls) {
    tbl.append(el("tr", {}, [
      el("td", {}, [el("code", { textContent: e.name })]),
      el("td", { textContent: fmtBytes(e.size) }),
      el("td", {}, [
        el("button", { type: "button", className: "mini", textContent: "preview", onclick: () => previewLibrary(e.name) }),
        el("button", { type: "button", className: "mini", textContent: "use", onclick: () => useLibrary(e.name) }),
        el("button", { type: "button", className: "mini danger", textContent: "delete", onclick: () => deleteLibrary(e.name) }),
      ]),
    ]));
  }
  host.append(tbl);
}
async function uploadLibrary() {
  const input = $("lib-upload");
  if (!input.files.length) return;
  const fd = new FormData();
  for (const f of input.files) fd.append("file", f);
  try {
    const r = await fetch(api("/library"), { method: "POST", body: fd });
    toast(r.ok ? "Uploaded to library." : "Upload failed: " + ((await r.json().catch(() => ({}))).error || r.status));
  } catch (e) { toast("Upload failed: " + e); }
  input.value = "";
  refreshLibrary();
}
async function previewLibrary(name) {
  let v;
  try { v = await (await fetch(api("/library/" + encodeURIComponent(name) + "/preview"))).json(); } catch { return; }
  $("preview-title").textContent = name;
  $("preview-meta").textContent = `first ${(v.lines || []).length} line(s)`;
  $("preview-body").textContent = (v.lines || []).join("\n");
  openModal($("preview-modal"));
}
async function deleteLibrary(name) {
  if (!confirm("Delete library wordlist " + name + "?")) return;
  try { await fetch(api("/library/" + encodeURIComponent(name)), { method: "DELETE" }); } catch {}
  refreshLibrary();
}
function useLibrary(name) {
  const ta = $("lib_names");
  const have = ta.value.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!have.includes(name)) ta.value = (ta.value.trim() ? ta.value.replace(/\n+$/, "") + "\n" : "") + name;
  toast(name + " added to the Crack form's library list.");
}

async function clusterHealth() {
  const out = $("cluster-health"); out.textContent = "Checking…";
  const body = new URLSearchParams(); body.set("servers", $("servers").value);
  let v;
  try { v = await (await fetch(api("/cluster/health"), { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body })).json(); }
  catch (e) { out.textContent = "Network error: " + e; return; }
  if (v.error) { out.textContent = "✕ " + v.error; return; }
  out.textContent = "";
  const tbl = el("table", { className: "stat-table" });
  tbl.append(el("tr", {}, [el("th", { textContent: "server" }), el("th", { textContent: "status" }), el("th", { textContent: "ms" })]));
  for (const s of v.servers || []) {
    const label = s.ok ? "up" : (s.error ? "down" : "HTTP " + s.status);
    tbl.append(el("tr", {}, [
      el("td", {}, [el("code", { textContent: s.url })]),
      el("td", {}, [el("span", { className: "badge " + (s.ok ? "on" : "off"), textContent: label })]),
      el("td", { textContent: String(s.latency_ms || 0) }),
    ]));
  }
  out.append(tbl);
}

async function deleteHistoryJob(id) {
  if (!confirm("Delete this job and its working files?")) return;
  try { await fetch(api("/jobs/" + id), { method: "DELETE" }); } catch {}
  if (currentJob === id) { currentJob = null; if (evtSource) { evtSource.close(); evtSource = null; } }
  refreshHistory();
}

// openHistoryJob loads a saved (or still-running) job into the Crack tab's
// results panel: resume the live stream if it is still running, else render the
// stored snapshot.
async function openHistoryJob(id) {
  let job;
  try { job = await (await fetch(api("/jobs/" + id))).json(); } catch { return; }
  document.querySelector('#tabs button[data-tab="crack"]').click();
  currentJob = id;
  $("results-card").hidden = false;
  $("log").textContent = ""; $("latest-term").textContent = "";
  jobKeyspace = job.keyspace ?? -1;
  jobStart = job.started_at || job.created_at || Date.now();
  $("job-started").textContent = jobStart ? new Date(jobStart).toLocaleString() : "—";
  $("job-ended").textContent = "—";
  if (job.state === "running" || job.state === "queued") {
    setRunStatus("Running…"); $("run").disabled = true; $("cancel").disabled = false;
    startElapsed(); streamEvents(id);
    return;
  }
  if (evtSource) { evtSource.close(); evtSource = null; }
  stopElapsed(); $("run").disabled = false; $("cancel").disabled = true;
  $("job-elapsed").textContent = (job.ended_at && job.started_at) ? fmtDur(job.ended_at - job.started_at) : "—";
  $("job-ended").textContent = job.ended_at ? new Date(job.ended_at).toLocaleString() : "—";
  resetBar(); updateProgress(job.candidates || 0, "");
  const label = { done: "✓ Done", canceled: "Canceled", interrupted: "Interrupted" }[job.state] || "Error";
  setRunStatus(label, job.state !== "done");
  renderResults(job);
}

// ---- notifications / toast --------------------------------------------------
function notifyEnabled() { try { return localStorage.getItem("xcrack-notify") === "1"; } catch { return false; } }
function requestNotifyPermission() {
  if ("Notification" in window && Notification.permission === "default") { try { Notification.requestPermission(); } catch {} }
}
function notify(title, body) {
  toast(title + (body ? " — " + body : ""));
  if (!notifyEnabled() || !("Notification" in window) || Notification.permission !== "granted") return;
  try { new Notification(title, { body }); } catch {}
}
let toastTimer = null;
function toast(msg) {
  let t = $("toast");
  if (!t) {
    t = el("div", { id: "toast", className: "toast" });
    t.setAttribute("role", "status");
    t.setAttribute("aria-live", "polite");
    document.body.append(t);
  }
  t.textContent = msg; t.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove("show"), 4000);
}

// setTitleProgress reflects a live run in the browser tab so a backgrounded tab
// is a glanceable progress bar; flashTitle marks a just-finished run briefly.
function setTitleProgress(pct) { document.title = (pct >= 0 ? Math.floor(pct) + "% · " : "⋯ ") + "Xcrack"; }
function flashTitle(mark) { document.title = mark + " Xcrack"; setTimeout(() => { if (!evtSource) document.title = "Xcrack"; }, 8000); }

// ---- charts -----------------------------------------------------------------
const Charts = {
  plot: null, data: [[0], [0]], t0: 0,
  reset() { this.data = [[0], [0]]; this.t0 = Date.now(); if (this.plot) this.plot.setData(this.data); },
  point(c) { const t = (Date.now() - this.t0) / 1000; this.data[0].push(+t.toFixed(2)); this.data[1].push(c); if (this.plot) this.plot.setData(this.data); },
  show() {
    if (!window.uPlot) return;
    const host = $("run-charts"), w = host.clientWidth || 600;
    if (!this.plot) {
      host.textContent = "";
      this.plot = new window.uPlot({ width: w, height: 220, scales: { x: { time: false } },
        series: [{ label: "t (s)" }, { label: "candidates", stroke: "#5c7cfa", width: 2, fill: "rgba(92,124,250,.15)" }], axes: [{ stroke: "#888" }, { stroke: "#888" }] }, this.data, host);
    } else { this.plot.setSize({ width: w, height: 220 }); this.plot.setData(this.data); }
  },
};

// renderSysInfo fills the Statistics "System & acceleration" card from /meta.
function renderSysInfo() {
  const host = $("sys-body"); if (!host) return;
  host.textContent = "";
  host.append(el("p", {}, ["Version: ", el("code", { textContent: META.version || "?" })]));
  const tag = (t, on) => el("span", { className: "badge " + (on ? "on" : "off"), textContent: t });
  host.append(el("p", {}, [
    tag(META.gpu_available ? "GPU tier available" : "GPU tier not built", !!META.gpu_available),
    tag(META.tpm_build ? "TPM build" : "no TPM build", !!META.tpm_build),
  ]));
  host.append(el("p", { className: "hint", textContent: META.gpu_available
    ? "Jobs can request the GPU tier (Advanced → GPU); dual-pipeline races the CPU and GPU over one keyspace."
    : "This build is CPU-only; rebuild with -tags opencl for the GPU tier." }));
}

// ---- statistics -------------------------------------------------------------
async function refreshStats() {
  renderSysInfo();
  let s; try { s = await (await fetch(api("/stats"))).json(); } catch { return; }
  const cards = [["Jobs", s.jobs_total], ["Active", s.jobs_active], ["Finished", s.jobs_finished],
    ["Files processed", s.files_processed], ["Candidates tried", (s.candidates_tried || 0).toLocaleString()],
    ["Decrypted", s.nodes_decrypted], ["Still locked", s.nodes_locked]];
  const host = $("stat-cards"); host.textContent = "";
  for (const [label, val] of cards) host.append(el("div", { className: "card statcard" }, [el("div", { className: "statval", textContent: String(val ?? 0) }), el("div", { className: "statlabel", textContent: label })]));

  const algo = $("algo-speed"); algo.textContent = "";
  const speeds = s.algo_speed || [];
  if (!speeds.length) algo.append(el("p", { className: "hint", textContent: "No finished jobs yet." }));
  else {
    const tbl = el("table", { className: "stat-table" });
    tbl.append(el("tr", {}, [el("th", { textContent: "format" }), el("th", { textContent: "cand/sec" }), el("th", { textContent: "files" })]));
    for (const a of speeds) tbl.append(el("tr", {}, [el("td", { textContent: a.format }), el("td", { textContent: Math.round(a.candidates_per_sec).toLocaleString() }), el("td", { textContent: String(a.files) })]));
    algo.append(tbl);
  }

  const top = $("top-pw"); top.textContent = "";
  if (!s.expose_secrets) top.append(el("p", { className: "hint", textContent: "Password display is disabled on this server (--expose-secrets=false)." }));
  else if (!(s.top_passwords || []).length) top.append(el("p", { className: "hint", textContent: "No passwords recovered yet." }));
  else {
    const ol = el("ol", { className: "toplist" });
    for (const e of s.top_passwords) ol.append(el("li", {}, [el("code", { textContent: e.password }), el("span", { className: "count", textContent: " ×" + e.count })]));
    top.append(ol);
  }
}

// ---- docs -------------------------------------------------------------------
async function loadDocs() {
  let list; try { list = (await (await fetch(api("/docs"))).json()).docs; } catch { return; }
  const ul = $("doclist"); ul.textContent = "";
  (list || []).forEach((d) => ul.append(el("li", {}, [el("a", { href: "#", textContent: d.title, onclick: (e) => { e.preventDefault(); openDoc(d.name); } })])));
}
async function openDoc(name) {
  const md = await (await fetch(api("/docs/" + encodeURIComponent(name)))).text();
  $("docview").innerHTML = window.XcrackMarkdown ? window.XcrackMarkdown(md) : miniMarkdown(md);
}
function miniMarkdown(md) {
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const out = []; let inCode = false, inList = false;
  for (const raw of md.split("\n")) {
    if (raw.startsWith("```")) { out.push(inCode ? "</code></pre>" : "<pre><code>"); inCode = !inCode; continue; }
    if (inCode) { out.push(esc(raw)); continue; }
    let line = esc(raw).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>").replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { if (inList) { out.push("</ul>"); inList = false; } out.push(`<h${h[1].length}>${h[2]}</h${h[1].length}>`); continue; }
    if (/^[-*]\s+/.test(raw)) { if (!inList) { out.push("<ul>"); inList = true; } out.push("<li>" + line.replace(/^[-*]\s+/, "") + "</li>"); continue; }
    if (inList) { out.push("</ul>"); inList = false; }
    out.push(raw.trim() === "" ? "" : "<p>" + line + "</p>");
  }
  if (inList) out.push("</ul>"); if (inCode) out.push("</code></pre>");
  return out.join("\n");
}

// ---- tools (specialist, non-cracking subcommands) --------------------------
// The quick inspect/recover tools call synchronous /tools/* endpoints; the long
// key sweeps and table generation are turned into a copy-ready CLI command.
const QUICK = {
  identify: "/identify",
  hashline: "/tools/hashline",
  "vba-recover": "/tools/vba-recover",
  "access-recover": "/tools/access-recover",
};

function wireTools() {
  document.querySelectorAll(".tool-run[data-tool]").forEach((b) =>
    b.addEventListener("click", () => runQuickTool(b.dataset.tool)));
  $("export-challenge-run").addEventListener("click", exportChallenge);
  $("pdf-table-run").addEventListener("click", pdfTable);
  $("wl-run").addEventListener("click", wordlistTool);
  $("rt-run").addEventListener("click", ruleTest);
  $("kp-run").addEventListener("click", runKP);
  wireCLI();
}

// runKP launches the ZipCrypto known-plaintext recovery as a background job and
// streams its progress into the tool card (with a download link on success).
async function runKP() {
  const out = toolOut("kp");
  const plain = $("kp-plain").files[0], cipher = $("kp-cipher").files[0];
  if (!plain || !cipher) { out.textContent = "Choose the known plaintext and its ciphertext."; return; }
  const fd = new FormData();
  fd.append("plain", plain);
  fd.append("cipher", cipher);
  if ($("kp-zip").files[0]) fd.append("zip", $("kp-zip").files[0]);
  if ($("kp-entry").files[0]) fd.append("entry", $("kp-entry").files[0]);
  fd.append("offset", $("kp-offset").value || "0");
  out.textContent = "Starting…";
  let res;
  try { res = await fetch(api("/tools/kp"), { method: "POST", body: fd }); }
  catch (e) { out.textContent = "Network error: " + e; return; }
  if (!res.ok) { const e = await res.json().catch(() => ({})); out.textContent = "✕ " + (e.error || res.status); return; }
  const { id } = await res.json();
  out.textContent = "";
  const log = el("pre", { className: "log" });
  out.append(log);
  const append = (s) => { log.textContent += s + "\n"; };
  const es = new EventSource(api("/jobs/" + id + "/events"));
  es.onmessage = (m) => {
    let e; try { e = JSON.parse(m.data); } catch { return; }
    if (e.type === "log") append("[" + (e.level || "info") + "] " + e.message);
    else if (e.type === "found") append("🔓 " + (e.file || "") + (e.password ? " → " + e.password : ""));
    else if (e.type === "state" && ["done", "error", "canceled"].includes(e.state)) {
      es.close();
      append("[" + e.state + "]");
      if (e.state === "done") out.append(el("a", { href: api("/jobs/" + id + "/download"), className: "mini", textContent: "download decrypted output" }));
    }
  };
  es.onerror = () => {};
}

// ruleTest shows what mangling rules do to a sample word (engine rule compiler).
async function ruleTest() {
  const out = toolOut("rule-test");
  const word = $("rt-word").value;
  if (!word) { out.textContent = "Enter a sample word."; return; }
  out.textContent = "Testing…";
  const fd = new FormData(); fd.append("word", word); fd.append("rules", $("rt-rules").value);
  let res;
  try { res = await fetch(api("/tools/rule-test"), { method: "POST", body: fd }); }
  catch (e) { out.textContent = "Network error: " + e; return; }
  if (!res.ok) { const e = await res.json().catch(() => ({})); out.textContent = "✕ " + (e.error || res.status); return; }
  const j = await res.json();
  out.textContent = "";
  const results = j.results || [];
  if (!results.length) { out.append(el("p", { className: "hint", textContent: "No rules to apply." })); return; }
  const tbl = el("table", { className: "stat-table" });
  tbl.append(el("tr", {}, [el("th", { textContent: "rule" }), el("th", { textContent: "→ output" })]));
  for (const r of results) {
    tbl.append(el("tr", {}, [
      el("td", {}, [el("code", { textContent: r.rule })]),
      el("td", {}, r.kept ? [el("code", { textContent: r.output })] : [el("span", { className: "hint", textContent: "(rejected)" })]),
    ]));
  }
  out.append(tbl);
}

// ---- mask builder -----------------------------------------------------------
function wireMaskBuilder() {
  const mask = [];
  const sizes = { "?l": 26, "?u": 26, "?d": 10, "?s": 33, "?a": 95 };
  const render = () => {
    $("mb-mask").textContent = mask.length ? mask.join("") : "(empty)";
    let ks = 1n;
    for (const t of mask) ks *= BigInt(sizes[t] || 1);
    $("mb-keyspace").textContent = mask.length ? `keyspace: ${ks.toLocaleString()} (${mask.length} chars)` : "keyspace: 1";
  };
  document.querySelectorAll(".mb-tok").forEach((b) => b.addEventListener("click", () => {
    const t = b.dataset.tok;
    if (t === "clear") mask.length = 0;
    else if (t === "backspace") mask.pop();
    else mask.push(t);
    render();
  }));
  $("mb-insert").addEventListener("click", () => {
    if (!mask.length) return;
    const ta = $("masks");
    ta.value = (ta.value.trim() ? ta.value.replace(/\n+$/, "") + "\n" : "") + mask.join("");
  });
  render();
}

// ---- attack wizard ----------------------------------------------------------
// Preset = a starting configuration of the wizard controls (not the Crack form);
// the user can then tweak before pressing Build.
const WZ_PRESETS = {
  personal:   { kind: "word",  min: 6,  max: 14, l: true,  u: false, d: true,  s: false, cap: true,  upper: false, leet: true,  digit: true,  bang: true,  markov: true,  kw: false, prince: false, toggle: false, loopback: true },
  corporate:  { kind: "word",  min: 8,  max: 16, l: true,  u: true,  d: true,  s: true,  cap: true,  upper: false, leet: true,  digit: true,  bang: true,  markov: true,  kw: false, prince: false, toggle: false, loopback: true },
  passphrase: { kind: "word",  min: 10, max: 30, l: true,  u: false, d: false, s: false, cap: true,  upper: false, leet: false, digit: false, bang: false, markov: false, kw: false, prince: true,  toggle: false, loopback: false },
  pin:        { kind: "pin",   min: 4,  max: 8,  l: false, u: false, d: true,  s: false, cap: false, upper: false, leet: false, digit: false, bang: false, markov: false, kw: false, prince: false, toggle: false, loopback: false },
  keyboard:   { kind: "word",  min: 6,  max: 12, l: true,  u: false, d: true,  s: true,  cap: false, upper: false, leet: false, digit: false, bang: false, markov: false, kw: true,  prince: false, toggle: false, loopback: false },
};

function wireWizard() {
  const modal = $("wizard-modal");
  $("wizard-open").addEventListener("click", () => { wzPopulateWordlists(); wzSyncKind(); openModal(modal); });
  $("wizard-close").addEventListener("click", () => closeModal(modal));
  modal.addEventListener("click", (e) => { if (e.target === modal) closeModal(modal); });
  $("wizard-build").addEventListener("click", buildFromWizard);
  $("wz-kind").addEventListener("change", wzSyncKind);
  modal.querySelectorAll(".wz-chip").forEach((b) => b.addEventListener("click", () => wzApplyPreset(b.dataset.preset)));
  // Recompute the feasibility estimate and section visibility on any change.
  modal.querySelectorAll("input, select").forEach((el) => {
    el.addEventListener("input", wzUpdateEstimate);
    el.addEventListener("change", wzUpdateEstimate);
  });
}

// wzPopulateWordlists fills the wordlist picker with the built-in list plus any
// saved Library wordlists, preserving the current selection.
async function wzPopulateWordlists() {
  const sel = $("wz-wordlist");
  const keep = sel.value;
  let names = [];
  try { names = ((await (await fetch(api("/library"))).json()).wordlists || []).map((w) => w.name); } catch {}
  sel.textContent = "";
  sel.append(el("option", { value: "__default__", textContent: "Built-in common list" }));
  for (const n of names) sel.append(el("option", { value: n, textContent: "Library: " + n }));
  if ([...sel.options].some((o) => o.value === keep)) sel.value = keep;
}

// wzSyncKind shows/hides the dictionary-only and brute-only sections for the
// selected attack kind, then refreshes the estimate.
function wzSyncKind() {
  const kind = $("wz-kind").value;
  const dict = kind === "word" || kind === "unsure";
  const brute = kind === "brute" || kind === "pin" || kind === "unsure";
  $("wizard-modal").querySelectorAll(".wz-dict-only").forEach((e) => { e.style.display = dict ? "" : "none"; });
  $("wizard-modal").querySelectorAll(".wz-brute-only").forEach((e) => { e.style.display = brute && kind !== "pin" ? "" : "none"; });
  wzUpdateEstimate();
}

function wzApplyPreset(name) {
  const p = WZ_PRESETS[name];
  if (!p) return;
  $("wz-kind").value = p.kind;
  $("wz-min").value = p.min; $("wz-max").value = p.max;
  for (const [id, k] of [["wz-l", "l"], ["wz-u", "u"], ["wz-d", "d"], ["wz-s", "s"], ["wz-cap", "cap"],
    ["wz-upper", "upper"], ["wz-leet", "leet"], ["wz-digit", "digit"], ["wz-bang", "bang"],
    ["wz-markov", "markov"], ["wz-kw", "kw"], ["wz-prince", "prince"], ["wz-toggle", "toggle"], ["wz-loopback", "loopback"]]) {
    $(id).checked = !!p[k];
  }
  wzSyncKind();
  toast("Preset applied — adjust anything, then Build.");
}

// wzClasses returns the selected brute-force character classes as mask tokens.
function wzClasses(kind) {
  if (kind === "pin") return "?d";
  return ($("wz-l").checked ? "?l" : "") + ($("wz-u").checked ? "?u" : "") +
    ($("wz-d").checked ? "?d" : "") + ($("wz-s").checked ? "?s" : "");
}

// wzUpdateEstimate computes and renders a pre-run feasibility estimate: the
// brute-force keyspace (when a brute force is in the mix) with a plain verdict,
// and a note for the dictionary pass. It never runs anything.
function wzUpdateEstimate() {
  const host = $("wz-estimate");
  if (!host) return;
  const kind = $("wz-kind").value;
  const min = +$("wz-min").value || 0, max = +$("wz-max").value || 0;
  const prefix = $("wz-prefix").value.trim(), suffix = $("wz-suffix").value.trim();
  const lines = [];
  if (kind === "word" || kind === "unsure") {
    const n = wzRules().length, hy = $("wz-digit").checked ? " + 1–2 appended digits" : "";
    lines.push(`Dictionary: wordlist × ${n} rule${n === 1 ? "" : "s"}${hy} — usually completes quickly.`);
  }
  if (kind === "brute" || kind === "pin" || kind === "unsure") {
    const sizes = { "?l": 26, "?u": 26, "?d": 10, "?s": 33 };
    const cls = wzClasses(kind);
    const toks = cls.match(/\?[luds]/g) || [];
    let per = 0n; for (const t of toks) per += BigInt(sizes[t] || 0);
    if (per === 0n) {
      lines.push("Brute force: pick at least one character type.");
    } else {
      const fixed = prefix.length + suffix.length;
      let ks = 0n;
      const lo = Math.max(1, min), hi = Math.max(lo, max || min || 8);
      for (let L = lo; L <= hi; L++) {
        const vary = L - fixed;
        if (vary < 0) continue;
        ks += per ** BigInt(vary);
      }
      lines.push(`Brute force: ≈ ${ks.toLocaleString()} candidate${ks === 1n ? "" : "s"} — ${wzVerdict(ks)}.`);
    }
  }
  host.textContent = "";
  for (const l of lines) host.append(el("div", { textContent: l }));
}

function wzVerdict(ks) {
  if (ks < 100000000n) return "small, fast on any format";
  if (ks < 1000000000000n) return "moderate, feasible";
  if (ks < 1000000000000000n) return "large — practical mainly on fast formats or a GPU";
  return "impractical as pure brute force; prefer a word + rules";
}

// wzRules builds the hashcat rule set from the mangling choices as the cross
// product of prefix transforms (identity/capitalise/upper/leet) and suffix
// appends (nothing / '!' / each significant year). ':' is the no-op (try the
// word unchanged). Years like 2024 append as $2$0$2$4.
function wzRules() {
  const prefixes = [""];
  if ($("wz-cap").checked) prefixes.push("c");
  if ($("wz-upper").checked) prefixes.push("u");
  if ($("wz-leet").checked) prefixes.push("sa@se3si1so0ss$");
  const suffixes = [""];
  if ($("wz-bang").checked) suffixes.push("$!");
  for (const y of ($("wz-years").value.match(/\d{2,4}/g) || [])) {
    suffixes.push(y.split("").map((d) => "$" + d).join(""));
  }
  const out = new Set();
  for (const p of prefixes) for (const s of suffixes) out.add((p + s) || ":");
  return [...out];
}

function buildFromWizard() {
  const kind = $("wz-kind").value;
  const prefix = $("wz-prefix").value.trim(), suffix = $("wz-suffix").value.trim();
  const min = +$("wz-min").value || 0, max = +$("wz-max").value || 0;
  const tokens = $("wz-tokens").value.trim();
  const dict = kind === "word" || kind === "unsure";
  const brute = kind === "brute" || kind === "pin" || kind === "unsure";

  // Known parts → explicit guesses tried first.
  const guesses = [];
  if (prefix) guesses.push(prefix);
  if (suffix) guesses.push(suffix);
  if (prefix && suffix) guesses.push(prefix + suffix);
  $("passwords").value = guesses.join("\n");

  if (min) $("min_length").value = min;
  if (max) $("max_length").value = max;

  // Wordlist source (dictionary kinds).
  const wl = $("wz-wordlist").value;
  $("use_default").checked = !dict ? false : wl === "__default__";
  $("lib_names").value = dict && wl !== "__default__" ? wl : "";

  // Mangling rules + appended digits (dictionary kinds).
  $("rules").value = dict ? wzRules().join("\n") : "";
  $("hybrid_append").value = dict && $("wz-digit").checked ? "?d\n?d?d" : "";

  // Personal / org words → spray set + name/sibling context; years → spray years.
  $("spray").checked = !!tokens;
  $("spray_tokens").value = tokens;
  $("spray_years").value = ($("wz-years").value.match(/\d{2,4}/g) || []).join(",");
  $("context").checked = !!tokens;

  // Extra sources.
  $("markov").checked = $("wz-markov").checked;
  $("keyboard_walk").checked = $("wz-kw").checked;
  $("prince").checked = dict && $("wz-prince").checked;
  $("toggle_case").checked = dict && $("wz-toggle").checked;
  $("loopback").checked = $("wz-loopback").checked;

  // Brute-force mask over the chosen classes (and literal prefix/suffix).
  if (brute) {
    const cls = wzClasses(kind);
    if (cls) {
      $("cc1").value = cls;
      const fixed = prefix.length + suffix.length;
      const target = max || min || 8;
      const vary = Math.max(1, target - fixed);
      // A literal prefix/suffix pins the structure; otherwise sweep the length range.
      $("masks").value = prefix + "?1".repeat(vary) + suffix;
      $("increment").value = (!fixed && min && max && min < max) ? min + ":" + max : "";
    }
  } else {
    $("masks").value = "";
    $("increment").value = "";
    $("cc1").value = "";
  }

  if (!$("advanced").checked) { $("advanced").checked = true; document.body.classList.add("adv"); }
  closeModal($("wizard-modal"));
  toast("Wizard filled the Crack form — review the options and press Run.");
}

const toolOut = (name) => document.querySelector(`.tool-out[data-out="${name}"]`);

async function runQuickTool(tool) {
  const out = toolOut(tool);
  const input = document.querySelector(`.tool-files[data-tool="${tool}"]`);
  if (!input || !input.files.length) { out.textContent = "Choose at least one file first."; return; }
  out.textContent = "Working…";
  const fd = new FormData();
  for (const f of input.files) fd.append("source", f);
  let res;
  try { res = await fetch(api(QUICK[tool]), { method: "POST", body: fd }); }
  catch (e) { out.textContent = "Network error: " + e; return; }
  if (!res.ok) { const e = await res.json().catch(() => ({})); out.textContent = "✕ " + (e.error || res.status); return; }
  renderTool(tool, await res.json(), out);
}

function renderTool(tool, data, out) {
  out.textContent = "";
  const files = data.files || [];
  if (!files.length) { out.append(el("p", { className: "hint", textContent: "No result." })); return; }
  for (const f of files) {
    const card = el("div", { className: "tool-file" });
    card.append(el("div", { className: "tool-file-name", textContent: f.name }));
    if (f.error) { card.append(el("div", { className: "err", textContent: f.error })); out.append(card); continue; }
    if (tool === "identify") card.append(renderIdentify(f));
    else if (tool === "hashline") card.append(renderHashline(f));
    else card.append(renderKV(f)); // vba-recover / access-recover
    out.append(card);
  }
}

function renderIdentify(f) {
  const wrap = el("div", { className: "id-row" });
  if (f.unknown) { wrap.append(el("span", { className: "badge off", textContent: "unknown format" })); return wrap; }
  wrap.append(el("span", { className: "fmt", textContent: f.format }));
  wrap.append(el("span", { className: "badge " + (f.encrypted ? "on" : "off"), textContent: f.encrypted ? "encrypted" : "cleartext" }));
  if (f.container) wrap.append(el("span", { className: "badge on", textContent: "container" }));
  if (f.explodable) wrap.append(el("span", { className: "badge on", textContent: "explodable" }));
  return wrap;
}

function renderHashline(f) {
  const wrap = el("div", {});
  if (f.note) wrap.append(el("div", { className: "hint", textContent: f.note }));
  for (const l of f.lines || []) {
    const meta = [];
    if (l.target) meta.push(l.target);
    if (l.hashcat >= 0) meta.push("hashcat -m " + l.hashcat);
    if (l.john) meta.push("john --format=" + l.john);
    if (meta.length) wrap.append(el("div", { className: "hint", textContent: meta.join(" · ") }));
    wrap.append(el("pre", { className: "hashline", textContent: l.line }));
  }
  return wrap;
}

// renderKV shows the meaningful fields of a vba-recover / access-recover result.
function renderKV(f) {
  const dl = el("dl", { className: "kv" });
  const secretKey = (k) => k === "password" || k === "hashcat" || k === "john";
  for (const k of ["kind", "variant", "has_password", "password", "hashcat", "john", "note"]) {
    const v = f[k];
    if (v === undefined || v === null || v === "") continue;
    dl.append(el("dt", { textContent: k.replace(/_/g, " ") }));
    const text = typeof v === "boolean" ? (v ? "yes" : "no") : String(v);
    dl.append(el("dd", {}, [secretKey(k) ? el("code", { textContent: text }) : text]));
  }
  if (!dl.childNodes.length) dl.append(el("dd", { textContent: "(no result)" }));
  return dl;
}

async function exportChallenge() {
  const out = toolOut("export-challenge");
  const input = document.querySelector('.tool-files[data-tool="export-challenge"]');
  if (!input.files.length) { out.textContent = "Choose at least one file first."; return; }
  out.textContent = "Exporting…";
  const fd = new FormData();
  for (const f of input.files) fd.append("source", f);
  let res;
  try { res = await fetch(api("/tools/export-challenge"), { method: "POST", body: fd }); }
  catch (e) { out.textContent = "Network error: " + e; return; }
  // Success streams a downloadable JSON (Content-Disposition set); otherwise the
  // body is a JSON {error} explaining why nothing was exported.
  if (res.ok && res.headers.get("Content-Disposition")) {
    downloadBlob(await res.blob(), "challenges.json");
    out.textContent = "✓ Downloaded challenges.json — solve it externally, then bring the result back via Crack → Resume (or xcrack --resume-from).";
    return;
  }
  const j = await res.json().catch(() => ({}));
  out.textContent = j.error || ("HTTP " + res.status);
}

async function pdfTable() {
  const out = toolOut("pdf-table");
  const src = $("pdf-table-src").files[0], tbl = $("pdf-table-tbl").files[0];
  if (!src || !tbl) { out.textContent = "Choose a PDF and a thunder table."; return; }
  out.textContent = "Inverting…";
  const fd = new FormData(); fd.append("source", src); fd.append("table", tbl);
  let res;
  try { res = await fetch(api("/tools/pdf-keyattack-table"), { method: "POST", body: fd }); }
  catch (e) { out.textContent = "Network error: " + e; return; }
  if (!res.ok) { const e = await res.json().catch(() => ({})); out.textContent = "✕ " + (e.error || res.status); return; }
  const j = await res.json();
  out.textContent = "";
  if (j.found) {
    out.append(el("div", { className: "ok", textContent: "🔑 file key recovered" }));
    out.append(el("pre", { className: "hashline", textContent: j.key_hex }));
  } else {
    out.append(el("div", { className: "hint", textContent: j.note || "not found" }));
  }
}

async function wordlistTool() {
  const out = toolOut("wordlist");
  const file = $("wl-file").files[0], text = $("wl-text").value;
  if (!file && !text.trim()) { out.textContent = "Upload a wordlist or paste some lines."; return; }
  out.textContent = "Processing…";
  const fd = new FormData();
  if (file) fd.append("source", file);
  if (text.trim()) fd.append("text", text);
  fd.append("op", $("wl-op").value);
  fd.append("min_length", $("wl-min").value || "0");
  fd.append("max_length", $("wl-max").value || "0");
  fd.append("split", $("wl-split").value || "0");
  let res;
  try { res = await fetch(api("/tools/wordlist"), { method: "POST", body: fd }); }
  catch (e) { out.textContent = "Network error: " + e; return; }
  if (!res.ok) { const e = await res.json().catch(() => ({})); out.textContent = "✕ " + (e.error || res.status); return; }
  if ((res.headers.get("Content-Type") || "").startsWith("application/zip")) {
    downloadBlob(await res.blob(), "wordlist-split.zip");
    out.textContent = "✓ Downloaded wordlist-split.zip";
    return;
  }
  const body = await res.text();
  const lines = body ? body.replace(/\n$/, "").split("\n") : [];
  out.textContent = "";
  out.append(el("div", { className: "row tool-actions" }, [
    el("span", { className: "hint", textContent: `${lines.length.toLocaleString()} line(s)` }),
    el("button", { type: "button", className: "mini", textContent: "download .txt", onclick: () => downloadBlob(new Blob([body], { type: "text/plain" }), "wordlist.txt") }),
  ]));
  const preview = lines.slice(0, 200).join("\n");
  out.append(el("pre", { className: "hashline", textContent: preview + (lines.length > 200 ? `\n… (${(lines.length - 200).toLocaleString()} more)` : "") }));
}

// ---- CLI command builder (long-running sweeps / table generation) ----------
const CLI_SPECS = {
  "pdf-keyattack": {
    positional: { label: "PDF file", placeholder: "secret.pdf" },
    flags: [
      { flag: "--table", type: "text", label: "Thunder table (optional, instant V1/R2 lookup)", placeholder: "v1r2.thunder" },
      { flag: "--gpu", type: "bool", label: "Offload the 2⁴⁰ sweep to an OpenCL device" },
      { flag: "--workers", type: "num", label: "CPU workers (0 = all cores)", def: 0 },
      { flag: "--shard", type: "text", label: "Shard i/N for distribution (optional)", placeholder: "0/8" },
      { flag: "--quiet", type: "bool", label: "Suppress progress output" },
    ],
  },
  "office-keyattack": {
    positional: { label: "Office file", placeholder: "secret.doc" },
    flags: [
      { flag: "--gpu", type: "bool", label: "Offload the 2⁴⁰ sweep to an OpenCL device" },
      { flag: "--workers", type: "num", label: "CPU workers (0 = all cores)", def: 0 },
      { flag: "--shard", type: "text", label: "Shard i/N for distribution (optional)", placeholder: "0/8" },
      { flag: "--quiet", type: "bool", label: "Suppress progress output" },
    ],
  },
  "thunder-gen": {
    positional: null,
    flags: [
      { flag: "--out", type: "text", label: "Output table file (required)", placeholder: "v1r2.thunder", required: true },
      { flag: "--bits", type: "num", label: "Key-space exponent (40 inverts every V1/R2)", def: 40 },
      { flag: "--length", type: "num", label: "Chain length t (smaller = faster lookup, larger table)", def: 4096 },
      { flag: "--chains", type: "num", label: "Chains per sub-table", def: 1 << 26 },
      { flag: "--tables", type: "num", label: "Independent sub-tables (more = higher coverage)", def: 4 },
      { flag: "--workers", type: "num", label: "Generation workers (0 = all cores)", def: 0 },
      { flag: "--gpu", type: "bool", label: "Offload chain generation to an OpenCL device" },
      { flag: "--progress", type: "text", label: "Periodic progress (e.g. 5%, 2hour, 1day)", placeholder: "5%" },
      { flag: "--dry-run", type: "bool", label: "Print the plan (work, size, time) and exit" },
    ],
  },
};
const flagId = (fl) => "cli-f-" + fl.flag.replace(/^--/, "").replace(/[^a-z0-9]/gi, "-");

function wireCLI() {
  const op = $("cli-op"), fields = $("cli-fields");
  const render = () => {
    renderCLIFields(CLI_SPECS[op.value], fields);
    // thunder-gen generates a table from parameters; the key attacks need a file.
    $("cli-upload-field").style.display = op.value === "thunder-gen" ? "none" : "";
    updateCLI();
  };
  op.addEventListener("change", render);
  fields.addEventListener("input", updateCLI);
  fields.addEventListener("change", updateCLI);
  $("cli-copy").addEventListener("click", async () => {
    let ok = false;
    try { await navigator.clipboard.writeText($("cli-cmd").textContent); ok = true; } catch {}
    $("cli-copy-status").textContent = ok ? "copied" : "copy failed — select the command manually";
    setTimeout(() => { $("cli-copy-status").textContent = ""; }, 1800);
  });
  $("cli-run").addEventListener("click", runCLIAsJob);
  render();
}

// runCLIAsJob launches the selected long-running attack as a server-side job and
// opens it, so the browser-only operator gets live progress + cancel + download
// without a shell. Numeric fields are read from the same inputs the CLI command
// builder uses; the key attacks also take the uploaded document.
async function runCLIAsJob() {
  const opv = $("cli-op").value;
  const status = $("cli-run-status");
  const numField = (flag) => { const e = $("cli-f-" + flag); return e && e.value.trim() ? e.value.trim() : ""; };
  const fd = new FormData();
  let endpoint;
  if (opv === "thunder-gen") {
    endpoint = "/tools/thunder-gen";
    for (const k of ["bits", "length", "chains", "tables", "workers"]) { const v = numField(k); if (v) fd.append(k, v); }
  } else {
    endpoint = opv === "pdf-keyattack" ? "/tools/pdf-keyattack" : "/tools/office-keyattack";
    const f = $("cli-upload").files[0];
    if (!f) { status.textContent = "Choose a document to attack first."; return; }
    fd.append("source", f);
    const wk = numField("workers"); if (wk) fd.append("workers", wk);
  }
  status.textContent = "Submitting…";
  let res;
  try { res = await fetch(api(endpoint), { method: "POST", body: fd }); }
  catch (e) { status.textContent = "Network error: " + e; return; }
  if (!res.ok) { const e = await res.json().catch(() => ({})); status.textContent = "✕ " + (e.error || res.status); return; }
  const { id } = await res.json();
  status.textContent = "";
  toast("Started — opening the job.");
  openHistoryJob(id);
}

function renderCLIFields(spec, host) {
  host.textContent = "";
  if (spec.positional) host.append(fieldRow("cli-pos", spec.positional.label, "text", spec.positional.placeholder || "", ""));
  for (const fl of spec.flags) {
    const id = flagId(fl);
    if (fl.type === "bool") host.append(boolRow(id, fl.label));
    else host.append(fieldRow(id, fl.label, fl.type === "num" ? "number" : "text", fl.placeholder || "", fl.def !== undefined ? String(fl.def) : ""));
  }
}
function fieldRow(id, label, type, placeholder, value) {
  return el("div", { className: "field" }, [
    el("label", { textContent: label, htmlFor: id }),
    el("input", { id, type, placeholder, value }),
  ]);
}
function boolRow(id, label) {
  return el("label", { className: "check cli-check" }, [el("input", { id, type: "checkbox" }), " " + label]);
}

function updateCLI() {
  const spec = CLI_SPECS[$("cli-op").value];
  const parts = ["xcrack", $("cli-op").value];
  for (const fl of spec.flags) {
    const e = $(flagId(fl));
    if (!e) continue;
    if (fl.type === "bool") { if (e.checked) parts.push(fl.flag); continue; }
    const v = e.value.trim();
    if (fl.type === "num") {
      if (v !== "" && Number(v) !== (fl.def ?? 0)) parts.push(fl.flag, v);
    } else if (v) {
      parts.push(fl.flag, shq(v));
    } else if (fl.required) {
      parts.push(fl.flag, fl.flag.replace(/^--/, "").toUpperCase());
    }
  }
  if (spec.positional) {
    const v = ($("cli-pos")?.value || "").trim();
    parts.push(v ? shq(v) : "FILE");
  }
  $("cli-cmd").textContent = parts.join(" ");
}
// shq single-quotes a value for a POSIX shell unless it is already a safe token.
function shq(v) {
  return /^[\w.,:/@=+%-]+$/.test(v) ? v : "'" + v.replace(/'/g, "'\\''") + "'";
}

function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = el("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

boot();
