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
  initTheme();
  wireTabs();
  wireAdvanced();
  wireFiles();
  wireRun();
  wireEditorButtons();
  wirePreview();
  applyHelp();
  try { META = await (await fetch(api("/meta"))).json(); } catch { META = {}; }
  renderBadges();
  Editor.set(META.starter_spec || "");
  loadDocs();
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

// ---- tabs / advanced --------------------------------------------------------
function wireTabs() {
  document.querySelectorAll("#tabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#tabs button").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      btn.classList.add("active");
      $("tab-" + btn.dataset.tab).classList.add("active");
      if (btn.dataset.tab === "stats") { refreshStats(); Charts.show(); }
      if (btn.dataset.tab === "config") setTimeout(() => Editor.refresh(), 0);
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

// ---- wordlist / file preview (client-side) ---------------------------------
function wirePreview() {
  const modal = $("preview-modal");
  $("preview-close").addEventListener("click", () => { modal.hidden = true; });
  modal.addEventListener("click", (e) => { if (e.target === modal) modal.hidden = true; });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") modal.hidden = true; });
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
  $("preview-modal").hidden = false;
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
  find_all: "Keep searching every encrypted node even after some are unlocked, instead of stopping at the first success per file.",
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
    ["adaptive", "adaptive"], ["cost_queue", "cost_queue"], ["find_all", "find_all"], ["loopback", "loopback"], ["spray", "spray"]]) {
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
}
function setYamlStatus(msg, ok) { const s = $("yaml-status"); s.textContent = msg; s.className = ok ? "ok" : "err"; }

// ---- run / events -----------------------------------------------------------
function wireRun() {
  $("run").addEventListener("click", runJob);
  $("cancel").addEventListener("click", async () => { if (currentJob) await fetch(api("/jobs/" + currentJob + "/cancel"), { method: "POST" }); });
}

async function runJob() {
  if (pickedSources.length === 0) { setRunStatus("Choose at least one file first.", true); return; }
  const fd = new FormData();
  fd.append("spec", specForRun());
  for (const f of pickedSources) fd.append("source", f);
  for (const f of $("wordlists").files) fd.append("aux", f);
  for (const f of $("aux").files) fd.append("aux", f);
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
  startElapsed();
  streamEvents(id);
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

function streamEvents(id) {
  if (evtSource) evtSource.close();
  evtSource = new EventSource(api("/jobs/" + id + "/events"));
  evtSource.onmessage = (m) => { let e; try { e = JSON.parse(m.data); } catch { return; } handleEvent(e); };
  evtSource.onerror = () => {};
}

function handleEvent(e) {
  switch (e.type) {
    case "log": appendLog(`[${e.level || "info"}] ${e.message}`); break;
    case "found": appendLog(`🔓 FOUND ${e.file} (${e.format || "?"})` + (e.password ? ` → ${e.password}` : "")); break;
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
    $("progress-text").textContent = `${candidates.toLocaleString()} / ${jobKeyspace.toLocaleString()} (${pct.toFixed(1)}%) · ${rate.toLocaleString()}/s`;
  } else {
    bar.classList.add("indeterminate");
    fill.style.width = "100%";
    $("progress-text").textContent = `${candidates.toLocaleString()} candidates · ${rate.toLocaleString()}/s`;
  }
  if (latest) $("latest-term").innerHTML = "latest: <code>" + escapeHTML(latest) + "</code>";
  const srcLabel = $("run-source");
  srcLabel.textContent = latest ? "testing: " + latest : "";
}
function resetBar() {
  const fill = $("bar-fill"); fill.style.width = "0%"; fill.parentElement.classList.remove("indeterminate");
  $("progress-text").textContent = "—"; $("run-source").textContent = "";
}
function escapeHTML(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

function appendLog(s) { const log = $("log"); log.textContent += s + "\n"; log.scrollTop = log.scrollHeight; }

async function finishRun(state) {
  if (evtSource) { evtSource.close(); evtSource = null; }
  stopElapsed();
  $("run").disabled = false; $("cancel").disabled = true;
  setRunStatus(state === "done" ? "✓ Done" : state === "canceled" ? "Canceled" : "Error", state !== "done");
  if (!currentJob) return;
  const job = await (await fetch(api("/jobs/" + currentJob))).json();
  if (job.ended_at && job.started_at) $("job-elapsed").textContent = fmtDur(job.ended_at - job.started_at);
  updateProgress(job.candidates || 0, "");
  renderResults(job);
}

function renderResults(job) {
  const root = $("results"); root.textContent = "";
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

// ---- statistics -------------------------------------------------------------
async function refreshStats() {
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

boot();
