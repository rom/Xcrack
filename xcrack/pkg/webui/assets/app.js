"use strict";
// Xcrack web console. Talks to the JSON/SSE API in pkg/webui. Kept dependency-
// free here; the richer build swaps in a code editor, charts and a Markdown
// renderer (see editor.js / charts.js / docs.js when present).
const api = (p) => "/api/v1" + p;
const $ = (id) => document.getElementById(id);
const el = (t, props = {}, kids = []) => {
  const e = document.createElement(t);
  Object.assign(e, props);
  for (const k of [].concat(kids)) e.append(k);
  return e;
};

let META = {};
let pickedSources = [];
let currentJob = null;
let evtSource = null;

// ---- editor seam: the plain textarea, replaced by editor.js if loaded -------
const Editor = {
  get: () => $("yaml").value,
  set: (v) => { $("yaml").value = v; },
  onChange: (fn) => $("yaml").addEventListener("input", fn),
};
window.XcrackEditor = Editor; // editor.js (rich build) may enhance this

// ---- bootstrap --------------------------------------------------------------
async function boot() {
  wireTabs();
  wireAdvanced();
  wireFiles();
  wireRun();
  wireEditorButtons();
  try {
    META = await (await fetch(api("/meta"))).json();
  } catch { META = {}; }
  renderBadges();
  Editor.set(META.starter_spec || "");
  loadDocs();
}

function renderBadges() {
  const b = $("meta-badges");
  b.textContent = "";
  const tag = (t, on) => el("span", { className: "badge " + (on ? "on" : "off"), textContent: t });
  if (META.version) b.append(el("span", { className: "badge ver", textContent: "v" + META.version }));
  b.append(tag("GPU", META.gpu_available));
  if (META.tpm_build) b.append(tag("TPM", true));
}

// ---- tabs / mode ------------------------------------------------------------
function wireTabs() {
  document.querySelectorAll("#tabs button").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#tabs button").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      btn.classList.add("active");
      $("tab-" + btn.dataset.tab).classList.add("active");
      if (btn.dataset.tab === "stats") refreshStats();
    });
  });
}

function wireAdvanced() {
  $("advanced").addEventListener("change", (e) => {
    document.body.classList.toggle("adv", e.target.checked);
  });
}

// ---- files ------------------------------------------------------------------
function wireFiles() {
  const dz = $("dropzone");
  $("pick").addEventListener("click", () => $("files").click());
  $("files").addEventListener("change", (e) => addSources(e.target.files));
  ["dragover", "dragenter"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("over"); }));
  dz.addEventListener("drop", (e) => addSources(e.dataTransfer.files));
}

function addSources(fileList) {
  for (const f of fileList) pickedSources.push(f);
  renderFileList();
}

function renderFileList() {
  const ul = $("filelist");
  ul.textContent = "";
  pickedSources.forEach((f, i) => {
    ul.append(el("li", {}, [
      el("span", { textContent: f.name }),
      el("button", { type: "button", className: "x", textContent: "✕", onclick: () => { pickedSources.splice(i, 1); renderFileList(); } }),
    ]));
  });
}

// ---- spec building ----------------------------------------------------------
function lines(id) {
  return $(id).value.split("\n").map((s) => s.trim()).filter(Boolean);
}

// formToSpec builds the job spec object from the easy-mode form. Emitted as
// JSON, which the server parses as YAML (JSON is a YAML subset).
function formToSpec() {
  const spec = { candidates: {}, patterns: {}, search: {}, concurrency: {}, limits: {}, budget: {} };
  spec.candidates.use_default_list = $("use_default").checked;
  const pw = lines("passwords"); if (pw.length) spec.candidates.passwords = pw;
  const wl = [...$("wordlists").files].map((f) => f.name); if (wl.length) spec.candidates.wordlists = wl;
  const masks = lines("masks"); if (masks.length) spec.patterns.masks = masks;
  const rules = lines("rules"); if (rules.length) spec.patterns.rules = rules;
  for (const [id, key] of [["markov", "markov"], ["prince", "prince"], ["toggle_case", "toggle_case"],
    ["keyboard_walk", "keyboard_walk"], ["context", "context_candidates"], ["hint", "hint_candidates"]]) {
    if ($(id).checked) spec.search[key] = true;
  }
  const workers = +$("workers").value; if (workers > 0) spec.concurrency.workers = workers;
  if ($("gpu").checked) spec.concurrency.gpu = true;
  if ($("dual_pipeline").checked) spec.concurrency.dual_pipeline = true;
  const mc = +$("max_candidates").value; if (mc > 0) spec.limits.max_candidates = mc;
  const pf = $("per_file").value.trim(); if (pf) spec.budget.per_file = pf;
  // prune empty blocks
  for (const k of Object.keys(spec)) if (Object.keys(spec[k]).length === 0) delete spec[k];
  return spec;
}

function specForRun() {
  // In advanced mode the YAML editor is authoritative; otherwise the form.
  return $("advanced").checked ? Editor.get() : JSON.stringify(formToSpec());
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
    if (res.ok) { Editor.set((await res.json()).yaml); setYamlStatus("from form", true); }
  });
}
function setYamlStatus(msg, ok) {
  const s = $("yaml-status");
  s.textContent = msg; s.className = ok ? "ok" : "err";
}

// ---- run / events -----------------------------------------------------------
function wireRun() {
  $("run").addEventListener("click", runJob);
  $("cancel").addEventListener("click", async () => {
    if (currentJob) await fetch(api("/jobs/" + currentJob + "/cancel"), { method: "POST" });
  });
}

async function runJob() {
  if (pickedSources.length === 0) { setRunStatus("Choose at least one file first.", true); return; }
  const fd = new FormData();
  fd.append("spec", specForRun());
  for (const f of pickedSources) fd.append("source", f);
  for (const f of $("wordlists").files) fd.append("aux", f);
  $("log").textContent = ""; $("results").textContent = ""; $("results-card").hidden = false;
  setRunStatus("Submitting…");
  let res;
  try { res = await fetch(api("/jobs"), { method: "POST", body: fd }); }
  catch (e) { return setRunStatus("Network error: " + e, true); }
  if (!res.ok) { const e = await res.json().catch(() => ({})); return setRunStatus("✕ " + (e.error || res.status), true); }
  const { id } = await res.json();
  currentJob = id;
  $("run").disabled = true; $("cancel").disabled = false;
  setRunStatus("Running…");
  streamEvents(id);
}

function streamEvents(id) {
  if (evtSource) evtSource.close();
  evtSource = new EventSource(api("/jobs/" + id + "/events"));
  evtSource.onmessage = (m) => {
    let e; try { e = JSON.parse(m.data); } catch { return; }
    handleEvent(e);
  };
  evtSource.onerror = () => { /* server closes the stream at job end */ };
}

function handleEvent(e) {
  switch (e.type) {
    case "log":
      appendLog(`[${e.level || "info"}] ${e.message}`); break;
    case "found":
      appendLog(`🔓 FOUND ${e.file} (${e.format || "?"})` + (e.password ? ` → ${e.password}` : "")); break;
    case "progress":
      setRunStatus(`Running… ${e.file}: ${e.candidates.toLocaleString()} candidates`); break;
    case "file_done":
      appendLog(`• ${e.file} done (${e.files_done}/${e.files_total})`); break;
    case "state":
      if (["done", "error", "canceled"].includes(e.state)) finishRun(e.state);
      break;
  }
  if ($("tab-stats").classList.contains("active")) refreshStats();
}

function appendLog(s) {
  const log = $("log");
  log.textContent += s + "\n";
  log.scrollTop = log.scrollHeight;
}

async function finishRun(state) {
  if (evtSource) { evtSource.close(); evtSource = null; }
  $("run").disabled = false; $("cancel").disabled = true;
  setRunStatus(state === "done" ? "✓ Done" : state === "canceled" ? "Canceled" : "Error", state !== "done");
  if (!currentJob) return;
  const job = await (await fetch(api("/jobs/" + currentJob))).json();
  renderResults(job);
}

function renderResults(job) {
  const root = $("results");
  root.textContent = "";
  (job.results || []).forEach((fr) => {
    const card = el("div", { className: "result" });
    card.append(el("div", { className: "result-head" }, [
      el("strong", { textContent: fr.name }),
      fr.error ? el("span", { className: "err", textContent: " — " + fr.error }) : "",
    ]));
    const rep = fr.report;
    if (rep) {
      const pws = rep.recovered_passwords || [];
      card.append(el("div", { className: "pw" }, pws.length ? "🔑 " + pws.join(", ") : "No password recovered"));
      card.append(renderNode(rep.root));
      if (rep.stats) card.append(el("div", { className: "stat-line", textContent:
        `${rep.stats.candidates_tried.toLocaleString()} candidates · ${rep.stats.elapsed_ms} ms` }));
    }
    root.append(card);
  });
  if ((job.results || []).some((r) => r.report)) {
    root.append(el("a", { className: "download", href: api("/jobs/" + job.id + "/download"), textContent: "⬇ Download decrypted output (zip)" }));
  }
}

function renderNode(n) {
  const li = el("li", {}, [
    el("span", { className: "status s-" + n.status, textContent: n.status }),
    " " + (n.path || "(root)") + (n.format ? ` [${n.format}]` : "") + (n.password ? ` → ${n.password}` : ""),
  ]);
  if (n.children && n.children.length) {
    li.append(el("ul", {}, n.children.map(renderNode)));
  }
  return el("ul", { className: "tree" }, [li]);
}

function setRunStatus(msg, err) {
  const s = $("run-status"); s.textContent = msg; s.className = err ? "err" : "";
}

// ---- statistics -------------------------------------------------------------
async function refreshStats() {
  let s; try { s = await (await fetch(api("/stats"))).json(); } catch { return; }
  const cards = [
    ["Jobs", s.jobs_total], ["Active", s.jobs_active], ["Finished", s.jobs_finished],
    ["Files processed", s.files_processed], ["Candidates tried", (s.candidates_tried || 0).toLocaleString()],
    ["Decrypted", s.nodes_decrypted], ["Still locked", s.nodes_locked],
  ];
  const host = $("stat-cards"); host.textContent = "";
  for (const [label, val] of cards) {
    host.append(el("div", { className: "card statcard" }, [
      el("div", { className: "statval", textContent: String(val ?? 0) }),
      el("div", { className: "statlabel", textContent: label }),
    ]));
  }
  window.XcrackCharts && window.XcrackCharts.render(s);
}

// ---- docs -------------------------------------------------------------------
async function loadDocs() {
  let list; try { list = (await (await fetch(api("/docs"))).json()).docs; } catch { return; }
  const ul = $("doclist"); ul.textContent = "";
  (list || []).forEach((d) => {
    ul.append(el("li", {}, [el("a", { href: "#", textContent: d.title, onclick: (e) => { e.preventDefault(); openDoc(d.name); } })]));
  });
}

async function openDoc(name) {
  const md = await (await fetch(api("/docs/" + encodeURIComponent(name)))).text();
  $("docview").innerHTML = window.XcrackMarkdown ? window.XcrackMarkdown(md) : miniMarkdown(md);
}

// miniMarkdown is a tiny fallback renderer; the rich build replaces it with a
// full Markdown library via window.XcrackMarkdown.
function miniMarkdown(md) {
  const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const out = [];
  let inCode = false, inList = false;
  for (const raw of md.split("\n")) {
    if (raw.startsWith("```")) {
      if (inCode) { out.push("</code></pre>"); inCode = false; } else { out.push("<pre><code>"); inCode = true; }
      continue;
    }
    if (inCode) { out.push(esc(raw)); continue; }
    let line = esc(raw);
    line = line.replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { if (inList) { out.push("</ul>"); inList = false; } out.push(`<h${h[1].length}>${h[2]}</h${h[1].length}>`); continue; }
    if (/^[-*]\s+/.test(raw)) { if (!inList) { out.push("<ul>"); inList = true; } out.push("<li>" + line.replace(/^[-*]\s+/, "") + "</li>"); continue; }
    if (inList) { out.push("</ul>"); inList = false; }
    out.push(raw.trim() === "" ? "" : "<p>" + line + "</p>");
  }
  if (inList) out.push("</ul>");
  if (inCode) out.push("</code></pre>");
  return out.join("\n");
}

boot();
