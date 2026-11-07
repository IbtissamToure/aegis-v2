"use strict";
// Aegis dashboard. All text from requests/responses is inserted with textContent (never innerHTML).

let CONFIG = null;
const CAT_LABEL = { pii: "Personal", credential: "Credential", financial: "Financial", confidential: "Confidential", quasi_identifier: "Quasi-identifier" };

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || (data.detail && JSON.stringify(data.detail)) || `HTTP ${r.status}`);
  return data;
}

function el(tag, props, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k === "style") n.style.cssText = v; // CSSOM: allowed under the strict CSP
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    n.appendChild(typeof c === "string" || typeof c === "number" ? document.createTextNode(String(c)) : c);
  }
  return n;
}
const $ = (id) => document.getElementById(id);
const fmt = (x, d = 1) => (x === null || x === undefined ? "—" : Number(x).toLocaleString(undefined, { maximumFractionDigits: d }));
const tag = (action) => el("span", { class: `tag ${action}` }, action);
function clear(node, ...children) { node.replaceChildren(...children); return node; }

// ---------------------------------------------------------------- navigation
function show(view) {
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${view}`));
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  ({ overview: loadOverview, audit: loadAudit, evaluation: loadEval, policies: loadPolicies, demo: loadScenarios, exposure: loadExposure })[view]?.();
}
document.querySelectorAll("#nav button").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));

async function init() {
  CONFIG = await api("/api/v1/config");
  const purposeOpts = Object.entries(CONFIG.purposes).map(([k, v]) => el("option", { value: k }, v.label));
  $("in-purpose").append(...purposeOpts.map((o) => o.cloneNode(true)));
  $("sim-purpose").append(...purposeOpts.map((o) => o.cloneNode(true)));
  for (const [k, v] of Object.entries(CONFIG.policies)) {
    $("in-policy").append(el("option", { value: k, selected: k === CONFIG.default_policy ? "selected" : null }, v.label));
    $("pol-pick").append(el("option", { value: k }, v.label));
  }
  const llm = CONFIG.llm;
  $("llm-status").textContent = llm.available ? `Model: ${llm.provider} (${llm.location})` : "Model: none (rules only — decisions never need a model)";
  $("pop-name").textContent = `${CONFIG.population.name} — ${CONFIG.population.size.toLocaleString()} people, synthetic`;
  loadOverview();
}

// ---------------------------------------------------------------- overview
function bars(node, pairs, total) {
  const max = Math.max(1, ...pairs.map((p) => p[1]));
  clear(node, ...(pairs.length ? pairs.map(([label, n]) => el("div", { class: "bar-row" },
    el("span", {}, label), el("div", { class: "bar" }, el("i", { style: `width:${(100 * n) / max}%` })), el("b", {}, String(n)))) : [el("p", { class: "muted" }, "No decisions yet — try the demo scenarios.")]));
}
async function loadOverview() {
  const s = await api("/api/v1/stats");
  const k = [["Decisions", s.total], ["Blocked", s.actions.BLOCK], ["Generalized", s.actions.GENERALIZE], ["Warnings", s.actions.WARN],
    ["Injection detections", s.injection_detected], ["Exposure interventions", s.exposure_interventions],
    ["Latency p50 / p95", s.latency_p50_ms === null ? "—" : `${fmt(s.latency_p50_ms)} / ${fmt(s.latency_p95_ms)} ms`]];
  clear($("kpis"), ...k.map(([l, v]) => el("div", { class: "kpi" }, el("div", { class: "v" }, String(v)), el("div", { class: "l" }, l))));
  bars($("action-bars"), Object.entries(s.actions), s.total);
  bars($("type-bars"), s.top_types.map(([t, n]) => [CONFIG.entity_types[t]?.label || t, n]));
  bars($("rule-bars"), s.top_rules);
  $("demo-note").textContent = s.demo_rows ? `${s.demo_rows} of these come from demo scenarios (synthetic data).` : "";
}

// ---------------------------------------------------------------- decision rendering
function highlight(text, findings, signals) {
  const spans = [];
  findings.filter((f) => f.confidence >= 0.5).forEach((f) => spans.push({ s: f.start, e: f.end, cls: `c-${f.category}`, title: `${CONFIG.entity_types[f.type]?.label || f.type} · ${f.detector} · conf ${f.confidence} · ${f.id}` }));
  (signals || []).filter((x) => x.end - x.start < text.length || text.length < 200).forEach((x) => spans.push({ s: x.start, e: x.end, cls: "c-inj", title: `Injection: ${x.evidence} (${x.family}, w=${x.weight})` }));
  spans.sort((a, b) => a.s - b.s || b.e - a.e);
  const out = el("div", { class: "hl", dir: "auto" });
  let pos = 0;
  for (const sp of spans) {
    if (sp.s < pos) continue;
    out.append(text.slice(pos, sp.s), el("mark", { class: sp.cls, title: sp.title }, text.slice(sp.s, sp.e)));
    pos = sp.e;
  }
  out.append(text.slice(pos));
  return out;
}
function legend() {
  return el("div", { class: "legend" }, ...Object.entries(CAT_LABEL).map(([c, l]) => el("span", { class: `c-${c}` }, l)), el("span", { class: "c-inj" }, "Injection"));
}

function exposurePanel(x, policyName) {
  if (x.status === "not_tracked") return el("p", { class: "muted" }, x.explanation);
  const pol = CONFIG.policies[policyName].exposure;
  const N = x.population;
  const pos = (k) => Math.max(0, Math.min(100, (100 * Math.log10(Math.max(k, 1))) / Math.log10(N)));
  const color = x.k_estimate_after < pol.k_min ? "var(--block)" : x.k_estimate_after < pol.k_warn ? "var(--warn)" : "var(--allow)";
  return el("div", {},
    el("p", {}, x.explanation),
    el("div", { class: "small muted" }, "People still matching (log scale, right = anonymous):"),
    el("div", { class: "gauge" },
      el("i", { style: `width:${pos(x.k_estimate_after)}%;background:${color}` }),
      el("b", { style: `left:${pos(pol.k_min)}%` }, el("span", {}, `floor ${pol.k_min}`)),
      el("b", { style: `left:${pos(pol.k_warn)}%` }, el("span", {}, `warn ${pol.k_warn}`))),
    el("div", { class: "metric" }, el("span", {}, "Estimated matching people (before → after)"), el("b", {}, `${fmt(x.k_estimate_before)} → ${fmt(x.k_estimate_after)}`)),
    x.k_requested !== null && x.status === "generalized" ? el("div", { class: "metric" }, el("span", {}, "If sent as requested"),
      el("b", {}, `${x.k_requested < 1 ? "fewer than 1 (unique)" : fmt(x.k_requested)} — exact ${x.k_exact_requested ?? "—"}`)) : null,
    x.k_exact_after !== null ? el("div", { class: "metric" }, el("span", {}, "Exact count in the synthetic directory"), el("b", {}, String(x.k_exact_after))) : null,
    el("div", { class: "metric" }, el("span", {}, "Information disclosed"), el("b", {}, `${fmt(x.bits_after, 2)} of ${fmt(x.budget_bits, 2)} bits`)),
    x.attributes.length ? el("div", { class: "table-wrap" }, table(["Attribute", "Disclosed as", "Share of population", "Bits"],
      x.attributes.map((a) => [a.attribute, `${a.value} (${a.level})`, `${fmt(100 * a.share, 2)}%`, fmt(a.bits, 2)]))) : null);
}

function table(headers, rows) {
  return el("table", {}, el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, ...rows.map((r) => el("tr", {}, ...r.map((c) => el("td", {}, c instanceof Node ? c : String(c ?? "")))))));
}

function renderDecision(d, prompt, content, opts = {}) {
  const root = el("div", { class: "decision-block" });
  const verdict = el("div", { class: `verdict ${d.action}` }, el("div", { class: "a" }, d.action),
    el("div", { class: "s" }, `${d.severity} severity · policy: ${d.policy}`), el("div", { class: "s" }, `purpose: ${d.purpose.label}`));
  root.append(el("div", { class: "card" }, el("div", { class: "decision" }, verdict, el("ul", { class: "rationale" }, ...d.rationale.map((r) => el("li", {}, r))))));

  const pf = d.findings.filter((f) => f.segment === "prompt"), cf = d.findings.filter((f) => f.segment === "content");
  const ps = d.injection.signals.filter((s) => s.segment === "prompt"), cs = d.injection.signals.filter((s) => s.segment === "content");
  const left = el("div", {}, el("h3", {}, "Original — what was detected"), highlight(prompt, pf, ps), content ? el("div", { class: "small muted" }, "Attached content:") : null,
    content ? highlight(content, cf, cs) : null, legend());
  const sent = d.action === "BLOCK" ? el("div", { class: "out blocked" }, "Nothing is sent. " + (d.remediation[0] || ""))
    : el("div", {}, el("div", { class: "out", dir: "auto" }, d.minimized_prompt), d.minimized_content ? el("div", { class: "small muted" }, "Attached content:") : null,
      d.minimized_content ? el("div", { class: "out", dir: "auto" }, d.minimized_content) : null);
  const right = el("div", {}, el("h3", {}, d.action === "BLOCK" ? "Outcome" : "What leaves the organization"), sent,
    d.action === "WARN" ? el("p", { class: "small" }, "Sending requires the user's confirmation.") : null,
    d.model_output ? el("div", {}, el("h3", {}, "Model answer"), el("div", { class: "out", dir: "auto" }, d.model_output)) : null);
  root.append(el("div", { class: "card two" }, left, right));

  if (d.changes.length) root.append(el("div", { class: "card" }, el("h3", {}, "Generalization — before / after"),
    el("div", { class: "table-wrap" }, table(["Finding", "Type", "Original (masked)", "Sent as", "Level", "Why"],
      d.changes.map((c) => [c.finding_id, CONFIG.entity_types[c.type]?.label || c.type, c.original_preview, c.replacement, c.level, c.reason])))));
  if (d.fired_rules.length) root.append(el("div", { class: "card" }, el("h3", {}, "Policy rules triggered"),
    el("div", { class: "table-wrap" }, table(["Rule", "Action", "Severity", "Description", "Findings"],
      d.fired_rules.map((r) => [r.rule_id, tag(r.action), r.severity, r.description, r.finding_ids.join(", ")])))));
  const extras = el("div", { class: "grid2" });
  extras.append(el("div", { class: "card" }, el("h3", {}, "Identifiability budget"), exposurePanel(d.exposure, d.policy)));
  extras.append(el("div", { class: "card" }, el("h3", {}, `Prompt injection — score ${fmt(d.injection.score, 2)}`),
    el("p", {}, d.injection.explanation),
    d.injection.signals.length ? table(["Family", "Where", "Weight", "Evidence"], d.injection.signals.map((s) => [s.family, s.segment, fmt(s.weight, 2), s.evidence])) : null));
  if (d.counterfactual) extras.append(el("div", { class: "card" }, el("h3", {}, "Smallest change that lowers this decision"),
    d.counterfactual.steps.length ? el("div", {}, el("ul", {}, ...d.counterfactual.steps.map((s) => el("li", {}, s))),
      el("p", {}, "→ would become ", tag(d.counterfactual.target_action || "ALLOW"))) : null,
    d.counterfactual.note ? el("p", { class: "small muted" }, d.counterfactual.note) : null));
  extras.append(el("div", { class: "card" }, el("h3", {}, "Processing"),
    el("div", { class: "metric" }, el("span", {}, "Where"), el("b", {}, `${d.processing.location} (destination: ${d.processing.destination})`)),
    el("div", { class: "metric" }, el("span", {}, "External call made"), el("b", {}, d.processing.external_call ? "yes" : "no")),
    el("div", { class: "metric" }, el("span", {}, "Latency"), el("b", {}, `${fmt(d.latency_ms.total, 2)} ms`)),
    el("div", { class: "small muted" }, Object.entries(d.latency_ms).filter(([k]) => k !== "total").map(([k, v]) => `${k} ${fmt(v, 2)}`).join(" · "))));
  root.append(extras);
  return root;
}

// ---------------------------------------------------------------- inspect
async function runInspect(dry) {
  const body = { prompt: $("in-prompt").value, content: $("in-content").value || null, purpose: $("in-purpose").value || null,
    policy: $("in-policy").value, session_id: $("in-session").value || null, dry_run: dry };
  const out = $("inspect-out");
  if (!body.prompt.trim()) return clear(out, el("p", { class: "err" }, "Enter a prompt first."));
  try {
    const d = await api("/api/v1/evaluate", body);
    clear(out, renderDecision(d, body.prompt, body.content || ""));
  } catch (e) { clear(out, el("p", { class: "err" }, e.message)); }
}
$("btn-eval").addEventListener("click", () => runInspect(false));
$("btn-dry").addEventListener("click", () => runInspect(true));

// ---------------------------------------------------------------- exposure
function timeline(history, pol, N) {
  const W = 640, H = 220, L = 56, R = 20, T = 16, B = 34;
  const n = Math.max(history.length, 2);
  const x = (i) => L + ((W - L - R) * i) / (n - 1);
  const y = (k) => T + (H - T - B) * (1 - Math.log10(Math.max(k, 0.5) / 0.5) / Math.log10(N / 0.5));
  const ns = "http://www.w3.org/2000/svg";
  const s = (t, a, txt) => { const e = document.createElementNS(ns, t); for (const [k, v] of Object.entries(a)) e.setAttribute(k, v); if (txt !== undefined) e.textContent = txt; return e; };
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img", "aria-label": "Matching people per turn" });
  [1, 10, 100, 1000, N].forEach((k) => { svg.append(s("line", { x1: L, x2: W - R, y1: y(k), y2: y(k), stroke: "#E3E9E7" }), s("text", { x: L - 6, y: y(k) + 4, "text-anchor": "end", "font-size": 11, fill: "#5E6E6B" }, k.toLocaleString())); });
  [[pol.k_warn, "#C88A04", "warn"], [pol.k_min, "#C0392B", "floor"]].forEach(([k, c, l]) => { svg.append(s("line", { x1: L, x2: W - R, y1: y(k), y2: y(k), stroke: c, "stroke-dasharray": "5 4" }), s("text", { x: L + 6, y: y(k) - 4, "text-anchor": "start", "font-size": 11, fill: c }, `${l} (${k})`)); });
  const pts = history.map((h, i) => `${x(i)},${y(h.k)}`).join(" ");
  svg.append(s("polyline", { points: pts, fill: "none", stroke: "#0E3F3C", "stroke-width": 2.5 }));
  history.forEach((h, i) => {
    const c = { BLOCK: "#C0392B", GENERALIZE: "#2F6FB3", WARN: "#C88A04", ALLOW: "#1F8A5B" }[h.decision] || "#0E3F3C";
    svg.append(s("circle", { cx: x(i), cy: y(h.k), r: 6, fill: c }), s("text", { x: x(i), y: H - 12, "text-anchor": "middle", "font-size": 11, fill: "#5E6E6B" }, `turn ${h.turn}`),
      s("text", { x: x(i), y: y(h.k) - 11, "text-anchor": "middle", "font-size": 11.5, "font-weight": 700, fill: "#15211F" }, `${fmt(h.k)}`));
  });
  return svg;
}
async function loadExposure() {
  const id = $("ex-session").value.trim();
  if (!id) return;
  const snap = await api(`/api/v1/sessions/${encodeURIComponent(id)}`);
  const out = $("exposure-out");
  if (!snap.exists || !snap.subjects.length) return clear(out, el("p", { class: "muted" }, "No tracked subjects in this session yet. Run the “Three harmless prompts” demo scenario, or use Inspect with this session id."));
  const pol = CONFIG.policies[CONFIG.default_policy].exposure;
  clear(out, ...snap.subjects.map((sub) => el("div", { class: "card" },
    el("h3", {}, `${sub.label}${sub.active ? " (active)" : ""} — about ${fmt(sub.k)} of ${snap.population.toLocaleString()} people match · ${fmt(sub.bits, 2)} / ${fmt(snap.budget_bits, 2)} bits`),
    sub.history.length ? timeline(sub.history, pol, snap.population) : null,
    table(["Attribute", "Disclosed as", "Share", "Bits", "Turn"], sub.contributions.map((a) => [a.attribute, `${a.value} (${a.level})`, `${fmt(100 * a.share, 2)}%`, fmt(a.bits, 2), a.turn])),
    el("p", { class: "small muted" }, `Exact count in the synthetic directory: ${sub.k_exact ?? "—"}. Session memory expires in ${Math.round(snap.expires_in_s / 60)} min; only attribute categories are kept, never names or prompts.`))));
}
$("btn-ex").addEventListener("click", loadExposure);
$("btn-ex-reset").addEventListener("click", async () => { await api(`/api/v1/sessions/${encodeURIComponent($("ex-session").value)}/reset`, {}); loadExposure(); });

// ---------------------------------------------------------------- simulate
function simCard(name, d) {
  return el("div", { class: "card" }, el("div", { class: "step-head" }, el("h3", {}, CONFIG.policies[name].label), tag(d.action)),
    el("p", { class: "small muted" }, CONFIG.policies[name].description),
    d.action === "BLOCK" ? el("div", { class: "out blocked" }, "Blocked — nothing is sent.") : el("div", { class: "out", dir: "auto" }, d.minimized_prompt),
    el("ul", { class: "small" }, ...d.fired_rules.map((r) => el("li", {}, `${r.rule_id} → ${r.action}: ${r.description}`))),
    d.counterfactual && d.counterfactual.steps.length ? el("p", { class: "small" }, "To lower: " + d.counterfactual.steps.join("; ")) : null);
}
async function runSim(prompt, content, purpose, target) {
  const r = await api("/api/v1/simulate", { prompt, content: content || null, purpose: purpose || null });
  clear(target, ...r.policies.map((p) => simCard(p, r.results[p])));
  return r;
}
$("btn-sim").addEventListener("click", async () => {
  try { await runSim($("sim-prompt").value, $("sim-content").value, $("sim-purpose").value, $("sim-out")); } catch (e) { clear($("sim-out"), el("p", { class: "err" }, e.message)); }
});

// ---------------------------------------------------------------- demo
let SCENARIOS = null;
async function loadScenarios() {
  if (!SCENARIOS) SCENARIOS = await api("/api/v1/demo/scenarios");
  clear($("scenarios"), ...SCENARIOS.scenarios.map((sc) => {
    const out = el("div", { class: "steps" });
    const btn = el("button", { class: "primary", onclick: () => runScenario(sc, out, btn) }, "Run");
    return el("div", { class: "card scenario" }, el("div", { class: "step-head" }, el("h3", {}, sc.title), btn), sc.note ? el("p", { class: "muted" }, sc.note) : null,
      el("ol", { class: "small" }, ...sc.steps.map((s) => el("li", { dir: "auto" }, s.prompt.length > 160 ? s.prompt.slice(0, 160) + "…" : s.prompt))), out);
  }));
}
async function runScenario(sc, out, btn) {
  btn.disabled = true; clear(out);
  try {
    if (sc.session) await api(`/api/v1/sessions/${encodeURIComponent(sc.session)}/reset`, {});
    for (const [i, st] of sc.steps.entries()) {
      if (sc.simulate) { const grid = el("div", { class: "sim-grid" }); out.append(grid); await runSim(st.prompt, st.content, st.purpose, grid); continue; }
      const d = await api("/api/v1/evaluate", { prompt: st.prompt, content: st.content || null, purpose: st.purpose || null, session_id: sc.session || `demo-${sc.id}-${Date.now()}`, demo: true });
      out.append(el("h3", {}, `Step ${i + 1}`), renderDecision(d, st.prompt, st.content || ""));
    }
    if (sc.session) {
      const snap = await api(`/api/v1/sessions/${encodeURIComponent(sc.session)}`);
      const sub = snap.subjects.find((s) => s.history.length);
      if (sub) out.append(el("div", { class: "card" }, el("h3", {}, "Matching people after each prompt"), timeline(sub.history, CONFIG.policies[CONFIG.default_policy].exposure, snap.population)));
    }
  } catch (e) { out.append(el("p", { class: "err" }, e.message)); }
  btn.disabled = false;
}

// ---------------------------------------------------------------- policies
async function loadPolicies() {
  const types = ["person_name", "age", "gender", "city", "nationality", "department", "job_title", "join_year", "money_amount", "salary", "date", "project_codename", "email", "phone"];
  const rows = Object.entries(CONFIG.purposes).map(([k, p]) => [p.label, ...types.map((t) => p.needs[t] || "remove")]);
  clear($("contracts"), el("div", { class: "table-wrap" }, table(["Purpose", ...types.map((t) => CONFIG.entity_types[t].label)], rows)));
  const load = async () => { const r = await api(`/api/v1/policies/${$("pol-pick").value}/source`); $("pol-src").textContent = r.yaml; };
  $("pol-pick").onchange = load; load();
}

// ---------------------------------------------------------------- audit
async function loadAudit() {
  const r = await api("/api/v1/audit?limit=100");
  clear($("audit-out"), r.rows.length ? table(["Time", "Action", "Policy", "Purpose", "Data types", "Rules", "Injection", "k after", "ms", "Demo"],
    r.rows.map((x) => [new Date(x.ts * 1000).toLocaleTimeString(), tag(x.action), x.policy, x.purpose,
      Object.entries(x.finding_types || {}).map(([t, n]) => `${t}×${n}`).join(" "), (x.rules || []).join(" "), fmt(x.injection_score, 2),
      x.exposure_status === "not_tracked" ? "—" : fmt(x.k_estimate), fmt(x.latency_ms, 2), x.demo ? "demo" : ""])) : el("p", { class: "muted" }, "Empty."));
}
$("btn-audit").addEventListener("click", loadAudit);

// ---------------------------------------------------------------- evaluation
async function loadEval() {
  const r = await api("/api/v1/eval/latest");
  const out = $("eval-out");
  if (!r.available) return clear(out, el("p", { class: "muted" }, r.message));
  const ci = (m) => (m.ci ? ` [${fmt(m.ci[0] * (m.pct ? 100 : 1), 1)}–${fmt(m.ci[1] * (m.pct ? 100 : 1), 1)}]` : "");
  const val = (m) => (m.pct ? `${fmt(m.value * 100, 1)}%` : `${fmt(m.value, 3)}${m.unit ? " " + m.unit : ""}`);
  clear(out, el("p", { class: "small muted" }, `Generated ${r.generated_at} · Aegis ${r.version} · ${r.machine || ""}`),
    ...r.sections.map((s) => el("div", { class: "card" }, el("h3", {}, s.title), s.description ? el("p", { class: "muted small" }, s.description) : null,
      ...(s.metrics || []).map((m) => el("div", { class: "metric" }, el("span", {}, `${m.label}${m.n ? ` (n=${m.n})` : ""}`), el("b", {}, val(m) + ci(m)))),
      ...(s.tables || []).map((t) => el("div", { class: "table-wrap" }, el("h4", {}, t.title), table(t.columns, t.rows))),
      ...(s.notes || []).map((n) => el("p", { class: "small muted" }, n)))));
}

init().catch((e) => document.body.prepend(el("p", { class: "err" }, `Failed to start: ${e.message}`)));
