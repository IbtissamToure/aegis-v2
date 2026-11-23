"use strict";
// Aegis dashboard. All text from requests/responses is inserted with textContent (never innerHTML).
// UI strings come from i18n.js (t()); engine-generated explanations stay as returned by the API.

let CONFIG = null;
const CATS = ["pii", "credential", "financial", "confidential", "quasi_identifier"];
const cols = (key) => t(key).split("|");

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
const fmt = (x, d = 1) => (x === null || x === undefined ? "-" : Number(x).toLocaleString(numLocale(), { maximumFractionDigits: d }));
const tag = (action) => el("span", { class: `tag ${action}` }, action);
function clear(node, ...children) { node.replaceChildren(...children.filter((c) => c !== null && c !== undefined && c !== false)); return node; }

// ---------------------------------------------------------------- navigation
const VIEWS = ["overview", "inspect", "demo", "exposure", "simulate", "policies", "audit", "evaluation"];
let CURRENT = "overview";
function show(view, push = true) {
  if (!VIEWS.includes(view)) view = "overview";
  CURRENT = view;
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${view}`));
  document.querySelectorAll("#nav button").forEach((b) => { const a = b.dataset.view === view; b.classList.toggle("active", a); if (a) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); });
  if (push && location.hash !== `#${view}`) history.replaceState(null, "", `#${view}`);
  document.body.classList.remove("side-open"); $("side-toggle").setAttribute("aria-expanded", "false");
  if (!CONFIG) return;
  ({ overview: loadOverview, audit: loadAudit, evaluation: loadEval, policies: loadPolicies, demo: loadScenarios, exposure: loadExposure })[view]?.();
}
document.querySelectorAll("#nav button").forEach((b) => b.addEventListener("click", () => { show(b.dataset.view); window.scrollTo({ top: 0 }); }));
window.addEventListener("hashchange", () => show(location.hash.slice(1), false));
$("side-toggle").addEventListener("click", () => { const o = document.body.classList.toggle("side-open"); $("side-toggle").setAttribute("aria-expanded", String(o)); });

function modelStatus() {
  const llm = CONFIG.llm;
  $("llm-status").textContent = llm.available ? t("app.model.on", { p: llm.provider, l: llm.location })
    : llm.provider === "none" ? t("app.model.none")
    : t("app.model.na", { p: llm.problem || "unknown" });
  $("llm-status").classList.toggle("on", !!llm.available);
}

async function init() {
  CONFIG = await api("/api/v1/config");
  api("/api/v1/health").then((h) => { $("ver").textContent = `Aegis v${h.version}`; }).catch(() => {});
  const purposeOpts = Object.entries(CONFIG.purposes).map(([k, v]) => el("option", { value: k }, v.label));
  $("in-purpose").append(...purposeOpts.map((o) => o.cloneNode(true)));
  $("sim-purpose").append(...purposeOpts.map((o) => o.cloneNode(true)));
  for (const [k, v] of Object.entries(CONFIG.policies)) {
    $("in-policy").append(el("option", { value: k, selected: k === CONFIG.default_policy ? "selected" : null }, v.label));
    $("pol-pick").append(el("option", { value: k }, v.label));
  }
  modelStatus();
  $("pop-name").textContent = t("app.ex.pop", { name: CONFIG.population.name, n: CONFIG.population.size.toLocaleString(numLocale()) });
  show(location.hash.slice(1) || "overview", false);
}

// ---------------------------------------------------------------- overview
function bars(node, pairs, total) {
  const max = Math.max(1, ...pairs.map((p) => p[1]));
  clear(node, ...(pairs.length ? pairs.map(([label, n]) => el("div", { class: "bar-row" },
    el("span", {}, label), el("div", { class: "bar" }, el("i", { style: `width:${(100 * n) / max}%` })), el("b", {}, String(n)))) : [el("p", { class: "muted" }, t("app.ov.empty"))]));
}
async function loadOverview() {
  const s = await api("/api/v1/stats");
  const k = [[t("kpi.total"), s.total], [t("kpi.block"), s.actions.BLOCK], [t("kpi.gen"), s.actions.GENERALIZE], [t("kpi.warn"), s.actions.WARN],
    [t("kpi.inj"), s.injection_detected], [t("kpi.exp"), s.exposure_interventions],
    [`${t("app.d.latency")} p50 / p95`, s.latency_p50_ms === null ? "-" : `${fmt(s.latency_p50_ms)} / ${fmt(s.latency_p95_ms)} ms`]];
  clear($("kpis"), ...k.map(([l, v]) => el("div", { class: "kpi" }, el("div", { class: "v" }, String(v)), el("div", { class: "l" }, l))));
  bars($("action-bars"), Object.entries(s.actions), s.total);
  bars($("type-bars"), s.top_types.map(([ty, n]) => [CONFIG.entity_types[ty]?.label || ty, n]));
  bars($("rule-bars"), s.top_rules);
  $("demo-note").textContent = s.demo_rows ? t("app.ov.demo", { n: s.demo_rows }) : "";
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
  return el("div", { class: "legend" }, ...CATS.map((c) => el("span", { class: `c-${c}` }, t(`app.cat.${c}`))), el("span", { class: "c-inj" }, t("app.cat.inj")));
}

function exposurePanel(x, policyName) {
  if (x.status === "not_tracked") return el("p", { class: "muted" }, x.explanation);
  const pol = CONFIG.policies[policyName].exposure;
  const N = x.population;
  const pos = (k) => Math.max(0, Math.min(100, (100 * Math.log10(Math.max(k, 1))) / Math.log10(N)));
  const color = x.k_estimate_after < pol.k_min ? "var(--block)" : x.k_estimate_after < pol.k_warn ? "var(--warn)" : "var(--allow)";
  return el("div", {},
    el("p", { dir: "auto" }, x.explanation),
    el("div", { class: "small muted" }, t("app.x.scale")),
    el("div", { class: "gauge" },
      el("i", { style: `width:${pos(x.k_estimate_after)}%;background:${color}` }),
      el("b", { style: `inset-inline-start:${pos(pol.k_min)}%` }, el("span", {}, t("app.x.floor", { k: pol.k_min }))),
      el("b", { style: `inset-inline-start:${pos(pol.k_warn)}%` }, el("span", {}, t("app.x.warn", { k: pol.k_warn })))),
    el("div", { class: "metric" }, el("span", {}, t("app.x.est")), el("b", {}, `${fmt(x.k_estimate_before)} → ${fmt(x.k_estimate_after)}`)),
    x.k_requested !== null && x.status === "generalized" ? el("div", { class: "metric" }, el("span", {}, t("app.x.req")),
      el("b", {}, `${x.k_requested < 1 ? t("app.x.unique") : fmt(x.k_requested)}${x.k_exact_requested ? t("app.x.exact", { k: x.k_exact_requested }) : ""}`)) : null,
    x.k_exact_after !== null ? el("div", { class: "metric" }, el("span", {}, t("app.x.after")), el("b", {}, String(x.k_exact_after))) : null,
    el("div", { class: "metric" }, el("span", {}, t("app.x.info")), el("b", {}, t("app.x.bits", { a: fmt(x.bits_after, 2), b: fmt(x.budget_bits, 2) }))),
    x.attributes.length ? el("div", { class: "table-wrap" }, table(cols("app.x.cols"),
      x.attributes.map((a) => [a.attribute, `${a.value} (${a.level})`, `${fmt(100 * a.share, 2)}%`, fmt(a.bits, 2)]))) : null);
}

function table(headers, rows) {
  return el("table", {}, el("thead", {}, el("tr", {}, ...headers.map((h) => el("th", {}, h)))),
    el("tbody", {}, ...rows.map((r) => el("tr", {}, ...r.map((c) => el("td", { dir: c instanceof Node ? null : "auto" }, c instanceof Node ? c : String(c ?? "")))))));
}

function renderDecision(d, prompt, content, opts = {}) {
  const root = el("div", { class: "decision-block" });
  const summary = {
    ALLOW: t("app.d.ALLOW"),
    GENERALIZE: d.changes.length === 1 ? t("app.d.GENERALIZE.1") : t("app.d.GENERALIZE.n", { n: d.changes.length }),
    WARN: t("app.d.WARN"),
    BLOCK: t("app.d.BLOCK"),
  }[d.action];

  // ---------------- RESULT (top)
  const verdict = el("div", { class: `verdict ${d.action}` }, el("div", { class: "a" }, d.action),
    el("div", { class: "s" }, t("app.d.purpose", { p: d.purpose.label })), el("div", { class: "s" }, t("app.d.policy", { p: d.policy })));
  const sentBox = d.action === "BLOCK"
    ? el("div", { class: "out blocked", dir: "auto" }, d.remediation[0] || t("app.d.fix"))
    : el("div", {}, el("div", { class: "out", dir: "auto" }, d.minimized_prompt),
      d.minimized_content ? el("div", { class: "small muted" }, t("app.d.attached")) : null,
      d.minimized_content ? el("div", { class: "out", dir: "auto" }, d.minimized_content) : null,
      el("div", { class: "btns" }, el("button", { onclick: (ev) => {
        navigator.clipboard.writeText(d.minimized_prompt + (d.minimized_content ? "\n\n" + d.minimized_content : ""));
        ev.target.textContent = t("app.d.copied"); } }, t("app.d.copy"))));
  const noModel = !d.model_output && opts.forwarded && d.action !== "BLOCK" ? el("p", { class: "small muted" },
    CONFIG.llm.available ? t("app.d.noanswer") : t("app.d.nomodel")) : null;
  if (d.model_output) root.append(el("div", { class: "card answer-card" }, el("h3", {}, t("app.d.answer")),
    el("div", { class: "answer-text", dir: "auto" }, d.model_output),
    el("p", { class: "small muted" }, t("app.d.answer.n"))));
  root.append(el("div", { class: "card result" },
    el("div", { class: "decision" }, verdict, el("div", { class: "result-main" },
      el("p", { class: "summary" }, summary),
      el("h3", {}, d.action === "BLOCK" ? t("app.d.why.stop") : t("app.d.leaves")), sentBox, noModel))));

  // ---------------- ANALYSIS (below)
  root.append(el("h2", { class: "section-title" }, t("app.d.analysis")));
  const pf = d.findings.filter((f) => f.segment === "prompt"), cf = d.findings.filter((f) => f.segment === "content");
  const ps = d.injection.signals.filter((s) => s.segment === "prompt"), cs = d.injection.signals.filter((s) => s.segment === "content");
  root.append(el("div", { class: "card two" },
    el("div", {}, el("h3", {}, t("app.d.detected")), highlight(prompt, pf, ps), content ? el("div", { class: "small muted" }, t("app.d.attached")) : null,
      content ? highlight(content, cf, cs) : null, legend()),
    el("div", {}, el("h3", {}, t("app.d.why")), el("ul", { class: "rationale" }, ...d.rationale.map((r) => el("li", { dir: "auto" }, r))),
      LANG === "ar" ? el("p", { class: "small muted" }, t("app.d.why.n")) : null)));

  if (d.changes.length) root.append(el("div", { class: "card" }, el("h3", {}, t("app.d.gen")),
    el("div", { class: "table-wrap" }, table(cols("app.d.gen.cols"),
      d.changes.map((c) => [c.finding_id, CONFIG.entity_types[c.type]?.label || c.type, c.original_preview, c.replacement, c.level, c.reason])))));
  if (d.fired_rules.length) root.append(el("div", { class: "card" }, el("h3", {}, t("app.d.rules")),
    el("div", { class: "table-wrap" }, table(cols("app.d.rules.cols"),
      d.fired_rules.map((r) => [r.rule_id, tag(r.action), r.severity, r.description, r.finding_ids.join(", ")])))));
  const extras = el("div", { class: "grid2" });
  extras.append(el("div", { class: "card" }, el("h3", {}, t("app.d.budget")), exposurePanel(d.exposure, d.policy)));
  extras.append(el("div", { class: "card" }, el("h3", {}, t("app.d.inj", { s: fmt(d.injection.score, 2) })),
    el("p", { dir: "auto" }, d.injection.explanation),
    d.injection.signals.length ? el("div", { class: "table-wrap" }, table(cols("app.d.inj.cols"), d.injection.signals.map((s) => [s.family, s.segment, fmt(s.weight, 2), s.evidence]))) : null));
  if (d.counterfactual) extras.append(el("div", { class: "card" }, el("h3", {}, t("app.d.cf")),
    d.counterfactual.steps.length ? el("div", {}, el("ul", {}, ...d.counterfactual.steps.map((s) => el("li", { dir: "auto" }, s))),
      el("p", {}, t("app.d.cf.would"), tag(d.counterfactual.target_action || "ALLOW"))) : null,
    d.counterfactual.note ? el("p", { class: "small muted", dir: "auto" }, d.counterfactual.note) : null));
  extras.append(el("div", { class: "card" }, el("h3", {}, t("app.d.proc")),
    el("div", { class: "metric" }, el("span", {}, t("app.d.where")), el("b", {}, t("app.d.where.v", { l: d.processing.location, d: d.processing.destination }))),
    el("div", { class: "metric" }, el("span", {}, t("app.d.ext")), el("b", {}, d.processing.external_call ? t("app.d.yes") : t("app.d.no"))),
    el("div", { class: "metric" }, el("span", {}, t("app.d.latency")), el("b", {}, `${fmt(d.latency_ms.total, 2)} ms`)),
    el("div", { class: "small muted", dir: "ltr" }, Object.entries(d.latency_ms).filter(([k]) => k !== "total").map(([k, v]) => `${k} ${fmt(v, 2)}`).join(" · "))));
  root.append(extras);
  return root;
}

// ---------------------------------------------------------------- inspect
async function runInspect(dry, forward = false) {
  const body = { prompt: $("in-prompt").value, content: $("in-content").value || null, purpose: $("in-purpose").value || null,
    policy: $("in-policy").value, session_id: $("in-session").value || null, dry_run: dry, forward, confirm: forward };
  const out = $("inspect-out");
  if (!body.prompt.trim()) return clear(out, el("p", { class: "err" }, t("app.in.empty")));
  try {
    const d = await api("/api/v1/evaluate", body);
    clear(out, renderDecision(d, body.prompt, body.content || "", { forwarded: forward }));
  } catch (e) { clear(out, el("p", { class: "err" }, e.message)); }
}
$("btn-eval").addEventListener("click", () => runInspect(false));
$("btn-dry").addEventListener("click", () => runInspect(true));
$("btn-send").addEventListener("click", async (ev) => {
  const b = ev.currentTarget; b.disabled = true; const label = b.textContent; b.textContent = t("app.in.wait");
  await runInspect(false, true); b.disabled = false; b.textContent = label;
});

// ---------------------------------------------------------------- exposure
function timeline(history, pol, N) {
  const W = 640, H = 220, L = 56, R = 20, T = 16, B = 34;
  const n = Math.max(history.length, 2);
  const x = (i) => L + ((W - L - R) * i) / (n - 1);
  const y = (k) => T + (H - T - B) * (1 - Math.log10(Math.max(k, 0.5) / 0.5) / Math.log10(N / 0.5));
  const ns = "http://www.w3.org/2000/svg";
  const s = (tg, a, txt) => { const e = document.createElementNS(ns, tg); for (const [k, v] of Object.entries(a)) e.setAttribute(k, v); if (txt !== undefined) e.textContent = txt; return e; };
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, width: "100%", role: "img", "aria-label": t("app.x.aria"), direction: "ltr" });
  [1, 10, 100, 1000, N].forEach((k) => { svg.append(s("line", { x1: L, x2: W - R, y1: y(k), y2: y(k), stroke: "#1c2c4d" }), s("text", { x: L - 6, y: y(k) + 4, "text-anchor": "end", "font-size": 11, fill: "#8296b8" }, k.toLocaleString(numLocale()))); });
  [[pol.k_warn, "#fbbf24", t("app.x.warn", { k: pol.k_warn })], [pol.k_min, "#f87171", t("app.x.floor", { k: pol.k_min })]].forEach(([k, c, l]) => { svg.append(s("line", { x1: L, x2: W - R, y1: y(k), y2: y(k), stroke: c, "stroke-dasharray": "5 4" }), s("text", { x: L + 6, y: y(k) - 4, "text-anchor": "start", "font-size": 11, fill: c }, l)); });
  const pts = history.map((h, i) => `${x(i)},${y(h.k)}`).join(" ");
  svg.append(s("polyline", { points: pts, fill: "none", stroke: "#48d6ff", "stroke-width": 2.5 }));
  history.forEach((h, i) => {
    const c = { BLOCK: "#f87171", GENERALIZE: "#60a5fa", WARN: "#fbbf24", ALLOW: "#34d399" }[h.decision] || "#48d6ff";
    svg.append(s("circle", { cx: x(i), cy: y(h.k), r: 6, fill: c }), s("text", { x: x(i), y: H - 12, "text-anchor": "middle", "font-size": 11, fill: "#8296b8" }, t("app.x.turn", { n: h.turn })),
      s("text", { x: x(i), y: y(h.k) - 11, "text-anchor": "middle", "font-size": 11.5, "font-weight": 700, fill: "#e7efff" }, `${fmt(h.k)}`));
  });
  return svg;
}
async function loadExposure() {
  const id = $("ex-session").value.trim();
  if (!id) return;
  const snap = await api(`/api/v1/sessions/${encodeURIComponent(id)}`);
  const out = $("exposure-out");
  if (!snap.exists || !snap.subjects.length) return clear(out, el("p", { class: "muted" }, t("app.ex.empty")));
  const pol = CONFIG.policies[CONFIG.default_policy].exposure;
  clear(out, ...snap.subjects.map((sub) => el("div", { class: "card" },
    el("h3", { dir: "auto" }, t("app.ex.sub", { label: sub.label, active: sub.active ? t("app.ex.active") : "", k: fmt(sub.k), N: snap.population.toLocaleString(numLocale()), b: fmt(sub.bits, 2), B: fmt(snap.budget_bits, 2) })),
    sub.history.length ? timeline(sub.history, pol, snap.population) : null,
    el("div", { class: "table-wrap" }, table(cols("app.x.cols2"), sub.contributions.map((a) => [a.attribute, `${a.value} (${a.level})`, `${fmt(100 * a.share, 2)}%`, fmt(a.bits, 2), a.turn]))),
    el("p", { class: "small muted" }, t("app.ex.foot", { k: sub.k_exact ?? "-", m: Math.round(snap.expires_in_s / 60) })))));
}
$("btn-ex").addEventListener("click", loadExposure);
$("btn-ex-reset").addEventListener("click", async () => { await api(`/api/v1/sessions/${encodeURIComponent($("ex-session").value)}/reset`, {}); loadExposure(); });

// ---------------------------------------------------------------- simulate
function simCard(name, d) {
  return el("div", { class: "card" }, el("div", { class: "step-head" }, el("h3", {}, CONFIG.policies[name].label), tag(d.action)),
    el("p", { class: "small muted", dir: "auto" }, CONFIG.policies[name].description),
    d.action === "BLOCK" ? el("div", { class: "out blocked" }, t("app.si.blocked")) : el("div", { class: "out", dir: "auto" }, d.minimized_prompt),
    el("ul", { class: "small" }, ...d.fired_rules.map((r) => el("li", {}, `${r.rule_id} → ${r.action}: ${r.description}`))),
    d.counterfactual && d.counterfactual.steps.length ? el("p", { class: "small" }, t("app.si.lower") + d.counterfactual.steps.join("; ")) : null);
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
  if ($("scenarios").dataset.lang === LANG && $("scenarios").children.length) return; // keep results already on screen
  $("scenarios").dataset.lang = LANG;
  clear($("scenarios"), ...SCENARIOS.scenarios.map((sc) => {
    const out = el("div", { class: "steps" });
    const btn = el("button", { class: "primary", onclick: () => runScenario(sc, out, btn) }, t("app.de.run"));
    return el("div", { class: "card scenario" }, el("div", { class: "step-head" }, el("h3", { dir: "auto" }, sc.title), btn), sc.note ? el("p", { class: "muted", dir: "auto" }, sc.note) : null,
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
      out.append(el("h3", {}, t("app.de.step", { n: i + 1 })), renderDecision(d, st.prompt, st.content || ""));
    }
    if (sc.session) {
      const snap = await api(`/api/v1/sessions/${encodeURIComponent(sc.session)}`);
      const sub = snap.subjects.find((s) => s.history.length);
      if (sub) out.append(el("div", { class: "card" }, el("h3", {}, t("app.de.timeline")), timeline(sub.history, CONFIG.policies[CONFIG.default_policy].exposure, snap.population)));
    }
  } catch (e) { out.append(el("p", { class: "err" }, e.message)); }
  btn.disabled = false;
}

// ---------------------------------------------------------------- policies
async function loadPolicies() {
  const types = ["person_name", "age", "gender", "city", "nationality", "department", "job_title", "join_year", "money_amount", "salary", "date", "project_codename", "email", "phone"];
  const rows = Object.entries(CONFIG.purposes).map(([k, p]) => [p.label, ...types.map((ty) => p.needs[ty] || "remove")]);
  clear($("contracts"), el("div", { class: "table-wrap" }, table([t("app.po.purpose"), ...types.map((ty) => CONFIG.entity_types[ty].label)], rows)));
  const load = async () => { const r = await api(`/api/v1/policies/${$("pol-pick").value}/source`); $("pol-src").textContent = r.yaml; };
  $("pol-pick").onchange = load; load();
}

// ---------------------------------------------------------------- audit
async function loadAudit() {
  const r = await api("/api/v1/audit?limit=100");
  clear($("audit-out"), r.rows.length ? table(cols("app.au.cols"),
    r.rows.map((x) => [new Date(x.ts * 1000).toLocaleTimeString(numLocale()), tag(x.action), x.policy, x.purpose,
      Object.entries(x.finding_types || {}).map(([ty, n]) => `${ty}×${n}`).join(" "), (x.rules || []).join(" "), fmt(x.injection_score, 2),
      x.exposure_status === "not_tracked" ? "-" : fmt(x.k_estimate), fmt(x.latency_ms, 2), x.demo ? "demo" : ""])) : el("p", { class: "muted" }, t("app.au.empty")));
}
$("btn-audit").addEventListener("click", loadAudit);

// ---------------------------------------------------------------- evaluation
async function loadEval() {
  const r = await api("/api/v1/eval/latest");
  const out = $("eval-out");
  if (!r.available) return clear(out, el("p", { class: "muted" }, r.message));
  const ci = (m) => (m.ci ? ` [${fmt(m.ci[0] * (m.pct ? 100 : 1), 1)}–${fmt(m.ci[1] * (m.pct ? 100 : 1), 1)}]` : "");
  const val = (m) => (m.pct ? `${fmt(m.value * 100, 1)}%` : `${fmt(m.value, 3)}${m.unit ? " " + m.unit : ""}`);
  clear(out, el("p", { class: "small muted" }, t("app.ev.gen", { d: r.generated_at, v: r.version, m: r.machine || "" })),
    LANG === "ar" ? el("p", { class: "small muted" }, t("app.ev.note")) : null,
    ...r.sections.map((s) => el("div", { class: "card", dir: "ltr", lang: "en" }, el("h3", {}, s.title), s.description ? el("p", { class: "muted small" }, s.description) : null,
      ...(s.metrics || []).map((m) => el("div", { class: "metric" }, el("span", {}, `${m.label}${m.n ? ` (n=${m.n})` : ""}`), el("b", {}, val(m) + ci(m)))),
      ...(s.tables || []).map((tb) => el("div", { class: "table-wrap" }, el("h4", {}, tb.title), table(tb.columns, tb.rows))),
      ...(s.notes || []).map((n) => el("p", { class: "small muted" }, n)))));
}

// ---------------------------------------------------------------- language switch
onLangChange(() => {
  if (!CONFIG) return;
  modelStatus();
  $("pop-name").textContent = t("app.ex.pop", { name: CONFIG.population.name, n: CONFIG.population.size.toLocaleString(numLocale()) });
  document.title = LANG === "ar" ? "درع | العرض الحي" : "AEGIS | Live demo";
  show(CURRENT, false);
});
if (LANG === "ar") document.title = "درع | العرض الحي";

init().catch((e) => document.body.prepend(el("p", { class: "err" }, t("app.fail", { e: e.message }))));
