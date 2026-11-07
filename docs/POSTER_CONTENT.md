# Poster content — Aegis (SAIF 2026, official template order)

Every number below is produced by `python -m eval.run` (eval/reports/latest.json, generated on the test split).
Figures: `eval/reports/figures/` (300 dpi). UI screenshots: `eval/reports/screenshots/` (2×).
All personal data shown or used is synthetic.

---

## Title

**AEGIS: Purpose-Bound Data Minimization and Cumulative Identifiability Control for Enterprise Generative-AI Use**

Tagline: *Your AI. Your Data. Your Control.*

---

## 1 · Introduction

- Employees paste customer records, HR cases, code and credentials into external AI tools ("shadow AI").
- Existing AI-DLP tools ask **"Is this data sensitive?"** and check **one prompt at a time** — so they either block useful work or let it through.
- Two gaps: (1) the same field can be necessary for one task and excessive for another; (2) details that are harmless one prompt at a time can **add up to one person** across a conversation.
- **Objective:** a local gateway that sends only what each task needs, and stops a conversation before it identifies someone — with deterministic, auditable decisions aligned with Saudi PDPL purpose limitation and data minimization (Art. 11).

## 2 · Methodology

Use the architecture diagram (docs/ARCHITECTURE.md) — six stages, rules decide, LLM optional:

1. **Injection screen** — direct and indirect (attached content), English/Arabic, de-obfuscation (base64, spaced letters, leetspeak).
2. **Detection** — checksum validators (Saudi ID/Iqama, IBAN mod-97, Luhn), bilingual lexicons with Arabic clitics, structural name rules, CSV header typing.
3. **Purpose contract** — per task, the least revealing form of each data type (e.g. age → 5-year band, city → region, name → pseudonym, ID → removed). YAML, owned by the DPO.
4. **Policy engine** — YAML rules → ALLOW / WARN / GENERALIZE / BLOCK with rationale and counterfactual ("smallest change that would allow this").
5. **Identifiability budget** — bits disclosed per person across the session:
   `I = Σ −log₂ p(attribute)`, `people still matching ≈ N · 2^−I`. If fewer than *k* (= 5) would match, Aegis coarsens the new details one step at a time, or blocks.
6. **Generalization** — rewrites the prompt (EN/AR); audit log stores metadata and keyed hashes only.

**Evaluation protocol:** synthetic 5,000-employee directory; dev/test split (dev used for error analysis only; test uses fresh seeds and unseen names); two public external benchmarks; 95% Wilson confidence intervals; ablations against baselines.

## 3 · Results (test split)

| What we measured | Result |
|---|---|
| Identifying multi-prompt sessions protected — **with identifiability budget** | **96.9%** [92.4–98.8], n = 130 |
| …same sessions, purpose minimization only (budget off) | 60.8% [52.2–68.7] |
| …no protection | 0% |
| Identifying sessions where **no single prompt** looks identifying | 99.2% [95.8–99.9] |
| Non-identifying sessions where the budget intervened (cost) | 10.9% [6.3–18.1], n = 110 |
| Unnecessary personal values leaked — Aegis | **0.0%** [0–1.2], n = 315 |
| Task-needed facts kept — Aegis vs. redact-everything | **100%** [98.5–100] vs. 0%, n = 255 |
| Sensitive-data detection, 20 types, EN/AR/mixed (synthetic) | P 97.9%, R 99.4%, F1 0.987 (n = 715) |
| Names never seen by the system | 94.7% recall [87.2–97.9] |
| Estimator vs. exact counts (frequency tables only) | Spearman ρ = 0.99; finds 97.0% of "fewer than 5" cases |
| Policy decisions repeatable / as specified | 100% / 100% (36 runs) |
| End-to-end latency, no model, on the M1 | p50 3.3 ms, p95 8.9 ms |
| Prompt injection — held-out in-the-wild jailbreaks | 56.1% detected [52.9–59.3], n = 905; 17.9% of benign flagged* |
| Prompt injection — team Arabic/English set | 90.0% detected, 3.3% false alarms (n = 30 + 30) |

\* The public dataset labels "Ignore all previous instructions…" templates as benign; Aegis flags them by design. Excluding them: 11.9%.

**Figures to place:** `fig_cumulative_example.png` (hero), `fig_budget_ablation.png`, `fig_privacy_utility.png`;
screenshots `ui_necessity_demographic.png` + `ui_policy_simulator.png` (prototype evidence).

Caption for the hero figure: *Four harmless prompts about a Logistics employee (age 35, Jeddah, joined 2024). As written they leave 1 matching person; Aegis sends "30–39", "Western Region" and drops the year — 23 people still match.*

## 4 · Innovation

- **Necessity, not sensitivity:** purpose contracts choose the *least revealing form* a task needs — 100% of needed facts kept where blanket redaction keeps 0%.
- **Memory across prompts:** an identifiability budget measured in bits, enforced at the gateway — raises protection of identifying conversations from 61% to 97%.
- **Auditable by design:** deterministic YAML policy, counterfactual explanations, content-free audit log; LLM optional and never decides.
- **Local and bilingual:** runs offline on an 8 GB laptop; Arabic and Saudi identifiers built in.

| | Typical AI-DLP | Research (AirGapAgent) | **Aegis** |
|---|---|---|---|
| Decides by | sensitivity | LLM judgment | **purpose contract (auditable)** |
| Across prompts | no | no | **identifiability budget** |
| Arabic / Saudi IDs | limited | no | **yes** |

## 5 · Conclusion

Aegis is a working, tested prototype (REST API, dashboard, MCP server; 29 automated tests). On held-out synthetic sessions it protected 97% of conversations that would otherwise identify an employee, while keeping every fact the task needed and leaking no unnecessary personal value. It can be deployed today as a local gateway in pilot settings.

## 6 · Future Work & References

**Future work**
1. Pilot with real (consented) organizational text and an HR directory to replace synthetic data and calibrate the estimator — 3 months.
2. Model-based prompt-injection and Arabic NER detectors behind the existing plug-in interface, to raise held-out injection recall above 56%.
3. Inline proxy enforcement for AI agents (MCP is advisory today).

**References (behind the QR code)**
1. Bagdasarian et al., *AirGapAgent: Protecting Privacy-Conscious Conversational Agents*, ACM CCS 2024. arXiv:2405.05175
2. *Privacy in Action: Towards Realistic Privacy Mitigation and Evaluation for LLM-Powered Agents* (PrivacyChecker), arXiv:2509.17488
3. Shen et al., *"Do Anything Now": Characterizing and Evaluating In-The-Wild Jailbreak Prompts on LLMs*, ACM CCS 2024 (dataset: github.com/verazuo/jailbreak_llms)
4. Yi et al., *Benchmarking and Defending Against Indirect Prompt Injection Attacks on LLMs* (BIPIA, github.com/microsoft/BIPIA)
5. Sweeney, *k-Anonymity: A Model for Protecting Privacy*, IJUFKS 10(5), 2002
6. Saudi Personal Data Protection Law (PDPL), SDAIA — purpose limitation and data minimization, Art. 11
7. Source code and evaluation: github repository / Google Drive link

**Limitations to state if asked:** synthetic, template-generated data; independence assumption (mitigated by a safety factor chosen on dev data); heuristic subject linking; prompt injection is not solved (4% on BIPIA task-style attacks).
