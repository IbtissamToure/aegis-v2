# Aegis architecture

```
 Dashboard ─┐   AI agent (MCP) ─┐   Any app (REST) ─┐
            ▼                   ▼                   ▼
 ┌─────────────────────── Aegis gateway (local, FastAPI) ───────────────────────┐
 │ 1 Injection screen → 2 Detection (EN/AR) → 3 Purpose resolver                 │
 │                                              ↓                                │
 │ 6 Generalizer ← 5 Policy engine (YAML) ← 4 Identifiability ledger             │
 └───────┬──────────────────────┬──────────────────────────────┬────────────────┘
         ▼                      ▼                              ▲
  Model provider        Audit log (SQLite,              Config (YAML): policies,
  (none / local Ollama;  metadata + keyed hashes)        purpose contracts, population
   external opt-in)
```

## Request flow (`aegis/gateway.py`)

| Step | Module | What it does | Deterministic |
|---|---|---|---|
| 1 | `injection/detector.py` | Signature families (override, role hijack, prompt extraction, guardrail bypass, exfiltration, indirect markers) on normalized + de-obfuscated text; noisy-OR score; content segment weighted as indirect | yes |
| 2 | `detection/` | Validators (Saudi ID/Iqama check digit, IBAN mod-97, Luhn, secret entropy), bilingual lexicons with Arabic clitics, structural name rules (Al-/nisba), CSV header typing, context cues | yes |
| 3 | `purpose.py` | Keyword evidence → purpose contract; optional local LLM picks from a closed list only when rules are unsure | rules: yes |
| 4 | `policy/engine.py` | Ordered YAML rules over findings + request context → fired rules, per-finding disclosure level | yes |
| 5 | `exposure/` | Links the prompt to a subject in the session; computes bits disclosed and people still matching; coarsens this prompt's attributes (greedy, one ladder step at a time) to keep ≥ k | yes |
| 6 | `generalization/` | Renders each finding at its level (EN/AR), consistent pseudonyms, grammar-safe junctions | yes |
| 7 | `llm/providers.py` | Optional: forwards the minimized prompt to a model | n/a |
| 8 | `audit/store.py` | Writes metadata only | yes |

## Identifiability model

For subject *s* with disclosed attribute values *A* (after generalization):

    I(A) = Σ −log₂ p(a)          bits disclosed (p from frequency tables)
    k̂   = N · 2^−I(A)           estimated people still matching
    budget = log₂ N              (N = 5,000 → 12.3 bits)

Policy floor *k_min* is enforced as `k̂ ≥ k_min × safety_factor` (safety factor 2 in balanced/strict, chosen on the
dev set because independence makes the estimate optimistic in ~28% of cases). `exact` mode counts rows in a local
directory instead.

Subject linking: a name → that person; "another employee" → new subject; pronouns, Arabic third-person forms or any
tracked detail after a person was introduced → same subject (conservative default); organization-level facts without
a person cue are not tracked.

## Security boundaries

* Prompt text, attached content and tool output are **untrusted data**; Aegis never executes or obeys them.
* The optional LLM sees the request as quoted data and can only return one key from a closed enum.
* API: Pydantic validation with size limits, generic error messages (no echo, no stack traces), localhost bind,
  strict CSP (`default-src 'self'`, no inline script), dashboard renders all user text with `textContent`.
* Storage: audit log has no raw values (enforced by `tests/test_api_security.py`); ledger keeps coarse attribute
  values in memory only, with TTL; secrets via environment or a 0600 key file; `.env` git-ignored.

## Configuration

* `config/policies/*.yaml`, rules, actions, levels, exposure floor, PDPL principle per rule
* `config/purposes.yaml`, disclosure contracts
* `config/org_terms.yaml`, internal project registry
* `config/population/synthetic_directory.csv`, reference population (synthetic; regenerate with `scripts/generate_directory.py`)
