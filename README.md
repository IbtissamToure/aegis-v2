# Aegis — Your AI. Your Data. Your Control.

Aegis is a local-first policy gateway between employees (or AI agents) and external AI models.
It decides **what an AI request needs to know**, and **remembers what has already been revealed**.

* **Necessity, not just sensitivity.** Each task purpose has a *disclosure contract* (YAML, owned by the
  data-protection officer) that states the least revealing form of each data type the task can work with:
  age → 5-year band, city → region, name → consistent pseudonym, ID → removed. Aegis rewrites the prompt
  to exactly that level instead of blocking or blanket-redacting.
* **Identifiability budget.** Aegis measures, across prompts in a session, how many people would still match
  what has left the organization (bits of information against a population model). When harmless-looking
  details add up to fewer than *k* people, it generalizes the new details or blocks.
* **Deterministic and auditable.** ALLOW / WARN / GENERALIZE / BLOCK comes from YAML rules, never from an LLM.
  The audit log stores metadata and keyed hashes only, never prompt text.
* Bilingual detection (English / Arabic / mixed), Saudi identifiers with checksum validation, credentials,
  prompt-injection screening (direct and indirect), a real MCP server, and a dashboard.

All personal data in this repository (directory, demo scenarios, datasets) is **synthetic**.

## Quick start (macOS, Apple M1, 8 GB — no Docker, no GPU, no model needed)

```bash
cd ~/Documents/aegis-v2
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                      # 29 tests
uvicorn api.server:app --port 8000       # dashboard: http://127.0.0.1:8000  ·  API docs: /api/docs
```

Open the dashboard → **Demo scenarios** → *Run* each scenario.

## Reproduce every number on the poster

```bash
python -m eval.run        # ~40 s → eval/reports/latest.json, EVALUATION_REPORT.md, figures/*.png
```

Datasets are versioned in `eval/datasets/` (synthetic, `_dev` used for error analysis, `_test` for reported results)
and `eval/external/` (subsets of two public MIT-licensed benchmarks; see `eval/external/README.md`).
To regenerate the synthetic data: `python -m eval.generate_datasets dev` and `... test`.

## MCP server

```bash
python -m mcp_server.server     # stdio
```

Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{ "mcpServers": { "aegis": { "command": "/Users/<you>/Documents/aegis-v2/.venv/bin/python",
                             "args": ["-m", "mcp_server.server"],
                             "cwd": "/Users/<you>/Documents/aegis-v2" } } }
```

Tools: `scan_prompt`, `evaluate_policy`, `generalize_sensitive_data`, `inspect_exposure_budget`,
`explain_security_decision`, `list_policies`. Integration test: `tests/test_mcp.py` (starts the server and calls it
with the official MCP client).

## Optional local model

Aegis needs no LLM. To let a local model break ties in purpose recognition and answer minimized prompts:

```bash
brew install ollama && ollama pull qwen3:1.7b     # ~1.4 GB, fits an 8 GB M1
export AEGIS_LLM_PROVIDER=ollama
```

External (hosted) providers are disabled unless `AEGIS_ALLOW_EXTERNAL_LLM=1`; only the minimized prompt is ever sent.

## Layout

```
aegis/            core engine
  detection/      validators, bilingual lexicons, structural name rules, table headers
  generalization/ ladders (exact → … → remove) and purpose contracts
  injection/      prompt-injection detector
  exposure/       population model + identifiability ledger
  policy/         YAML policy engine
  llm/            provider abstraction (none / Ollama / OpenAI-compatible)
  audit/          content-free SQLite audit log
  gateway.py      the end-to-end pipeline
api/              FastAPI server (+ serves the dashboard)
mcp_server/       MCP server (official SDK)
web/              dashboard (vanilla JS, strict CSP, no external assets)
config/           policies, purpose contracts, org registry, synthetic directory, demo scenarios
eval/             dataset generator, evaluation harness, reports
docs/             architecture, limitations, API, poster results
tests/            unit, integration, security tests
```

See `docs/ARCHITECTURE.md` and `docs/LIMITATIONS.md`.
