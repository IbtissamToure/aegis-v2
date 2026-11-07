# Status and limitations

| Capability | Implemented | Unit/integration tested | Experimentally evaluated | Notes |
|---|---|---|---|---|
| Bilingual sensitive-data detection | yes | yes | yes (§1) | synthetic, template-generated text |
| Purpose contracts + generalization ladders | yes | yes | yes (§3) | 7 purposes |
| Identifiability budget (cumulative exposure) | yes | yes | yes (§4, §5) | synthetic 5,000-person directory |
| Policy engine, 3 policies, counterfactual | yes | yes | yes (§7) | |
| Prompt-injection detection | yes | yes | yes (§6) | 2 external benchmarks + own set |
| Content-free audit log, retention | yes | yes (security test) | - | |
| REST API + dashboard | yes | yes | - | |
| MCP server (official SDK, stdio) | yes | yes (end-to-end) | - | advisory, see below |
| Local LLM provider (Ollama) | yes | no live test | no | optional; never decides |
| External LLM provider | yes (off by default) | no | no | |
| Arabic NER model | interface only (`NERPlugin`) | - | no | Hugging Face unreachable from the build environment |
| Proxy enforcement for agents | no | - | - | planned |

## Known limitations

1. **Synthetic evaluation data.** Detection, minimization and session datasets are generated from templates by the
   same team that built the detector. The test split uses fresh seeds and unseen names, but real employee text is
   messier; the 99% detection figure should be read as an upper bound. The first run on the dev split (before
   structural name rules) found only 19% recall on unseen names, that error drove the fix.
2. **Independence assumption.** The estimate treats attributes as independent; it is conservative in 72% of cases
   and the safety factor compensates. Correlated attributes in a real organization should be measured.
3. **Subject linking is heuristic.** One active person per session; paraphrased references across many prompts or
   two people discussed alternately can be mis-linked.
4. **Prompt injection is not solved.** Recall is 56% on held-out in-the-wild jailbreaks and 4% on BIPIA task-style
   indirect attacks (instructions with no override wording). Aegis does not claim complete protection.
5. **Dataset label mismatch.** The jailbreak dataset labels "Ignore all previous instructions…" SEO templates as
   regular; Aegis flags them by design, which counts as false positives.
6. **MCP is advisory.** An agent decides whether to call the tool; mandatory enforcement needs Aegis in the request path.
7. **Purpose recognition** uses keywords; ambiguous requests fall back to the conservative `general` contract.
8. **PDPL.** Rules are mapped to PDPL principles (purpose limitation, minimization, Art. 11); this is alignment, not
   certified compliance.
