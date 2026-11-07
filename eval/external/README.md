# External evaluation data

Subsets of two public, MIT-licensed benchmarks, extracted by `eval/prepare_external.py`:

* `jailbreak_dev.jsonl`, `jailbreak_test.jsonl` — from **verazuo/jailbreak_llms** (Shen et al., "Do Anything Now":
  Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models, ACM CCS 2024).
  *dev* = 2023-05-07 release (used while writing signatures). *test* = prompts that first appear in the 2023-12-25
  release (held out). Regular prompts: random 1,500 per split (seed 42).
* `bipia_email_test.jsonl` — from **microsoft/BIPIA** (Yi et al., Benchmarking and Defending Against Indirect Prompt
  Injection Attacks on LLMs). Test text attacks inserted at start/middle/end of the test emails; clean emails as negatives.

Original licenses (MIT) apply to this data.
