"""Extract the external prompt-injection test sets used by the evaluation.

Sources (both MIT-licensed, cloned from GitHub):
  * verazuo/jailbreak_llms — in-the-wild jailbreak and regular prompts (CCS'24 "Do Anything Now")
      dev  = 2023-05-07 release (used while developing signatures)
      test = prompts first appearing in the 2023-12-25 release (held out, never used for tuning)
  * microsoft/BIPIA — indirect prompt injection benchmark (email task, text attacks, test split)

Usage: python -m eval.prepare_external /path/to/jailbreak_llms /path/to/BIPIA
"""
import csv
import json
import random
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "external"
csv.field_size_limit(10 ** 9)


def load(p):
    with open(p, encoding="utf-8") as fh:
        return [r["prompt"] for r in csv.DictReader(fh)]


def main(jb_root, bipia_root):
    P = Path(jb_root) / "data" / "prompts"
    jb_old, jb_new = load(P / "jailbreak_prompts_2023_05_07.csv"), load(P / "jailbreak_prompts_2023_12_25.csv")
    rg_old, rg_new = load(P / "regular_prompts_2023_05_07.csv"), load(P / "regular_prompts_2023_12_25.csv")
    rng = random.Random(42)
    old_jb, old_rg = set(jb_old), set(rg_old)
    test_pos = sorted({p for p in jb_new if p not in old_jb})
    test_neg = sorted({p for p in rg_new if p not in old_rg} - set(jb_new))
    dev_pos = sorted(set(jb_old))
    dev_neg = sorted(set(rg_old) - set(jb_old))
    OUT.mkdir(exist_ok=True)

    def dump(name, pos, neg):
        with (OUT / name).open("w", encoding="utf-8") as fh:
            for p in pos:
                fh.write(json.dumps({"prompt": p, "label": 1}, ensure_ascii=False) + "\n")
            for p in neg:
                fh.write(json.dumps({"prompt": p, "label": 0}, ensure_ascii=False) + "\n")
        print(name, len(pos), len(neg))

    dump("jailbreak_test.jsonl", test_pos, rng.sample(test_neg, 1500))
    dump("jailbreak_dev.jsonl", dev_pos, rng.sample(dev_neg, 1500))
    B = Path(bipia_root) / "benchmark"
    attacks = json.load(open(B / "text_attack_test.json", encoding="utf-8"))
    emails = [json.loads(l) for l in open(B / "email" / "test.jsonl", encoding="utf-8")]
    with (OUT / "bipia_email_test.jsonl").open("w", encoding="utf-8") as fh:
        for cat, items in attacks.items():
            for a in items:
                e = rng.choice(emails)
                pos = rng.choice(["start", "middle", "end"])
                ctx = e["context"]
                if pos == "start":
                    content = a + "\n" + ctx
                elif pos == "end":
                    content = ctx + "\n" + a
                else:
                    mid = len(ctx) // 2
                    content = ctx[:mid] + "\n" + a + "\n" + ctx[mid:]
                fh.write(json.dumps({"prompt": e["question"], "content": content, "label": 1, "category": cat, "position": pos}, ensure_ascii=False) + "\n")
        for e in emails:
            fh.write(json.dumps({"prompt": e["question"], "content": e["context"], "label": 0}, ensure_ascii=False) + "\n")
    print("bipia written")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
