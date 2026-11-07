"""Generate the SYNTHETIC 5,000-person organization directory used by the
identifiability model and its evaluation.

No real people: every row is sampled from fixed distributions with a fixed seed,
so the file is reproducible. Correlations are intentional (age with seniority,
joining year with age, engineer titles in technology units) so that the
independence assumption of the estimator is tested against realistic data.

Usage:  python scripts/generate_directory.py
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

SEED = 20261107
N = 5000
OUT = Path(__file__).resolve().parents[1] / "config" / "population" / "synthetic_directory.csv"

DEPTS = {"operations": 14, "customer_service": 13, "sales": 11, "it": 9, "logistics": 8, "finance": 7, "marketing": 6, "hr": 5,
         "procurement": 4, "cybersecurity": 3, "data_ai": 3, "rnd": 2.5, "legal": 2, "internal_audit": 2, "compliance": 2, "strategy": 1.5}
TECH = {"it", "cybersecurity", "data_ai", "rnd"}
CITIES = {"riyadh": 50, "jeddah": 18, "dammam": 10, "khobar": 5, "makkah": 3, "madinah": 3, "abha": 2, "buraidah": 2, "tabuk": 1.5,
          "jazan": 1.5, "hail": 1, "taif": 1, "jubail": 1, "dhahran": 0.5, "ahsa": 0.5, "najran": 0.5, "alula": 0.3, "neom": 0.2}
TITLES_STAFF = {"analyst": 22, "specialist": 27, "senior_specialist": 13, "intern": 4}
TITLES_TECH = {"engineer": 30, "senior_engineer": 14, "analyst": 10, "specialist": 8, "intern": 4}
TITLES_MGMT = {"team_lead": 8, "manager": 7, "senior_manager": 4, "director": 2.5, "vp": 0.8, "chief": 0.2}
NATS = {"saudi": 72, "egyptian": 6, "indian": 6, "pakistani": 3, "filipino": 3, "jordanian": 3, "sudanese": 2, "yemeni": 1.5,
        "syrian": 1.5, "british": 1, "american": 1}
PROJECTS = ["falcon", "najm", "sahab", "rimal", "wadi", "qimma", "noor", "oasis", "atlas", "horizon", "mirage", "sadeem", "tuwaiq",
            "hejaz", "asir", "zahra", "bayan", "thuraya", "shams", "hilal", "nakheel", "jazeera", "marjan", "yasmin", "dhow", "sarab",
            "majd", "raed", "wafra", "rawdah", "tamr", "faris", "sanad", "afaq", "nebras", "ruya", "sahil", "barq", "ghaith", "mizan"]
AGE_BY_TITLE = {"intern": (22, 1.5), "analyst": (28, 4), "specialist": (31, 5), "engineer": (29, 4), "senior_specialist": (37, 5),
                "senior_engineer": (35, 5), "team_lead": (37, 5), "manager": (41, 6), "senior_manager": (45, 6), "director": (48, 6),
                "vp": (52, 5), "chief": (55, 5)}


def pick(rng, table):
    keys = list(table)
    return rng.choices(keys, weights=[table[k] for k in keys])[0]


def main() -> None:
    rng = random.Random(SEED)
    sizes = [max(4, int(150 / (i + 1) ** 0.9)) for i in range(len(PROJECTS))]
    rows = []
    for i in range(N):
        dept = pick(rng, DEPTS)
        is_mgmt = rng.random() < 0.2
        title = pick(rng, TITLES_MGMT if is_mgmt else (TITLES_TECH if dept in TECH else TITLES_STAFF))
        mu, sd = AGE_BY_TITLE[title]
        age = int(min(64, max(20, round(rng.gauss(mu, sd)))))
        female_p = {"hr": 0.6, "marketing": 0.5, "customer_service": 0.5, "data_ai": 0.45}.get(dept, 0.33)
        gender = "female" if rng.random() < female_p else "male"
        nat = pick(rng, NATS)
        tenure = rng.randint(0, max(0, min(age - 21, 25)))
        join_year = 2026 - tenure
        city = pick(rng, CITIES)
        project = ""
        if rng.random() < 0.7:
            project = rng.choices(PROJECTS, weights=sizes)[0]
        rows.append({"emp_id": f"SYN-{i + 1:05d}", "department": dept, "job_title": title, "city": city, "age": age, "gender": gender,
                     "nationality": nat, "join_year": join_year, "project": project})
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} synthetic employees to {OUT}")


if __name__ == "__main__":
    main()
