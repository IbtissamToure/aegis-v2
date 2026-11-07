"""Population model for measuring identifiability.

Two ways to answer "how many people match what has been disclosed?":

* ``estimate`` (default) uses only per-attribute frequency tables (marginals):
      I(A) = sum_a -log2 p(a)          (bits disclosed)
      k_est = N * 2^-I(A)              (estimated anonymity set)
  This assumes attributes are independent. Correlated attributes (e.g. age and
  seniority) make the true k larger than estimated, so the estimate errs on the
  side of protection. The evaluation measures this error against exact counts.

* ``exact`` counts matching rows in a directory the organization holds locally.
"""
from __future__ import annotations

import csv
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

from aegis.detection.types import TRACKED_ATTRIBUTES
from aegis.generalization.ladders import LADDERS, coarse_value

ATTR_TO_TYPE = {v: k for k, v in TRACKED_ATTRIBUTES.items()}


class Population:
    def __init__(self, rows: list[dict[str, str]], name: str = "population"):
        self.name = name
        self.rows = rows
        self.N = len(rows)
        # counts[attr][level][value]
        self.counts: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
        self._row_coarse: list[dict[tuple[str, str], Optional[str]]] = []
        for r in rows:
            rc = {}
            for attr, etype in ATTR_TO_TYPE.items():
                raw = r.get(attr) or None
                for level in LADDERS[etype]:
                    if level == "remove":
                        continue
                    cv = coarse_value(etype, raw, level) if raw else None
                    rc[(attr, level)] = cv
                    if cv is not None:
                        self.counts[attr][level][cv] += 1
            self._row_coarse.append(rc)

    @classmethod
    def from_csv(cls, path: str | Path) -> "Population":
        with open(path, encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        return cls(rows, name=Path(path).stem)

    def probability(self, attr: str, level: str, value: str) -> float:
        c = self.counts.get(attr, {}).get(level, Counter()).get(value, 0)
        # Unseen values are treated as very rare (half a person): conservative.
        return max(c, 0.5) / self.N

    def bits(self, attr: str, level: str, value: Optional[str]) -> float:
        if value is None:
            return 0.0
        return -math.log2(self.probability(attr, level, value))

    def exact_k(self, disclosed: dict[str, tuple[str, str]]) -> int:
        """Count of people matching every (attr -> (level, value)) disclosed."""
        if not disclosed:
            return self.N
        items = [((a, lv), v) for a, (lv, v) in disclosed.items() if v is not None]
        return sum(1 for rc in self._row_coarse if all(rc.get(k) == v for k, v in items))

    @property
    def budget_bits(self) -> float:
        return math.log2(self.N)
