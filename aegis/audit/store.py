"""Content-free audit log (SQLite).

Stored per decision: decision metadata, rule IDs, entity TYPES and COUNTS, keyed
hashes (HMAC-SHA256, truncated) of detected values, exposure numbers, latency.
Never stored: prompt text, content text, detected values, names, outputs.
Retention is enforced by ``purge`` (called on startup and by the API).
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
  request_id TEXT PRIMARY KEY,
  ts REAL NOT NULL,
  session_hash TEXT,
  policy TEXT, purpose TEXT, purpose_confidence REAL,
  action TEXT, severity TEXT,
  injection_score REAL, injection_families TEXT,
  exposure_status TEXT, k_estimate REAL, bits REAL,
  finding_types TEXT, value_hashes TEXT,
  rules TEXT, principles TEXT, changes INTEGER,
  destination TEXT, processing TEXT, latency_ms REAL, demo INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ts ON decisions(ts);
"""


class AuditStore:
    def __init__(self, path: str | Path, retention_days: float = 30):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.executescript(SCHEMA)
        self.purge()

    def record(self, row: dict[str, Any]) -> None:
        cols = ["request_id", "ts", "session_hash", "policy", "purpose", "purpose_confidence", "action", "severity", "injection_score",
                "injection_families", "exposure_status", "k_estimate", "bits", "finding_types", "value_hashes", "rules", "principles",
                "changes", "destination", "processing", "latency_ms", "demo"]
        vals = [json.dumps(row[c], ensure_ascii=False) if isinstance(row.get(c), (list, dict)) else row.get(c) for c in cols]
        with self._lock:
            self._db.execute(f"INSERT OR REPLACE INTO decisions ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", vals)
            self._db.commit()

    def recent(self, limit: int = 50) -> list[dict]:
        with self._lock:
            cur = self._db.execute("SELECT * FROM decisions ORDER BY ts DESC LIMIT ?", (min(int(limit), 500),))
            names = [d[0] for d in cur.description]
            rows = [dict(zip(names, r)) for r in cur.fetchall()]
        for r in rows:
            for k in ("injection_families", "finding_types", "value_hashes", "rules", "principles"):
                if r.get(k):
                    r[k] = json.loads(r[k])
        return rows

    def stats(self) -> dict:
        rows = self.recent(500)
        actions = Counter(r["action"] for r in rows)
        types: Counter = Counter()
        for r in rows:
            for t, n in (r.get("finding_types") or {}).items():
                types[t] += n
        rules = Counter(rid for r in rows for rid in (r.get("rules") or []))
        policies = Counter(r["policy"] for r in rows)
        lat = sorted(r["latency_ms"] for r in rows if r.get("latency_ms") is not None)
        return {
            "total": len(rows),
            "actions": {a: actions.get(a, 0) for a in ("ALLOW", "WARN", "GENERALIZE", "BLOCK")},
            "top_types": types.most_common(10),
            "top_rules": rules.most_common(8),
            "policies": dict(policies),
            "injection_detected": sum(1 for r in rows if (r.get("injection_score") or 0) >= 0.5),
            "exposure_interventions": sum(1 for r in rows if r.get("exposure_status") in ("warn", "generalized", "blocked")),
            "latency_p50_ms": lat[len(lat) // 2] if lat else None,
            "latency_p95_ms": lat[min(len(lat) - 1, int(len(lat) * 0.95))] if lat else None,
            "demo_rows": sum(1 for r in rows if r.get("demo")),
            "window": "last 500 decisions",
        }

    def purge(self, retention_days: Optional[float] = None) -> int:
        days = self.retention_days if retention_days is None else retention_days
        cutoff = time.time() - days * 86400
        with self._lock:
            n = self._db.execute("DELETE FROM decisions WHERE ts < ?", (cutoff,)).rowcount
            self._db.commit()
        return n

    def clear(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM decisions")
            self._db.commit()
