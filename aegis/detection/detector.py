"""Detection engine: runs recognizers (+ optional NER plug-ins + table headers),
resolves overlaps and returns ``Finding`` objects with original-text offsets."""
from __future__ import annotations

import csv
import io
import re
from typing import Iterable, Optional, Protocol

from aegis.detection import lexicons as L
from aegis.detection.recognizers import CITY, DEPT, NATION, TITLE, Candidate, recognize
from aegis.detection.types import ENTITY_TYPES, TRACKED_ATTRIBUTES
from aegis.models import Finding
from aegis.text import normalize


class NERPlugin(Protocol):
    """Optional model-based recognizer (e.g. an Arabic NER model).

    ``predict`` receives normalized text and returns Candidates. Plug-ins only
    add evidence; they never remove pattern/validator findings.
    """

    name: str

    def predict(self, text: str) -> list[Candidate]: ...


_HEADER_KEYS = {normalize(k).text.strip().lower(): v for k, v in L.HEADER_TYPES.items()}


def _lookup(matcher, value: str) -> Optional[str]:
    for key, s, e in matcher.find(value):
        return key
    return None


def _tabular(nt_text: str) -> list[Candidate]:
    """If the text contains a CSV/TSV block with recognizable headers, type each cell by its column."""
    out: list[Candidate] = []
    lines = nt_text.split("\n")
    i = 0
    while i < len(lines) - 1:
        line = lines[i]
        delim = "," if line.count(",") >= 1 else ("\t" if line.count("\t") >= 1 else None)
        if not delim:
            i += 1
            continue
        headers = [h.strip().lower() for h in next(csv.reader([line], delimiter=delim))]
        types = [_HEADER_KEYS.get(h) for h in headers]
        if not any(types):
            i += 1
            continue
        offset = sum(len(l) + 1 for l in lines[: i + 1])
        j = i + 1
        while j < len(lines) and lines[j].count(delim) == line.count(delim) and lines[j].strip():
            row = lines[j]
            pos = 0
            for col, cell in enumerate(row.split(delim)):
                typ = types[col] if col < len(types) else None
                raw = cell.strip()
                if typ and raw and raw.lower() not in {"n/a", "na", "-", "null"}:
                    lead = len(cell) - len(cell.lstrip())
                    s = offset + pos + lead
                    e = s + len(raw)
                    value = _cell_value(typ, raw)
                    out.append(Candidate(typ, s, e, 0.9, "tabular:header", f"Cell in column '{headers[col]}'", value))
                pos += len(cell) + 1
            offset += len(row) + 1
            j += 1
        i = j
    return out


def _cell_value(typ: str, raw: str) -> Optional[str]:
    if typ == "city":
        return _lookup(CITY, raw) or raw.lower()
    if typ == "department":
        return _lookup(DEPT, raw) or raw.lower()
    if typ == "job_title":
        return _lookup(TITLE, raw) or raw.lower()
    if typ == "nationality":
        return _lookup(NATION, raw) or raw.lower()
    if typ == "gender":
        r = raw.lower()
        return "female" if r in {"f", "female", "woman", "انثى", "انثي", "امراة"} else ("male" if r in {"m", "male", "man", "ذكر", "رجل"} else r)
    if typ in {"age", "join_year"}:
        m = re.search(r"\d+", raw)
        return m.group(0) if m else None
    if typ in {"money_amount", "salary"}:
        m = re.search(r"[\d,]+(?:\.\d+)?", raw)
        return m.group(0).replace(",", "") if m else None
    if typ == "person_name":
        return raw.lower()
    return raw


class Detector:
    def __init__(self, codenames: Optional[dict] = None, plugins: Iterable[NERPlugin] = (), min_confidence: float = 0.4):
        """``codenames``: alias -> canonical project key (from config/org_terms.yaml)."""
        self.codenames = {normalize(k).text.lower(): v for k, v in (codenames or {}).items()}
        self.plugins = list(plugins)
        self.min_confidence = min_confidence

    def detect(self, text: str, segment: str = "prompt", start_id: int = 1) -> list[Finding]:
        if not text:
            return []
        nt = normalize(text)
        cands = recognize(nt, self.codenames)
        cands += _tabular(nt.text)
        for p in self.plugins:
            try:
                cands += p.predict(nt.text)
            except Exception:  # a broken plug-in must never break detection
                continue
        cands = [c for c in cands if c.confidence >= self.min_confidence and c.type in ENTITY_TYPES]
        kept = _resolve_overlaps(cands)
        findings = []
        for n, c in enumerate(sorted(kept, key=lambda c: c.start)):
            s, e = nt.span(c.start, c.end)
            info = ENTITY_TYPES[c.type]
            findings.append(Finding(
                id=f"{segment[0]}{start_id + n}", type=c.type, category=info["category"], segment=segment,
                start=s, end=e, text=text[s:e], confidence=round(c.confidence, 3), severity=info["severity"],
                detector=c.detector, evidence=c.evidence, attribute=TRACKED_ATTRIBUTES.get(c.type), value_norm=c.value_norm,
            ))
        return findings


_PRIORITY_DETECTORS = ("tabular:", "validator:")


def _resolve_overlaps(cands: list[Candidate]) -> list[Candidate]:
    """Keep the most specific candidate when spans overlap.

    Order: tabular/validator evidence first, then severity, then span length, then confidence.
    """
    def key(c: Candidate):
        prio = 1 if c.detector.startswith(_PRIORITY_DETECTORS) else 0
        return (-prio, -ENTITY_TYPES[c.type]["severity"].rank, -(c.end - c.start), -c.confidence)

    kept: list[Candidate] = []
    for c in sorted(cands, key=key):
        if all(c.end <= k.start or c.start >= k.end for k in kept):
            kept.append(c)
    return kept
