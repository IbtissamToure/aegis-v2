"""Identifiability ledger: cumulative exposure across prompts in a session.

For every person a session talks about ("subject"), the ledger keeps the most
specific value of each quasi-identifier that has actually LEFT the organization
(after generalization). Before a new prompt is sent, Aegis computes how many
people would still match if it were sent. If the anonymity set falls below the
policy floor, Aegis generalizes the new prompt's attributes (one ladder step at
a time, largest information first) or blocks, depending on policy.

What is stored: attribute names, coarse values and keyed hashes, in memory only,
expiring after a configurable TTL. Raw prompts and names are never stored.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import math
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from aegis.detection.types import TRACKED_ATTRIBUTES
from aegis.exposure.population import Population
from aegis.generalization.ladders import LADDERS, PseudonymRegistry, coarse_value, level_index
from aegis.models import Finding
from aegis.text import normalize

PERSON_CUE = re.compile(
    r"\b(?:employee|colleague|co-?worker|staff member|person|someone|he|she|him|her|his|manager|boss|teammate|supervisor|subordinate|"
    r"candidate|applicant|intern|they work|who works|this guy|this lady|the same person)\b|"
    r"(?:موظف|موظفة|زميل|زميلة|زميلي|زميلتي|شخص|مديري|مديرتي|هو |هي |يعمل|تعمل|المتدرب|المتدربة|نفس الشخص|نفس الموظف)", re.I)
NEW_SUBJECT_CUE = re.compile(r"\b(?:another|a different|a second|other)\s+(?:employee|colleague|person|staff member|manager)\b|"
                             r"(?:موظف اخر|موظفة اخرى|زميل اخر|زميلة اخرى|شخص اخر)", re.I)
REFERENCE_CUE = re.compile(r"\b(?:he|she|him|her|his|they|the same (?:person|employee|colleague)|this (?:employee|colleague|person))\b|"
                           r"(?:هو|هي|نفس الشخص|نفس الموظف|نفس الزميل|هذا الموظف|هذه الموظفة|يعمل|تعمل)|"
                           # Arabic third-person forms: pronoun suffixes (عمرها، مقره) and feminine past verbs (انضمت، التحقت)
                           r"(?<![\u0621-\u064a])[\u0621-\u064a]{2,}(?:ها|ه)(?![\u0621-\u064a])|(?:انضمت|التحقت|عملت|انتقلت|ترقت)", re.I)


@dataclass
class Disclosure:
    attr: str
    entity_type: str
    level: str
    value: str  # coarse value (e.g. "jeddah", "30-34"), never a name or ID
    turn: int


@dataclass
class Subject:
    key: str
    label: str
    disclosures: dict[str, Disclosure] = field(default_factory=dict)
    history: list[dict] = field(default_factory=list)
    direct_identifier: bool = False


@dataclass
class Session:
    key: str
    created: float
    last_seen: float
    turn: int = 0
    subjects: dict[str, Subject] = field(default_factory=dict)
    active: Optional[str] = None
    pseudonyms: PseudonymRegistry = field(default_factory=PseudonymRegistry)


class ExposureEngine:
    def __init__(self, population: Population, secret: bytes, mode: str = "estimate", ttl_minutes: float = 240):
        self.pop = population
        self.secret = secret
        self.mode = mode
        self.ttl = ttl_minutes * 60
        self.sessions: dict[str, Session] = {}

    # ----------------------------------------------------------- sessions
    def _hash(self, s: str) -> str:
        return hmac.new(self.secret, s.encode(), hashlib.sha256).hexdigest()[:16]

    def session(self, session_id: Optional[str], ephemeral: bool = False) -> Session:
        """Return the session; with ``ephemeral`` a private copy that is never stored (dry runs)."""
        self._expire()
        key = self._hash("session|" + (session_id or "anonymous"))
        now = time.time()
        if ephemeral:
            existing = self.sessions.get(key)
            return copy.deepcopy(existing) if existing else Session(key=key, created=now, last_seen=now)
        if key not in self.sessions:
            self.sessions[key] = Session(key=key, created=now, last_seen=now)
        s = self.sessions[key]
        s.last_seen = now
        return s

    def reset(self, session_id: str) -> bool:
        key = self._hash("session|" + session_id)
        return self.sessions.pop(key, None) is not None

    def _expire(self) -> None:
        now = time.time()
        for k in [k for k, s in self.sessions.items() if now - s.last_seen > self.ttl]:
            del self.sessions[k]

    # ------------------------------------------------------------ linking
    def link_subject(self, session: Session, prompt: str, findings: list[Finding]) -> tuple[Optional[str], str]:
        """Decide which person (if any) the tracked attributes in this prompt describe."""
        text = normalize(prompt).text
        names = [f for f in findings if f.type == "person_name" and f.segment == "prompt"]
        tracked = [f for f in findings if f.type in TRACKED_ATTRIBUTES and f.segment == "prompt"]
        if not tracked and not names:
            return None, "no quasi-identifiers about a person"
        if names:
            key = self._hash("person|" + (names[0].value_norm or names[0].text).lower())
            if key not in session.subjects:
                session.subjects[key] = Subject(key=key, label=f"Subject {len(session.subjects) + 1}")
            session.active = key
            return key, "named person"
        if NEW_SUBJECT_CUE.search(text):
            key = self._hash(f"anon|{session.key}|{session.turn}")
            session.subjects[key] = Subject(key=key, label=f"Subject {len(session.subjects) + 1}")
            session.active = key
            return key, "new person introduced"
        if session.active and (REFERENCE_CUE.search(text) or PERSON_CUE.search(text)):
            return session.active, "continues the same person"
        if session.active and tracked:
            # Conservative default: details following a person, with no new subject introduced, are counted
            # against that person rather than silently dropped.
            return session.active, "assumed to continue the same person (no new person introduced)"
        if PERSON_CUE.search(text):
            key = self._hash(f"anon|{session.key}|{session.turn}")
            session.subjects[key] = Subject(key=key, label=f"Subject {len(session.subjects) + 1}")
            session.active = key
            return key, "unnamed person described"
        return None, "attributes describe the organization, not a person"

    # ---------------------------------------------------------- measuring
    def _merged(self, subject: Optional[Subject], proposal: list[tuple[Finding, str]], turn: int) -> dict[str, Disclosure]:
        merged = dict(subject.disclosures) if subject else {}
        for f, level in proposal:
            attr = TRACKED_ATTRIBUTES.get(f.type)
            if not attr or f.confidence < 0.45:
                continue
            value = coarse_value(f.type, f.value_norm, level)
            if value is None:
                continue
            old = merged.get(attr)
            if old is None or level_index(f.type, level) < level_index(f.type, old.level):
                merged[attr] = Disclosure(attr, f.type, level, value, turn)
        return merged

    def measure(self, disclosures: dict[str, Disclosure], with_exact: bool = True) -> dict:
        contributions = []
        bits = 0.0
        for d in disclosures.values():
            b = self.pop.bits(d.attr, d.level, d.value)
            bits += b
            contributions.append({"attribute": d.attr, "level": d.level, "value": d.value, "bits": round(b, 2), "turn": d.turn,
                                  "share": round(self.pop.probability(d.attr, d.level, d.value), 4)})
        k_est = self.pop.N * 2 ** (-bits)
        need_exact = (with_exact or self.mode == "exact") and self.pop.rows
        exact = self.pop.exact_k({d.attr: (d.level, d.value) for d in disclosures.values()}) if need_exact else None
        if self.mode == "exact" and exact is not None:
            k_used = float(max(exact, 0))
            bits_used = math.log2(self.pop.N / max(exact, 1))
        else:
            k_used, bits_used = k_est, bits
        contributions.sort(key=lambda c: -c["bits"])
        return {"bits": round(bits_used, 3), "bits_independent": round(bits, 3), "k": k_used, "k_estimate": round(k_est, 3),
                "k_exact": exact, "contributions": contributions}

    def assess(self, session: Session, subject_key: Optional[str], proposal: list[tuple[Finding, str]],
               with_exact: bool = True) -> tuple[dict, dict]:
        subj = session.subjects.get(subject_key) if subject_key else None
        before = self.measure(dict(subj.disclosures) if subj else {}, with_exact)
        after = self.measure(self._merged(subj, proposal, session.turn + 1), with_exact)
        return before, after

    def plan_generalization(self, session: Session, subject_key: str, proposal: list[tuple[Finding, str]],
                            k_floor: float) -> tuple[list[tuple[Finding, str]], dict, bool]:
        """Coarsen this prompt's tracked attributes until k >= k_floor (greedy, largest bit reduction first)."""
        plan = list(proposal)
        _, after = self.assess(session, subject_key, plan)
        while after["k"] < k_floor:
            best = None
            for i, (f, lv) in enumerate(plan):
                if f.type not in TRACKED_ATTRIBUTES:
                    continue
                ladder = LADDERS[f.type]
                idx = level_index(f.type, lv)
                if idx >= len(ladder) - 1:
                    continue
                trial = list(plan)
                trial[i] = (f, ladder[idx + 1])
                _, t_after = self.assess(session, subject_key, trial, with_exact=False)
                gain = t_after["bits"] - after["bits"]
                if best is None or gain < best[0]:
                    best = (gain, trial, t_after)
            if best is None:
                return plan, self.assess(session, subject_key, plan)[1], False
            _, plan, after = best
        return plan, self.assess(session, subject_key, plan)[1], True

    def commit(self, session: Session, subject_key: Optional[str], sent: list[tuple[Finding, str]], after: dict, decision: str) -> None:
        session.turn += 1
        if not subject_key:
            return
        subj = session.subjects[subject_key]
        subj.disclosures = self._merged(subj, sent, session.turn)
        if any(f.type == "person_name" and lv == "exact" for f, lv in sent):
            subj.direct_identifier = True
        subj.history.append({"turn": session.turn, "bits": after["bits"], "k": round(after["k"], 3), "k_exact": after["k_exact"],
                             "decision": decision, "attributes": sorted(subj.disclosures)})

    def snapshot(self, session_id: str) -> dict:
        key = self._hash("session|" + session_id)
        s = self.sessions.get(key)
        if not s:
            return {"exists": False, "subjects": [], "population": self.pop.N, "budget_bits": round(self.pop.budget_bits, 2)}
        subjects = []
        for subj in s.subjects.values():
            m = self.measure(subj.disclosures)
            subjects.append({"label": subj.label, "active": subj.key == s.active, "bits": m["bits"], "k": round(m["k"], 3),
                             "k_exact": m["k_exact"], "contributions": m["contributions"], "history": subj.history,
                             "direct_identifier": subj.direct_identifier})
        return {"exists": True, "turns": s.turn, "subjects": subjects, "population": self.pop.N, "budget_bits": round(self.pop.budget_bits, 2),
                "mode": self.mode, "expires_in_s": int(self.ttl - (time.time() - s.last_seen))}
