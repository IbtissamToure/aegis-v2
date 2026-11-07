"""Purpose contracts and the text generalizer."""
from __future__ import annotations

import hashlib
import re
import hmac
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from aegis.generalization.ladders import LADDERS, PseudonymRegistry, coarse_value, level_index, render
from aegis.models import Change, Finding
from aegis.text import mask_preview


@dataclass
class Contract:
    key: str
    label: str
    description: str
    keywords_en: list[str]
    keywords_ar: list[str]
    needs: dict[str, str]

    def allowed_level(self, entity_type: str) -> str:
        """Most revealing level this purpose may see for ``entity_type``."""
        if entity_type not in LADDERS:
            return "remove"
        lv = LADDERS[entity_type]
        if lv == ["exact"]:
            return "exact"  # markers are not transformable; policy decides WARN/BLOCK
        want = self.needs.get(entity_type, "remove")
        return want if want in lv else "remove"

    def requires_exact(self, entity_type: str) -> bool:
        return self.allowed_level(entity_type) == "exact"


def load_contracts(path: str | Path) -> tuple[dict[str, Contract], str]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    out = {}
    for key, p in data["purposes"].items():
        kw = p.get("keywords") or {}
        out[key] = Contract(key, p.get("label", key), p.get("description", ""), list(kw.get("en") or []), list(kw.get("ar") or []),
                            dict(p.get("needs") or {}))
    return out, data.get("default_purpose", "general")


def value_key(secret: bytes, f: Finding) -> str:
    """Keyed hash of a value: lets Aegis recognize repeats without storing the value."""
    base = (f.value_norm or f.text).strip().lower()
    return hmac.new(secret, f"{f.type}|{base}".encode(), hashlib.sha256).hexdigest()[:16]


def apply(text: str, segment: str, findings: list[Finding], levels: dict[str, str], reasons: dict[str, str],
          pseudo: PseudonymRegistry, secret: bytes) -> tuple[str, list[Change]]:
    """Replace each finding in ``text`` by its rendering at the chosen level (right to left)."""
    changes: list[Change] = []
    out = text
    for f in sorted((f for f in findings if f.segment == segment), key=lambda f: f.start, reverse=True):
        level = levels.get(f.id, "exact")
        if level == "exact":
            continue
        window = text[max(0, f.start - 25):f.end + 25]
        rep = render(f, level, pseudo, value_key(secret, f), context=window)
        before = out[: f.start]
        # keep English grammar intact at the junction: "the a corporate function" -> "the corporate function"
        if re.search(r"\b(?:the|a|an|our|their|his|her|its)\s+$", before, re.I):
            rep = re.sub(r"^(?:a|an|the)\s+", "", rep)
        out = before + rep + out[f.end:]
        changes.append(Change(finding_id=f.id, type=f.type, segment=segment, original_preview=mask_preview(f.text),
                              replacement=rep, level=level, reason=reasons.get(f.id, "")))
    changes.reverse()
    return out, changes


def disclosed_value(f: Finding, level: str) -> Optional[str]:
    return coarse_value(f.type, f.value_norm, level)


def stricter(entity_type: str, a: Optional[str], b: Optional[str]) -> str:
    if a is None:
        return b or "exact"
    if b is None:
        return a
    return a if level_index(entity_type, a) >= level_index(entity_type, b) else b
