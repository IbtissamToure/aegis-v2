"""Generalization ladders: for every entity type, an ordered list of disclosure
levels from most revealing ("exact") to least ("remove").

Each level has two meanings that must stay consistent:
  * ``render``: the text that replaces the value in the prompt, and
  * ``coarse_value``: the value the receiver can still infer, used by the
    identifiability ledger to measure what actually left the organization.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Optional

from aegis.detection import lexicons as L
from aegis.models import Finding
from aegis.text import has_arabic, normalize

LADDERS: dict[str, list[str]] = {
    "age": ["exact", "band_5", "band_10", "life_stage", "remove"],
    "date": ["exact", "month", "quarter", "year", "remove"],
    "date_of_birth": ["exact", "year", "decade", "remove"],
    "city": ["exact", "region", "country", "remove"],
    "money_amount": ["exact", "range", "magnitude", "remove"],
    "salary": ["exact", "range", "magnitude", "remove"],
    "person_name": ["exact", "pseudonym", "role", "remove"],
    "department": ["exact", "function", "remove"],
    "job_title": ["exact", "level", "remove"],
    "nationality": ["exact", "group", "remove"],
    "gender": ["exact", "remove"],
    "join_year": ["exact", "range", "remove"],
    "email": ["exact", "domain", "remove"],
    "phone": ["exact", "masked", "remove"],
    "national_id": ["exact", "masked", "remove"],
    "passport": ["exact", "remove"],
    "iban": ["exact", "masked", "remove"],
    "payment_card": ["exact", "masked", "remove"],
    "address": ["exact", "remove"],
    "project_codename": ["exact", "pseudonym", "remove"],
    "internal_host": ["exact", "remove"],
    "api_key": ["exact", "remove"],
    "password": ["exact", "remove"],
    "private_key": ["exact", "remove"],
    "connection_string": ["exact", "remove"],
    "confidential_marker": ["exact"],
    "business_sensitive": ["exact"],
}

PLACEHOLDER = {
    "age": ("[AGE]", "[العمر]"), "date": ("[DATE]", "[التاريخ]"), "date_of_birth": ("[DATE_OF_BIRTH]", "[تاريخ الميلاد]"),
    "city": ("[LOCATION]", "[الموقع]"), "money_amount": ("[AMOUNT]", "[المبلغ]"), "salary": ("[SALARY]", "[الراتب]"),
    "person_name": ("[NAME]", "[الاسم]"), "department": ("[DEPARTMENT]", "[القسم]"), "job_title": ("[JOB_TITLE]", "[المسمى]"),
    "nationality": ("[NATIONALITY]", "[الجنسية]"), "gender": ("[GENDER]", "[الجنس]"), "join_year": ("[YEAR]", "[السنة]"),
    "email": ("[EMAIL]", "[البريد]"), "phone": ("[PHONE]", "[الجوال]"), "national_id": ("[NATIONAL_ID]", "[رقم الهوية]"),
    "passport": ("[PASSPORT]", "[الجواز]"), "iban": ("[IBAN]", "[الآيبان]"), "payment_card": ("[CARD]", "[البطاقة]"),
    "address": ("[ADDRESS]", "[العنوان]"), "project_codename": ("[PROJECT]", "[المشروع]"),
    "internal_host": ("[INTERNAL_HOST]", "[خادم داخلي]"), "api_key": ("[SECRET]", "[مفتاح سري]"),
    "password": ("[PASSWORD]", "[كلمة المرور]"), "private_key": ("[PRIVATE_KEY]", "[مفتاح خاص]"),
    "connection_string": ("[CONNECTION_STRING]", "[رابط قاعدة بيانات]"),
}

_AR_MONTHS = ["يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو", "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر"]
_EN_MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
_AR_QUARTERS = ["الربع الأول", "الربع الثاني", "الربع الثالث", "الربع الرابع"]
_NAT_GROUP = {"gcc": ("GCC", "خليجي"), "arab": ("Arab", "عربي"), "asian": ("Asian", "آسيوي"), "western": ("Western", "غربي")}
_LEVEL = {"staff": ("staff-level employee", "موظف"), "management": ("manager-level employee", "موظف بمستوى إداري"),
          "executive": ("senior executive", "قيادي")}
_FUNCTION = {"corporate": ("corporate function", "إدارة مساندة"), "technology": ("technology function", "إدارة تقنية"),
             "commercial": ("commercial function", "إدارة تجارية"), "operations": ("operations function", "إدارة تشغيلية")}
_MONEY_EDGES = [0, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 250_000, 500_000, 1_000_000, 5_000_000, 10_000_000, 50_000_000,
                100_000_000, 1_000_000_000, 10 ** 13]


def levels_for(entity_type: str) -> list[str]:
    return LADDERS.get(entity_type, ["exact", "remove"])


def level_index(entity_type: str, level: str) -> int:
    lv = levels_for(entity_type)
    if level in lv:
        return lv.index(level)
    return len(lv) - 1  # unknown level -> most private


def more_private(entity_type: str, a: str, b: str) -> str:
    return a if level_index(entity_type, a) >= level_index(entity_type, b) else b


@dataclass
class PseudonymRegistry:
    """Consistent pseudonyms within a session. Stores labels keyed by a hash, not names."""

    people: dict[str, str] = field(default_factory=dict)
    projects: dict[str, str] = field(default_factory=dict)

    def person(self, key_hash: str) -> str:
        if key_hash not in self.people:
            self.people[key_hash] = f"PERSON_{len(self.people) + 1}"
        return self.people[key_hash]

    def project(self, key_hash: str) -> str:
        if key_hash not in self.projects:
            self.projects[key_hash] = f"PROJECT_{chr(ord('A') + len(self.projects) % 26)}"
        return self.projects[key_hash]


def _ar_prefix(text: str) -> str:
    """Proclitic letters attached to an Arabic lexicon word (e.g. 'ب' in 'بالرياض')."""
    t = normalize(text).text.strip()
    if t.startswith("ال"):
        return ""
    m = re.match(r"^([وف]?[بك]?)ال", t)
    if m and m.group(1):
        return m.group(1)
    m = re.match(r"^([وف]?)لل", t)
    if m:
        return m.group(1) + "ل"
    for n in (2, 1):
        if len(t) > n and all(c in "وفبكل" for c in t[:n]) and _is_known_ar(t[n:]):
            return t[:n]
    return ""


_KNOWN_AR = None


def _is_known_ar(word: str) -> bool:
    global _KNOWN_AR
    if _KNOWN_AR is None:
        _KNOWN_AR = {normalize(a).text for tbl in (L.CITIES, L.DEPARTMENTS) for _, _, ar in tbl.values() for a in ar}
    return word in _KNOWN_AR


def _attach_ar(prefix: str, label: str) -> str:
    if not prefix:
        return label
    if prefix.endswith("ل") and label.startswith("ال"):
        return prefix[:-1] + "لل" + label[2:]
    return prefix + label


def _money_bucket(v: float) -> tuple[float, float]:
    for lo, hi in zip(_MONEY_EDGES, _MONEY_EDGES[1:]):
        if lo <= v < hi:
            return lo, hi
    return _MONEY_EDGES[-2], _MONEY_EDGES[-1]


def _fmt_money(v: float) -> str:
    if v >= 1_000_000_000:
        return f"{v / 1e9:g}B"
    if v >= 1_000_000:
        return f"{v / 1e6:g}M"
    if v >= 1_000:
        return f"{v / 1e3:g}K"
    return f"{v:g}"


def _currency(text: str) -> str:
    t = text.upper()
    for cur, label in (("USD", "USD"), ("$", "USD"), ("€", "EUR"), ("EUR", "EUR"), ("£", "GBP"), ("AED", "AED"), ("دولار", "USD")):
        if cur in t or cur in text:
            return label
    return "SAR"


def coarse_value(entity_type: str, value: Optional[str], level: str) -> Optional[str]:
    """What the receiver can still learn about this attribute at ``level`` (None = nothing)."""
    if value is None or level == "remove":
        return None
    if level == "exact":
        return value
    try:
        if entity_type == "age":
            a = int(value)
            if level == "band_5":
                return f"{a // 5 * 5}-{a // 5 * 5 + 4}"
            if level == "band_10":
                return f"{a // 10 * 10}-{a // 10 * 10 + 9}"
            if level == "life_stage":
                return "under25" if a < 25 else ("25-44" if a < 45 else ("45-59" if a < 60 else "60plus"))
        if entity_type == "city":
            if level == "region":
                return L.CITIES[value][0] if value in L.CITIES else None
            return None
        if entity_type == "department" and level == "function":
            return L.DEPARTMENTS[value][0] if value in L.DEPARTMENTS else None
        if entity_type == "job_title" and level == "level":
            return L.JOB_TITLES[value][0] if value in L.JOB_TITLES else None
        if entity_type == "nationality" and level == "group":
            return L.NATIONALITIES[value][0] if value in L.NATIONALITIES else None
        if entity_type == "join_year" and level == "range":
            y = int(value)
            return f"{y // 5 * 5}-{y // 5 * 5 + 4}"
    except (ValueError, KeyError):
        return None
    return None  # pseudonym/role/masked/etc. reveal no population attribute


def render(f: Finding, level: str, pseudo: PseudonymRegistry, key_hash: str, context: Optional[str] = None) -> str:
    """Replacement text for finding ``f`` at disclosure ``level``.

    Language follows the value itself, or (for digits/codes) the surrounding text.
    """
    ar = has_arabic(f.text) or (context is not None and has_arabic(context))
    t = f.type
    v = f.value_norm
    if level == "exact":
        return f.text
    if level == "remove":
        en, arl = PLACEHOLDER.get(t, ("[REDACTED]", "[محذوف]"))
        return arl if ar else en
    try:
        if t == "age":
            a = int(v)
            if level in ("band_5", "band_10"):
                w = 5 if level == "band_5" else 10
                lo = a // w * w
                return f"{lo}–{lo + w - 1}"
            if level == "life_stage":
                stage = coarse_value("age", v, "life_stage")
                labels = {"under25": ("under 25", "أقل من 25"), "25-44": ("25–44", "25–44"), "45-59": ("45–59", "45–59"), "60plus": ("60+", "60+")}
                return labels[stage][1 if ar else 0]
        if t in ("date", "date_of_birth") and v:
            y, m, _ = (int(x) for x in v.split("-"))
            if level == "month":
                return f"{_AR_MONTHS[m - 1]} {y}" if ar else f"{_EN_MONTHS[m - 1]} {y}"
            if level == "quarter":
                q = (m - 1) // 3
                return f"{_AR_QUARTERS[q]} {y}" if ar else f"Q{q + 1} {y}"
            if level == "year":
                return str(y)
            if level == "decade":
                return f"{y // 10 * 10}s" if not ar else f"عقد {y // 10 * 10}"
        if t == "city":
            if level == "region" and v in L.CITIES:
                en, arl = L.REGION_LABELS[L.CITIES[v][0]]
                return _attach_ar(_ar_prefix(f.text), arl) if ar else f"the {en}"
            if level == "country":
                return _attach_ar(_ar_prefix(f.text), "المملكة") if ar else "Saudi Arabia"
        if t in ("money_amount", "salary") and v:
            val = float(v)
            if level == "range":
                lo, hi = _money_bucket(val)
                cur = _currency(f.text)
                return f"{_fmt_money(lo)}–{_fmt_money(hi)} {'ريال' if ar and cur == 'SAR' else cur}" if ar else f"{cur} {_fmt_money(lo)}–{_fmt_money(hi)}"
            if level == "magnitude":
                digits = len(str(int(val))) if val >= 1 else 1
                return f"مبلغ من {digits} خانات" if ar else f"a {digits}-figure amount"
        if t == "person_name":
            if level == "pseudonym":
                return f"[{pseudo.person(key_hash)}]"
            if level == "role":
                return "شخص" if ar else "a person"
        if t == "department" and level == "function" and v in L.DEPARTMENTS:
            en, arl = _FUNCTION[L.DEPARTMENTS[v][0]]
            return _attach_ar(_ar_prefix(f.text), arl) if ar else f"a {en}"
        if t == "job_title" and level == "level" and v in L.JOB_TITLES:
            en, arl = _LEVEL[L.JOB_TITLES[v][0]]
            if ar and normalize(f.text).text.strip().endswith(("ة", "ه")):  # keep Arabic gender agreement
                arl = {"موظف": "موظفة", "موظف بمستوى إداري": "موظفة بمستوى إداري", "قيادي": "قيادية"}.get(arl, arl)
            return arl if ar else en
        if t == "nationality" and level == "group" and v in L.NATIONALITIES:
            en, arl = _NAT_GROUP[L.NATIONALITIES[v][0]]
            return arl if ar else en
        if t == "join_year" and level == "range":
            y = int(v)
            return f"{y // 5 * 5}–{y // 5 * 5 + 4}"
        if t == "email" and level == "domain":
            return "[user]@" + f.text.split("@", 1)[1]
        if t in ("phone", "national_id", "iban", "payment_card") and level == "masked":
            digits = re.sub(r"\W", "", f.text)
            tail = digits[-4:] if t != "phone" else digits[-3:]
            label = {"phone": ("phone ending", "جوال ينتهي بـ"), "national_id": ("ID ending", "هوية تنتهي بـ"),
                     "iban": ("IBAN ending", "آيبان ينتهي بـ"), "payment_card": ("card ending", "بطاقة تنتهي بـ")}[t]
            return f"[{label[1 if ar else 0]} {tail}]"
        if t == "project_codename" and level == "pseudonym":
            return f"[{pseudo.project(key_hash)}]"
    except (ValueError, TypeError, KeyError, IndexError):
        pass
    # Level not applicable to this value -> fall back to the placeholder (never leak)
    en, arl = PLACEHOLDER.get(t, ("[REDACTED]", "[محذوف]"))
    return arl if ar else en


def bits_hint(entity_type: str) -> float:
    """Rough fallback surprisal (bits) for tracked attributes without population stats."""
    return {"age": 5.0, "city": 2.0, "department": 4.0, "job_title": 3.0, "nationality": 2.0, "gender": 1.0,
            "join_year": 4.0, "project_codename": 7.0}.get(entity_type, math.log2(10))
