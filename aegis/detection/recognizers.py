"""Recognizers: each one returns candidate entities over normalized text.

Three kinds of evidence are combined, never regex alone:
  * validators (checksums: Saudi ID/Iqama, IBAN mod-97, Luhn, entropy for secrets)
  * lexicons (bilingual vocabularies with Arabic clitic handling)
  * context (cue words near a candidate raise or lower confidence, and can change
    its type, e.g. a money amount near "salary" becomes ``salary``)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from aegis.detection import lexicons as L
from aegis.detection.validators import (char_classes, iban_valid, luhn_valid, saudi_id_valid,
                                        shannon_entropy)
from aegis.text import NormText, normalize

AR = "\u0600-\u06ff"
AR_WORD = f"[{AR}]+"
_NOT_AR_BEFORE = f"(?<![{AR}A-Za-z0-9_])"
_NOT_AR_AFTER = f"(?![{AR}A-Za-z0-9_])"


@dataclass
class Candidate:
    type: str
    start: int  # normalized-text offsets
    end: int
    confidence: float
    detector: str
    evidence: str
    value_norm: Optional[str] = None


def _norm(s: str) -> str:
    return normalize(s).text


def _ar_alt(word: str) -> str:
    """Regex for an Arabic lexicon entry allowing common proclitics (و ف ب ك ل، ال)."""
    w = _norm(word)
    parts = w.split(" ")
    first, rest = parts[0], parts[1:]
    if first.startswith("ال") and len(first) > 3:
        core = re.escape(first[2:])
        head = f"(?:[وفبك]?ال|[وف]?لل){core}"
    else:
        head = f"(?:[وفبلك]{{1,2}})?{re.escape(first)}"
    tail = "".join(r"\s+" + re.escape(p) for p in rest)
    return head + tail


def _context(text: str, start: int, end: int, cues: Iterable[str], before: int = 40, after: int = 15) -> Optional[str]:
    window = text[max(0, start - before):start].lower() + " " + text[end:end + after].lower()
    for cue in cues:
        c = cue.lower()
        if re.search(r"(?<![a-z])" + re.escape(c) + r"(?![a-z])", window) if c.isascii() else c in window:
            return cue
    return None


class LexiconMatcher:
    """Compiles one regex per canonical key over English + Arabic aliases."""

    def __init__(self, table: dict[str, tuple], case_sensitive_en: Callable[[str], bool] = lambda a: False):
        self.patterns: list[tuple[str, re.Pattern]] = []
        for key, (_, en, ar) in table.items():
            alts_ci, alts_cs = [], []
            for a in sorted(en, key=len, reverse=True):
                pat = r"\s+".join(re.escape(p) for p in a.split())
                (alts_cs if case_sensitive_en(a) else alts_ci).append(pat)
            for a in sorted(ar, key=len, reverse=True):
                alts_ci.append(_ar_alt(a))
            if alts_ci:
                self.patterns.append((key, re.compile(_NOT_AR_BEFORE + "(?:" + "|".join(alts_ci) + ")" + _NOT_AR_AFTER, re.I)))
            if alts_cs:
                self.patterns.append((key, re.compile(_NOT_AR_BEFORE + "(?:" + "|".join(alts_cs) + ")" + _NOT_AR_AFTER)))

    def find(self, text: str):
        for key, pat in self.patterns:
            for m in pat.finditer(text):
                yield key, m.start(), m.end()


_SHORT_UPPER = lambda a: (a.isupper() and len(a) <= 4) or a in {"Hail", "Ops", "Legal", "Sales", "Strategy", "Compliance", "Marketing", "Operations", "Finance", "Logistics", "Analytics"}

CITY = LexiconMatcher(L.CITIES, case_sensitive_en=lambda a: a in {"Hail"})
DEPT = LexiconMatcher(L.DEPARTMENTS, case_sensitive_en=_SHORT_UPPER)
TITLE = LexiconMatcher(L.JOB_TITLES, case_sensitive_en=lambda a: a.isupper())
NATION = LexiconMatcher(L.NATIONALITIES)

_DEPT_GENERIC = re.compile(
    r"(?<![A-Za-z])(" + "|".join(sorted({re.escape(a.lower()) for _, en, _ in [v for v in L.DEPARTMENTS.values()] for a in en}, key=len, reverse=True))
    + r")\s+(?:department|team|division|unit|dept)\b", re.I)
_DEPT_ALIAS_TO_KEY = {a.lower(): k for k, (_, en, _) in L.DEPARTMENTS.items() for a in en}

# ---------------------------------------------------------------- patterns
EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}(?![\w-])")
PHONE_SA_RE = re.compile(r"(?<![\d+])(?:(?:\+|00)966[\s-]?5\d(?:[\s-]?\d){7}|05\d(?:[\s-]?\d){7}|(?:\+|00)966[\s-]?1\d(?:[\s-]?\d){6})(?!\d)")
PHONE_INTL_RE = re.compile(r"(?<![\w+])\+\d{1,3}(?:[\s-]?\d){7,12}(?!\d)")
NID_RE = re.compile(r"(?<!\d)[12]\d{9}(?!\d)")
IBAN_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?(?![A-Za-z0-9])")
CARD_RE = re.compile(r"(?<![\d-])(?:[3456]\d{3})(?:[ -]?\d{2,4}){3,4}(?![\d-])")
PASSPORT_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]\d{7,8}(?![A-Za-z0-9])")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----|$)")
CONN_RE = re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|mssql|sqlserver|jdbc:\w+)://[^\s:/@]+:[^\s@]+@[^\s'\"]+", re.I)
KNOWN_KEY_RES = [
    (re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), "anthropic_key"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}"), "openai_style_key"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key"),
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "aws_temp_key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "github_token"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "github_pat"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"), "slack_token"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "google_api_key"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"), "gitlab_token"),
    (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), "stripe_key"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "jwt"),
]
ASSIGNED_SECRET_RE = re.compile(
    r"(?:api[_\- ]?key|apikey|secret(?:[_\- ]?key)?|access[_\- ]?token|auth[_\- ]?token|token|bearer|client[_\- ]?secret|"
    r"مفتاح(?:\s+ال)?(?:api|واجهة)?|التوكن|الرمز السري)\s*(?:is|=|:|هو)?\s*['\"]?([A-Za-z0-9_\-\.\/+=]{16,})", re.I)
PASSWORD_RE = re.compile(
    r"(?:password|passwd|pwd|passcode|pass|كلمة المرور|كلمة السر|الباسورد|الرقم السري|كلمه المرور|كلمه السر)"
    r"\s*(?:is|was|=|:|هي|هو|كانت)?\s*['\"]?([^\s'\",;]{4,64})", re.I)
PRIVATE_IP_RE = re.compile(r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])")
INTERNAL_HOST_RE = re.compile(r"\b[a-z0-9][a-z0-9\-]*(?:\.[a-z0-9\-]+)*\.(?:internal|corp|local|lan|intranet|intra)\b", re.I)

_NUM = r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?"
_SCALE = r"(?:\s?(?:k|K|m|M|mn|million|millions|bn|billion|thousand|الف|مليون|مليار))?"
_CUR_BEFORE = r"(?:SAR|SR|USD|US\$|\$|€|EUR|GBP|£|AED)"
_CUR_AFTER = r"(?:SAR|SR|riyals?|Riyals?|USD|dollars?|EUR|euros?|AED|ريال(?:\s+سعودي)?|ر\.س|دولار|درهم|يورو)"
MONEY_RE = re.compile(rf"(?<![\w.]){_CUR_BEFORE}\s?(?:{_NUM}){_SCALE}(?![\w])|(?<![\w.,])(?:{_NUM}){_SCALE}\s?{_CUR_AFTER}(?![A-Za-z])")

_MONTHS_EN = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"]
_MONTHS_SHORT = [m[:3] for m in _MONTHS_EN]
_MONTHS_AR = ["يناير", "فبراير", "مارس", "ابريل", "مايو", "يونيو", "يوليو", "اغسطس", "سبتمبر", "اكتوبر", "نوفمبر", "ديسمبر"]
_MONTH_ALT = "|".join(_MONTHS_EN + _MONTHS_SHORT + _MONTHS_AR)
DATE_RES = [
    re.compile(r"(?<!\d)((?:19|20)\d{2})-(0?[1-9]|1[0-2])-(0?[1-9]|[12]\d|3[01])(?!\d)"),
    re.compile(r"(?<![\d/])(0?[1-9]|[12]\d|3[01])[/.-](0?[1-9]|1[0-2])[/.-]((?:19|20)\d{2})(?![\d/])"),
    re.compile(rf"(?<!\d)(0?[1-9]|[12]\d|3[01])\s+({_MONTH_ALT})\.?,?\s+((?:19|20)\d{{2}})(?!\d)", re.I),
    re.compile(rf"(?<![A-Za-z])({_MONTH_ALT})\.?\s+(0?[1-9]|[12]\d|3[01]),?\s+((?:19|20)\d{{2}})(?!\d)", re.I),
]
AGE_RES = [
    re.compile(r"(?<!\d)(\d{1,2})\s?(?:-\s?)?(?:years?|yrs?)(?:\s|-)old\b", re.I),
    re.compile(r"\baged\s+(\d{1,2})(?!\d)", re.I),
    re.compile(r"\bage\s*(?:is|of|:|=)?\s*(\d{1,2})(?!\d)", re.I),
    re.compile(r"(?:عمره|عمرها|عمري|العمر|عمر|يبلغ من العمر|تبلغ من العمر|بعمر|سنه|سنها)\s*:?\s*(\d{1,2})(?!\d)"),
    re.compile(r"(?<!\d)(\d{1,2})\s?(?:سنة|سنه|عاما|عام)\s+(?:من العمر)"),
]
JOIN_RES = [
    re.compile(r"\b(?:joined|hired|started|employed)(?:\s+\w+){0,3}?\s+(?:in|since)\s+((?:19|20)\d{2})\b", re.I),
    re.compile(r"\b(?:joined|hired)\s+((?:19|20)\d{2})\b", re.I),
    re.compile(r"(?:انضم|انضمت|التحق|التحقت|توظف|توظفت|يعمل منذ|تعمل منذ)\s*(?:الينا|للشركة|بالشركة)?\s*(?:في|عام|سنة|منذ)?\s*((?:19|20)\d{2})"),
]
PROJECT_EN_RE = re.compile(r"\b(?:Project|Program|Programme|Operation|Initiative)\s+([A-Z][A-Za-z0-9\-]{2,})")
PROJECT_AR_RE = re.compile(r"(?:مشروع|برنامج)\s+((?:ال)?[\u0621-\u064a]{3,})")
ADDRESS_RES = [
    re.compile(r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St\.?|Road|Rd\.?|Avenue|Ave\.?|Boulevard|Blvd\.?)(?![A-Za-z])"),
    re.compile(rf"(?:شارع|طريق)\s+[{AR}]+(?:\s+(?:بن|ابن|ال)?[{AR}]+)?"),
    re.compile(rf"(?<![{AR}])حي\s+(?:ال)?[{AR}]{{3,}}"),
    re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}\d{4}(?![A-Za-z0-9])"),  # Saudi short national address
]

_AR_STOP = set(_norm(w) for w in "في من الى على عن و او ثم الذي التي هذا هذه ذلك تلك هو هي قد لقد كان كانت يعمل تعمل مع بعد قبل عند لدى ان انه انها لم لن ما لا اي كل بين حتى".split())
_AR_AMBIGUOUS = set(_norm(w) for w in ["امل", "عادل", "منى", "بدر", "ريم", "جود", "شوق", "اثير", "هيا", "علي", "حسن", "صالح", "نور", "سامي", "هند", "رنا", "ماجد", "راكان", "حمد", "عبير", "وجدان", "بشاير", "لطيفة", "نايف", "مها", "دانة", "سلطان"])
_EN_AMBIGUOUS = {"Mark", "Will", "May", "Dana", "Hind", "Amal", "Ali", "Paul", "Sultan", "Juan", "Rim", "Nora"}
_EN_NOT_NAME = set(["The", "This", "That", "These", "Those", "In", "On", "At", "For", "From", "To", "And", "Or", "But", "Our", "My", "Your",
                    "His", "Her", "Their", "Please", "Can", "Could", "Would", "Should", "Summarize", "Analyze", "Write", "Draft", "Review",
                    "Department", "Team", "Office", "Project", "Program", "Saudi", "Arabia", "Riyadh", "Jeddah", "Dammam", "Monday",
                    "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday", "I", "We", "He", "She", "It", "They", "Ltd", "Inc",
                    "Company", "Bank", "Ministry", "University", "Street", "Road", "Q1", "Q2", "Q3", "Q4", "AI", "HR", "IT", "Is", "Was",
                    "Has", "Have", "Also", "Then", "Now", "Today", "Hello", "Hi", "Dear", "Thanks", "Regards", "Best", "Kind", "Report",
                    "Meeting", "Email", "Subject", "Note", "Notes", "Ignore", "Customer", "Client", "Employee", "Manager", "Director",
                    "Analyst", "Engineer", "Specialist", "Intern", "Senior", "Head", "Chief", "Vice", "President", "Mr", "Mrs", "Ms", "Dr"]
                   + [m.capitalize() for m in _MONTHS_EN] + [c for _, en, _ in L.CITIES.values() for c in en]
                   + [d for _, en, _ in L.DEPARTMENTS.values() for d in en])
_FIRST_EN = set(L.FIRST_NAMES_EN)
_FIRST_AR = set(_norm(n) for n in L.FIRST_NAMES_AR)
_CAP = r"[A-Z][a-z]+(?:[-'][A-Z]?[a-z]+)?"
_CAP_OR_AL = rf"(?:(?:Al|AL|El|bin|bint|ibn|Bin|Ibn|Abu|Abdul)[\s-])?{_CAP}"
HON_EN_RE = re.compile(r"\b(?:Mr|Mrs|Ms|Miss|Dr|Eng|Prof|Sheikh)\.?\s+(" + _CAP_OR_AL + r"(?:\s+" + _CAP_OR_AL + r"){0,2})")
FIRST_EN_RE = re.compile(r"(?<![A-Za-z])(" + "|".join(sorted(map(re.escape, _FIRST_EN), key=len, reverse=True)) + r")((?:\s+" + _CAP_OR_AL + r"){0,3})(?![A-Za-z])")
CUE_EN_RE = re.compile(r"\b(?:named|called|employee|colleague|customer|client|manager|candidate|patient|applicant|contractor|supervisor)\s+(" + _CAP + r"(?:\s+" + _CAP_OR_AL + r"){0,2})")
HON_AR_RE = re.compile(r"(?:" + "|".join(sorted((re.escape(_norm(h)) for h in L.HONORIFICS_AR), key=len, reverse=True)) + rf")\s*/?\s*((?:[{AR}]+)(?:\s+(?:بن|بنت|ابن|ابو|ام|عبد)?\s*[{AR}]+){{0,3}})")
CUE_AR_RE = re.compile(r"(?:" + "|".join(re.escape(_norm(c)) for c in L.NAME_CUES_AR) + rf")\s*:?\s*((?:[{AR}]+)(?:\s+(?:بن|بنت)?\s*[{AR}]+){{0,2}})")
FIRST_AR_RE = re.compile(_NOT_AR_BEFORE + r"(" + "|".join(sorted(map(re.escape, _FIRST_AR), key=len, reverse=True)) + rf")((?:\s+(?:بن|بنت|ابن|ابو)?\s*[{AR}]+){{0,3}})" + _NOT_AR_AFTER)

_NATION_EXCLUDE_AFTER = re.compile(r"^\s*(?:Arabia|Aramco|riyals?|market|government|law|PDPL|Vision|national ID|ID|Electricity|Telecom|Airlines|Exchange|Central Bank)", re.I)
_NATION_EXCLUDE_BEFORE = re.compile(rf"(?:ريال|الريال|السوق|المملكة|الحكومة|النظام|الهوية|البنك|السعودية للكهرباء|الاتصالات|الخطوط)\s*$")
_PERSON_WORDS = re.compile(r"\b(?:employee|colleague|staff|person|man|woman|national|citizen|nationality|he|she|engineer|manager|analyst|worker|resident|candidate|customer|client)\b|موظف|زميل|شخص|جنسيته|جنسيتها|الجنسية|مقيم|مواطن", re.I)


def _trim_name_en(words: list[str]) -> list[str]:
    out = []
    for w in words:
        if w in _EN_NOT_NAME:
            break
        out.append(w)
    return out


def _trim_name_ar(words: list[str], allow_unknown: bool = True) -> list[str]:
    out = []
    for w in words:
        if w in _AR_STOP or _is_ar_lexicon_term(w):
            break
        out.append(w)
    return out


_AR_LEX_TERMS = None


def _is_ar_lexicon_term(word: str) -> bool:
    global _AR_LEX_TERMS
    if _AR_LEX_TERMS is None:
        terms = set()
        for table in (L.CITIES, L.DEPARTMENTS, L.JOB_TITLES, L.NATIONALITIES):
            for _, _, ar in table.values():
                for a in ar:
                    for w in _norm(a).split():
                        terms.add(w)
                        if w.startswith("ال"):
                            terms.add(w[2:])
        terms |= {_norm(w) for w in ["الشركة", "القسم", "الادارة", "المشروع", "العميل", "التقرير", "يناير", "مارس", "شركة", "مكتب", "فرع", "سنة", "عام", "عمره", "عمرها", "ويعمل", "وتعمل", "يعمل", "تعمل", "راتبه", "راتبها", "انضم", "انضمت", "بالرياض", "بجدة", "الموارد", "المالية", "البشرية"]}
        _AR_LEX_TERMS = terms
    return word in _AR_LEX_TERMS


# ------------------------------------------------------------- recognizers

def recognize(nt: NormText, codenames: Optional[dict] = None) -> list[Candidate]:
    t = nt.text
    out: list[Candidate] = []
    add = out.append

    for m in EMAIL_RE.finditer(t):
        add(Candidate("email", m.start(), m.end(), 0.95, "pattern:email", "RFC-style address", m.group(0).lower()))

    for m in PHONE_SA_RE.finditer(t):
        add(Candidate("phone", m.start(), m.end(), 0.92, "pattern:phone_sa", "Saudi phone number format", re.sub(r"\D", "", m.group(0))))
    for m in PHONE_INTL_RE.finditer(t):
        cue = _context(t, m.start(), m.end(), ["phone", "mobile", "call", "whatsapp", "tel", "جوال", "هاتف", "اتصل", "رقم"])
        add(Candidate("phone", m.start(), m.end(), 0.85 if cue else 0.7, "pattern:phone_intl",
                      "International number" + (f" near '{cue}'" if cue else ""), re.sub(r"\D", "", m.group(0))))

    for m in NID_RE.finditer(t):
        cue = _context(t, m.start(), m.end(), ["id", "national", "iqama", "identity", "nid", "هوية", "الهوية", "اقامة", "الاقامة", "سجل مدني"])
        if saudi_id_valid(m.group(0)):
            add(Candidate("national_id", m.start(), m.end(), 0.97 if cue else 0.9, "validator:saudi_id",
                          ("Iqama" if m.group(0)[0] == "2" else "National ID") + " with valid check digit", m.group(0)))
        elif cue:
            add(Candidate("national_id", m.start(), m.end(), 0.6, "pattern:saudi_id_context",
                          f"10-digit ID format near '{cue}' (check digit invalid)", m.group(0)))

    for m in IBAN_RE.finditer(t):
        raw = m.group(0)
        if iban_valid(raw):
            add(Candidate("iban", m.start(), m.end(), 0.98, "validator:iban_mod97", "IBAN with valid mod-97 checksum", "".join(raw.split()).upper()))
        elif raw[:2].upper() == "SA" and _context(t, m.start(), m.end(), ["iban", "account", "حساب", "ايبان", "الايبان"]):
            add(Candidate("iban", m.start(), m.end(), 0.6, "pattern:iban_context", "SA-IBAN format near account cue (checksum invalid)", None))

    for m in CARD_RE.finditer(t):
        digits = re.sub(r"\D", "", m.group(0))
        if luhn_valid(digits):
            add(Candidate("payment_card", m.start(), m.end(), 0.95, "validator:luhn", "Card number with valid Luhn checksum", digits[-4:]))

    for m in PASSPORT_RE.finditer(t):
        cue = _context(t, m.start(), m.end(), ["passport", "جواز", "جواز السفر"])
        if cue:
            add(Candidate("passport", m.start(), m.end(), 0.85, "pattern:passport_context", f"Passport format near '{cue}'", None))

    for m in PRIVATE_KEY_RE.finditer(t):
        add(Candidate("private_key", m.start(), m.end(), 0.99, "pattern:pem_private_key", "PEM private key block", None))
    for m in CONN_RE.finditer(t):
        add(Candidate("connection_string", m.start(), m.end(), 0.95, "pattern:connection_string", "Database URL with embedded credentials", None))
    for rx, name in KNOWN_KEY_RES:
        for m in rx.finditer(t):
            add(Candidate("api_key", m.start(), m.end(), 0.96, f"pattern:{name}", f"Known {name.replace('_', ' ')} format", None))
    for m in ASSIGNED_SECRET_RE.finditer(t):
        val = m.group(1)
        ent = shannon_entropy(val)
        if ent >= 3.3 and char_classes(val) >= 2:
            add(Candidate("api_key", m.start(1), m.end(1), 0.88, "context:assigned_secret",
                          f"High-entropy value (H={ent:.1f} bits/char) assigned to a key/token label", None))
    for m in PASSWORD_RE.finditer(t):
        val = m.group(1)
        if val.lower() in {"reset", "policy", "manager", "change", "expired", "required", "field", "please", "was", "is"}:
            continue
        add(Candidate("password", m.start(1), m.end(1), 0.9, "context:password_label", "Value following a password label", None))

    for m in PRIVATE_IP_RE.finditer(t):
        add(Candidate("internal_host", m.start(), m.end(), 0.9, "pattern:private_ipv4", "RFC 1918 private address", m.group(0)))
    for m in INTERNAL_HOST_RE.finditer(t):
        if "@" in t[max(0, m.start() - 1):m.start()]:
            continue
        add(Candidate("internal_host", m.start(), m.end(), 0.85, "pattern:internal_hostname", "Internal domain suffix", m.group(0).lower()))

    for m in MONEY_RE.finditer(t):
        cue = _context(t, m.start(), m.end(), L.SALARY_CUES_EN + [_norm(c) for c in L.SALARY_CUES_AR], before=50, after=20)
        value = _money_value(m.group(0))
        if cue:
            add(Candidate("salary", m.start(), m.end(), 0.88, "context:money+salary_cue", f"Amount near '{cue}'", value))
        else:
            add(Candidate("money_amount", m.start(), m.end(), 0.85, "pattern:money", "Currency amount", value))

    for rx in DATE_RES:
        for m in rx.finditer(t):
            iso = _date_iso(m)
            cue = _context(t, m.start(), m.end(), L.DOB_CUES_EN + [_norm(c) for c in L.DOB_CUES_AR], before=35, after=5)
            if cue:
                add(Candidate("date_of_birth", m.start(), m.end(), 0.9, "context:date+birth_cue", f"Date near '{cue}'", iso))
            else:
                add(Candidate("date", m.start(), m.end(), 0.85, "pattern:date", "Calendar date", iso))

    for rx in AGE_RES:
        for m in rx.finditer(t):
            age = int(m.group(1))
            if 14 <= age <= 90:
                add(Candidate("age", m.start(1), m.end(1), 0.9, "context:age_phrase", "Number in an age phrase", str(age)))

    for rx in JOIN_RES:
        for m in rx.finditer(t):
            add(Candidate("join_year", m.start(1), m.end(1), 0.85, "context:joining_phrase", "Year in a joining/hiring phrase", m.group(1)))

    known = codenames or {}
    for m in PROJECT_EN_RE.finditer(t):
        name = m.group(1)
        conf = 0.92 if name.lower() in known else 0.7
        add(Candidate("project_codename", m.start(), m.end(), conf, "pattern:project_name" + (":known" if conf > 0.9 else ""),
                      "Named internal project" + (" (in organization registry)" if conf > 0.9 else ""), known.get(name.lower(), name.lower())))
    for m in PROJECT_AR_RE.finditer(t):
        name = m.group(1)
        if name in _AR_STOP or name in {"تخرج", "التخرج", "بحث", "البحث", "جديد", "الجديد", "عمل", "العمل"}:
            continue
        core = name[2:] if name.startswith("ال") else name
        canon = known.get(name) or known.get(core) or known.get("ال" + core)
        conf = 0.92 if canon else 0.55
        add(Candidate("project_codename", m.start(), m.end(), conf, "pattern:project_name_ar", "Named project (Arabic)", canon or core))

    for rx in ADDRESS_RES:
        for m in rx.finditer(t):
            add(Candidate("address", m.start(), m.end(), 0.75, "pattern:address", "Street / district / short address", None))

    _lexicon_entities(t, out)
    _names(t, out)
    return out


def _lexicon_entities(t: str, out: list[Candidate]) -> None:
    for key, s, e in CITY.find(t):
        out.append(Candidate("city", s, e, 0.85, "lexicon:city", "Saudi city / office location", key))
    seen = set()
    for key, s, e in DEPT.find(t):
        seen.add((s, e))
        out.append(Candidate("department", s, e, 0.8, "lexicon:department", "Organizational unit", key))
    for m in _DEPT_GENERIC.finditer(t):
        key = _DEPT_ALIAS_TO_KEY.get(m.group(1).lower())
        if key:
            out.append(Candidate("department", m.start(), m.end(), 0.85, "lexicon:department+unit_word", "Organizational unit", key))
    for key, s, e in TITLE.find(t):
        out.append(Candidate("job_title", s, e, 0.8, "lexicon:job_title", "Job title", key))
    for key, s, e in NATION.find(t):
        if _NATION_EXCLUDE_AFTER.match(t[e:e + 30]) or _NATION_EXCLUDE_BEFORE.search(t[max(0, s - 25):s]):
            continue
        near = _PERSON_WORDS.search(t[max(0, s - 40):e + 40])
        out.append(Candidate("nationality", s, e, 0.85 if near else 0.6, "lexicon:nationality",
                             "Nationality" + (" describing a person" if near else ""), key))
    for gender, (en, ar) in L.GENDER_TERMS.items():
        for w in en:
            for m in re.finditer(rf"\b{w}\b", t, re.I):
                pron = w.lower() in {"she", "her", "he", "his", "him"}
                out.append(Candidate("gender", m.start(), m.end(), 0.45 if pron else 0.8, "lexicon:gender",
                                     "Gendered pronoun" if pron else "Explicit gender term", gender))
        for w in ar:
            for m in re.finditer(_NOT_AR_BEFORE + re.escape(_norm(w)) + _NOT_AR_AFTER, t):
                pron = w in {"هو", "هي", "زميلي", "زميلتي", "موظفة"}
                out.append(Candidate("gender", m.start(), m.end(), 0.45 if pron else 0.8, "lexicon:gender",
                                     "Gendered word" if pron else "Explicit gender term", gender))

    def lex(terms, typ, conf, det, ev):
        for term in terms:
            n = _norm(term)
            pat = (r"(?<![A-Za-z])" + r"\s+".join(map(re.escape, n.split())) + r"(?![A-Za-z])") if n.isascii() else _ar_alt(term) + _NOT_AR_AFTER
            for m in re.finditer(pat if n.isascii() else _NOT_AR_BEFORE + pat, t, re.I):
                out.append(Candidate(typ, m.start(), m.end(), conf, det, ev, n.lower()))

    lex(L.CONFIDENTIAL_MARKERS_EN + L.CONFIDENTIAL_MARKERS_AR, "confidential_marker", 0.85, "lexicon:confidential_marker", "Document labelled confidential")
    lex(L.BUSINESS_SENSITIVE_EN + L.BUSINESS_SENSITIVE_AR, "business_sensitive", 0.7, "lexicon:business_sensitive", "Business-sensitive topic")


def _names(t: str, out: list[Candidate]) -> None:
    def add(s, e, conf, det, ev):
        val = re.sub(r"\s+", " ", t[s:e]).strip()
        if len(val) >= 2:
            out.append(Candidate("person_name", s, e, conf, det, ev, val.lower()))

    for m in HON_EN_RE.finditer(t):
        words = _trim_name_en(m.group(1).split())
        if words:
            end = m.start(1) + len(" ".join(words))
            add(m.start(1), end, 0.92, "context:honorific_en", "Name after an honorific")
    for m in CUE_EN_RE.finditer(t):
        words = _trim_name_en(m.group(1).split())
        if words and (len(words) >= 2 or words[0] in _FIRST_EN):
            add(m.start(1), m.start(1) + len(" ".join(words)), 0.8, "context:person_cue_en", "Capitalized name after a person cue")
    for m in FIRST_EN_RE.finditer(t):
        first = m.group(1)
        rest = _trim_name_en(m.group(2).split())
        if first in _EN_AMBIGUOUS and not rest:
            continue
        if rest:
            add(m.start(1), m.start(1) + len(first) + len(m.group(2)) - len(m.group(2).lstrip()) + len(" ".join(rest)), 0.88,
                "lexicon:first_name+surname", "Known given name followed by a surname")
        else:
            add(m.start(1), m.end(1), 0.62, "lexicon:first_name", "Known given name")

    for m in HON_AR_RE.finditer(t):
        words = _trim_name_ar(m.group(1).split())
        if words:
            seg = " ".join(words)
            add(m.start(1), m.start(1) + len(seg), 0.9, "context:honorific_ar", "اسم بعد لقب / Name after an Arabic honorific")
    for m in CUE_AR_RE.finditer(t):
        words = _trim_name_ar(m.group(1).split())
        if words:
            add(m.start(1), m.start(1) + len(" ".join(words)), 0.82, "context:person_cue_ar", "Name after a person cue")
    for m in FIRST_AR_RE.finditer(t):
        first = m.group(1)
        rest = _trim_name_ar(m.group(2).split())
        has_link = any(w in {"بن", "بنت", "ابن", "ابو"} for w in rest)
        if first in _AR_AMBIGUOUS and not has_link:
            continue
        if rest:
            seg_end = m.start(2) + len(m.group(2)) - len(m.group(2).lstrip()) + len(" ".join(rest))
            add(m.start(1), seg_end, 0.85, "lexicon:first_name_ar+family", "Known Arabic given name followed by family name")
        else:
            add(m.start(1), m.end(1), 0.62, "lexicon:first_name_ar", "Known Arabic given name")


def _money_value(s: str) -> Optional[str]:
    m = re.search(r"\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?", s)
    if not m:
        return None
    v = float(m.group(0).replace(",", ""))
    low = s.lower()
    if re.search(r"\d\s?(k)\b", low) or "thousand" in low or "الف" in s:
        v *= 1_000
    elif re.search(r"\d\s?(m|mn)\b", low) or "million" in low or "مليون" in s:
        v *= 1_000_000
    elif re.search(r"\d\s?bn\b", low) or "billion" in low or "مليار" in s:
        v *= 1_000_000_000
    return f"{v:.0f}"


def _date_iso(m: re.Match) -> Optional[str]:
    g = m.groups()
    try:
        if len(g[0]) == 4:
            y, mo, d = int(g[0]), int(g[1]), int(g[2])
        elif g[0].isdigit() and g[1].isdigit():
            d, mo, y = int(g[0]), int(g[1]), int(g[2])
        elif g[0].isdigit():
            d, mo, y = int(g[0]), _month(g[1]), int(g[2])
        else:
            mo, d, y = _month(g[0]), int(g[1]), int(g[2])
        return f"{y:04d}-{mo:02d}-{d:02d}"
    except Exception:
        return None


def _month(word: str) -> int:
    w = word.lower().rstrip(".")
    if w in _MONTHS_EN:
        return _MONTHS_EN.index(w) + 1
    if w in _MONTHS_SHORT:
        return _MONTHS_SHORT.index(w) + 1
    return _MONTHS_AR.index(word) + 1
