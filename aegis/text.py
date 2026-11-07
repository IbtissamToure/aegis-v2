"""Offset-preserving text normalization for Arabic and English.

Detection runs on a normalized copy of the text (Arabic diacritics/tatweel and
zero-width characters removed, alef/yaa variants and Arabic-Indic digits
unified, NFKC applied). ``NormText.span`` maps a span in the normalized text
back to the original text so replacements land on the user's real characters.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

_DIACRITIC_RE = re.compile("[ؐ-ًؚ-ٰٟۖ-ۭـ]")
_INVISIBLE = set("​‌‍⁠﻿‎‏‪‫‬‭‮⁦⁧⁨⁩­")
_CHAR_MAP = {
    "أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ى": "ي",
    "٠": "0", "١": "1", "٢": "2", "٣": "3", "٤": "4", "٥": "5", "٦": "6", "٧": "7", "٨": "8", "٩": "9",
    "۰": "0", "۱": "1", "۲": "2", "۳": "3", "۴": "4", "۵": "5", "۶": "6", "۷": "7", "۸": "8", "۹": "9",
    "٫": ".", "٬": ",", "،": ",",
}

ARABIC_RE = re.compile("[؀-ۿ]")


@dataclass
class NormText:
    original: str
    text: str
    index: list[int]  # index[i] = position in original of normalized char i; len = len(text)+1
    invisible_count: int

    def span(self, start: int, end: int) -> tuple[int, int]:
        if end <= start:
            o = self.index[start]
            return o, o
        return self.index[start], self.index[end - 1] + 1


def normalize(text: str) -> NormText:
    out: list[str] = []
    idx: list[int] = []
    invisible = 0
    for i, ch in enumerate(text):
        if ch in _INVISIBLE:
            invisible += 1
            continue
        if _DIACRITIC_RE.match(ch):
            continue
        c = _CHAR_MAP.get(ch)
        if c is None:
            c = unicodedata.normalize("NFKC", ch)
        for cc in c:
            out.append(_CHAR_MAP.get(cc, cc))
            idx.append(i)
    idx.append(len(text))
    return NormText(text, "".join(out), idx, invisible)


def has_arabic(text: str) -> bool:
    return bool(ARABIC_RE.search(text))


def mask_preview(value: str) -> str:
    """Short masked preview safe to show in change lists (never the full value)."""
    v = value.strip()
    if len(v) <= 2:
        return "•" * len(v)
    if len(v) <= 6:
        return v[0] + "•" * (len(v) - 1)
    return v[:2] + "•" * min(len(v) - 4, 8) + v[-2:]
