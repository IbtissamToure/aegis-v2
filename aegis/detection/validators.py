"""Checksum validators and entropy measures.

Validators turn "looks like" into "is": a 10-digit number is only reported as a
Saudi national ID / Iqama with high confidence when its check digit is valid.
"""
from __future__ import annotations

import math
from collections import Counter


def saudi_id_valid(digits: str) -> bool:
    """Saudi National ID (starts with 1) / Iqama (starts with 2) Luhn-style check."""
    if len(digits) != 10 or not digits.isdigit() or digits[0] not in "12":
        return False
    total = 0
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            total += d // 10 + d % 10
        else:
            total += d
    return total % 10 == 0


def saudi_id_check_digit(first9: str) -> str:
    """Return the check digit that makes ``first9 + d`` a valid Saudi ID (used by test generators)."""
    for d in "0123456789":
        if saudi_id_valid(first9 + d):
            return d
    raise ValueError("no check digit")


def luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


IBAN_LENGTHS = {"SA": 24, "AE": 23, "KW": 30, "BH": 22, "QA": 29, "OM": 23, "EG": 29, "JO": 30, "GB": 22, "DE": 22, "FR": 27}


def iban_valid(raw: str) -> bool:
    s = "".join(raw.split()).upper()
    if len(s) < 15 or not s[:2].isalpha() or not s[2:4].isdigit():
        return False
    expected = IBAN_LENGTHS.get(s[:2])
    if expected and len(s) != expected:
        return False
    rearranged = s[4:] + s[:4]
    num = ""
    for ch in rearranged:
        if ch.isdigit():
            num += ch
        elif ch.isalpha():
            num += str(ord(ch) - 55)
        else:
            return False
    return int(num) % 97 == 1


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def char_classes(s: str) -> int:
    return sum([any(c.islower() for c in s), any(c.isupper() for c in s), any(c.isdigit() for c in s),
                any(not c.isalnum() for c in s)])
