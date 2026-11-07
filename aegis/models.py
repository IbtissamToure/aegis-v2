"""Core data models shared by every Aegis component.

Raw prompt text and raw detected values live only in memory for the duration
of a request. Anything persisted (audit log, session ledger) is built from the
metadata fields of these models, never from ``Finding.text``.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Action(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    GENERALIZE = "GENERALIZE"
    BLOCK = "BLOCK"

    @property
    def rank(self) -> int:
        return {"ALLOW": 0, "WARN": 1, "GENERALIZE": 2, "BLOCK": 3}[self.value]


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


def max_action(actions) -> Action:
    best = Action.ALLOW
    for a in actions:
        if a.rank > best.rank:
            best = a
    return best


def max_severity(sevs) -> Severity:
    best = Severity.LOW
    for s in sevs:
        if s.rank > best.rank:
            best = s
    return best


class Finding(BaseModel):
    """One detected entity. A finding is NOT a violation; policy decides that."""

    id: str
    type: str
    category: str
    segment: str = "prompt"  # "prompt" or "content"
    start: int
    end: int
    text: str = Field(description="Raw value. In memory only; never persisted.")
    confidence: float
    severity: Severity
    detector: str
    evidence: str
    attribute: Optional[str] = None  # quasi-identifier attribute name (city, age, ...)
    value_norm: Optional[str] = None  # canonical value used for population lookup


class Change(BaseModel):
    finding_id: str
    type: str
    segment: str
    original_preview: str  # masked preview, never the full raw value
    replacement: str
    level: str
    reason: str


class InjectionSignal(BaseModel):
    family: str
    segment: str
    weight: float
    evidence: str
    start: int
    end: int


class InjectionResult(BaseModel):
    score: float
    severity: Severity
    detected: bool
    direct: bool
    indirect: bool
    signals: list[InjectionSignal]
    explanation: str


class PurposeResult(BaseModel):
    purpose: str
    label: str
    confidence: float
    method: str  # explicit | rules | llm | default
    candidates: list[dict[str, Any]] = []


class FiredRule(BaseModel):
    rule_id: str
    description: str
    action: Action
    severity: Severity
    finding_ids: list[str] = []
    remediation: str = ""


class ExposureState(BaseModel):
    subject: Optional[str]
    population: int
    bits_before: float
    bits_after: float
    budget_bits: float
    k_estimate_before: float
    k_estimate_after: float
    k_exact_after: Optional[int] = None
    k_requested: Optional[float] = None  # matching people if the prompt had been sent as requested
    k_exact_requested: Optional[int] = None
    attributes: list[dict[str, Any]] = []
    status: str  # ok | warn | generalized | blocked | not_tracked
    explanation: str


class Decision(BaseModel):
    request_id: str
    action: Action
    severity: Severity
    policy: str
    purpose: PurposeResult
    findings: list[Finding]
    violations: list[str]  # finding ids that triggered a rule
    fired_rules: list[FiredRule]
    injection: InjectionResult
    exposure: ExposureState
    minimized_prompt: Optional[str]
    minimized_content: Optional[str]
    changes: list[Change]
    rationale: list[str]
    remediation: list[str]
    counterfactual: Optional[dict[str, Any]] = None
    processing: dict[str, Any]
    latency_ms: dict[str, float]
    model_output: Optional[str] = None
