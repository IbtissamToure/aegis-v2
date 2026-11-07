"""Deterministic policy engine.

A policy is a YAML file of ordered rules. A rule fires when ALL its conditions
hold; finding-level conditions select which findings it applies to. The final
action is the most restrictive fired action (BLOCK > GENERALIZE > WARN > ALLOW).
No LLM is involved: the same input and policy always give the same decision.

Condition keys
  finding-level: type_any, category_any, min_confidence, not_required_by_purpose,
                 segment, severity_at_least
  request-level: injection_score_gte, purpose_any, purpose_confidence_lt,
                 destination, has_findings_in_category
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from aegis.generalization.engine import Contract, stricter
from aegis.models import Action, FiredRule, Finding, InjectionResult, Severity

_FINDING_KEYS = {"type_any", "category_any", "min_confidence", "not_required_by_purpose", "segment", "severity_at_least"}
_REQUEST_KEYS = {"injection_score_gte", "purpose_any", "purpose_confidence_lt", "destination", "has_findings_in_category"}


@dataclass
class Rule:
    id: str
    description: str
    when: dict[str, Any]
    action: Action
    severity: Severity
    level: Optional[str] = None
    remediation: str = ""
    principle: str = ""

    @property
    def finding_scoped(self) -> bool:
        return bool(_FINDING_KEYS & set(self.when))


@dataclass
class ExposurePolicy:
    k_warn: float = 25
    k_min: float = 5
    on_breach: Action = Action.GENERALIZE
    mode: str = "estimate"


@dataclass
class Policy:
    name: str
    label: str
    description: str
    destination: str
    rules: list[Rule]
    exposure: ExposurePolicy
    default_min_confidence: float = 0.5
    raw: dict = field(default_factory=dict)


def load_policy(path: str | Path) -> Policy:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    rules = []
    for r in data.get("rules", []):
        unknown = set(r.get("when", {})) - _FINDING_KEYS - _REQUEST_KEYS
        if unknown:
            raise ValueError(f"Policy {path}: rule {r.get('id')} has unknown condition(s) {sorted(unknown)}")
        rules.append(Rule(id=r["id"], description=r.get("description", ""), when=r.get("when", {}), action=Action(r["action"]),
                          severity=Severity(r.get("severity", "medium")), level=r.get("level"), remediation=r.get("remediation", ""),
                          principle=r.get("principle", "")))
    ex = data.get("exposure", {})
    exposure = ExposurePolicy(k_warn=float(ex.get("k_warn", 25)), k_min=float(ex.get("k_min", 5)),
                              on_breach=Action(ex.get("on_breach", "GENERALIZE")), mode=ex.get("mode", "estimate"))
    return Policy(name=data["name"], label=data.get("label", data["name"]), description=data.get("description", ""),
                  destination=data.get("destination", "external"), rules=rules, exposure=exposure,
                  default_min_confidence=float(data.get("default_min_confidence", 0.5)), raw=data)


@dataclass
class PolicyOutcome:
    action: Action
    fired: list[FiredRule]
    levels: dict[str, str]  # finding id -> disclosure level to send
    reasons: dict[str, str]
    violations: list[str]
    principles: list[str]


def _finding_matches(rule: Rule, f: Finding, contract: Contract, default_min_conf: float) -> bool:
    w = rule.when
    if f.confidence < float(w.get("min_confidence", default_min_conf)):
        return False
    if "type_any" in w and f.type not in w["type_any"]:
        return False
    if "category_any" in w and f.category not in w["category_any"]:
        return False
    if "segment" in w and f.segment != w["segment"]:
        return False
    if "severity_at_least" in w and f.severity.rank < Severity(w["severity_at_least"]).rank:
        return False
    if w.get("not_required_by_purpose") and contract.allowed_level(f.type) == "exact":
        return False
    return True


def _request_matches(rule: Rule, ctx: dict) -> bool:
    w = rule.when
    if "injection_score_gte" in w and ctx["injection"].score < float(w["injection_score_gte"]):
        return False
    if "purpose_any" in w and ctx["purpose"] not in w["purpose_any"]:
        return False
    if "purpose_confidence_lt" in w and ctx["purpose_confidence"] >= float(w["purpose_confidence_lt"]):
        return False
    if "destination" in w and ctx["destination"] != w["destination"]:
        return False
    if "has_findings_in_category" in w and not any(f.category in w["has_findings_in_category"] and f.confidence >= 0.5
                                                    for f in ctx["findings"]):
        return False
    return True


def evaluate(policy: Policy, findings: list[Finding], contract: Contract, injection: InjectionResult, purpose: str,
             purpose_confidence: float, destination: Optional[str] = None) -> PolicyOutcome:
    ctx = {"injection": injection, "purpose": purpose, "purpose_confidence": purpose_confidence,
           "destination": destination or policy.destination, "findings": findings}
    fired: list[FiredRule] = []
    levels: dict[str, str] = {}
    reasons: dict[str, str] = {}
    violations: set[str] = set()
    principles: list[str] = []
    for rule in policy.rules:
        if not _request_matches(rule, ctx):
            continue
        matched: list[Finding] = []
        if rule.finding_scoped:
            matched = [f for f in findings if _finding_matches(rule, f, contract, policy.default_min_confidence)]
            if not matched:
                continue
        fired.append(FiredRule(rule_id=rule.id, description=rule.description, action=rule.action, severity=rule.severity,
                               finding_ids=[f.id for f in matched], remediation=rule.remediation))
        if rule.principle and rule.principle not in principles:
            principles.append(rule.principle)
        for f in matched:
            violations.add(f.id)
            if rule.action in (Action.GENERALIZE, Action.BLOCK):
                target = rule.level or contract.allowed_level(f.type)
                if target != "exact":
                    levels[f.id] = stricter(f.type, levels.get(f.id), target)
                    reasons.setdefault(f.id, f"{rule.id}: {rule.description}")
    action = Action.ALLOW
    for fr in fired:
        if fr.action.rank > action.rank:
            action = fr.action
    return PolicyOutcome(action=action, fired=fired, levels=levels, reasons=reasons, violations=sorted(violations), principles=principles)
