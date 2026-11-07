"""The Aegis gateway: one call evaluates a request end to end.

    injection screen -> detection -> purpose -> policy -> identifiability budget
    -> generalization -> (optional) model call -> audit

Every step is deterministic except the optional LLM purpose fallback and the
optional model call, neither of which can change a security decision.
"""
from __future__ import annotations

import copy
import itertools
import os
import secrets
import threading
import time
import uuid
from collections import Counter
from pathlib import Path
from typing import Optional

import yaml

from aegis.audit.store import AuditStore
from aegis.detection.detector import Detector
from aegis.detection.types import ENTITY_TYPES, TRACKED_ATTRIBUTES
from aegis.exposure.ledger import ExposureEngine
from aegis.exposure.population import Population
from aegis.generalization import engine as gen
from aegis.generalization.ladders import LADDERS
from aegis.injection.detector import InjectionDetector
from aegis.llm.providers import LLMProvider, provider_from_env
from aegis.models import (Action, Decision, ExposureState, FiredRule, InjectionResult, Severity, max_action, max_severity)
from aegis.policy.engine import Policy, evaluate as policy_evaluate, load_policy
from aegis.purpose import PurposeResolver

ROOT = Path(__file__).resolve().parents[1]
MAX_PROMPT = 20_000
MAX_CONTENT = 100_000


class InputError(ValueError):
    pass


def _load_secret(data_dir: Path) -> bytes:
    env = os.environ.get("AEGIS_SECRET")
    if env:
        return env.encode()
    path = data_dir / ".aegis_secret"
    if path.exists():
        return path.read_bytes()
    data_dir.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


class Aegis:
    def __init__(self, root: Optional[Path] = None, audit_path: Optional[str] = None, llm: Optional[LLMProvider] = None,
                 data_dir: Optional[Path] = None):
        self.root = Path(root or ROOT)
        cfg = self.root / "config"
        self.data_dir = Path(data_dir or os.environ.get("AEGIS_DATA_DIR", self.root / "data"))
        self.secret = _load_secret(self.data_dir)
        self.contracts, self.default_purpose = gen.load_contracts(cfg / "purposes.yaml")
        self.policies: dict[str, Policy] = {p.name: p for p in (load_policy(f) for f in sorted((cfg / "policies").glob("*.yaml")))}
        self.default_policy = os.environ.get("AEGIS_DEFAULT_POLICY", "balanced")
        org = yaml.safe_load((cfg / "org_terms.yaml").read_text(encoding="utf-8")) or {}
        codenames = {alias: key for key, aliases in (org.get("projects") or {}).items() for alias in [key, *aliases]}
        self.detector = Detector(codenames=codenames)
        self.injection = InjectionDetector()
        self.population = Population.from_csv(cfg / "population" / "synthetic_directory.csv")
        self.exposure = ExposureEngine(self.population, self.secret, ttl_minutes=float(os.environ.get("AEGIS_SESSION_TTL_MIN", 240)))
        retention = float(os.environ.get("AEGIS_AUDIT_RETENTION_DAYS", 30))
        self.audit = AuditStore(audit_path or os.environ.get("AEGIS_AUDIT_DB", str(self.data_dir / "audit.db")), retention_days=retention)
        self.llm = llm if llm is not None else provider_from_env()
        self.resolver = PurposeResolver(self.contracts, self.default_purpose, self.llm)
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ API
    def evaluate(self, prompt: str, content: Optional[str] = None, purpose: Optional[str] = None, policy: Optional[str] = None,
                 session_id: Optional[str] = None, destination: Optional[str] = None, dry_run: bool = False, forward: bool = False,
                 confirm: bool = False, demo: bool = False) -> Decision:
        if not isinstance(prompt, str) or not prompt.strip():
            raise InputError("prompt must be a non-empty string")
        if len(prompt) > MAX_PROMPT or (content and len(content) > MAX_CONTENT):
            raise InputError(f"input too large (prompt <= {MAX_PROMPT} chars, content <= {MAX_CONTENT} chars)")
        pol = self.policies.get(policy or self.default_policy)
        if pol is None:
            raise InputError(f"unknown policy '{policy}'")
        with self._lock:
            return self._evaluate(prompt, content or "", purpose, pol, session_id, destination, dry_run, forward, confirm, demo)

    def simulate(self, prompt: str, content: Optional[str] = None, purpose: Optional[str] = None, policies: Optional[list[str]] = None,
                 session_id: Optional[str] = None) -> dict:
        names = policies or list(self.policies)
        results = {n: self.evaluate(prompt, content, purpose, n, session_id, dry_run=True) for n in names}
        return {"policies": names, "results": results,
                "actions": {n: d.action.value for n, d in results.items()},
                "same_decision": len({d.action for d in results.values()}) == 1}

    # ------------------------------------------------------------ internals
    def _evaluate(self, prompt, content, purpose, pol: Policy, session_id, destination, dry_run, forward, confirm, demo) -> Decision:
        t0 = time.perf_counter()
        lat: dict[str, float] = {}

        def tick(name, start):
            lat[name] = round((time.perf_counter() - start) * 1000, 3)
            return time.perf_counter()

        t = time.perf_counter()
        inj = self.injection.scan(prompt, content)
        t = tick("injection", t)
        findings = self.detector.detect(prompt, "prompt")
        findings += self.detector.detect(content, "content", start_id=len(findings) + 1) if content else []
        t = tick("detection", t)
        try:
            pur = self.resolver.resolve(prompt, purpose)
        except ValueError as e:
            raise InputError(str(e))
        contract = self.contracts[pur.purpose]
        t = tick("purpose", t)
        out = policy_evaluate(pol, findings, contract, inj, pur.purpose, pur.confidence, destination)
        t = tick("policy", t)

        # ---- identifiability budget
        self.exposure.mode = pol.exposure.mode
        # The floor is enforced with a safety margin on the frequency-table estimate (absorbs estimator error).
        floor = pol.exposure.k_min * (pol.exposure.safety_factor if pol.exposure.mode == "estimate" else 1.0)
        session = self.exposure.session(session_id, ephemeral=dry_run)
        subject_key, link_reason = self.exposure.link_subject(session, prompt, findings)
        levels = dict(out.levels)
        fired = list(out.fired)
        proposal = [(f, levels.get(f.id, "exact")) for f in findings if f.segment == "prompt" and f.type in TRACKED_ATTRIBUTES]
        before, after = self.exposure.assess(session, subject_key, proposal)
        requested = after
        exp_action = Action.ALLOW
        status = "not_tracked"
        if subject_key:
            ex = pol.exposure
            if after["k"] >= max(ex.k_warn, floor):
                status = "ok"
            elif after["k"] >= floor:
                status = "warn"
                exp_action = Action.WARN
                fired.append(FiredRule(rule_id="X-EXP-WARN", description=f"Subject is becoming identifiable (fewer than {ex.k_warn:g} people match)",
                                       action=Action.WARN, severity=Severity.MEDIUM, finding_ids=[f.id for f, _ in proposal],
                                       remediation="Avoid adding further details about this person."))
            else:
                if ex.on_breach == Action.GENERALIZE:
                    plan, planned_after, ok = self.exposure.plan_generalization(session, subject_key, proposal, floor)
                    if ok:
                        status = "generalized"
                        exp_action = Action.GENERALIZE
                        changed = []
                        for (f, lv_old), (_, lv_new) in zip(proposal, plan):
                            if lv_new != lv_old:
                                levels[f.id] = gen.stricter(f.type, levels.get(f.id), lv_new)
                                out.reasons[f.id] = f"X-EXP-GEN: keeps at least {ex.k_min:g} people matching this subject"
                                changed.append(f.id)
                        after = planned_after
                        fired.append(FiredRule(rule_id="X-EXP-GEN", description=f"Cumulative disclosures would identify a person (fewer than {ex.k_min:g} matches); details generalized",
                                               action=Action.GENERALIZE, severity=Severity.HIGH, finding_ids=changed,
                                               remediation="The prompt was sent with broader details so the person stays among a group."))
                        proposal = plan
                    else:
                        status = "blocked"
                        exp_action = Action.BLOCK
                else:
                    status = "blocked" if ex.on_breach == Action.BLOCK else "warn"
                    exp_action = ex.on_breach
                if status == "blocked":
                    fired.append(FiredRule(rule_id="X-EXP-BLOCK", description=f"Cumulative disclosures would identify a person (fewer than {ex.k_min:g} matches)",
                                           action=Action.BLOCK, severity=Severity.HIGH, finding_ids=[f.id for f, _ in proposal],
                                           remediation="Remove identifying details about this person, or start a new, unrelated request."))
                elif ex.on_breach == Action.WARN:
                    fired.append(FiredRule(rule_id="X-EXP-WARN", description=f"Subject identifiable (fewer than {ex.k_min:g} matches)",
                                           action=Action.WARN, severity=Severity.HIGH, finding_ids=[f.id for f, _ in proposal]))
        t = tick("exposure", t)

        action = max_action([out.action, exp_action])
        severity = max_severity([fr.severity for fr in fired] + ([inj.severity] if inj.detected else []) or [Severity.LOW])

        # ---- generalize
        pseudo = session.pseudonyms
        changes = []
        min_prompt = min_content = None
        if action != Action.BLOCK:
            min_prompt, ch1 = gen.apply(prompt, "prompt", findings, levels, out.reasons, pseudo, self.secret)
            changes += ch1
            if content:
                min_content, ch2 = gen.apply(content, "content", findings, levels, out.reasons, pseudo, self.secret)
                changes += ch2
        t = tick("generalization", t)

        exposure_state = self._exposure_state(subject_key, session, before, after, status, pol, link_reason, proposal, requested)
        if subject_key:
            exposure_state.k_requested = round(requested["k"], 3)
            exposure_state.k_exact_requested = requested["k_exact"]
        if not dry_run and action != Action.BLOCK:
            self.exposure.commit(session, subject_key, [(f, levels.get(f.id, "exact")) for f, _ in proposal], after, action.value)
        elif not dry_run:
            session.turn += 1

        counterfactual = self._counterfactual(pol, findings, contract, inj, pur, destination, action, status) if action != Action.ALLOW else None
        rationale = self._rationale(pur, fired, inj, exposure_state, findings, action)
        remediation = list(dict.fromkeys(fr.remediation for fr in fired if fr.remediation))

        model_output = None
        external_call = False
        if forward and action in (Action.ALLOW, Action.GENERALIZE) or (forward and action == Action.WARN and confirm):
            if self.llm.available():
                payload = min_prompt + (f"\n\n---\n{min_content}" if min_content else "")
                try:
                    model_output = self.llm.complete(payload, max_tokens=512)
                    external_call = self.llm.location == "external"
                except Exception as e:  # model failures never affect the decision
                    model_output = f"[model call failed: {type(e).__name__}]"
        t = tick("model", t)
        lat["total"] = round((time.perf_counter() - t0) * 1000, 3)

        decision = Decision(
            request_id=uuid.uuid4().hex[:12], action=action, severity=severity, policy=pol.name, purpose=pur, findings=findings,
            violations=sorted(set(out.violations) | {i for fr in fired for i in fr.finding_ids}), fired_rules=fired, injection=inj,
            exposure=exposure_state, minimized_prompt=min_prompt, minimized_content=min_content, changes=changes, rationale=rationale,
            remediation=remediation, counterfactual=counterfactual,
            processing={"location": "local", "llm_provider": getattr(self.llm, "name", "none"), "llm_location": getattr(self.llm, "location", "none"),
                        "external_call": external_call, "destination": destination or pol.destination},
            latency_ms=lat, model_output=model_output)
        if not dry_run:
            self._audit(decision, session.key, out.principles, demo)
        return decision

    def _exposure_state(self, subject_key, session, before, after, status, pol, link_reason, proposal, requested=None) -> ExposureState:
        N = self.population.N
        k_req = (requested or after)["k"]
        if not subject_key:
            expl = f"Not tracked: {link_reason}."
        else:
            label = session.subjects[subject_key].label
            k = after["k"]
            top = ", ".join(f"{c['attribute']}={c['value']} ({c['bits']:.1f} bits)" for c in after["contributions"][:4])
            expl = (f"{label} ({link_reason}). After this prompt about {k:.1f} of {N:,} people would match "
                    f"({after['bits']:.1f} of {self.population.budget_bits:.1f} bits). Disclosed so far: {top or 'nothing'}.")
            if status == "generalized":
                expl += f" Sent as requested, about {k_req:.1f} would have matched; details were generalized to keep at least {pol.exposure.k_min:g}."
            elif status == "blocked":
                expl += f" This would leave fewer than {pol.exposure.k_min:g} people matching."
        return ExposureState(subject=session.subjects[subject_key].label if subject_key else None, population=N,
                             bits_before=before["bits"], bits_after=after["bits"], budget_bits=round(self.population.budget_bits, 3),
                             k_estimate_before=round(before["k"], 3), k_estimate_after=round(after["k"], 3), k_exact_after=after["k_exact"],
                             attributes=after["contributions"], status=status, explanation=expl)

    def _counterfactual(self, pol, findings, contract, inj, pur, destination, action, exp_status) -> Optional[dict]:
        """Smallest set of removals that would lower the decision (policy rules only)."""
        target = Action.GENERALIZE if action == Action.BLOCK else Action.ALLOW
        if action == Action.GENERALIZE:
            return None
        items = [("finding", f.id) for f in findings if f.confidence >= 0.5 and f.category in ("credential", "pii", "financial", "confidential")]
        if inj.score >= 0.3:
            items.append(("injection", "injection"))
        items = items[:10]
        clean_inj = InjectionResult(score=0.0, severity=Severity.LOW, detected=False, direct=False, indirect=False, signals=[], explanation="")
        for size in range(1, 4):
            for combo in itertools.combinations(items, size):
                drop = {i for k, i in combo if k == "finding"}
                use_inj = clean_inj if any(k == "injection" for k, _ in combo) else inj
                o = policy_evaluate(pol, [f for f in findings if f.id not in drop], contract, use_inj, pur.purpose, pur.confidence, destination)
                if o.action.rank <= target.rank:
                    by_id = {f.id: f for f in findings}
                    steps = [("Remove the embedded instruction text" if k == "injection" else
                              f"Remove the {ENTITY_TYPES[by_id[i].type]['label'].lower()} ({i})") for k, i in combo]
                    note = None
                    if exp_status == "blocked":
                        note = "The identifiability budget may still block; also remove details about the person."
                    return {"target_action": o.action.value, "steps": steps, "note": note}
        return {"target_action": None, "steps": [], "note": "No change of up to three items lowers this decision."}

    def _rationale(self, pur, fired, inj, exposure, findings, action) -> list[str]:
        lines = [f"Purpose: {pur.label} ({pur.method}, confidence {pur.confidence:.2f})."]
        if findings:
            c = Counter(ENTITY_TYPES[f.type]["label"] for f in findings if f.confidence >= 0.5)
            lines.append("Detected: " + ", ".join(f"{n}× {t}" for t, n in c.most_common()) + ".")
        else:
            lines.append("No sensitive data detected.")
        if inj.score > 0:
            lines.append("Injection: " + inj.explanation)
        for fr in fired:
            lines.append(f"{fr.rule_id} → {fr.action.value}: {fr.description}.")
        if exposure.status != "not_tracked":
            lines.append("Identifiability: " + exposure.explanation)
        lines.append(f"Decision: {action.value}.")
        return lines

    def _audit(self, d: Decision, session_key: str, principles: list[str], demo: bool) -> None:
        types = Counter(f.type for f in d.findings if f.confidence >= 0.5)
        hashes = sorted({gen.value_key(self.secret, f) for f in d.findings if f.confidence >= 0.5})
        self.audit.record({
            "request_id": d.request_id, "ts": time.time(), "session_hash": session_key, "policy": d.policy, "purpose": d.purpose.purpose,
            "purpose_confidence": d.purpose.confidence, "action": d.action.value, "severity": d.severity.value,
            "injection_score": d.injection.score, "injection_families": sorted({s.family for s in d.injection.signals}),
            "exposure_status": d.exposure.status, "k_estimate": d.exposure.k_estimate_after, "bits": d.exposure.bits_after,
            "finding_types": dict(types), "value_hashes": hashes, "rules": [fr.rule_id for fr in d.fired_rules], "principles": principles,
            "changes": len(d.changes), "destination": d.processing["destination"], "processing": "local", "latency_ms": d.latency_ms["total"],
            "demo": 1 if demo else 0})

    # ---------------------------------------------------------- helpers
    def scan(self, text: str) -> list:
        if len(text) > MAX_CONTENT:
            raise InputError("input too large")
        return self.detector.detect(text, "prompt")

    def describe(self) -> dict:
        return {
            "policies": {n: {"label": p.label, "description": p.description, "destination": p.destination,
                             "exposure": vars(p.exposure) | {"on_breach": p.exposure.on_breach.value},
                             "rules": [{"id": r.id, "description": r.description, "action": r.action.value, "when": r.when, "level": r.level}
                                       for r in p.rules]} for n, p in self.policies.items()},
            "purposes": {k: {"label": c.label, "description": c.description, "needs": c.needs} for k, c in self.contracts.items()},
            "entity_types": {k: {"label": v["label"], "category": v["category"], "severity": v["severity"].value, "ladder": LADDERS.get(k, [])}
                             for k, v in ENTITY_TYPES.items()},
            "population": {"name": self.population.name, "size": self.population.N, "budget_bits": round(self.population.budget_bits, 2),
                           "synthetic": True},
            "llm": {"provider": getattr(self.llm, "name", "none"), "location": getattr(self.llm, "location", "none"),
                    "available": bool(self.llm.available())},
            "default_policy": self.default_policy,
        }
