"""Aegis as a Model Context Protocol (MCP) server.

Exposes Aegis to any MCP client (Claude Desktop, MCP Inspector, agent
frameworks) over stdio, using the official MCP Python SDK.

Tools: scan_prompt, evaluate_policy, generalize_sensitive_data,
       inspect_exposure_budget, explain_security_decision, list_policies

Note: an MCP server is ADVISORY — the agent chooses to call it. Mandatory
enforcement requires putting Aegis in the request path (the REST gateway).

Run:  python -m mcp_server.server
"""
from __future__ import annotations

from typing import Optional

try:  # MCP Python SDK 2.x
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # MCP Python SDK 1.x
    from mcp.server.fastmcp import FastMCP

from aegis.gateway import Aegis, InputError

mcp = FastMCP("aegis", instructions=(
    "Aegis checks text before it is sent to an AI model or tool. Call evaluate_policy with the exact text you intend to send; "
    "if the action is BLOCK do not send it; if GENERALIZE send `minimized_prompt` instead of the original."))
_aegis: Optional[Aegis] = None


def engine() -> Aegis:
    global _aegis
    if _aegis is None:
        _aegis = Aegis()
    return _aegis


def _check(text: str, limit: int = 20_000) -> None:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text must be a non-empty string")
    if len(text) > limit:
        raise ValueError(f"text longer than {limit} characters")


def _compact(d) -> dict:
    return {
        "action": d.action.value, "severity": d.severity.value, "policy": d.policy,
        "purpose": {"key": d.purpose.purpose, "confidence": d.purpose.confidence, "method": d.purpose.method},
        "minimized_prompt": d.minimized_prompt, "minimized_content": d.minimized_content,
        "rules": [{"id": r.rule_id, "action": r.action.value, "description": r.description} for r in d.fired_rules],
        "findings": [{"id": f.id, "type": f.type, "confidence": f.confidence, "segment": f.segment} for f in d.findings if f.confidence >= 0.5],
        "injection": {"score": d.injection.score, "direct": d.injection.direct, "indirect": d.injection.indirect},
        "exposure": {"status": d.exposure.status, "k_after": d.exposure.k_estimate_after, "bits_after": d.exposure.bits_after},
        "remediation": d.remediation, "request_id": d.request_id,
    }


@mcp.tool()
def scan_prompt(text: str) -> dict:
    """Detect sensitive data (PII, credentials, financial, confidential, quasi-identifiers) in text. Returns types and spans, not a decision."""
    _check(text, 100_000)
    fs = engine().scan(text)
    return {"count": len(fs), "findings": [{"type": f.type, "category": f.category, "start": f.start, "end": f.end, "confidence": f.confidence,
                                             "severity": f.severity.value, "evidence": f.evidence} for f in fs]}


@mcp.tool()
def evaluate_policy(prompt: str, content: Optional[str] = None, purpose: Optional[str] = None, policy: Optional[str] = None,
                    session_id: Optional[str] = None) -> dict:
    """Decide ALLOW / WARN / GENERALIZE / BLOCK for text an agent intends to send. `content` is untrusted attached data
    (documents, tool output). Use the same session_id across calls about the same task so cumulative exposure is tracked."""
    _check(prompt)
    try:
        return _compact(engine().evaluate(prompt, content, purpose, policy, session_id))
    except InputError as e:
        raise ValueError(str(e))


@mcp.tool()
def generalize_sensitive_data(text: str, purpose: Optional[str] = None) -> dict:
    """Return a minimized version of `text` for the given purpose (or the detected one) and the list of changes. Does not update session state."""
    _check(text)
    d = engine().evaluate(text, purpose=purpose, dry_run=True)
    return {"purpose": d.purpose.purpose, "action": d.action.value, "minimized": d.minimized_prompt,
            "changes": [c.model_dump(mode="json") for c in d.changes]}


@mcp.tool()
def inspect_exposure_budget(session_id: str) -> dict:
    """Show how identifiable each person discussed in a session has become (bits disclosed, estimated matching people)."""
    _check(session_id, 128)
    return engine().exposure.snapshot(session_id)


@mcp.tool()
def explain_security_decision(prompt: str, content: Optional[str] = None, purpose: Optional[str] = None, policy: Optional[str] = None) -> dict:
    """Explain, in plain language, what Aegis would decide for this text and the smallest change that would lower the decision. Dry run."""
    _check(prompt)
    d = engine().evaluate(prompt, content, purpose, policy, dry_run=True)
    return {"action": d.action.value, "rationale": d.rationale, "remediation": d.remediation, "counterfactual": d.counterfactual}


@mcp.tool()
def list_policies() -> dict:
    """List available policies and purposes."""
    desc = engine().describe()
    return {"policies": {k: v["label"] for k, v in desc["policies"].items()}, "purposes": {k: v["label"] for k, v in desc["purposes"].items()},
            "default_policy": desc["default_policy"]}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
