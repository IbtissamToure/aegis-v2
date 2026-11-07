"""Integration test: start the real MCP server over stdio and call its tools with the official MCP client."""
import json
import os
import sys
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def _run():
    env = dict(os.environ, AEGIS_AUDIT_DB=":memory:", AEGIS_DATA_DIR=str(ROOT / "data" / "test"), PYTHONPATH=str(ROOT))
    params = StdioServerParameters(command=sys.executable, args=["-m", "mcp_server.server"], cwd=str(ROOT), env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            tools = {t.name for t in (await s.list_tools()).tools}
            res = await s.call_tool("evaluate_policy", {"prompt": "Fix this: token = sk-proj-Q7f9Lk2mN4pR8sT1vW3xY6zA0bC5dE", "purpose": "code_review"})
            blocked = json.loads(res.content[0].text)
            res2 = await s.call_tool("generalize_sensitive_data", {"text": "Mr. Fahad Alotaibi is 34 years old and lives in Jeddah.", "purpose": "demographic_analysis"})
            gen = json.loads(res2.content[0].text)
            bad = await s.call_tool("scan_prompt", {"text": ""})
            return tools, blocked, gen, bad


def test_mcp_server_end_to_end():
    tools, blocked, gen, bad = anyio.run(_run)
    assert {"scan_prompt", "evaluate_policy", "generalize_sensitive_data", "inspect_exposure_budget", "explain_security_decision"} <= tools
    assert blocked["action"] == "BLOCK"
    assert any(r["id"] == "R-CRED-01" for r in blocked["rules"])
    assert "Fahad" not in gen["minimized"] and "30–34" in gen["minimized"]
    assert getattr(bad, "is_error", None) or getattr(bad, "isError", None)  # input validation rejects empty text
