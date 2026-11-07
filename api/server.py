"""Aegis REST API + dashboard host (FastAPI).

Run:  uvicorn api.server:app --host 127.0.0.1 --port 8000
Binds to localhost by default: Aegis processes data on this machine.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from aegis import __version__
from aegis.gateway import MAX_CONTENT, MAX_PROMPT, ROOT, Aegis, InputError

app = FastAPI(title="Aegis API", version=__version__, description="Your AI. Your Data. Your Control.",
              docs_url="/api/docs", redoc_url=None, openapi_url="/api/openapi.json")
_aegis: Optional[Aegis] = None


def engine() -> Aegis:
    global _aegis
    if _aegis is None:
        _aegis = Aegis()
    return _aegis


def set_engine(a: Aegis) -> None:  # used by tests
    global _aegis
    _aegis = a


class EvaluateIn(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT)
    content: Optional[str] = Field(None, max_length=MAX_CONTENT, description="Attached document / email / tool output (untrusted)")
    purpose: Optional[str] = Field(None, max_length=64)
    policy: Optional[str] = Field(None, max_length=64)
    session_id: Optional[str] = Field(None, max_length=128)
    destination: Optional[str] = Field(None, pattern="^(external|local)$")
    dry_run: bool = False
    forward: bool = False
    confirm: bool = False
    demo: bool = False


class SimulateIn(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT)
    content: Optional[str] = Field(None, max_length=MAX_CONTENT)
    purpose: Optional[str] = Field(None, max_length=64)
    policies: Optional[list[str]] = Field(None, max_length=10)
    session_id: Optional[str] = Field(None, max_length=128)


class TextIn(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_CONTENT)


class InjectionIn(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT)
    content: Optional[str] = Field(None, max_length=MAX_CONTENT)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if not request.url.path.startswith("/api/docs"):
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                                   "font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
    return resp


@app.exception_handler(InputError)
async def input_error(_: Request, exc: InputError):
    return JSONResponse(status_code=422, content={"error": str(exc)})


@app.exception_handler(Exception)
async def generic_error(_: Request, exc: Exception):
    # never echo request content or stack traces to clients
    return JSONResponse(status_code=500, content={"error": "internal error", "type": type(exc).__name__})


@app.get("/api/v1/health")
def health():
    a = engine()
    return {"status": "ok", "version": __version__, "processing": "local", "llm": a.describe()["llm"],
            "population": a.population.N, "policies": list(a.policies)}


@app.post("/api/v1/evaluate")
def evaluate(body: EvaluateIn):
    d = engine().evaluate(body.prompt, body.content, body.purpose, body.policy, body.session_id, body.destination,
                          body.dry_run, body.forward, body.confirm, body.demo)
    return d.model_dump(mode="json")


@app.post("/api/v1/simulate")
def simulate(body: SimulateIn):
    r = engine().simulate(body.prompt, body.content, body.purpose, body.policies, body.session_id)
    r["results"] = {k: v.model_dump(mode="json") for k, v in r["results"].items()}
    return r


@app.post("/api/v1/scan")
def scan(body: TextIn):
    return {"findings": [f.model_dump(mode="json") for f in engine().scan(body.text)]}


@app.post("/api/v1/injection")
def injection(body: InjectionIn):
    return engine().injection.scan(body.prompt, body.content).model_dump(mode="json")


@app.get("/api/v1/sessions/{session_id}")
def session(session_id: str):
    if len(session_id) > 128:
        raise HTTPException(422, "session id too long")
    return engine().exposure.snapshot(session_id)


@app.post("/api/v1/sessions/{session_id}/reset")
def reset_session(session_id: str):
    return {"reset": engine().exposure.reset(session_id[:128])}


@app.get("/api/v1/config")
def config():
    return engine().describe()


@app.get("/api/v1/policies/{name}/source")
def policy_source(name: str):
    a = engine()
    if name not in a.policies:
        raise HTTPException(404, "unknown policy")
    return {"name": name, "yaml": (a.root / "config" / "policies" / f"{name}.yaml").read_text(encoding="utf-8")}


@app.get("/api/v1/audit")
def audit(limit: int = 50):
    return {"rows": engine().audit.recent(limit), "stored_fields_note": "Metadata only: no prompt text or detected values are stored."}


@app.get("/api/v1/stats")
def stats():
    return engine().audit.stats()


@app.post("/api/v1/audit/purge")
def purge(days: float = 30):
    return {"deleted": engine().audit.purge(days)}


@app.get("/api/v1/demo/scenarios")
def scenarios():
    data = yaml.safe_load((ROOT / "config" / "demo_scenarios.yaml").read_text(encoding="utf-8"))
    return data


@app.get("/api/v1/eval/latest")
def eval_latest():
    p = ROOT / "eval" / "reports" / "latest.json"
    if not p.exists():
        return {"available": False, "message": "Run `python -m eval.run` to generate the evaluation report."}
    return {"available": True, **json.loads(p.read_text(encoding="utf-8"))}


WEB = ROOT / "web"
app.mount("/static", StaticFiles(directory=WEB), name="static")


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")
