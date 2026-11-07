"""LLM provider abstraction.

The security decision NEVER depends on an LLM. Providers are used only for:
  * choosing a purpose when keyword rules are unsure (from a closed list), and
  * forwarding an already-minimized prompt to a model when the user asks.

Default is ``NullProvider`` (no model). ``OllamaProvider`` runs fully local.
``OpenAICompatibleProvider`` can reach hosted APIs (e.g. a free tier) but is
disabled unless AEGIS_ALLOW_EXTERNAL_LLM=1, and Aegis only ever sends it the
MINIMIZED prompt.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional, Protocol


class LLMProvider(Protocol):
    name: str
    location: str  # "local" | "external" | "none"

    def available(self) -> bool: ...

    def complete(self, prompt: str, max_tokens: int = 256) -> str: ...


class NullProvider:
    name = "none"
    location = "none"

    def available(self) -> bool:
        return False

    def complete(self, prompt: str, max_tokens: int = 256) -> str:
        raise RuntimeError("No LLM provider configured")


class OllamaProvider:
    location = "local"

    def __init__(self, model: str = "qwen3:1.7b", url: str = "http://127.0.0.1:11434", timeout: float = 60.0, num_ctx: int = 2048):
        self.model = model
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.num_ctx = num_ctx
        self.name = f"ollama:{model}"
        self._ok: Optional[bool] = None

    def available(self) -> bool:
        if self._ok is None:
            try:
                with urllib.request.urlopen(self.url + "/api/tags", timeout=1.5) as r:
                    tags = json.loads(r.read())
                self._ok = any(m.get("name", "").startswith(self.model.split(":")[0]) for m in tags.get("models", []))
            except Exception:
                self._ok = False
        return self._ok

    def complete(self, prompt: str, max_tokens: int = 256) -> str:
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False, "think": False,
                           "options": {"num_predict": max_tokens, "num_ctx": self.num_ctx, "temperature": 0}}).encode()
        req = urllib.request.Request(self.url + "/api/generate", data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read()).get("response", "")


class OpenAICompatibleProvider:
    """Any /chat/completions endpoint. External: only minimized text is ever sent."""

    location = "external"

    def __init__(self, base_url: str, model: str, api_key_env: str = "AEGIS_LLM_API_KEY", timeout: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key_env = api_key_env
        self.timeout = timeout
        self.name = f"external:{model}"

    def available(self) -> bool:
        return os.environ.get("AEGIS_ALLOW_EXTERNAL_LLM") == "1" and bool(os.environ.get(self.api_key_env))

    def complete(self, prompt: str, max_tokens: int = 256) -> str:
        if not self.available():
            raise RuntimeError("External LLM disabled (set AEGIS_ALLOW_EXTERNAL_LLM=1 and an API key)")
        body = json.dumps({"model": self.model, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens,
                           "temperature": 0}).encode()
        req = urllib.request.Request(self.base_url + "/chat/completions", data=body,
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {os.environ[self.api_key_env]}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.loads(r.read())["choices"][0]["message"]["content"]


def provider_from_env() -> LLMProvider:
    kind = os.environ.get("AEGIS_LLM_PROVIDER", "none").lower()
    if kind == "ollama":
        return OllamaProvider(model=os.environ.get("AEGIS_OLLAMA_MODEL", "qwen3:1.7b"),
                              url=os.environ.get("AEGIS_OLLAMA_URL", "http://127.0.0.1:11434"))
    if kind == "openai_compatible":
        return OpenAICompatibleProvider(base_url=os.environ.get("AEGIS_LLM_BASE_URL", ""), model=os.environ.get("AEGIS_LLM_MODEL", ""))
    return NullProvider()
