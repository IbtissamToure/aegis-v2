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
import time
import urllib.error
import urllib.request
from typing import Optional, Protocol


class LLMProvider(Protocol):
    name: str
    location: str  # "local" | "external" | "none"

    def available(self) -> bool: ...

    def complete(self, prompt: str, max_tokens: int = 256, system: Optional[str] = None) -> str: ...


EXECUTE_SYSTEM = (
    "You carry out the user's task and return ONLY the result. "
    "No introduction, no explanation of your steps, no notes, no follow-up questions, no offers. "
    "If the task is an analysis or calculation, give the final figures or findings directly (a short table or list is fine). "
    "If it is writing, give only the finished text. Answer in the same language as the task. "
    "Bracketed tokens such as [PERSON_1] or [PHONE] are anonymized values: keep them exactly as they are and do not ask about them."
)


SUMMARY_SYSTEM = ("You compress answers. Output only the final result in at most three short plain sentences. "
                  "Never add an introduction, steps, headings, bullet points or Markdown. Keep bracketed tokens like [PERSON_1] unchanged. "
                  "Use the same language as the answer.")


def strip_reasoning(text: str) -> str:
    """Remove <think>…</think> blocks some local models emit."""
    import re
    return re.sub(r"<think>[\s\S]*?</think>", "", text).strip()


_SECTION_PRIORITY = [
    r"conclusion|الخلاصة|الاستنتاج|خلاصة",
    r"final answer|final result|النتيجة النهائية|الاجابة النهائية|الإجابة النهائية",
    r"result|summary|answer|النتيجة|الملخص|الإجابة|الاجابة",
]


def final_answer(text: str) -> str:
    """Keep only the conclusion / final answer of a model reply, as plain text (no Markdown).

    Small local models often show their working despite instructions; the user wants the result only.
    """
    import re
    text = strip_reasoning(text)
    lines = text.splitlines()
    heads = []  # (line index, title)
    for i, ln in enumerate(lines):
        m = re.match(r"^\s*(?:#{1,6}\s*(.+?)\s*#*\s*$|\*\*\s*([^*]{2,60}?)\s*:?\s*\*\*\s*:?\s*$)", ln)
        if m:
            heads.append((i, (m.group(1) or m.group(2)).strip(" *:")))
    chosen = None
    for pattern in _SECTION_PRIORITY:
        for idx, (i, title) in reversed(list(enumerate(heads))):
            if re.search(pattern, title, re.I):
                end = heads[idx + 1][0] if idx + 1 < len(heads) else len(lines)
                body = "\n".join(lines[i + 1:end]).strip()
                if body:
                    chosen = body
                    break
        if chosen:
            break
    out = chosen if chosen else text
    out = re.sub(r"^\s*#{1,6}\s*", "", out, flags=re.M)          # headings
    out = re.sub(r"^\s*(?:-{3,}|\*{3,}|_{3,})\s*$", "", out, flags=re.M)  # rules
    out = re.sub(r"^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$", "", out, flags=re.M)  # table separators
    out = re.sub(r"\*\*|__|`", "", out)                            # bold / code marks
    out = re.sub(r"(?<!\w)\*(?!\s)([^*\n]+?)\*(?!\w)", r"\1", out)  # italics
    out = re.sub(r"^\s*[-*]\s+", "• ", out, flags=re.M)           # bullets
    out = re.sub(r"\s*\u2014\s*", ", ", out)                       # no em dashes in answers
    out = re.sub(r"\n{3,}", "\n\n", out)
    return out.strip()


class NullProvider:
    name = "none"
    location = "none"

    def available(self) -> bool:
        return False

    def complete(self, prompt: str, max_tokens: int = 256, system: Optional[str] = None) -> str:
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
        self._checked = 0.0
        self.last_error = ""

    def available(self) -> bool:
        # re-check every 10 s, so starting Ollama after Aegis is picked up without a restart
        if self._ok is None or time.time() - self._checked > 10:
            self._checked = time.time()
            try:
                with urllib.request.urlopen(self.url + "/api/tags", timeout=2) as r:
                    tags = json.loads(r.read())
                names = [m.get("name", "") for m in tags.get("models", [])]
                self._ok = self.model in names or any(n.split(":")[0] == self.model.split(":")[0] for n in names)
                self.last_error = "" if self._ok else f"Ollama is running but model '{self.model}' is not pulled (found: {', '.join(names) or 'none'})"
            except Exception as e:
                self._ok = False
                self.last_error = f"Cannot reach Ollama at {self.url} ({type(e).__name__})"
        return self._ok

    def complete(self, prompt: str, max_tokens: int = 256, system: Optional[str] = None) -> str:
        payload = {"model": self.model, "prompt": prompt, "stream": False, "think": False,
                   "options": {"num_predict": max_tokens, "num_ctx": self.num_ctx, "temperature": 0.2}}
        if system:
            payload["system"] = system
        req = urllib.request.Request(self.url + "/api/generate", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
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

    def complete(self, prompt: str, max_tokens: int = 256, system: Optional[str] = None) -> str:
        if not self.available():
            raise RuntimeError("External LLM disabled (set AEGIS_ALLOW_EXTERNAL_LLM=1 and an API key)")
        messages = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": prompt}]
        body = json.dumps({"model": self.model, "messages": messages, "max_tokens": max_tokens,
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
