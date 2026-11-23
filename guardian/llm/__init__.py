"""LLM router: picks a provider from .env, falls back to the next one on failure, and finally to
rule-based logic (callers receive None). Every call is logged (provider, model, purpose, outcome)
to the run's audit trail - prompts may contain repo data, so keys are never logged.

.env:
  LLM_PROVIDER=auto | claude | gemini | groq | none     (auto = claude > gemini > groq, whichever has a key)
  ANTHROPIC_API_KEY=...   CLAUDE_MODEL=claude-opus-5-5   CLAUDE_EFFORT=medium
  GEMINI_API_KEY=...      GEMINI_MODEL=gemini-2.5-flash
  GROQ_API_KEY=...        GROQ_MODEL=llama-3.3-70b-versatile
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .. import config
from .providers import PROVIDERS, ProviderError

ORDER = ["claude", "gemini", "groq"]


def chain() -> list:
    choice = config.get("LLM_PROVIDER", "auto").lower()
    if choice == "none":
        return []
    names = ORDER if choice == "auto" else [choice] + [n for n in ORDER if n != choice]
    return [p for p in (PROVIDERS[n]() for n in names if n in PROVIDERS) if p.available]


def extract_json(text: str):
    """Models sometimes wrap JSON in prose or ``` fences - take the first complete JSON object."""
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                esc = (ch == "\\") and not esc
                if ch == '"' and not esc:
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = text.find("{", start + 1)
    raise ValueError("no JSON object in model output")


class Router:
    def __init__(self, audit: Path | None = None) -> None:
        self.providers = chain()
        self.audit = audit
        self.calls = []

    @property
    def enabled(self) -> bool:
        return bool(self.providers)

    def describe(self) -> str:
        return " -> ".join(f"{p.name}:{p.model}" for p in self.providers) + " -> rule-based" if self.providers else "rule-based only (no API key configured)"

    def ask_json(self, system: str, user: str, purpose: str) -> tuple[dict | None, dict]:
        """-> (parsed JSON or None, meta). None means every provider failed: caller uses rules."""
        errors = []
        for p in self.providers:
            t0 = time.time()
            try:
                out = extract_json(p.complete(system + "\nRespond with a single JSON object only.", user))
                meta = {"provider": p.name, "model": p.model, "purpose": purpose, "ok": True,
                        "seconds": round(time.time() - t0, 1), "errors": errors}
                self._log(meta)
                return out, meta
            except (ProviderError, ValueError) as e:
                errors.append(f"{p.name}: {e}")
        meta = {"provider": "rule-based", "model": "", "purpose": purpose, "ok": False, "errors": errors}
        self._log(meta)
        return None, meta

    def _log(self, meta: dict) -> None:
        self.calls.append(meta)
        if self.audit:
            from ..audit import log
            log(self.audit, "llm_call", meta)


def check() -> list[dict]:
    """Ping every configured provider with a tiny JSON task (used by `guardian llm-check`)."""
    results = []
    for name in ORDER:
        p = PROVIDERS[name]()
        if not p.available:
            results.append({"provider": name, "status": "no key"})
            continue
        t0 = time.time()
        try:
            out = extract_json(p.complete("You are a health check.", 'Return {"ok": true, "provider": "<your name>"} as JSON.'))
            results.append({"provider": name, "model": p.model, "status": "OK", "seconds": round(time.time() - t0, 1),
                            "reply": out})
        except Exception as e:
            r = {"provider": name, "model": p.model, "status": f"FAILED: {e}"}
            if hasattr(p, "list_models"):
                try:
                    r["available_models"] = p.list_models()[:25]
                except Exception:
                    pass
            results.append(r)
    return results
