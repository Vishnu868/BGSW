"""LLM router: picks a provider from .env, falls back to the next one on failure, and finally to
rule-based logic (callers receive None). Every call is logged (provider, model, purpose, outcome)
to the run's audit trail - prompts may contain repo data, so keys are never logged.

.env:
  LLM_PROVIDER=auto | claude | gemini | groq | none     (auto = claude > gemini > groq, whichever has a key)
  ANTHROPIC_API_KEY=...   CLAUDE_MODEL=claude-opus-5-5   CLAUDE_EFFORT=medium
  GEMINI_API_KEY=...      GEMINI_MODEL=gemini-2.5-flash
  GROQ_API_KEY=...        GROQ_MODEL=llama-3.3-70b-versatile
  LLM_CACHE=on            identical questions are answered from .cache/llm (repeatable, free demo reruns)
  <AGENT>_PROVIDER / <AGENT>_MODEL   give one agent a different provider/model, e.g. CRITIC_PROVIDER=gemini
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path

from pathlib import Path

from .. import config
from .providers import PROVIDERS, ProviderError

ORDER = ["claude", "gemini", "groq"]
CACHE = Path(__file__).resolve().parents[2] / ".cache" / "llm"


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

    def for_agent(self, agent: str) -> "Router":
        """A router for one agent: <AGENT>_PROVIDER moves that provider first, <AGENT>_MODEL overrides its model.
        Example: CRITIC_PROVIDER=gemini makes the critic use a different model family than the specialists."""
        prov = config.get(f"{agent.upper()}_PROVIDER").lower()
        model = config.get(f"{agent.upper()}_MODEL")
        if not prov and not model:
            return self
        r = Router.__new__(Router)
        r.audit, r.calls = self.audit, self.calls
        ps = [PROVIDERS[p.name]() for p in self.providers]
        if prov:
            ps.sort(key=lambda p: p.name != prov)
        if model and ps:
            ps[0].model = model
        r.providers = ps
        return r

    def ask_json(self, system: str, user: str, purpose: str) -> tuple[dict | None, dict]:
        """-> (parsed JSON or None, meta). None means every provider failed: caller uses rules."""
        errors = []
        use_cache = config.get("LLM_CACHE", "on").lower() != "off"
        for p in self.providers:
            t0 = time.time()
            key = hashlib.sha256(json.dumps([p.name, p.model, system, user]).encode()).hexdigest()
            cache_file = CACHE / f"{key}.json"
            if use_cache and cache_file.exists():
                out = json.loads(cache_file.read_text(encoding="utf-8"))
                meta = {"provider": p.name, "model": p.model, "purpose": purpose, "ok": True, "cached": True,
                        "seconds": 0.0, "errors": errors}
                self._log(meta)
                return out, meta
            try:
                out = extract_json(p.complete(system + "\nRespond with a single JSON object only.", user))
                meta = {"provider": p.name, "model": p.model, "purpose": purpose, "ok": True,
                        "seconds": round(time.time() - t0, 1), "errors": errors}
                if use_cache:
                    CACHE.mkdir(parents=True, exist_ok=True)
                    cache_file.write_text(json.dumps(out), encoding="utf-8")
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
