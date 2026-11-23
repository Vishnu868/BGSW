"""One interface, three providers. Each returns plain text; JSON parsing happens in guardian.llm.

  Claude  - official `anthropic` Python SDK (adaptive thinking, effort, server-side refusal fallback)
  Gemini  - Google Generative Language REST API (JSON response mode)
  Groq    - Groq REST API, OpenAI-compatible chat completions (JSON object mode)
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .. import config


class ProviderError(Exception):
    """Raised when a provider cannot answer; the router then tries the next provider."""


def _post(url: str, body: dict, headers: dict, timeout: int = 120, retries: int = 3) -> dict:
    import time
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "supply-chain-guardian/0.2",
                                          **headers})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:300]
            if e.code in (429, 500, 502, 503) and attempt < retries:     # free tiers rate-limit: back off briefly
                wait = float(e.headers.get("retry-after") or 0) or 2 * (attempt + 1)
                time.sleep(min(wait, 20))
                continue
            raise ProviderError(f"HTTP {e.code}: {detail}") from None
        except (urllib.error.URLError, TimeoutError) as e:
            raise ProviderError(f"network: {e}") from None
    raise ProviderError("retries exhausted")


class Claude:
    name = "claude"

    def __init__(self) -> None:
        self.key = config.get("ANTHROPIC_API_KEY")
        self.model = config.get("CLAUDE_MODEL", "claude-opus-5-5")
        self.effort = config.get("CLAUDE_EFFORT", "medium")
        self.fallbacks = config.get("CLAUDE_FALLBACKS", "on").lower() != "off"

    @property
    def available(self) -> bool:
        return bool(self.key)

    def complete(self, system: str, user: str, max_tokens: int = 16000) -> str:
        try:
            import anthropic
        except ImportError:
            raise ProviderError("the 'anthropic' package is not installed (pip install -r requirements.txt)") from None
        client = anthropic.Anthropic(api_key=self.key, max_retries=2, timeout=300)
        args = dict(model=self.model, max_tokens=max_tokens, system=system,
                    messages=[{"role": "user", "content": user}],
                    output_config={"effort": self.effort})
        try:
            if self.fallbacks:
                # On a safety decline the API re-runs the request on a fallback model in the same call.
                resp = client.beta.messages.create(**args, betas=["server-side-fallback-2026-07-01"], fallbacks="default")
            else:
                resp = client.messages.create(**args)
        except anthropic.BadRequestError as e:
            if self.fallbacks and "fallback" in str(e.message).lower():
                self.fallbacks = False          # model/account without server-side fallback - retry plain
                return self.complete(system, user, max_tokens)
            raise ProviderError(f"bad request: {e.message}") from None
        except anthropic.AuthenticationError:
            raise ProviderError("invalid ANTHROPIC_API_KEY") from None
        except anthropic.PermissionDeniedError:
            raise ProviderError("API key lacks permission (or no credit)") from None
        except anthropic.NotFoundError:
            raise ProviderError(f"unknown model {self.model}") from None
        except anthropic.RateLimitError:
            raise ProviderError("rate limited") from None
        except anthropic.APIStatusError as e:
            raise ProviderError(f"API error {e.status_code}: {e.message}") from None
        except anthropic.APIConnectionError:
            raise ProviderError("network error") from None
        if resp.stop_reason == "refusal":
            raise ProviderError("model declined the request (refusal)")
        text = "".join(b.text for b in resp.content if b.type == "text")
        if not text:
            raise ProviderError(f"empty response (stop_reason={resp.stop_reason})")
        return text


class Gemini:
    name = "gemini"

    def __init__(self) -> None:
        self.key = config.get("GEMINI_API_KEY") or config.get("GOOGLE_API_KEY")
        self.model = config.get("GEMINI_MODEL", "gemini-2.5-flash")

    @property
    def available(self) -> bool:
        return bool(self.key)

    def complete(self, system: str, user: str, max_tokens: int = 8192) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        body = {"systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": max_tokens,
                                     "responseMimeType": "application/json"}}
        data = _post(url, body, {"x-goog-api-key": self.key})
        try:
            cand = data["candidates"][0]
            text = "".join(p.get("text", "") for p in cand["content"]["parts"])
        except (KeyError, IndexError):
            raise ProviderError(f"no answer (blocked or empty): {str(data)[:200]}") from None
        if not text:
            raise ProviderError(f"empty response (finishReason={cand.get('finishReason')})")
        return text

    def list_models(self) -> list[str]:
        req = urllib.request.Request("https://generativelanguage.googleapis.com/v1beta/models?pageSize=100",
                                     headers={"x-goog-api-key": self.key})
        with urllib.request.urlopen(req, timeout=20) as r:
            return [m["name"].split("/")[-1] for m in json.loads(r.read()).get("models", [])
                    if "generateContent" in m.get("supportedGenerationMethods", [])]


class Groq:
    name = "groq"

    def __init__(self) -> None:
        self.key = config.get("GROQ_API_KEY")
        self.model = config.get("GROQ_MODEL", "llama-3.3-70b-versatile")

    @property
    def available(self) -> bool:
        return bool(self.key)

    def complete(self, system: str, user: str, max_tokens: int = 8000) -> str:
        body = {"model": self.model, "temperature": 0.2, "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        data = _post("https://api.groq.com/openai/v1/chat/completions", body, {"Authorization": f"Bearer {self.key}"})
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError):
            raise ProviderError(f"unexpected response: {str(data)[:200]}") from None

    def list_models(self) -> list[str]:
        req = urllib.request.Request("https://api.groq.com/openai/v1/models",
                                     headers={"Authorization": f"Bearer {self.key}", "User-Agent": "supply-chain-guardian/0.2"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return [m["id"] for m in json.loads(r.read()).get("data", [])]


PROVIDERS = {"claude": Claude, "gemini": Gemini, "groq": Groq}
