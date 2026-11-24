"""One interface, four providers. Each returns plain text; JSON parsing happens in guardian.llm.

  Claude  - official `anthropic` Python SDK (adaptive thinking, effort, server-side refusal fallback)
  Gemini  - Google Generative Language REST API (JSON response mode)
  Ollama  - local model on this computer (default qwen3:4b): no key, no rate limit, nothing leaves the machine
  Groq    - Groq REST API, OpenAI-compatible chat completions (JSON object mode); only when chosen explicitly
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from .. import config


class ProviderError(Exception):
    """Raised when a provider cannot answer; the router then tries the next provider."""


def _post(url: str, body: dict, headers: dict, timeout: int = 120, retries: int = 5) -> dict:
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
            # a used-up daily/plan quota will not come back in a minute: fail at once so the router moves on
            if e.code == 429 and any(s in detail.lower() for s in ("exceeded your current quota", "per day", "billing")):
                raise ProviderError(f"HTTP 429 quota exhausted: {detail[:160]}") from None
            if e.code in (429, 500, 502, 503) and attempt < retries:     # free tiers rate-limit: back off briefly
                wait = float(e.headers.get("retry-after") or 0) or 2 * (attempt + 1)
                time.sleep(min(wait + 1, 60))       # per-minute token limits reset within a minute
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
        self.model = config.get("GEMINI_MODEL", "gemini-3.5-flash")

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
        self.model = config.get("GROQ_MODEL", "qwen/qwen3.8-27b")

    @property
    def available(self) -> bool:
        return bool(self.key)

    def complete(self, system: str, user: str, max_tokens: int = 8000) -> str:
        # free tier counts max_tokens against tokens-per-minute (8k on gpt-oss-120b), so ask for what an answer needs
        body = {"model": self.model, "temperature": 0.2, "max_tokens": min(max_tokens, int(config.get("GROQ_MAX_TOKENS", "2000"))),
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        if "gpt-oss" in self.model:
            body["reasoning_effort"] = "low"
        url, auth = "https://api.groq.com/openai/v1/chat/completions", {"Authorization": f"Bearer {self.key}"}
        try:
            data = _post(url, body, auth)
        except ProviderError as e:
            if not any(s in str(e) for s in ("Failed to validate JSON", "json_validate_failed", "called a tool")):
                raise
            # gpt-oss likes native function calling; our agents use a plain-JSON tool protocol. Ask again in
            # free-text mode and accept either a JSON reply or a native tool call (converted below).
            body.pop("response_format", None)
            body["messages"][0]["content"] = system + "\nReply with one JSON object as plain text. Do not use native function calls."
            data = _post(url, body, auth)
        try:
            msg = data["choices"][0]["message"]
        except (KeyError, IndexError):
            raise ProviderError(f"unexpected response: {str(data)[:200]}") from None
        if msg.get("tool_calls") and not (msg.get("content") or "").strip():
            call = msg["tool_calls"][0]["function"]
            try:
                args = json.loads(call.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            return json.dumps({"tool": call.get("name", ""), "args": args, "why": "native tool call (converted)"})
        if not (msg.get("content") or "").strip():
            raise ProviderError(f"empty reply (finish_reason={data['choices'][0].get('finish_reason')})")
        return msg["content"]

    def list_models(self) -> list[str]:
        req = urllib.request.Request("https://api.groq.com/openai/v1/models",
                                     headers={"Authorization": f"Bearer {self.key}", "User-Agent": "supply-chain-guardian/0.2"})
        with urllib.request.urlopen(req, timeout=20) as r:
            return [m["id"] for m in json.loads(r.read()).get("data", [])]


class Ollama:
    """Local model served by Ollama (https://ollama.com) at OLLAMA_HOST (default http://127.0.0.1:11434).

    Uses /api/chat with JSON output mode. Thinking is switched off for Qwen 3 (`think: false`): the agents'
    protocol needs one JSON object per turn, and on a 4 GB laptop GPU thinking tokens mostly cost time."""
    name = "ollama"
    _up: dict = {}            # host -> (checked_at, reachable) - checked at most every 30 s

    def __init__(self) -> None:
        self.host = config.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
        self.model = config.get("OLLAMA_MODEL", "qwen3:4b")
        self.ctx = int(config.get("OLLAMA_NUM_CTX", "8192"))
        self.timeout = int(config.get("OLLAMA_TIMEOUT", "300"))

    @property
    def available(self) -> bool:
        """Usable when the Ollama server answers. Costs one local request, cached for 30 seconds."""
        import time
        at, ok = Ollama._up.get(self.host, (0.0, False))
        if time.time() - at > 30:
            try:
                with urllib.request.urlopen(f"{self.host}/api/version", timeout=2) as r:
                    ok = r.status == 200
            except (urllib.error.URLError, OSError, ValueError):
                ok = False
            Ollama._up[self.host] = (time.time(), ok)
        return ok

    def complete(self, system: str, user: str, max_tokens: int = 4000) -> str:
        body = {"model": self.model, "stream": False, "format": "json", "think": False,
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
                "options": {"temperature": 0.2, "num_ctx": self.ctx, "num_predict": min(max_tokens, 4000)}}
        try:
            data = _post(f"{self.host}/api/chat", body, {}, timeout=self.timeout, retries=1)
        except ProviderError as e:
            if "not found" in str(e) and "model" in str(e):
                raise ProviderError(f"model {self.model} is not pulled - run: ollama pull {self.model}") from None
            if "think" in str(e):          # older Ollama or a model without a thinking switch
                body.pop("think")
                data = _post(f"{self.host}/api/chat", body, {}, timeout=self.timeout, retries=1)
            else:
                raise
        text = ((data.get("message") or {}).get("content") or "").strip()
        if not text:
            raise ProviderError(f"empty reply (done_reason={data.get('done_reason')})")
        return text

    def list_models(self) -> list[str]:
        with urllib.request.urlopen(f"{self.host}/api/tags", timeout=10) as r:
            return [m["name"] for m in json.loads(r.read()).get("models", [])]


PROVIDERS = {"claude": Claude, "gemini": Gemini, "ollama": Ollama, "groq": Groq}
