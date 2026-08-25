"""OpenAI-compatible provider — one adapter for four ecosystems.

``POST {endpoint}/chat/completions`` is the lingua franca: OpenAI itself, Ollama
(``http://localhost:11434/v1``), LM Studio (``http://localhost:1234/v1``), vLLM, and
most agent gateways all speak it. Rather than depend on a vendor SDK we make the plain
HTTP call with ``httpx``, so the same code path covers all of them and there is exactly
one place where a request leaves the process.

``is_local`` is **computed from the endpoint**, never configured: a provider pointed at
``localhost``/``127.0.0.1``/``::1``/``*.local`` keeps the code on the machine, and
anything else does not — regardless of what the config file would like to believe.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, ClassVar

from vibeguard.ai.base import AIProvider, AIUnavailable, is_local_endpoint

__all__ = ["OpenAICompatibleProvider", "DEFAULT_ENDPOINT", "DEFAULT_MODEL", "DEFAULT_TIMEOUT"]

log = logging.getLogger(__name__)

#: Ollama's OpenAI-compatible surface — the local default, so an unconfigured
#: ``openai_compatible`` provider is a *local* one.
DEFAULT_ENDPOINT = "http://localhost:11434/v1"
DEFAULT_MODEL = "llama3.1"
DEFAULT_TIMEOUT = 120.0


class OpenAICompatibleProvider(AIProvider):
    """Chat completions over the OpenAI wire format."""

    name: ClassVar[str] = "openai_compatible"

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        model: str | None = None,
        api_key_env: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.endpoint = (endpoint or DEFAULT_ENDPOINT).rstrip("/")
        self.model = model or DEFAULT_MODEL
        self.api_key_env = api_key_env or None
        self.timeout = timeout
        self.is_local = is_local_endpoint(self.endpoint)

    # ------------------------------------------------------------- availability
    def api_key(self) -> str | None:
        if not self.api_key_env:
            return None
        return os.environ.get(self.api_key_env) or None

    def available(self) -> bool:
        """True when ``httpx`` is importable. The endpoint is not probed.

        Probing would mean a network call during ``doctor``, which is exactly the kind
        of surprise this package exists to avoid.
        """
        try:
            import httpx  # noqa: F401
        except Exception:  # pragma: no cover - depends on the environment
            return False
        return True

    def describe(self) -> str:
        where = "local" if self.is_local else "remote — code leaves this machine"
        return f"openai_compatible endpoint={self.endpoint} model={self.model} ({where})"

    @property
    def url(self) -> str:
        return f"{self.endpoint}/chat/completions"

    # ---------------------------------------------------------------- completion
    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
        try:
            import httpx
        except Exception as exc:  # pragma: no cover - depends on the environment
            raise AIUnavailable(
                "the `httpx` package is not installed — `pip install vibeguard[ai]`"
            ) from exc

        headers = {"content-type": "application/json"}
        key = self.api_key()
        if key:
            headers["authorization"] = f"Bearer {key}"
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
        }
        try:
            response = httpx.post(
                self.url, headers=headers, json=payload, timeout=self.timeout
            )
            response.raise_for_status()
            body = response.json()
        except Exception as exc:
            raise AIUnavailable(
                f"{self.url} did not answer: {type(exc).__name__}: {exc}"
            ) from exc
        return extract_content(body)


def extract_content(body: Any) -> str:
    """Pull ``choices[0].message.content`` out of an OpenAI-shaped response."""
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except ValueError as exc:
            raise AIUnavailable("provider returned a non-JSON body") from exc
    if not isinstance(body, dict):
        raise AIUnavailable("provider returned a non-object body")
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise AIUnavailable(f"provider returned no choices: {str(body)[:200]}")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise AIUnavailable("provider returned a choice with no text content")
    return content
