"""Anthropic provider — ARCHITECTURE.md §9.

The ``anthropic`` SDK is an optional dependency (``pip install vibeguard[ai]``) and is
imported lazily, inside the call that needs it: importing this module must never fail
because the SDK is absent, and ``vibeguard doctor`` must be able to report the
provider as unavailable rather than crash.

This provider is **never local**. Every completion it makes sends its prompt to
Anthropic's API, which is why :func:`vibeguard.ai.factory.get_provider` refuses to
build it under ``local_only``.
"""

from __future__ import annotations

import logging
import os
from typing import ClassVar

from vibeguard.ai.base import AIProvider, AIUnavailable

__all__ = ["AnthropicProvider", "DEFAULT_MODEL", "DEFAULT_API_KEY_ENV"]

log = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-sonnet-5"
DEFAULT_API_KEY_ENV = "ANTHROPIC_API_KEY"


class AnthropicProvider(AIProvider):
    """Completions via the Anthropic Messages API."""

    name: ClassVar[str] = "anthropic"
    is_local = False

    def __init__(
        self,
        *,
        model: str | None = None,
        api_key_env: str | None = None,
        endpoint: str | None = None,
    ) -> None:
        self.model = model or DEFAULT_MODEL
        self.api_key_env = api_key_env or DEFAULT_API_KEY_ENV
        self.endpoint = endpoint or None

    # ------------------------------------------------------------- availability
    def api_key(self) -> str | None:
        return os.environ.get(self.api_key_env) or None

    def available(self) -> bool:
        """True when the SDK is importable and an API key is in the environment."""
        if self.api_key() is None:
            return False
        try:
            import anthropic  # noqa: F401
        except Exception:  # pragma: no cover - depends on the environment
            return False
        return True

    def describe(self) -> str:
        if self.api_key() is None:
            return f"anthropic ({self.api_key_env} is not set)"
        return f"anthropic model={self.model} (remote — code leaves this machine)"

    # ---------------------------------------------------------------- completion
    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
        key = self.api_key()
        if key is None:
            raise AIUnavailable(
                f"{self.api_key_env} is not set; export it or set [ai] provider = \"null\""
            )
        try:
            import anthropic
        except Exception as exc:  # pragma: no cover - depends on the environment
            raise AIUnavailable(
                "the `anthropic` package is not installed — `pip install vibeguard[ai]`"
            ) from exc

        kwargs: dict[str, object] = {"api_key": key}
        if self.endpoint:
            kwargs["base_url"] = self.endpoint
        try:
            client = anthropic.Anthropic(**kwargs)  # type: ignore[arg-type]
            message = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
        except Exception as exc:
            raise AIUnavailable(f"anthropic request failed: {type(exc).__name__}: {exc}") from exc
        return _text_of(message)


def _text_of(message: object) -> str:
    """Concatenate the text blocks of a Messages API response."""
    content = getattr(message, "content", None)
    if content is None:
        return ""
    parts: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if text is None and isinstance(block, dict):
            text = block.get("text")
        if isinstance(text, str):
            parts.append(text)
    return "".join(parts)
