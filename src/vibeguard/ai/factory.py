"""Provider selection and the ``local_only`` gate — INTERFACES.md §10.

``get_provider(config)`` is the *only* way the rest of VibeGuard obtains a provider, so
the gate cannot be walked around:

    if local_only and not provider.is_local:  ->  warning event + NullProvider

The refusal is loud (an ``ai.blocked`` event, a warning string on the report) and total:
no rule gets a degraded remote provider, it gets no provider at all.
"""

from __future__ import annotations

import logging

from vibeguard.ai.anthropic import AnthropicProvider
from vibeguard.ai.base import AIProvider, NullProvider
from vibeguard.ai.openai_compat import OpenAICompatibleProvider
from vibeguard.core.config import AIConfig, VibeguardConfig
from vibeguard.core.events import EventBus

__all__ = ["get_provider", "build_provider"]

log = logging.getLogger(__name__)


def build_provider(ai: AIConfig) -> AIProvider:
    """Construct the configured provider, ignoring the ``local_only`` gate."""
    if ai.provider == "anthropic":
        return AnthropicProvider(
            model=ai.model, api_key_env=ai.api_key_env, endpoint=ai.endpoint
        )
    if ai.provider == "openai_compatible":
        return OpenAICompatibleProvider(
            endpoint=ai.endpoint, model=ai.model, api_key_env=ai.api_key_env
        )
    return NullProvider()


def get_provider(
    config: VibeguardConfig, *, events: EventBus | None = None
) -> AIProvider:
    """Return the provider this run may use, enforcing ``local_only``.

    A non-local provider under ``local_only`` is replaced by :class:`NullProvider` and
    announced on the bus as ``ai.blocked``; the run continues deterministically rather
    than failing, because AI is optional by construction (ARCHITECTURE.md §9).
    """
    provider = build_provider(config.ai)
    if config.local_only and not provider.is_local:
        reason = (
            f"--local-only refused the '{provider.name}' provider: it would send code off "
            "this machine. Running deterministic rules only."
        )
        log.warning("%s", reason)
        if events is not None:
            events.emit(
                "ai.blocked",
                provider=provider.name,
                reason=reason,
                local_only=True,
            )
        return NullProvider(reason)
    return provider
