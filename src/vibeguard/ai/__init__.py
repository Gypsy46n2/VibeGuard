"""AI provider abstraction — ARCHITECTURE.md §9, INTERFACES.md §10.

``AIProvider`` implementations produce text completions; ``AIGateway`` is the single
call site through which the rest of VibeGuard asks for one, so the ``local_only`` gate
and the "code is leaving this machine" notice cannot be bypassed.
"""

from vibeguard.ai.anthropic import AnthropicProvider
from vibeguard.ai.base import (
    LOCAL_HOSTS,
    AIProvider,
    AIUnavailable,
    NullProvider,
    is_local_endpoint,
)
from vibeguard.ai.factory import build_provider, get_provider
from vibeguard.ai.gateway import EXTERNAL_SEND_NOTICE, AIGateway
from vibeguard.ai.openai_compat import OpenAICompatibleProvider

__all__ = [
    "AIGateway",
    "AIProvider",
    "AIUnavailable",
    "AnthropicProvider",
    "EXTERNAL_SEND_NOTICE",
    "LOCAL_HOSTS",
    "NullProvider",
    "OpenAICompatibleProvider",
    "build_provider",
    "get_provider",
    "is_local_endpoint",
]
