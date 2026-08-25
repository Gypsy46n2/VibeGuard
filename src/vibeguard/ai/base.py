"""AI provider ABC — INTERFACES.md §10, ARCHITECTURE.md §9.

Three rules hold for everything in this package:

* **AI is always optional.** The whole pipeline runs with ``provider = "null"``; a
  rule that wants a completion and cannot have one degrades to deterministic-only and
  the report says so.
* **A provider never guesses.** :meth:`AIProvider.complete` either returns a real
  completion or raises :class:`AIUnavailable`. It never returns a placeholder that a
  caller could mistake for model output.
* **Nothing leaves the machine silently.** ``is_local`` is a property of the provider,
  not a promise from its configuration, and the single gateway through which
  completions are requested announces every non-local send before it happens.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

__all__ = ["AIProvider", "AIUnavailable", "NullProvider", "LOCAL_HOSTS", "is_local_endpoint"]

#: Hostnames that mean "this machine". ``*.local`` is included because that is what
#: mDNS names a host on the LAN — still the user's own network, never a vendor.
LOCAL_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"})


def is_local_endpoint(endpoint: str | None) -> bool:
    """True when ``endpoint`` resolves, by name, to this machine or the local network.

    Name-based on purpose: a DNS lookup would be a network call, and a hostile
    resolver could make a remote host *look* local. When in doubt the answer is
    ``False``, which is the conservative direction — it makes ``local_only`` refuse a
    provider rather than quietly permit one.
    """
    if not endpoint:
        return False
    text = endpoint.strip()
    if not text:
        return False
    if "//" in text:
        text = text.split("//", 1)[1]
    host = text.split("/", 1)[0].split("@")[-1]
    if host.startswith("["):  # bracketed IPv6 literal
        host = host.split("]", 1)[0] + "]"
    else:
        host = host.split(":", 1)[0]
    host = host.lower()
    return host in LOCAL_HOSTS or host.endswith(".local")


class AIUnavailable(RuntimeError):
    """No completion could be produced — no provider, no key, or no network."""


class AIProvider(ABC):
    """A source of text completions (INTERFACES.md §10)."""

    name: ClassVar[str]
    #: Whether requests stay on this machine. Instance-level: an OpenAI-compatible
    #: provider is local or not depending on the endpoint it was built with.
    is_local: bool = False

    @abstractmethod
    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
        """Return the model's completion, or raise :class:`AIUnavailable`."""

    def available(self) -> bool:
        """True when :meth:`complete` has a chance of succeeding. Never raises."""
        return True

    def describe(self) -> str:
        """One line for ``doctor`` and the report: what this provider will do."""
        where = "local" if self.is_local else "remote — code leaves this machine"
        return f"{self.name} ({where})"


class NullProvider(AIProvider):
    """The default: refuses every completion, so the pipeline stays deterministic."""

    name: ClassVar[str] = "null"
    is_local = True

    def __init__(self, reason: str = "no AI provider is configured") -> None:
        self.reason = reason

    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
        raise AIUnavailable(self.reason)

    def available(self) -> bool:
        return False

    def describe(self) -> str:
        return f"null ({self.reason})"
