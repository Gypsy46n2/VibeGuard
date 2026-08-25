"""The single place a completion is requested — and the only place code can leave.

Every AI-assisted code path goes through :meth:`AIGateway.complete`. That gives us one
choke point at which to keep three promises:

* **Announce before sending.** A non-local provider gets an ``ai.external_send`` event
  and a printed notice *before* the request is made, naming the provider, the endpoint,
  and how much text is about to go — ARCHITECTURE.md §9's "any time code would leave
  the machine, the CLI says so explicitly before sending".
* **Report truthfully.** ``ScanReport.ai_used`` is set from :attr:`AIGateway.used`,
  which only becomes true after a completion actually came back. A configured provider
  that was never called, or that failed, does not count as "AI used".
* **Degrade, never crash.** :meth:`try_complete` returns ``None`` when no completion is
  possible and records why, so a caller can fall back to deterministic behaviour.
"""

from __future__ import annotations

import logging
import sys
from typing import TextIO

from vibeguard.ai.base import AIProvider, AIUnavailable, NullProvider
from vibeguard.ai.factory import get_provider
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.events import EventBus

__all__ = ["AIGateway", "EXTERNAL_SEND_NOTICE"]

log = logging.getLogger(__name__)

EXTERNAL_SEND_NOTICE = "vibeguard: sending code to a remote AI provider"


class AIGateway:
    """Owns the provider, the notice, and the truth about whether AI was used."""

    def __init__(
        self,
        provider: AIProvider,
        *,
        events: EventBus | None = None,
        stream: TextIO | None = None,
        notify: bool = True,
    ) -> None:
        self.provider = provider
        self.events = events or EventBus()
        #: Where the "code is leaving this machine" notice is printed. stderr by
        #: default, so it never contaminates ``--output json`` on stdout.
        self.stream = stream if stream is not None else sys.stderr
        self.notify = notify
        #: True once a completion has actually been returned by the provider.
        self.used = False
        #: Number of prompts sent to a non-local provider.
        self.external_sends = 0
        #: Why the last completion was not possible (for the report).
        self.last_error: str = ""

    # ------------------------------------------------------------- availability
    @classmethod
    def from_config(
        cls,
        config: VibeguardConfig,
        *,
        events: EventBus | None = None,
        stream: TextIO | None = None,
    ) -> AIGateway:
        """Build the gateway for a run, applying the ``local_only`` gate."""
        bus = events or EventBus()
        return cls(get_provider(config, events=bus), events=bus, stream=stream)

    @property
    def available(self) -> bool:
        """True when a completion could plausibly be produced right now."""
        if isinstance(self.provider, NullProvider):
            return False
        try:
            return bool(self.provider.available())
        except Exception:  # pragma: no cover - a provider probe must never crash a scan
            log.debug("provider %s availability probe failed", self.provider.name, exc_info=True)
            return False

    @property
    def is_local(self) -> bool:
        return bool(self.provider.is_local)

    def describe(self) -> str:
        return self.provider.describe()

    def degraded_note(self) -> str:
        """The sentence a report uses to explain why AI-backed rules did not run."""
        if self.available:
            return ""
        return (
            f"AI-assisted rules degraded to deterministic-only: {self.provider.describe()}."
        )

    # ---------------------------------------------------------------- completion
    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
        """Request a completion, announcing the send first when it leaves the machine."""
        if not self.available:
            raise AIUnavailable(self.provider.describe())
        if not self.is_local:
            self._announce(len(system) + len(prompt))
        result = self.provider.complete(system, prompt, max_tokens=max_tokens)
        self.used = True
        return result

    def try_complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str | None:
        """:meth:`complete`, but ``None`` instead of an exception when unavailable."""
        try:
            return self.complete(system, prompt, max_tokens=max_tokens)
        except AIUnavailable as exc:
            self.last_error = str(exc)
            log.info("AI completion unavailable: %s", exc)
            return None

    # -------------------------------------------------------------------- notice
    def _announce(self, characters: int) -> None:
        endpoint = getattr(self.provider, "endpoint", None) or self.provider.name
        self.external_sends += 1
        self.events.emit(
            "ai.external_send",
            provider=self.provider.name,
            endpoint=str(endpoint),
            characters=characters,
            model=str(getattr(self.provider, "model", "") or ""),
        )
        if not self.notify or self.stream is None:
            return
        try:
            self.stream.write(
                f"{EXTERNAL_SEND_NOTICE}: {self.provider.name} ({endpoint}) — "
                f"{characters} characters of your code and findings are being sent now. "
                "Use --local-only to forbid this.\n"
            )
            self.stream.flush()
        except Exception:  # pragma: no cover - a closed stream must not break a scan
            log.debug("could not print the external-send notice", exc_info=True)
