"""AI provider abstraction, the local_only gate, and the external-send notice."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from tests.conftest import write_repo

from vibeguard.ai import (
    EXTERNAL_SEND_NOTICE,
    AIGateway,
    AIProvider,
    AIUnavailable,
    AnthropicProvider,
    NullProvider,
    OpenAICompatibleProvider,
    build_provider,
    get_provider,
    is_local_endpoint,
)
from vibeguard.ai.anthropic import DEFAULT_API_KEY_ENV, DEFAULT_MODEL, _text_of
from vibeguard.ai.openai_compat import extract_content
from vibeguard.core.config import AIConfig, VibeguardConfig
from vibeguard.core.events import EventBus
from vibeguard.core.models import AutofixSafety, Category, Confidence, Finding, Severity
from vibeguard.core.registry import RuleRegistry
from vibeguard.core.rule import Rule
from vibeguard.engine.orchestrator import Engine


class FakeProvider(AIProvider):
    """A provider that answers without a network — the only kind tests may use."""

    name = "fake"

    def __init__(self, *, is_local: bool = True, answer: str = "ok") -> None:
        self.is_local = is_local
        self.answer = answer
        self.calls: list[tuple[str, str]] = []
        self.endpoint = "http://localhost:1/v1" if is_local else "https://api.example.com/v1"
        self.model = "fake-1"

    def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
        self.calls.append((system, prompt))
        return self.answer


# --------------------------------------------------------------------- endpoints


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:11434/v1",
        "http://127.0.0.1:1234/v1",
        "http://[::1]:8000/v1",
        "https://workstation.local/v1",
        "http://0.0.0.0:8080",
    ],
)
def test_local_endpoints_are_recognised(endpoint: str):
    assert is_local_endpoint(endpoint) is True


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://api.openai.com/v1",
        "https://localhost.evil.com/v1",
        "http://10.0.0.5:11434/v1",
        "",
        None,
    ],
)
def test_remote_endpoints_are_not_mistaken_for_local(endpoint: str | None):
    assert is_local_endpoint(endpoint) is False


# --------------------------------------------------------------------- providers


def test_the_null_provider_refuses_rather_than_inventing_an_answer():
    provider = NullProvider()
    assert provider.is_local is True
    assert provider.available() is False
    with pytest.raises(AIUnavailable):
        provider.complete("s", "p")


def test_openai_compatible_computes_is_local_from_the_endpoint():
    assert OpenAICompatibleProvider(endpoint="http://localhost:11434/v1").is_local is True
    assert OpenAICompatibleProvider(endpoint="https://api.openai.com/v1").is_local is False
    # An unconfigured provider defaults to Ollama, which is local.
    assert OpenAICompatibleProvider().is_local is True


def test_openai_compatible_builds_the_chat_completions_url():
    provider = OpenAICompatibleProvider(endpoint="http://localhost:11434/v1/")
    assert provider.url == "http://localhost:11434/v1/chat/completions"


def test_openai_compatible_extracts_the_message_content():
    assert extract_content({"choices": [{"message": {"content": "hi"}}]}) == "hi"


@pytest.mark.parametrize(
    "body", [{}, {"choices": []}, {"choices": [{"message": {}}]}, "not json", 3]
)
def test_a_malformed_completion_is_an_error_not_an_empty_string(body: object):
    with pytest.raises(AIUnavailable):
        extract_content(body)


def test_anthropic_is_never_local_and_needs_a_key(monkeypatch):
    monkeypatch.delenv(DEFAULT_API_KEY_ENV, raising=False)
    provider = AnthropicProvider()
    assert provider.is_local is False
    assert provider.model == DEFAULT_MODEL
    assert provider.available() is False
    assert DEFAULT_API_KEY_ENV in provider.describe()
    with pytest.raises(AIUnavailable, match=DEFAULT_API_KEY_ENV):
        provider.complete("s", "p")


def test_anthropic_concatenates_the_text_blocks_of_a_response():
    class Block:
        def __init__(self, text: str) -> None:
            self.text = text

    class Message:
        content = [Block("a"), Block("b")]

    assert _text_of(Message()) == "ab"


# ----------------------------------------------------------------------- factory


def test_the_factory_builds_the_configured_provider():
    assert isinstance(build_provider(AIConfig(provider="null")), NullProvider)
    assert isinstance(build_provider(AIConfig(provider="anthropic")), AnthropicProvider)
    assert isinstance(
        build_provider(AIConfig(provider="openai_compatible")), OpenAICompatibleProvider
    )


def test_local_only_refuses_a_remote_provider_and_says_so():
    bus = EventBus()
    seen: list[tuple[str, dict]] = []
    bus.subscribe("*", lambda name, payload: seen.append((name, payload)))
    config = VibeguardConfig(local_only=True, ai=AIConfig(provider="anthropic"))

    provider = get_provider(config, events=bus)

    assert isinstance(provider, NullProvider)
    assert [name for name, _ in seen] == ["ai.blocked"]
    assert "--local-only" in seen[0][1]["reason"]


def test_local_only_leaves_a_local_provider_alone():
    config = VibeguardConfig(
        local_only=True,
        ai=AIConfig(provider="openai_compatible", endpoint="http://localhost:11434/v1"),
    )
    provider = get_provider(config)
    assert isinstance(provider, OpenAICompatibleProvider)
    assert provider.is_local is True


# ----------------------------------------------------------------------- gateway


def test_a_local_completion_is_not_announced():
    stream = io.StringIO()
    bus = EventBus()
    names: list[str] = []
    bus.subscribe("*", lambda name, _payload: names.append(name))
    gateway = AIGateway(FakeProvider(is_local=True), events=bus, stream=stream)

    assert gateway.complete("sys", "prompt") == "ok"
    assert gateway.used is True
    assert stream.getvalue() == ""
    assert "ai.external_send" not in names


def test_a_remote_completion_is_announced_before_it_is_sent():
    stream = io.StringIO()
    bus = EventBus()
    payloads: list[dict] = []
    bus.subscribe("ai.external_send", lambda _name, payload: payloads.append(payload))
    provider = FakeProvider(is_local=False)
    gateway = AIGateway(provider, events=bus, stream=stream)

    gateway.complete("sys", "prompt")

    assert payloads and payloads[0]["provider"] == "fake"
    assert payloads[0]["characters"] == len("sys") + len("prompt")
    notice = stream.getvalue()
    assert EXTERNAL_SEND_NOTICE in notice
    assert "--local-only" in notice
    assert gateway.external_sends == 1


def test_the_notice_precedes_the_request():
    """The announcement is worthless if it lands after the code has already gone."""
    order: list[str] = []
    stream = io.StringIO()

    class Recording(FakeProvider):
        def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
            order.append("sent")
            return "ok"

    bus = EventBus()
    bus.subscribe("ai.external_send", lambda *_: order.append("announced"))
    AIGateway(Recording(is_local=False), events=bus, stream=stream).complete("s", "p")

    assert order == ["announced", "sent"]


def test_an_unavailable_provider_never_counts_as_ai_used():
    gateway = AIGateway(NullProvider(), stream=io.StringIO())
    assert gateway.available is False
    assert gateway.try_complete("s", "p") is None
    assert gateway.used is False
    assert gateway.last_error
    assert "deterministic-only" in gateway.degraded_note()


def test_a_failing_provider_does_not_claim_ai_was_used():
    class Broken(FakeProvider):
        def complete(self, system: str, prompt: str, max_tokens: int = 4096) -> str:
            raise AIUnavailable("upstream is down")

    gateway = AIGateway(Broken(), stream=io.StringIO())
    assert gateway.try_complete("s", "p") is None
    assert gateway.used is False


# ------------------------------------------------------------------ engine wiring


class AIOnlyRule(Rule):
    id = "VG-TEST-AI1"
    category = Category.MAINTAINABILITY
    severity = Severity.LOW
    confidence = Confidence.LOW
    title = "needs a model"
    description = "d"
    why_it_matters = "w"
    autofix_safety = AutofixSafety.INFORMATIONAL
    requires_ai = True
    topics: set[str] = set()

    def detect(self, ctx) -> list[Finding]:
        assert ctx.ai_available(), "an AI rule must never run without a provider"
        return [self.make_finding(file="app.py", line=1, snippet=ctx.ai.complete("s", "p"))]


def _repo(tmp_path: Path) -> Path:
    return write_repo(tmp_path, {"app.py": "x = 1\n"})


def _engine_with(rule: type[Rule], gateway: AIGateway, **kwargs) -> Engine:
    registry = RuleRegistry()
    registry.register("test", rule)
    return Engine(registry=registry, ai=gateway, **kwargs)


def test_ai_rules_are_skipped_and_the_report_says_the_scan_was_degraded(tmp_path: Path):
    engine = _engine_with(AIOnlyRule, AIGateway(NullProvider(), stream=io.StringIO()))
    report = engine.audit(_repo(tmp_path))

    assert report.findings == []
    assert report.ai_used is False
    assert any("did not run" in warning for warning in report.warnings)
    assert "VG-TEST-AI1" in " ".join(report.warnings)


def test_ai_rules_run_when_a_provider_is_available(tmp_path: Path):
    gateway = AIGateway(FakeProvider(answer="model said so"), stream=io.StringIO())
    report = _engine_with(AIOnlyRule, gateway).audit(_repo(tmp_path))

    assert [f.rule_id for f in report.findings] == ["VG-TEST-AI1"]
    assert report.ai_used is True
    assert report.warnings == []


def test_ai_used_is_false_when_the_provider_was_configured_but_never_called(tmp_path: Path):
    gateway = AIGateway(FakeProvider(), stream=io.StringIO())
    report = Engine(ai=gateway).audit(_repo(tmp_path))
    assert report.ai_used is False


def test_a_remote_provider_makes_the_report_say_local_only_is_false(tmp_path: Path):
    gateway = AIGateway(FakeProvider(is_local=False), stream=io.StringIO())
    report = Engine(ai=gateway).audit(_repo(tmp_path))
    assert report.local_only is False
