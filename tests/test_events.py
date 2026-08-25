from __future__ import annotations

from vibeguard.core.events import EVENT_NAMES, EventBus


def test_emit_delivers_to_matching_subscribers():
    bus = EventBus()
    seen: list[tuple[str, dict]] = []
    bus.subscribe("scan.*", lambda name, payload: seen.append((name, payload)))
    bus.emit("scan.started", repo="/tmp/x")
    bus.emit("repair.started", finding_id="x")
    assert seen == [("scan.started", {"repo": "/tmp/x"})]


def test_wildcard_subscriber_sees_everything():
    bus = EventBus()
    seen: list[str] = []
    bus.subscribe("*", lambda name, _payload: seen.append(name))
    for name in EVENT_NAMES:
        bus.emit(name)
    assert seen == list(EVENT_NAMES)


def test_exact_name_subscription():
    bus = EventBus()
    hits: list[dict] = []
    bus.subscribe("scan.issue_found", lambda _n, payload: hits.append(payload))
    bus.emit("scan.issue_found", finding={"id": "VG-X-001:abc"})
    bus.emit("scan.completed")
    assert hits == [{"finding": {"id": "VG-X-001:abc"}}]


def test_subscriber_exception_does_not_break_emit():
    bus = EventBus()
    delivered: list[str] = []

    def boom(_name: str, _payload: dict) -> None:
        raise RuntimeError("subscriber exploded")

    bus.subscribe("*", boom)
    bus.subscribe("*", lambda name, _p: delivered.append(name))
    bus.emit("scan.completed")
    assert delivered == ["scan.completed"]


def test_unsubscribe():
    bus = EventBus()
    seen: list[str] = []

    fn = bus.subscribe("*", lambda name, _p: seen.append(name))
    bus.emit("scan.started")
    bus.unsubscribe(fn)
    bus.emit("scan.completed")
    assert seen == ["scan.started"]


# --------------------------------------- scan.discovery_progress (D70)


def test_discovery_progress_is_an_extension_event():
    from vibeguard.core.events import ALL_EVENT_NAMES, EVENT_NAMES, EXTENSION_EVENT_NAMES

    assert "scan.discovery_progress" in EXTENSION_EVENT_NAMES
    assert "scan.discovery_progress" in ALL_EVENT_NAMES
    # Additive: the INTERFACES.md §6 contract is untouched.
    assert "scan.discovery_progress" not in EVENT_NAMES


def test_discovery_progress_is_emitted_and_throttled(tmp_path):
    from vibeguard.core.config import VibeguardConfig
    from vibeguard.engine.orchestrator import Engine

    for index in range(40):
        (tmp_path / f"mod{index}.py").write_text(f"VALUE = {index}\n", encoding="utf-8")

    bus = EventBus()
    seen: list[dict] = []
    bus.subscribe("scan.discovery_progress", lambda _n, payload: seen.append(payload))
    stages: list[str] = []
    bus.subscribe("scan.stage", lambda _n, payload: stages.append(payload["stage"]))

    Engine(VibeguardConfig(), events=bus).build_context(tmp_path)

    assert seen, "discovery should report progress"
    assert {"phase", "files", "total", "detail"} <= set(seen[0])
    assert all(p["phase"].startswith("discovery.") for p in seen)
    # Throttled: far fewer events than files walked, across three phases.
    assert len(seen) <= 6
    assert "discovery.files" in stages


def test_subscribers_that_only_know_the_contract_are_unaffected():
    bus = EventBus()
    seen: list[str] = []
    bus.subscribe("scan.stage", lambda name, _p: seen.append(name))
    bus.emit("scan.discovery_progress", phase="discovery.files", files=1, total=None, detail="x")
    bus.emit("scan.stage", stage="detection")
    assert seen == ["scan.stage"]
