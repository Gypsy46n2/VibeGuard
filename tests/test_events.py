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
