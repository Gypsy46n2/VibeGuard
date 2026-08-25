"""VG-API-010 — realtime transports with no heartbeat or backpressure handling."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Evidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    line_at,
    source_files,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["RealtimeWithoutHeartbeatRule"]

_SERVER = re.compile(
    r"websockets\.serve\s*\(|WebSocketServer|new\s+WebSocket\.Server\s*\(|"
    r"new\s+ws\.Server\s*\(|new\s+Server\s*\(\s*\{[^}]*ws|socketio\.(?:Async)?Server\s*\(|"
    r"@\s*\w+\.websocket\s*\(|websocket_route|add_websocket_route|"
    r"EventSourceResponse\s*\(|text/event-stream|StreamingHttpResponse|"
    r"io\s*\(\s*(?:server|httpServer|\d)|require\(['\"]socket\.io['\"]\)"
)
_HEARTBEAT = re.compile(
    r"ping_interval|pingInterval|ping_timeout|pingTimeout|heartbeat|heartbeatInterval|"
    r"keepalive|keepAlive|\bping\s*\(|send_ping|pong|retry:\s*\d",
    re.IGNORECASE,
)
_BACKPRESSURE = re.compile(
    r"max_size|maxPayload|max_queue|maxQueue|bufferedAmount|backpressure|"
    r"write_limit|highWaterMark|drain|max_message_size|maxMessageSize",
    re.IGNORECASE,
)
_RECONNECT = re.compile(
    r"reconnect|reconnection|retry_interval|retryInterval|backoff|onclose.*connect",
    re.IGNORECASE,
)


class RealtimeWithoutHeartbeatRule(Rule):
    """Long-lived connections with no liveness check and no send-queue bound."""

    id: ClassVar[str] = "VG-API-010"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Realtime transport without heartbeat or backpressure handling"
    description: ClassVar[str] = (
        "A WebSocket or Server-Sent-Events server is started with no ping/pong heartbeat "
        "interval, no bound on message size or send-queue depth, and no client-side "
        "reconnect with backoff."
    )
    why_it_matters: ClassVar[str] = (
        "Long-lived connections die silently: a laptop closes its lid or a NAT box drops "
        "the flow, and without heartbeats the server keeps thousands of dead sockets and "
        "their buffers alive until it runs out of memory. Meanwhile a client that reads "
        "slower than you write has no backpressure, so the send queue grows without limit, "
        "and users on a flaky network never come back because nothing reconnects them."
    )
    references: ClassVar[list[str]] = [
        "https://websockets.readthedocs.io/en/stable/topics/keepalive.html",
        "https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events",
    ]
    technologies: ClassVar[set[str]] = {"websockets", "sse"}
    topics: ClassVar[set[str]] = {
        "api.websockets",
        "api.server-sent-events",
        "api.long-polling",
        "api.backpressure",
        "network.websockets",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        server: tuple[str, int, str] | None = None
        heartbeat = backpressure = reconnect = False

        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            text = ctx.read(rel)
            if not text:
                continue
            if server is None:
                match = _SERVER.search(text)
                if match:
                    line = line_at(text, match.start())
                    server = (rel, line, match.group(0).strip()[:200])
            heartbeat = heartbeat or bool(_HEARTBEAT.search(text))
            backpressure = backpressure or bool(_BACKPRESSURE.search(text))
            reconnect = reconnect or bool(_RECONNECT.search(text))

        if server is None:
            return []
        missing = [
            label
            for label, present in (
                ("a ping/pong heartbeat interval", heartbeat),
                ("a max message size or send-queue bound", backpressure),
                ("client reconnect with backoff", reconnect),
            )
            if not present
        ]
        if not missing:
            return []

        rel, line, snippet = server
        return [
            self.make_finding(
                file=rel,
                line=line,
                snippet=snippet,
                description=(
                    f"The realtime server started at {rel}:{line} is missing "
                    + ", ".join(missing)
                    + "."
                ),
                evidence=[
                    Evidence(
                        file=rel,
                        line=line,
                        snippet=snippet,
                        note="searched the whole repo for heartbeat, backpressure, and "
                        "reconnect settings",
                    )
                ],
                recommended_followup=(
                    "Enable heartbeats on the server (`websockets.serve(..., "
                    "ping_interval=20, ping_timeout=20)` or `new WebSocket.Server({ "
                    "clientTracking: true })` plus a ping loop), cap inbound message size "
                    "and the outbound queue, and give the client an exponential-backoff "
                    "reconnect loop."
                ),
            )
        ]
