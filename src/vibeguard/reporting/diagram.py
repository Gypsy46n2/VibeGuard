"""Diagrams for the report — a picture of the app, and of how healthy it is.

Four renderers, all pure stdlib and all deterministic:

``mermaid_architecture``
    The :class:`~vibeguard.core.models.ArchitectureGraph` as a ``flowchart LR``, for
    the markdown report (GitHub and GitLab render mermaid natively).
``svg_architecture``
    The same graph as inline SVG, hand-laid out in columns, for the HTML report.
``svg_scores``
    The category dashboard as a horizontal bar chart.
``svg_checklist``
    One stacked bar per checklist section, plus an "all sections" total.

Every SVG has a fixed ``viewBox``, inline presentation attributes only, dark text on a
light ground, no script, no external font and no external reference of any kind — the
HTML report must keep rendering with JavaScript disabled and with no network.

Health colouring
----------------

Each architecture node is coloured by the one category score that says the most about
it. The mapping is deliberately coarse — this is a glance, not an audit:

======================================  ============================
node kind                               score used
======================================  ============================
``database``                            ``database``
``cache``                               ``performance``
``broker``, ``queue``, ``worker``       ``reliability``
``external``                            ``api``
``entrypoint``, ``gateway``, ``client`` ``api``
``service``, ``app``, anything else     the overall readiness score
======================================  ============================

Scores come from ``scores_after``/``overall_after`` when the run repaired anything, so
a fix run shows the repaired state; otherwise from the ``_before`` pair. A node whose
category has no applicable rules — or a report with no scores at all — is drawn
neutral rather than green: we did not measure it, so we do not claim it is fine.

Bands: ``ok`` at 85 and above, ``warn`` from 60 to 84, ``bad`` below 60.
"""

from __future__ import annotations

from collections.abc import Sequence
from html import escape

from vibeguard.core.models import (
    ArchEdge,
    ArchitectureGraph,
    ArchNode,
    Category,
    ChecklistStatus,
    ScanReport,
)
from vibeguard.reporting.common import section_rollup

__all__ = [
    "MAX_NODES",
    "graph_is_trivial",
    "health_class",
    "mermaid_architecture",
    "node_health",
    "svg_architecture",
    "svg_checklist",
    "svg_scores",
]

#: Nodes drawn before the diagram collapses the rest into an "and N more…" node.
MAX_NODES = 30

OK_FLOOR = 85
WARN_FLOOR = 60

# ------------------------------------------------------------------- palettes

#: fill, stroke, text — one entry per health band. Light ground, dark text.
_HEALTH_COLOURS: dict[str, tuple[str, str, str]] = {
    "ok": ("#e4f4ea", "#1a7f4b", "#12281c"),
    "warn": ("#fbf1d8", "#b8860b", "#3a2e08"),
    "bad": ("#fae3e3", "#b21b1b", "#3a1010"),
    "unknown": ("#f1f4f7", "#8a939c", "#22262a"),
}

_STATUS_COLOURS: dict[ChecklistStatus, str] = {
    ChecklistStatus.PASS: "#1a7f4b",
    ChecklistStatus.FIXED: "#4bbd7f",
    ChecklistStatus.FAIL: "#b21b1b",
    ChecklistStatus.REVIEW_REQUIRED: "#c8951a",
    ChecklistStatus.NOT_APPLICABLE: "#9aa4ae",
}

_INK = "#1b1f24"
_MUTED = "#5b6570"
_LINE = "#c9d1d9"
_TRACK = "#e8ecf0"

# --------------------------------------------------------------------- layout

#: Column each node kind is laid out in, left to right.
_ENTRYPOINT_KINDS = frozenset({"entrypoint", "gateway", "ingress", "client", "user"})
_APP_KINDS = frozenset({"app", "service", "worker", "frontend", "backend"})
_DATA_KINDS = frozenset({"database", "cache", "broker", "queue", "storage"})
_EXTERNAL_KINDS = frozenset({"external", "external_service", "third_party", "saas"})

_COLUMN_TITLES = ("entrypoints", "app / services", "data & infrastructure", "external")

#: Category whose score colours each node kind. Absent → the overall score.
_KIND_CATEGORY: dict[str, Category] = {
    "database": Category.DATABASE,
    "storage": Category.DATABASE,
    "cache": Category.PERFORMANCE,
    "broker": Category.RELIABILITY,
    "queue": Category.RELIABILITY,
    "worker": Category.RELIABILITY,
    "external": Category.API,
    "external_service": Category.API,
    "third_party": Category.API,
    "saas": Category.API,
    "entrypoint": Category.API,
    "gateway": Category.API,
    "ingress": Category.API,
    "client": Category.API,
    "user": Category.API,
}


def _column_of(kind: str) -> int:
    kind = kind.lower()
    if kind in _ENTRYPOINT_KINDS:
        return 0
    if kind in _DATA_KINDS:
        return 2
    if kind in _EXTERNAL_KINDS:
        return 3
    if kind in _APP_KINDS:
        return 1
    return 1  # anything we do not recognise sits with the application


# --------------------------------------------------------------------- health


def health_class(score: int | None) -> str:
    """``ok`` / ``warn`` / ``bad`` for a score, ``unknown`` when there is none."""
    if score is None:
        return "unknown"
    if score >= OK_FLOOR:
        return "ok"
    if score >= WARN_FLOOR:
        return "warn"
    return "bad"


def _effective_scores(report: ScanReport) -> tuple[dict[Category, int], int | None]:
    """The score set a diagram should colour by: after a fix run, before otherwise."""
    if report.scores_after:
        scores, overall = report.scores_after, report.overall_after
    else:
        scores, overall = report.scores_before, report.overall_before
    if not scores:
        # Nothing was scored (a discovery-only `vibeguard graph`, say). Neutral, not
        # green: an unmeasured node must never look like a passing one.
        return {}, None
    return {score.category: score.score for score in scores if score.applicable}, overall


def node_health(report: ScanReport, node: ArchNode) -> tuple[str, int | None]:
    """The health band and score for one node — see the module docstring's table."""
    by_category, overall = _effective_scores(report)
    category = _KIND_CATEGORY.get(node.kind.lower())
    score = by_category.get(category) if category is not None else overall
    return health_class(score), score


def graph_is_trivial(graph: ArchitectureGraph) -> bool:
    """True when there is nothing worth drawing: at most one node and no edges."""
    return len(graph.nodes) <= 1 and not graph.edges


def _visible(graph: ArchitectureGraph) -> tuple[list[ArchNode], list[ArchEdge], int]:
    """Nodes within :data:`MAX_NODES`, the edges between them, and the overflow count."""
    kept = list(graph.nodes[:MAX_NODES])
    dropped = len(graph.nodes) - len(kept)
    ids = {node.id for node in kept}
    edges = [edge for edge in graph.edges if edge.src in ids and edge.dst in ids]
    return kept, edges, dropped


# -------------------------------------------------------------------- mermaid

#: Characters that would otherwise end a mermaid node label or start a new shape.
#: ``#`` goes first — its replacement introduces every other escape.
_MERMAID_ESCAPES: tuple[tuple[str, str], ...] = (
    ("#", "#35;"),
    ('"', "#quot;"),
    ("[", "#91;"),
    ("]", "#93;"),
    ("(", "#40;"),
    (")", "#41;"),
    ("{", "#123;"),
    ("}", "#125;"),
    ("<", "#60;"),
    (">", "#62;"),
    ("|", "#124;"),
    ("\\", "#92;"),
    ("`", "#96;"),
    ("&", "#38;"),
)

_MERMAID_SHAPES: dict[str, tuple[str, str]] = {
    "database": ('[("', '")]'),
    "storage": ('[("', '")]'),
    "cache": ('[("', '")]'),
    "broker": ('{{"', '"}}'),
    "queue": ('{{"', '"}}'),
    "worker": ('[["', '"]]'),
    "external": ('(["', '"])'),
    "external_service": ('(["', '"])'),
    "entrypoint": ('(("', '"))'),
    "gateway": ('(("', '"))'),
    "client": ('(("', '"))'),
    "user": ('(("', '"))'),
}
_DEFAULT_SHAPE = ('["', '"]')


def _mermaid_text(text: str) -> str:
    """Neutralise every character mermaid would read as syntax."""
    flat = " ".join(str(text).split())
    for char, replacement in _MERMAID_ESCAPES:
        flat = flat.replace(char, replacement)
    return flat or "unnamed"


def mermaid_architecture(report: ScanReport) -> str:
    """The architecture graph as a mermaid ``flowchart LR`` block (no fences)."""
    nodes, edges, dropped = _visible(report.graph)
    slot = {node.id: f"n{index}" for index, node in enumerate(nodes)}

    lines = ["flowchart LR"]
    banded: dict[str, list[str]] = {band: [] for band in _HEALTH_COLOURS}
    for column, title in enumerate(_COLUMN_TITLES):
        members = [node for node in nodes if _column_of(node.kind) == column]
        if not members:
            continue
        lines.append(f'  subgraph g{column}["{_mermaid_text(title)}"]')
        lines.append("    direction TB")
        for node in members:
            open_shape, close_shape = _MERMAID_SHAPES.get(node.kind.lower(), _DEFAULT_SHAPE)
            label = _mermaid_text(node.label or node.id)
            lines.append(f"    {slot[node.id]}{open_shape}{label}{close_shape}")
            banded[node_health(report, node)[0]].append(slot[node.id])
        lines.append("  end")

    if dropped:
        lines.append(f'  overflow["and {dropped} more#8230;"]')
        banded["unknown"].append("overflow")

    for edge in edges:
        label = _mermaid_text(edge.kind)
        lines.append(f"  {slot[edge.src]} -->|{label}| {slot[edge.dst]}")

    for band, (fill, stroke, ink) in _HEALTH_COLOURS.items():
        lines.append(f"  classDef {band} fill:{fill},stroke:{stroke},color:{ink};")
    for band, members in banded.items():
        if members:
            lines.append(f"  class {','.join(members)} {band};")
    return "\n".join(lines)


# ------------------------------------------------------------------ SVG parts


def _svg(width: int, height: int, title: str, body: Sequence[str]) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" height="auto" role="img" aria-label="{escape(title, quote=True)}" '
        'font-family="-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, '
        'Arial, sans-serif">'
        f"<title>{escape(title)}</title>"
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#ffffff"/>'
        + "".join(body)
        + "</svg>"
    )


def _text(
    x: float,
    y: float,
    value: str,
    *,
    size: float = 11,
    fill: str = _INK,
    anchor: str = "start",
    weight: str = "normal",
) -> str:
    return (
        f'<text x="{_n(x)}" y="{_n(y)}" font-size="{_n(size)}" fill="{fill}" '
        f'text-anchor="{anchor}" font-weight="{weight}">{escape(value)}</text>'
    )


def _n(value: float) -> str:
    """A short, locale-free number — keeps the SVG byte-stable across runs."""
    return f"{value:.2f}".rstrip("0").rstrip(".") if isinstance(value, float) else str(value)


def _rect(x: float, y: float, w: float, h: float, fill: str, stroke: str = "", r: float = 0) -> str:
    stroke_attr = f' stroke="{stroke}"' if stroke else ""
    radius = f' rx="{_n(r)}"' if r else ""
    return (
        f'<rect x="{_n(x)}" y="{_n(y)}" width="{_n(w)}" height="{_n(h)}" '
        f'fill="{fill}"{stroke_attr}{radius}/>'
    )


def _clip(value: str, limit: int) -> str:
    value = " ".join(str(value).split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _health_legend(x: float, y: float) -> list[str]:
    parts: list[str] = []
    labels = (
        ("ok", "healthy (85+)"),
        ("warn", "watch (60-84)"),
        ("bad", "at risk (<60)"),
        ("unknown", "not scored"),
    )
    for band, caption in labels:
        fill, stroke, _ = _HEALTH_COLOURS[band]
        parts.append(_rect(x, y - 8, 11, 11, fill, stroke, 2))
        parts.append(_text(x + 16, y + 1, caption, size=10, fill=_MUTED))
        x += 16 + 6.2 * len(caption) + 16
    return parts


# ---------------------------------------------------------- SVG architecture

_ARCH_WIDTH = 880
_BOX_W = 176
_BOX_H = 46
_ROW_GAP = 16
_COL_X = (24, 240, 456, 672)
_ARCH_TOP = 86


def svg_architecture(report: ScanReport) -> str:
    """The architecture graph as a deterministic four-column inline SVG."""
    nodes, edges, dropped = _visible(report.graph)
    columns: list[list[tuple[ArchNode, str]]] = [[], [], [], []]
    for node in nodes:
        band, _ = node_health(report, node)
        columns[_column_of(node.kind)].append((node, band))
    if dropped:
        columns[3].append((ArchNode(id="__overflow__", kind="", label=f"and {dropped} more…"),
                           "unknown"))

    placed: dict[str, tuple[float, float]] = {}
    for index, column in enumerate(columns):
        for row, (node, _) in enumerate(column):
            placed[node.id] = (_COL_X[index], _ARCH_TOP + row * (_BOX_H + _ROW_GAP))

    rows = max((len(column) for column in columns), default=0)
    height = _ARCH_TOP + max(rows, 1) * (_BOX_H + _ROW_GAP) + 46

    body: list[str] = [
        _text(24, 26, "Architecture", size=15, weight="bold"),
        _text(
            24,
            44,
            f"{len(report.graph.nodes)} node(s), {len(report.graph.edges)} edge(s), "
            "coloured by the category score that governs each one",
            size=10,
            fill=_MUTED,
        ),
    ]
    body.extend(_health_legend(24, height - 20))

    for index, title in enumerate(_COLUMN_TITLES):
        if columns[index]:
            body.append(_text(_COL_X[index], _ARCH_TOP - 14, title, size=10, fill=_MUTED))

    # Edges first, so boxes paint over their ends.
    body.append(
        '<defs><marker id="vg-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" '
        'markerHeight="7" orient="auto"><path d="M0 0 L8 4 L0 8 z" fill="#8a939c"/>'
        "</marker></defs>"
    )
    for edge in edges:
        start, end = placed.get(edge.src), placed.get(edge.dst)
        if start is None or end is None:
            continue
        x1, y1 = start[0] + _BOX_W, start[1] + _BOX_H / 2
        x2, y2 = end[0], end[1] + _BOX_H / 2
        if x2 <= x1:  # same or earlier column: skirt underneath rather than backwards
            x2 = end[0] + _BOX_W
            body.append(
                f'<path d="M{_n(x1)} {_n(y1)} H{_n(x1 + 18)} V{_n(y2)} H{_n(x2 + 18)} '
                f'V{_n(y2)}" fill="none" stroke="{_LINE}" stroke-width="1.2" '
                'marker-end="url(#vg-arrow)"/>'
            )
            continue
        mid = (x1 + x2) / 2
        body.append(
            f'<path d="M{_n(x1)} {_n(y1)} H{_n(mid)} V{_n(y2)} H{_n(x2)}" fill="none" '
            f'stroke="{_LINE}" stroke-width="1.2" marker-end="url(#vg-arrow)"/>'
        )
        if edge.kind:
            body.append(
                _text(mid, min(y1, y2) - 4, _clip(edge.kind, 18), size=9, fill=_MUTED,
                      anchor="middle")
            )

    for column in columns:
        for node, band in column:
            x, y = placed[node.id]
            fill, stroke, ink = _HEALTH_COLOURS[band]
            body.append(_rect(x, y, _BOX_W, _BOX_H, fill, stroke, 8))
            body.append(_text(x + 10, y + 20, _clip(node.label or node.id, 24), size=12,
                              fill=ink, weight="bold"))
            if node.kind:
                body.append(_text(x + 10, y + 35, _clip(node.kind, 24), size=9, fill=_MUTED))

    return _svg(_ARCH_WIDTH, int(height), "Architecture diagram", body)


# ---------------------------------------------------------------- SVG scores

_SCORE_WIDTH = 880
_SCORE_LABEL_W = 150
_SCORE_BAR_X = 166
_SCORE_BAR_W = 600
_SCORE_ROW_H = 24


def svg_scores(report: ScanReport) -> str:
    """Category scores as horizontal bars, with after-markers on a fix run."""
    scores = list(report.scores_before)
    after = {score.category: score.score for score in (report.scores_after or [])}
    height = 68 + max(len(scores), 1) * _SCORE_ROW_H + 26
    heading = f"Category scores — overall {report.overall_before}/100"
    if report.overall_after is not None:
        heading += f" → {report.overall_after}/100 after repairs"

    body: list[str] = [
        _text(24, 26, "Category scores", size=15, weight="bold"),
        _text(24, 44, heading, size=10, fill=_MUTED),
    ]
    if not scores:
        body.append(_text(24, 70, "no category scores were computed", size=11, fill=_MUTED))
        return _svg(_SCORE_WIDTH, 90, "Category scores", body)

    y = 68
    for score in scores:
        centre = y + _SCORE_ROW_H / 2
        body.append(_text(24, centre + 3, _clip(score.category.value, 22), size=11))
        body.append(_rect(_SCORE_BAR_X, y + 5, _SCORE_BAR_W, 12, _TRACK, "", 6))
        if score.applicable:
            band = health_class(score.score)
            fill, stroke, _ = _HEALTH_COLOURS[band]
            width = max(2.0, _SCORE_BAR_W * max(0, min(100, score.score)) / 100)
            body.append(_rect(_SCORE_BAR_X, y + 5, width, 12, stroke, "", 6))
            body.append(_text(_SCORE_BAR_X + _SCORE_BAR_W + 10, centre + 3,
                              str(score.score), size=11))
            later = after.get(score.category)
            if later is not None:
                marker = _SCORE_BAR_X + _SCORE_BAR_W * max(0, min(100, later)) / 100
                body.append(_rect(marker - 1.5, y + 1, 3, 20, _INK, "", 1))
                body.append(_text(_SCORE_BAR_X + _SCORE_BAR_W + 40, centre + 3,
                                  f"→ {later}", size=10, fill=_MUTED))
        else:
            body.append(_text(_SCORE_BAR_X + 8, centre + 3, "no applicable rules", size=10,
                              fill=_MUTED))
        y += _SCORE_ROW_H

    body.extend(_health_legend(24, height - 14))
    if after:
        body.append(
            _text(_SCORE_BAR_X + _SCORE_BAR_W - 150, height - 14,
                  "▮ marks the score after repairs", size=10, fill=_MUTED)
        )
    return _svg(_SCORE_WIDTH, int(height), "Category scores", body)


# ------------------------------------------------------------- SVG checklist

_CHECK_WIDTH = 880
_CHECK_BAR_X = 230
_CHECK_BAR_W = 480
_CHECK_ROW_H = 22


def svg_checklist(report: ScanReport) -> str:
    """One stacked bar per checklist section, plus an all-sections total."""
    rollup = section_rollup(report.checklist)
    body: list[str] = [
        _text(24, 26, "Checklist coverage", size=15, weight="bold"),
        _text(24, 44, f"{len(report.checklist)} topics across {len(rollup)} sections", size=10,
              fill=_MUTED),
    ]
    if not rollup:
        body.append(_text(24, 70, "no checklist was produced for this scan", size=11,
                          fill=_MUTED))
        return _svg(_CHECK_WIDTH, 90, "Checklist coverage", body)

    totals = dict.fromkeys(ChecklistStatus, 0)
    for _, counts in rollup:
        for status, count in counts.items():
            totals[status] += count
    rows: list[tuple[str, dict[ChecklistStatus, int]]] = [*rollup, ("all sections", totals)]
    height = 74 + len(rows) * _CHECK_ROW_H + 40

    y = 68
    for index, (section, counts) in enumerate(rows):
        total = sum(counts.values()) or 1
        if index == len(rows) - 1:
            y += 8
            body.append(_rect(24, y - 6, _CHECK_WIDTH - 48, 1, _LINE))
        centre = y + _CHECK_ROW_H / 2
        body.append(
            _text(24, centre + 3, _clip(section, 34), size=11,
                  weight="bold" if index == len(rows) - 1 else "normal")
        )
        x = _CHECK_BAR_X
        body.append(_rect(_CHECK_BAR_X, y + 4, _CHECK_BAR_W, 13, _TRACK))
        for status in ChecklistStatus:
            count = counts[status]
            if not count:
                continue
            width = _CHECK_BAR_W * count / total
            body.append(_rect(x, y + 4, width, 13, _STATUS_COLOURS[status]))
            x += width
        body.append(
            _text(_CHECK_BAR_X + _CHECK_BAR_W + 10, centre + 3,
                  " · ".join(f"{s.value} {counts[s]}" for s in ChecklistStatus if counts[s])
                  or "—",
                  size=9, fill=_MUTED)
        )
        y += _CHECK_ROW_H

    legend_x = 24.0
    for status in ChecklistStatus:
        body.append(_rect(legend_x, height - 26, 11, 11, _STATUS_COLOURS[status]))
        body.append(_text(legend_x + 16, height - 17, status.value, size=10, fill=_MUTED))
        legend_x += 16 + 6.2 * len(status.value) + 16
    return _svg(_CHECK_WIDTH, int(height), "Checklist coverage", body)
