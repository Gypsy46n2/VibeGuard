"""Report writing — the one place that turns a :class:`ScanReport` into files.

``vibeguard-report.json`` is canonical (INTERFACES.md §8) and is always written; the
markdown and HTML documents are rendered from exactly the same object, so the three
can never disagree. Writing happens here rather than in the engine so that library
embedders keep a pure ``Engine(config).audit(path)`` (DECISIONS.md D8).
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from vibeguard.core.events import EventBus
from vibeguard.core.models import ScanReport
from vibeguard.reporting.html import HTML_FILENAME, write_html
from vibeguard.reporting.markdown import MARKDOWN_FILENAME, write_markdown

__all__ = [
    "HTML_FILENAME",
    "JSON_FILENAME",
    "MARKDOWN_FILENAME",
    "RENDERED_FORMATS",
    "write_json",
    "write_reports",
]

JSON_FILENAME = "vibeguard-report.json"

#: Formats ``--output`` can request a file for.
RENDERED_FORMATS: tuple[str, ...] = ("json", "md", "html")


def write_json(report: ScanReport, root: str | Path) -> Path:
    """Write the canonical JSON report and return its path."""
    destination = Path(root) / JSON_FILENAME
    destination.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return destination


def write_reports(
    report: ScanReport,
    root: str | Path,
    formats: Iterable[str] = ("json",),
    *,
    events: EventBus | None = None,
) -> list[Path]:
    """Write the requested formats (JSON always) and emit ``report.generated``.

    ``formats`` accepts ``json``/``md``/``html``/``all``; unknown values (``table``,
    ``jsonl`` — terminal formats, not files) are ignored.
    """
    requested = {name.lower() for name in formats}
    if "all" in requested:
        requested |= set(RENDERED_FORMATS)

    paths: list[Path] = [write_json(report, root)]
    if "md" in requested:
        paths.append(write_markdown(report, root))
    if "html" in requested:
        paths.append(write_html(report, root))

    if events is not None:
        events.emit(
            "report.generated",
            path=str(paths[0]),
            format=",".join(sorted(requested & set(RENDERED_FORMATS)) or ["json"]),
            paths=[str(path) for path in paths],
        )
    return paths
