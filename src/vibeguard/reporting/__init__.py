"""Report rendering and scoring — ARCHITECTURE.md §8."""

from vibeguard.reporting.html import HTML_FILENAME, render_html, write_html
from vibeguard.reporting.markdown import MARKDOWN_FILENAME, render_markdown, write_markdown
from vibeguard.reporting.scoring import category_scores, overall_score, score_findings
from vibeguard.reporting.writer import JSON_FILENAME, write_json, write_reports

__all__ = [
    "HTML_FILENAME",
    "JSON_FILENAME",
    "MARKDOWN_FILENAME",
    "category_scores",
    "overall_score",
    "render_html",
    "render_markdown",
    "score_findings",
    "write_html",
    "write_json",
    "write_markdown",
    "write_reports",
]
