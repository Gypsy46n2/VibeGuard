"""VibeGuard command line interface (ARCHITECTURE.md §11).

``--output`` names everything a run should produce, as a comma-separated list
(DECISIONS.md D33):

``table``
    The rich terminal summary. The default.
``json``
    Echo the canonical report to stdout. ``vibeguard-report.json`` is written either
    way — INTERFACES.md §8 calls it canonical, so it is never optional.
``jsonl``
    Stream ``{"event", "ts", "data"}`` lines to stdout as the scan runs (§6).
``md`` / ``html``
    Write ``vibeguard-report.md`` / ``vibeguard-report.html`` next to the JSON.
``all``
    ``table,json,md,html``.

The default is ``table,md``, which — with the always-written JSON — gives the
documented "json + md" pair plus a readable terminal summary.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.table import Table

from vibeguard import __version__
from vibeguard.adapters import build_adapters
from vibeguard.baseline import (
    HISTORY_DIRNAME,
    Baseline,
    baseline_path,
    latest_history,
    load_baseline,
    save_baseline,
    write_history,
)
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.events import EventBus
from vibeguard.core.models import (
    Category,
    ChecklistStatus,
    FixStatus,
    ScanReport,
    Severity,
)
from vibeguard.core.registry import build_registry
from vibeguard.engine.checklist import section_rollup
from vibeguard.engine.orchestrator import (
    EXIT_DIRTY_WORKTREE,
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    Engine,
)
from vibeguard.fixers.git_safety import DirtyWorktreeError, GitSafetyError, NoGitRepoError
from vibeguard.reporting import JSON_FILENAME, write_json, write_reports
from vibeguard.validation.engine import ValidationEngine

__all__ = ["app", "main"]

REPORT_FILENAME = JSON_FILENAME

console = Console()
err_console = Console(stderr=True)

app = typer.Typer(
    name="vibeguard",
    help="Audit, repair, and harden vibe-coded applications.",
    no_args_is_help=True,
    add_completion=False,
)
baseline_app = typer.Typer(help="Manage the findings baseline.", no_args_is_help=True)
app.add_typer(baseline_app, name="baseline")


class OutputFormat(str, Enum):
    TABLE = "table"
    JSON = "json"
    JSONL = "jsonl"
    MD = "md"
    HTML = "html"
    ALL = "all"


DEFAULT_OUTPUT = "table,md"

_OUTPUT_HELP = (
    "Comma-separated outputs: table, json, jsonl, md, html, all. "
    "vibeguard-report.json is always written."
)


class OutputError(ValueError):
    """An ``--output`` list naming something VibeGuard cannot produce."""


def parse_outputs(spec: str) -> set[str]:
    """``"md, html"`` → ``{"md", "html"}``; ``"all"`` expands. Raises on nonsense."""
    tokens = [token.strip().lower() for token in spec.split(",") if token.strip()]
    if not tokens:
        tokens = [OutputFormat.TABLE.value]
    known = {fmt.value for fmt in OutputFormat}
    unknown = [token for token in tokens if token not in known]
    if unknown:
        raise OutputError(
            f"unknown output format(s): {', '.join(unknown)} — "
            f"choose from {', '.join(sorted(known))}"
        )
    requested = set(tokens)
    if OutputFormat.ALL.value in requested:
        requested.discard(OutputFormat.ALL.value)
        requested |= {
            OutputFormat.TABLE.value,
            OutputFormat.JSON.value,
            OutputFormat.MD.value,
            OutputFormat.HTML.value,
        }
    return requested


# --------------------------------------------------------------------- helpers


def _load_config(
    path: Path,
    *,
    packs: list[str] | None = None,
    local_only: bool | None = None,
    fail_on: Severity | None = None,
    use_baseline: bool | None = None,
    allow_no_git: bool | None = None,
    deep_validate: bool | None = None,
) -> VibeguardConfig:
    config = VibeguardConfig.load(path)
    return config.merge_cli(
        packs=packs,
        local_only=local_only,
        fail_on=fail_on,
        use_baseline=use_baseline,
        allow_no_git=allow_no_git,
        deep_validate=deep_validate,
    )


def _jsonl_subscriber(name: str, payload: dict[str, Any]) -> None:
    line = {
        "event": name,
        "ts": datetime.now(UTC).isoformat(),
        "data": payload,
    }
    try:
        sys.stdout.write(json.dumps(line, default=str) + "\n")
        sys.stdout.flush()
    except BrokenPipeError:  # pragma: no cover - consumer closed the stream
        pass


def _write_report(report: ScanReport, root: Path) -> Path:
    return write_json(report, root)


def _emit(report: ScanReport, root: Path, outputs: set[str], events: EventBus) -> list[Path]:
    """Write every requested report file plus the canonical JSON; print the paths."""
    paths = write_reports(report, root, outputs, events=events)
    for path in paths:
        console.print(f"report written to [bold]{path}[/]")
    return paths


def _persist_history(report: ScanReport, root: Path, config: VibeguardConfig) -> None:
    """Store this run so the next one can diff against it (INTERFACES.md §7).

    The engine deliberately does not do this (DECISIONS.md D32): writing history is a
    side effect of *running the tool*, not of computing a report.
    """
    if not config.history.enabled:
        return
    try:
        write_history(report, root, keep=config.history.keep)
    except OSError as exc:
        err_console.print(f"[yellow]warning:[/] could not record scan history: {exc}")


def _print_regression(report: ScanReport) -> None:
    diff = report.regression
    if diff is None:
        console.print("[dim]no previous scan on record — no regression comparison.[/]")
        return
    console.print(
        f"[bold]since last scan:[/] {len(diff.new)} new · {len(diff.resolved)} resolved · "
        f"{len(diff.regressed)} regressed · {diff.unchanged} unchanged"
    )
    if diff.regressed:
        console.print(
            "[yellow]regressed:[/] " + ", ".join(diff.regressed[:10]) + " — previously "
            "resolved, back again"
        )


def _severity_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }[severity]


_CHECKLIST_STYLE: dict[ChecklistStatus, str] = {
    ChecklistStatus.PASS: "green",
    ChecklistStatus.FAIL: "red",
    ChecklistStatus.FIXED: "bold green",
    ChecklistStatus.REVIEW_REQUIRED: "yellow",
    ChecklistStatus.NOT_APPLICABLE: "dim",
}


def _print_checklist(report: ScanReport) -> None:
    """Per-section rollup of the master audit checklist (INTERFACES.md §11)."""
    if not report.checklist:
        return
    rollup = section_rollup(report.checklist)
    table = Table(
        title=f"Master audit checklist ({len(report.checklist)} topics across {len(rollup)} "
        "sections)"
    )
    table.add_column("section")
    for status in ChecklistStatus:
        table.add_column(status.value, justify="right")
    totals = dict.fromkeys(ChecklistStatus, 0)
    for section, counts in rollup:
        row = [section]
        for status in ChecklistStatus:
            count = counts[status]
            totals[status] += count
            row.append(f"[{_CHECKLIST_STYLE[status]}]{count}[/]" if count else "[dim]·[/]")
        table.add_row(*row)
    table.add_row(
        "[bold]all[/]",
        *[f"[bold]{totals[status]}[/]" for status in ChecklistStatus],
    )
    console.print()
    console.print(table)
    console.print(
        "[dim]review_required includes topics with no automated detector yet — never "
        "silently passed.[/]"
    )


def _print_checklist_detail(report: ScanReport) -> None:
    """``--deep``: every checklist topic with its status, detectors, and note."""
    if not report.checklist:
        return
    section = ""
    table: Table | None = None
    for item in report.checklist:
        if item.section != section:
            if table is not None:
                console.print(table)
            section = item.section
            table = Table(title=f"checklist · {section}")
            table.add_column("topic")
            table.add_column("status")
            table.add_column("detectors")
            table.add_column("note")
        detail = item.note or item.validation
        table.add_row(
            item.name,
            f"[{_CHECKLIST_STYLE[item.status]}]{item.status.value}[/]",
            ", ".join(item.detectors) or "[dim]none[/]",
            detail[:70],
        )
    if table is not None:
        console.print(table)


def _print_summary(report: ScanReport) -> None:
    stack = Table(title="Detected stack", show_header=False, box=None, pad_edge=False)
    stack.add_column("field", style="bold")
    stack.add_column("value")
    tech = report.tech
    rows: list[tuple[str, str]] = [
        ("languages", ", ".join(f"{k} ({v})" for k, v in sorted(tech.languages.items()))),
        ("frameworks", ", ".join(tech.frameworks)),
        ("databases", ", ".join(tech.databases)),
        ("orms", ", ".join(tech.orms)),
        ("package managers", ", ".join(tech.package_managers)),
        ("containers", ", ".join(tech.containers)),
        ("ci/cd", ", ".join(tech.ci_cd)),
        ("tests", ", ".join(tech.test_frameworks)),
        ("auth", ", ".join(tech.auth)),
        ("scale", f"{report.scale.scale.value} — {report.scale.loc} LOC, "
                  f"{report.scale.service_count} service(s), "
                  f"sensitive data: {report.scale.has_sensitive_data}"),
    ]
    for label, value in rows:
        if value:
            stack.add_row(label, value)
    console.print(stack)
    console.print()

    severities = Table(title="Findings by severity")
    severities.add_column("severity")
    severities.add_column("count", justify="right")
    for severity in Severity:
        severities.add_row(
            f"[{_severity_style(severity)}]{severity.value}[/]",
            str(report.counts.get(severity.value, 0)),
        )
    severities.add_row("[bold]total[/]", str(report.counts.get("total", 0)))
    if report.counts.get("suppressed"):
        severities.add_row("suppressed", str(report.counts["suppressed"]))
    console.print(severities)
    console.print()

    scores = Table(title=f"Category scores (overall {report.overall_before}/100)")
    scores.add_column("category")
    scores.add_column("score", justify="right")
    scores.add_column("findings", justify="right")
    for score in report.scores_before:
        if not score.applicable:
            continue
        scores.add_row(score.category.value, str(score.score), str(score.finding_count))
    console.print(scores)

    _print_checklist(report)

    if report.findings:
        console.print()
        detail = Table(title="Findings")
        detail.add_column("rule")
        detail.add_column("severity")
        detail.add_column("location")
        detail.add_column("title")
        for finding in report.findings:
            location = finding.file or "."
            if finding.line:
                location = f"{location}:{finding.line}"
            detail.add_row(
                finding.rule_id,
                f"[{_severity_style(finding.severity)}]{finding.severity.value}[/]",
                location,
                finding.title,
            )
        console.print(detail)


# -------------------------------------------------------------------- commands


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug logging.")] = False,
    version: Annotated[bool, typer.Option("--version", help="Show version and exit.")] = False,
) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if version:
        console.print(f"vibeguard {__version__}")
        raise typer.Exit(EXIT_OK)
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit(EXIT_OK)


@app.command()
def audit(
    path: Annotated[Path, typer.Argument(help="Repository to audit.")] = Path("."),
    deep: Annotated[
        bool,
        typer.Option("--deep", help="Report every checklist topic, not just findings."),
    ] = False,
    packs: Annotated[
        list[str] | None, typer.Option("--packs", help="Restrict to these rule packs.")
    ] = None,
    local_only: Annotated[
        bool, typer.Option("--local-only", help="Never send code off this machine.")
    ] = False,
    output: Annotated[str, typer.Option("--output", "-o", help=_OUTPUT_HELP)] = DEFAULT_OUTPUT,
) -> None:
    """Audit a repository (read-only) and write the report files."""
    root = path.resolve()
    try:
        outputs = parse_outputs(output)
    except OutputError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    config = _load_config(root, packs=packs, local_only=local_only or None)
    events = EventBus()
    if OutputFormat.JSONL.value in outputs:
        events.subscribe("*", _jsonl_subscriber)

    try:
        engine = Engine(config, events=events)
        report = engine.audit(root)
    except NotADirectoryError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    except Exception as exc:  # pragma: no cover - unexpected failure path
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    if OutputFormat.TABLE.value in outputs:
        _print_summary(report)
        _print_regression(report)
        console.print()
    if OutputFormat.JSON.value in outputs:
        console.print_json(report.model_dump_json())
    _emit(report, root, outputs, events)
    _persist_history(report, root, config)
    if deep:
        _print_checklist_detail(report)


@app.command()
def fix(
    path: Annotated[Path, typer.Argument(help="Repository to repair.")] = Path("."),
    safe: Annotated[
        bool, typer.Option("--safe", help="Apply only SAFE_AUTOFIX repairs (default).")
    ] = False,
    interactive: Annotated[
        bool,
        typer.Option(
            "--interactive",
            help="Also offer review-recommended repairs, one diff at a time.",
        ),
    ] = False,
    deep_validate: Annotated[
        bool,
        typer.Option("--deep-validate", help="Add the container-build validation rung."),
    ] = False,
    local_only: Annotated[bool, typer.Option("--local-only")] = False,
    allow_no_git: Annotated[bool, typer.Option("--allow-no-git")] = False,
    output: Annotated[str, typer.Option("--output", "-o", help=_OUTPUT_HELP)] = DEFAULT_OUTPUT,
) -> None:
    """Repair findings on a dedicated branch, validating every change."""
    if safe and interactive:
        err_console.print("[red]error:[/] choose either --safe or --interactive, not both.")
        raise typer.Exit(EXIT_ERROR)
    mode: str = "interactive" if interactive else "safe"
    if not safe and not interactive:
        console.print(
            "[dim]no mode given — running [bold]--safe[/bold] (SAFE_AUTOFIX repairs only). "
            "Use --interactive to review the rest.[/]"
        )

    root = path.resolve()
    try:
        outputs = parse_outputs(output)
    except OutputError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    config = _load_config(
        root,
        local_only=local_only or None,
        allow_no_git=allow_no_git or None,
        deep_validate=deep_validate or None,
    )
    events = EventBus()
    engine = Engine(config, events=events)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("starting", total=None)
            events.subscribe(
                "scan.stage",
                lambda _n, payload: progress.update(
                    task, description=str(payload.get("stage", ""))
                ),
            )
            events.subscribe(
                "repair.started",
                lambda _n, payload: progress.update(
                    task, description=f"repairing {payload.get('rule_id', '')}"
                ),
            )
            scan_report = engine.fix(root, mode, confirm=_confirm_fix)  # type: ignore[arg-type]
    except DirtyWorktreeError as exc:
        err_console.print(f"[red]refusing to run:[/] {exc}")
        raise typer.Exit(EXIT_DIRTY_WORKTREE) from exc
    except (NoGitRepoError, GitSafetyError) as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    except NotADirectoryError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    _print_fix_summary(scan_report, engine)
    _print_regression(scan_report)
    console.print()
    _emit(scan_report, root, outputs, events)
    _persist_history(scan_report, root, config)
    raise typer.Exit(EXIT_OK)


def _confirm_fix(finding: Any, diff: str) -> bool:
    """Interactive approval: show the unified diff, then ask."""
    console.print()
    console.print(
        Panel(
            Syntax(diff or "(no diff)", "diff", theme="ansi_dark", word_wrap=True),
            title=f"{finding.rule_id} · {finding.title}",
            subtitle=f"{finding.file or '.'}:{finding.line or '-'}",
        )
    )
    return typer.confirm("apply this fix?", default=False)


_FIX_STYLE: dict[FixStatus, str] = {
    FixStatus.FIXED: "bold green",
    FixStatus.PARTIALLY_FIXED: "yellow",
    FixStatus.UNVERIFIED: "yellow",
    FixStatus.ATTEMPTED: "yellow",
    FixStatus.FAILED: "red",
    FixStatus.REQUIRES_REVIEW: "cyan",
    FixStatus.NOT_ATTEMPTED: "dim",
}


def _print_fix_summary(report: ScanReport, engine: Engine) -> None:
    """Per-fix table: status, commit, and the validation evidence behind it."""
    git = engine.last_git_safety
    if git is not None:
        console.print(f"[bold]safety:[/] {git.describe()}")
    validation = engine.last_validation
    if validation is not None and validation.baseline_note():
        console.print(f"[yellow]baseline:[/] {validation.baseline_note()}")

    attempted = [f for f in report.findings if f.fix is not None]
    table = Table(title="Repairs")
    table.add_column("rule")
    table.add_column("location")
    table.add_column("status")
    table.add_column("commit")
    table.add_column("validation")
    for finding in attempted:
        record = finding.fix
        assert record is not None
        location = finding.file or "."
        if finding.line:
            location = f"{location}:{finding.line}"
        evidence = ValidationEngine.summarise(record.validation) if record.validation else (
            record.patch_summary[:60] or "—"
        )
        table.add_row(
            finding.rule_id,
            location,
            f"[{_FIX_STYLE[record.status]}]{record.status.value}[/]",
            (record.commit_sha or "—")[:12],
            evidence,
        )
    if attempted:
        console.print(table)
    else:
        console.print("[dim]no finding was eligible for an automated repair.[/]")

    fixed = sum(
        1 for f in report.findings if f.fix is not None and f.fix.status is FixStatus.FIXED
    )
    console.print(
        f"\n[bold]{fixed}[/] finding(s) fixed and validated · overall score "
        f"{report.overall_before} → {report.overall_after}"
    )
    _print_checklist(report)


def _load_last_report(root: Path) -> tuple[ScanReport, str] | None:
    """The most recent stored scan: history first, then ``vibeguard-report.json``."""
    stored = latest_history(root)
    if stored is not None:
        return stored, f".vibeguard/{HISTORY_DIRNAME}/"
    destination = root / REPORT_FILENAME
    if not destination.is_file():
        return None
    try:
        return (
            ScanReport.model_validate_json(destination.read_text(encoding="utf-8")),
            str(destination),
        )
    except (OSError, ValueError):
        return None


@app.command()
def report(
    path: Annotated[Path, typer.Argument(help="Repository whose last scan to render.")] = Path("."),
    output: Annotated[str, typer.Option("--output", "-o", help=_OUTPUT_HELP)] = DEFAULT_OUTPUT,
) -> None:
    """Re-render the last recorded scan — no rescan, no repository access.

    Reads the newest ``.vibeguard/history/`` entry (falling back to
    ``vibeguard-report.json``) and renders it to the requested formats.
    """
    root = path.resolve()
    try:
        outputs = parse_outputs(output)
    except OutputError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    loaded = _load_last_report(root)
    if loaded is None:
        err_console.print(
            f"[red]no recorded scan[/] under {root} — neither .vibeguard/{HISTORY_DIRNAME}/ "
            f"nor {REPORT_FILENAME} holds a readable report. Run [bold]vibeguard audit[/] "
            "first."
        )
        raise typer.Exit(EXIT_ERROR)
    stored, source = loaded

    console.print(
        f"[dim]re-rendering the {stored.mode} scan of {stored.repo} from "
        f"{stored.scan_date.isoformat(timespec='seconds')} (source: {source})[/]"
    )
    if OutputFormat.TABLE.value in outputs:
        _print_summary(stored)
        _print_regression(stored)
        console.print()
    if OutputFormat.JSON.value in outputs:
        console.print_json(stored.model_dump_json())
    _emit(stored, root, outputs, EventBus())
    raise typer.Exit(EXIT_OK)


@app.command()
def ci(
    path: Annotated[Path, typer.Argument(help="Repository to check.")] = Path("."),
    fail_on: Annotated[
        Severity | None, typer.Option("--fail-on", help="Minimum severity that fails CI.")
    ] = None,
    baseline: Annotated[
        bool,
        typer.Option(
            "--baseline/--no-baseline",
            help="Exempt findings in .vibeguard/baseline.json from the gate.",
        ),
    ] = True,
    output: Annotated[str, typer.Option("--output", "-o", help=_OUTPUT_HELP)] = DEFAULT_OUTPUT,
) -> None:
    """Run an audit and fail when findings reach the configured threshold."""
    root = path.resolve()
    try:
        outputs = parse_outputs(output)
    except OutputError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    config = _load_config(root, fail_on=fail_on, use_baseline=baseline)
    events = EventBus()
    if OutputFormat.JSONL.value in outputs:
        events.subscribe("*", _jsonl_subscriber)

    try:
        engine = Engine(config, events=events)
        scan_report, exit_code = engine.ci(root)
    except Exception as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    if OutputFormat.TABLE.value in outputs:
        _print_summary(scan_report)
    if OutputFormat.JSON.value in outputs:
        console.print_json(scan_report.model_dump_json())
    _emit(scan_report, root, outputs, events)
    _persist_history(scan_report, root, config)

    console.print()
    _print_regression(scan_report)
    gating = engine.gating_findings(scan_report)
    exempt = sum(1 for f in scan_report.findings if f.suppressed or f.baselined)
    threshold = config.ci.fail_on.value
    if exempt:
        console.print(
            f"[dim]{exempt} finding(s) exempt from the gate (suppressed or baselined).[/]"
        )
    if exit_code == EXIT_FINDINGS:
        breaching = sum(1 for f in gating if f.severity.order >= config.ci.fail_on.order)
        err_console.print(
            f"[red]CI gate failed:[/] {breaching} finding(s) at or above '{threshold}'."
        )
    else:
        console.print(f"[green]CI gate passed:[/] no findings at or above '{threshold}'.")
    raise typer.Exit(exit_code)


@baseline_app.command("create")
def baseline_create(
    path: Annotated[Path, typer.Argument()] = Path("."),
    packs: Annotated[
        list[str] | None, typer.Option("--packs", help="Restrict to these rule packs.")
    ] = None,
    local_only: Annotated[bool, typer.Option("--local-only")] = False,
) -> None:
    """Scan, then record every open finding as the accepted baseline.

    The baseline is a scheduling decision, not an erasure: baselined findings stay in
    every report, keep counting towards the score, and only stop failing CI.
    """
    root = path.resolve()
    config = _load_config(root, packs=packs, local_only=local_only or None)
    try:
        scan = Engine(config).audit(root, mode="baseline")
        destination = save_baseline(root, scan)
    except NotADirectoryError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    except OSError as exc:
        err_console.print(f"[red]error:[/] could not write the baseline: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    stored = load_baseline(root)
    count = len(stored.fingerprints) if stored else 0
    console.print(
        f"baseline written to [bold]{destination}[/] — {count} fingerprint(s) accepted."
    )
    console.print(
        "[dim]These findings no longer fail `vibeguard ci`. They are still detected, "
        "still scored, and still printed in every report.[/]"
    )
    raise typer.Exit(EXIT_OK)


@baseline_app.command("show")
def baseline_show(
    path: Annotated[Path, typer.Argument()] = Path("."),
) -> None:
    """Show the stored baseline."""
    root = path.resolve()
    destination = baseline_path(root)
    stored: Baseline | None = load_baseline(root)
    if stored is None:
        if destination.is_file():
            err_console.print(f"[red]baseline at {destination} is not readable.[/]")
            raise typer.Exit(EXIT_ERROR)
        console.print(
            f"[yellow]no baseline at[/] {destination} — create one with "
            "[bold]vibeguard baseline create[/]."
        )
        raise typer.Exit(EXIT_OK)

    table = Table(title=f"baseline · {destination}")
    table.add_column("field", style="bold")
    table.add_column("value")
    table.add_row("created", stored.created.isoformat(timespec="seconds"))
    table.add_row("head sha", stored.head_sha or "— (not a git repository)")
    table.add_row("fingerprints", str(len(stored.fingerprints)))
    console.print(table)
    for fingerprint in stored.fingerprints:
        console.print(f"  [dim]{fingerprint}[/]")
    raise typer.Exit(EXIT_OK)


@app.command()
def doctor() -> None:
    """Report environment, git, and external adapter availability."""
    table = Table(title="vibeguard doctor")
    table.add_column("check")
    table.add_column("status")
    table.add_column("detail")

    py = sys.version_info
    py_ok = py >= (3, 11)
    table.add_row(
        "python",
        "[green]ok[/]" if py_ok else "[red]too old[/]",
        f"{py.major}.{py.minor}.{py.micro} (requires >= 3.11)",
    )
    table.add_row("vibeguard", "[green]ok[/]", __version__)

    git_path = shutil.which("git")
    git_detail = ""
    if git_path:
        try:
            git_detail = subprocess.run(
                ["git", "--version"], capture_output=True, text=True, timeout=10, check=False
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):  # pragma: no cover
            git_detail = git_path
    table.add_row(
        "git",
        "[green]available[/]" if git_path else "[yellow]missing[/]",
        git_detail or "fix mode requires git (or --allow-no-git)",
    )

    try:
        import tree_sitter  # noqa: F401

        table.add_row("tree-sitter", "[green]available[/]", "AST rules enabled")
    except ImportError:  # pragma: no cover - tree-sitter is a core dep
        table.add_row("tree-sitter", "[yellow]missing[/]", "AST rules degrade to regex")

    for adapter in build_adapters():
        available = adapter.available()
        detail_bits: list[str] = []
        location = shutil.which(adapter.command) if adapter.command else None
        if available and location:
            detail_bits.append(location)
            version = _probe_version(adapter.command)
            if version:
                detail_bits.append(version)
        elif not available:
            detail_bits.append("optional — install with the [scanners] extra")
        if adapter.requires_network:
            detail_bits.append("network required (skipped under --local-only)")
        table.add_row(
            f"adapter: {adapter.name}",
            "[green]available[/]" if available else "[dim]not installed[/]",
            " · ".join(detail_bits) or adapter.description,
        )

    console.print(table)
    console.print(
        "[dim]adapters are optional; VibeGuard's built-in rules run with zero external "
        "installs.[/]"
    )
    raise typer.Exit(EXIT_OK)


def _probe_version(command: str) -> str:
    """Best-effort ``<tool> --version`` probe; empty string when it does not answer."""
    try:
        proc = subprocess.run(
            [command, "--version"], capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - environment specific
        return ""
    output = (proc.stdout or proc.stderr or "").strip().splitlines()
    return output[0][:60] if output else ""


@app.command("rules")
def list_rules(
    pack: Annotated[str | None, typer.Option("--pack", help="Only show this pack.")] = None,
    category: Annotated[
        Category | None, typer.Option("--category", help="Only show this category.")
    ] = None,
) -> None:
    """List registered rules and their applicability."""
    registry = build_registry(None)
    table = Table(title="registered rules")
    table.add_column("id")
    table.add_column("pack")
    table.add_column("category")
    table.add_column("severity")
    table.add_column("confidence")
    table.add_column("min scale")
    table.add_column("technologies")
    table.add_column("autofix")

    shown = 0
    for entry in registry.registered:
        if pack and entry.pack != pack:
            continue
        cls = entry.cls
        if category and cls.category is not category:
            continue
        shown += 1
        table.add_row(
            cls.id,
            entry.pack,
            cls.category.value,
            f"[{_severity_style(cls.severity)}]{cls.severity.value}[/]",
            cls.confidence.value,
            cls.min_scale.value,
            ", ".join(sorted(cls.technologies)) or "any",
            cls.autofix_safety.value,
        )
    console.print(table)
    console.print(f"{shown} rule(s) across {len({e.pack for e in registry.registered})} pack(s).")
    raise typer.Exit(EXIT_OK)


def main() -> None:  # pragma: no cover - console-script shim
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
