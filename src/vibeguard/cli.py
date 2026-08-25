"""VibeGuard command line interface (ARCHITECTURE.md §11)."""

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
from rich.table import Table

from vibeguard import __version__
from vibeguard.core.config import VibeguardConfig
from vibeguard.core.events import EventBus
from vibeguard.core.models import Category, ScanReport, Severity
from vibeguard.core.registry import build_registry
from vibeguard.engine.orchestrator import (
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    Engine,
)

__all__ = ["app", "main"]

REPORT_FILENAME = "vibeguard-report.json"

#: Adapters planned for M2; availability is probed on PATH / importability.
KNOWN_ADAPTERS: tuple[tuple[str, str], ...] = (
    ("bandit", "command"),
    ("detect-secrets", "command"),
    ("pip-audit", "command"),
    ("semgrep", "command"),
    ("checkov", "command"),
    ("trivy", "command"),
    ("hadolint", "command"),
    ("npm", "command"),
)

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


class FixMode(str, Enum):
    SAFE = "safe"
    INTERACTIVE = "interactive"


# --------------------------------------------------------------------- helpers


def _load_config(
    path: Path,
    *,
    packs: list[str] | None = None,
    local_only: bool | None = None,
    fail_on: Severity | None = None,
    use_baseline: bool | None = None,
    allow_no_git: bool | None = None,
) -> VibeguardConfig:
    config = VibeguardConfig.load(path)
    return config.merge_cli(
        packs=packs,
        local_only=local_only,
        fail_on=fail_on,
        use_baseline=use_baseline,
        allow_no_git=allow_no_git,
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
    destination = root / REPORT_FILENAME
    destination.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return destination


def _severity_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }[severity]


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
    deep: Annotated[bool, typer.Option("--deep", help="Deep audit (M2+).")] = False,
    packs: Annotated[
        list[str] | None, typer.Option("--packs", help="Restrict to these rule packs.")
    ] = None,
    local_only: Annotated[
        bool, typer.Option("--local-only", help="Never send code off this machine.")
    ] = False,
    output: Annotated[
        OutputFormat, typer.Option("--output", "-o", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Audit a repository (read-only) and write vibeguard-report.json."""
    root = path.resolve()
    config = _load_config(root, packs=packs, local_only=local_only or None)
    events = EventBus()
    if output is OutputFormat.JSONL:
        events.subscribe("*", _jsonl_subscriber)

    try:
        engine = Engine(config, events=events)
        report = engine.audit(root)
        destination = _write_report(report, root)
    except NotADirectoryError as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    except Exception as exc:  # pragma: no cover - unexpected failure path
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    events.emit("report.generated", path=str(destination), format=output.value)

    if output is OutputFormat.JSON:
        console.print_json(report.model_dump_json())
    elif output is OutputFormat.TABLE:
        _print_summary(report)
        console.print(f"\nreport written to [bold]{destination}[/]")
    elif output in {OutputFormat.MD, OutputFormat.HTML}:
        console.print(
            f"{output.value} rendering lands in M4; JSON report written to {destination}"
        )
    if deep:
        console.print("[yellow]--deep has no additional effect until M2.[/]")


@app.command()
def fix(
    path: Annotated[Path, typer.Argument(help="Repository to repair.")] = Path("."),
    mode: Annotated[
        FixMode, typer.Option("--mode", help="safe = SAFE_AUTOFIX only.")
    ] = FixMode.SAFE,
    local_only: Annotated[bool, typer.Option("--local-only")] = False,
    allow_no_git: Annotated[bool, typer.Option("--allow-no-git")] = False,
) -> None:
    """Repair findings (implemented in M3)."""
    config = _load_config(
        path.resolve(), local_only=local_only or None, allow_no_git=allow_no_git or None
    )
    engine = Engine(config)
    try:
        engine.fix(path, mode.value)  # type: ignore[arg-type]
    except NotImplementedError:
        console.print(
            "[yellow]vibeguard fix is not yet implemented[/] — the repair engine, git "
            "safety, and validation ladder land in milestone M3. Run "
            "[bold]vibeguard audit[/] for the read-only report."
        )
    raise typer.Exit(EXIT_OK)


@app.command()
def report(
    path: Annotated[Path, typer.Argument(help="Repository whose last scan to render.")] = Path("."),
) -> None:
    """Re-render the last scan (renderers land in M4)."""
    destination = path.resolve() / REPORT_FILENAME
    if destination.is_file():
        console.print(
            f"[yellow]report rendering is not yet implemented[/] (M4). "
            f"The canonical JSON report is at [bold]{destination}[/]."
        )
    else:
        console.print(
            f"[yellow]no {REPORT_FILENAME} found[/] — run [bold]vibeguard audit[/] first."
        )
    raise typer.Exit(EXIT_OK)


@app.command()
def ci(
    path: Annotated[Path, typer.Argument(help="Repository to check.")] = Path("."),
    fail_on: Annotated[
        Severity | None, typer.Option("--fail-on", help="Minimum severity that fails CI.")
    ] = None,
    baseline: Annotated[
        bool, typer.Option("--baseline/--no-baseline", help="Use the stored baseline (M4).")
    ] = True,
    output: Annotated[
        OutputFormat, typer.Option("--output", "-o", help="Output format.")
    ] = OutputFormat.TABLE,
) -> None:
    """Run an audit and fail when findings reach the configured threshold."""
    root = path.resolve()
    config = _load_config(root, fail_on=fail_on, use_baseline=baseline)
    events = EventBus()
    if output is OutputFormat.JSONL:
        events.subscribe("*", _jsonl_subscriber)

    try:
        engine = Engine(config, events=events)
        scan_report, exit_code = engine.ci(root)
        destination = _write_report(scan_report, root)
    except Exception as exc:
        err_console.print(f"[red]error:[/] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    events.emit("report.generated", path=str(destination), format=output.value)

    if output is OutputFormat.JSON:
        console.print_json(scan_report.model_dump_json())
    elif output is OutputFormat.TABLE:
        _print_summary(scan_report)
        console.print(f"\nreport written to [bold]{destination}[/]")

    threshold = config.ci.fail_on.value
    if exit_code == EXIT_FINDINGS:
        err_console.print(f"[red]CI gate failed:[/] findings at or above '{threshold}'.")
    else:
        console.print(f"[green]CI gate passed:[/] no findings at or above '{threshold}'.")
    if config.ci.use_baseline:
        console.print("[dim]baseline comparison lands in M4.[/]")
    raise typer.Exit(exit_code)


@baseline_app.command("create")
def baseline_create(
    path: Annotated[Path, typer.Argument()] = Path("."),
) -> None:
    """Record current findings as the accepted baseline (M4)."""
    console.print("[yellow]baseline create is not yet implemented[/] (M4).")
    raise typer.Exit(EXIT_OK)


@baseline_app.command("show")
def baseline_show(
    path: Annotated[Path, typer.Argument()] = Path("."),
) -> None:
    """Show the stored baseline (M4)."""
    baseline_path = path.resolve() / ".vibeguard" / "baseline.json"
    if baseline_path.is_file():
        console.print_json(baseline_path.read_text(encoding="utf-8"))
    else:
        console.print(f"[yellow]no baseline at[/] {baseline_path} (baselines land in M4).")
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

    for name, _kind in KNOWN_ADAPTERS:
        found = shutil.which(name)
        table.add_row(
            f"adapter: {name}",
            "[green]available[/]" if found else "[dim]not installed[/]",
            found or "optional — install with the [scanners] extra",
        )

    console.print(table)
    console.print("[dim]adapters are wired into the pipeline in M2.[/]")
    raise typer.Exit(EXIT_OK)


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
    console.print(f"{shown} rule(s); more packs land in M2.")
    raise typer.Exit(EXIT_OK)


def main() -> None:  # pragma: no cover - console-script shim
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
