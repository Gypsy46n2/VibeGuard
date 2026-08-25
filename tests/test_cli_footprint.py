"""Zero-footprint scanning: ``--report-dir`` and ``--no-write`` (DECISIONS.md D59).

The promise these flags make is not "usually tidy" — it is *byte-identical*. Every
test that claims the repository was untouched proves it by hashing the whole tree,
names and contents both, and excluding nothing.
"""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vibeguard.baseline import baseline_path, history_files
from vibeguard.cli import app
from vibeguard.core.config import VibeguardConfig
from vibeguard.reporting import HTML_FILENAME, JSON_FILENAME, MARKDOWN_FILENAME

runner = CliRunner()

REPORT_FILENAMES = (JSON_FILENAME, MARKDOWN_FILENAME, HTML_FILENAME)


@pytest.fixture(autouse=True)
def wide_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setenv("TERM", "dumb")


@pytest.fixture
def repo(sample_app: Path, tmp_path: Path) -> Path:
    target = tmp_path / "repo"
    shutil.copytree(sample_app, target)
    return target


def tree_hash(root: Path) -> str:
    """A hash of every path under ``root`` — names, contents, and nothing excluded."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda p: p.as_posix()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"L" + str(path.readlink()).encode("utf-8"))
        elif path.is_file():
            digest.update(b"F" + hashlib.sha256(path.read_bytes()).digest())
        else:
            digest.update(b"D")
        digest.update(b"\n")
    return digest.hexdigest()


# ------------------------------------------------------------------ --report-dir


def test_report_dir_takes_every_artifact_and_the_repo_is_byte_identical(
    repo: Path, tmp_path: Path
):
    out = tmp_path / "reports" / "nested"  # also proves the directory is created
    before = tree_hash(repo)

    result = runner.invoke(app, ["audit", str(repo), "--report-dir", str(out), "-o", "all"])
    assert result.exit_code == 0, result.output

    for name in REPORT_FILENAMES:
        assert (out / name).is_file(), name
        assert not (repo / name).exists(), name
    assert history_files(out), "history must follow the reports"
    assert not (repo / ".vibeguard").exists()
    assert tree_hash(repo) == before


def test_report_dir_history_is_where_the_regression_diff_comes_from(
    repo: Path, tmp_path: Path
):
    out = tmp_path / "reports"
    first = runner.invoke(app, ["audit", str(repo), "--report-dir", str(out)])
    assert first.exit_code == 0, first.output
    assert "no previous scan on record" in first.output

    second = runner.invoke(app, ["audit", str(repo), "--report-dir", str(out)])
    assert second.exit_code == 0, second.output
    assert "since last scan" in second.output
    assert len(history_files(out)) == 2

    # The repository's own (empty) history knows nothing about those runs.
    elsewhere = runner.invoke(app, ["audit", str(repo), "--report-dir", str(tmp_path / "b")])
    assert "no previous scan on record" in elsewhere.output


def test_report_re_renders_from_a_custom_dir_without_touching_the_repo(
    repo: Path, tmp_path: Path
):
    out = tmp_path / "reports"
    assert runner.invoke(app, ["audit", str(repo), "--report-dir", str(out)]).exit_code == 0
    before = tree_hash(repo)

    result = runner.invoke(
        app, ["report", str(repo), "--report-dir", str(out), "-o", "md,html"]
    )
    assert result.exit_code == 0, result.output
    assert "re-rendering" in result.output
    assert (out / MARKDOWN_FILENAME).is_file()
    assert (out / HTML_FILENAME).is_file()
    assert tree_hash(repo) == before


def test_report_without_the_dir_cannot_find_a_relocated_scan(repo: Path, tmp_path: Path):
    assert (
        runner.invoke(
            app, ["audit", str(repo), "--report-dir", str(tmp_path / "reports")]
        ).exit_code
        == 0
    )
    result = runner.invoke(app, ["report", str(repo)])
    assert result.exit_code == 2
    assert "no recorded scan" in result.output


def test_baseline_create_and_show_honour_the_report_dir(repo: Path, tmp_path: Path):
    out = tmp_path / "reports"
    before = tree_hash(repo)

    created = runner.invoke(
        app, ["baseline", "create", str(repo), "--report-dir", str(out)]
    )
    assert created.exit_code == 0, created.output
    assert baseline_path(out).is_file()
    assert not baseline_path(repo).exists()
    assert tree_hash(repo) == before

    shown = runner.invoke(app, ["baseline", "show", str(repo), "--report-dir", str(out)])
    assert shown.exit_code == 0, shown.output
    assert "fingerprints" in shown.output

    # A baseline written aside is only honoured when the same directory is named.
    gated = runner.invoke(
        app, ["ci", str(repo), "--fail-on", "low", "--report-dir", str(out)]
    )
    assert "exempt from the gate" in gated.output
    ungated = runner.invoke(app, ["ci", str(repo), "--fail-on", "low"])
    assert "exempt from the gate" not in ungated.output


def test_fix_accepts_a_report_dir(repo: Path, tmp_path: Path):
    out = tmp_path / "reports"
    result = runner.invoke(
        app, ["fix", str(repo), "--safe", "--allow-no-git", "--report-dir", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert (out / JSON_FILENAME).is_file()
    assert not (repo / JSON_FILENAME).exists()


# --------------------------------------------------------------------- --no-write


def test_no_write_leaves_the_repo_and_the_report_dir_untouched(repo: Path, tmp_path: Path):
    out = tmp_path / "reports"
    before = tree_hash(repo)

    result = runner.invoke(
        app, ["audit", str(repo), "--no-write", "--report-dir", str(out), "-o", "all"]
    )
    assert result.exit_code == 0, result.output
    assert "--no-write" in result.output
    assert not out.exists(), "--no-write must not even create the report directory"
    assert tree_hash(repo) == before


def test_no_write_still_prints_the_table_and_the_json(repo: Path):
    before = tree_hash(repo)
    result = runner.invoke(app, ["audit", str(repo), "--no-write", "-o", "table,json"])
    assert result.exit_code == 0, result.output
    assert "Findings by severity" in result.output
    assert "report written to" not in result.output
    assert tree_hash(repo) == before


def test_ci_gates_correctly_with_no_write(repo: Path):
    before = tree_hash(repo)

    failing = runner.invoke(app, ["ci", str(repo), "--fail-on", "low", "--no-write"])
    assert failing.exit_code == 1
    assert "CI gate failed" in failing.output
    assert tree_hash(repo) == before

    passing = runner.invoke(app, ["ci", str(repo), "--fail-on", "critical", "--no-write"])
    assert passing.exit_code == 0, passing.output
    assert "CI gate passed" in passing.output
    assert tree_hash(repo) == before


def test_no_write_records_nothing_for_the_next_run_to_diff_against(repo: Path):
    assert runner.invoke(app, ["audit", str(repo), "--no-write"]).exit_code == 0
    second = runner.invoke(app, ["audit", str(repo), "--no-write"])
    assert "no previous scan on record" in second.output


# ------------------------------------------------------------------ config wiring


def test_config_report_dir_is_resolved_against_the_config_file(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    (root / ".vibeguard.toml").write_text(
        '[vibeguard]\nreport_dir = "../scan-output"\n', encoding="utf-8"
    )
    config = VibeguardConfig.load(root)
    assert config.report_dir == str((tmp_path / "scan-output").resolve())
    assert config.state_root(root) == (tmp_path / "scan-output").resolve()


def test_state_root_defaults_to_the_scanned_repository(tmp_path: Path):
    assert VibeguardConfig().state_root(tmp_path) == tmp_path


def test_the_cli_flag_overrides_the_configured_report_dir(repo: Path, tmp_path: Path):
    (repo / ".vibeguard.toml").write_text(
        f'[vibeguard]\nreport_dir = "{(tmp_path / "from-config").as_posix()}"\n',
        encoding="utf-8",
    )

    from_config = runner.invoke(app, ["audit", str(repo)])
    assert from_config.exit_code == 0, from_config.output
    assert (tmp_path / "from-config" / JSON_FILENAME).is_file()
    assert not (repo / JSON_FILENAME).exists()

    override = runner.invoke(
        app, ["audit", str(repo), "--report-dir", str(tmp_path / "from-flag")]
    )
    assert override.exit_code == 0, override.output
    assert (tmp_path / "from-flag" / JSON_FILENAME).is_file()
    assert len(history_files(tmp_path / "from-config")) == 1
