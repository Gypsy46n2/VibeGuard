"""Baseline, suppressions, history, and the regression diff — INTERFACES.md §7."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from conftest import make_finding, make_report
from vibeguard.baseline import (
    BASELINE_FILENAME,
    SUPPRESSIONS_FILENAME,
    Baseline,
    apply_baseline,
    apply_suppressions,
    baseline_path,
    history_files,
    inline_suppression_for,
    latest_history,
    load_baseline,
    load_suppressions,
    open_fingerprints,
    regression_against_history,
    regression_diff,
    save_baseline,
    suppressions_path,
    write_history,
)
from vibeguard.core.models import FixRecord, FixStatus, SuppressionReason

# ------------------------------------------------------------------- fixtures


def write_suppressions(root: Path, body: str) -> Path:
    path = suppressions_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# --------------------------------------------------------------------- store


def test_baseline_roundtrip_matches_the_documented_shape(tmp_path: Path):
    report = make_report(make_finding("a" * 64), make_finding("b" * 64, rule_id="VG-SEC-002"))
    path = save_baseline(tmp_path, report)

    assert path == baseline_path(tmp_path)
    assert path.name == BASELINE_FILENAME
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert set(raw) == {"created", "head_sha", "fingerprints"}
    assert raw["fingerprints"] == sorted(["a" * 64, "b" * 64])

    loaded = load_baseline(tmp_path)
    assert loaded is not None
    assert loaded.contains("a" * 64)
    assert not loaded.contains("c" * 64)


def test_missing_and_corrupt_baselines_load_as_none(tmp_path: Path):
    assert load_baseline(tmp_path) is None
    path = baseline_path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    assert load_baseline(tmp_path) is None


def test_suppressed_and_fixed_findings_are_not_baselined(tmp_path: Path):
    suppressed = make_finding("a" * 64)
    suppressed.suppressed = True
    fixed = make_finding("b" * 64, fix=FixRecord(status=FixStatus.FIXED))
    still_open = make_finding("c" * 64)

    save_baseline(tmp_path, make_report(suppressed, fixed, still_open))
    loaded = load_baseline(tmp_path)
    assert loaded is not None
    assert loaded.fingerprints == ["c" * 64]


def test_apply_baseline_marks_only_known_fingerprints():
    known = make_finding("a" * 64)
    unknown = make_finding("b" * 64)
    marked = apply_baseline([known, unknown], Baseline(created=datetime.now(UTC),
                                                      fingerprints=["a" * 64]))
    assert marked == 1
    assert known.baselined is True
    assert unknown.baselined is False


def test_apply_baseline_without_a_baseline_is_a_no_op():
    finding = make_finding()
    assert apply_baseline([finding], None) == 0
    assert finding.baselined is False


# -------------------------------------------------------------- suppressions


def test_suppression_by_fingerprint(tmp_path: Path):
    write_suppressions(
        tmp_path,
        f"""
- fingerprint: "{"a" * 64}"
  rule_id: VG-SEC-001
  reason: accepted_risk
  author: alice
  created: 2026-01-01
  note: internal service only
""",
    )
    hit = make_finding("a" * 64)
    miss = make_finding("b" * 64)
    outcome = apply_suppressions([hit, miss], tmp_path, lambda _rel: "")

    assert outcome.suppressed == 1
    assert hit.suppressed is True
    assert hit.suppression is not None
    assert hit.suppression.reason is SuppressionReason.ACCEPTED_RISK
    assert hit.suppression.author == "alice"
    assert miss.suppressed is False
    assert outcome.entries and outcome.entries[0].note == "internal service only"


def test_suppression_by_rule_id_covers_every_finding_of_that_rule(tmp_path: Path):
    write_suppressions(
        tmp_path,
        """
- rule_id: VG-SEC-001
  reason: false_positive
  author: bob
""",
    )
    one = make_finding("a" * 64)
    two = make_finding("b" * 64)
    other = make_finding("c" * 64, rule_id="VG-SEC-009")
    outcome = apply_suppressions([one, two, other], tmp_path, lambda _rel: "")

    assert outcome.suppressed == 2
    assert one.suppressed and two.suppressed
    assert other.suppressed is False


def test_expired_suppressions_are_ignored_and_warned_about(tmp_path: Path):
    yesterday = (datetime.now(UTC) - timedelta(days=1)).date().isoformat()
    write_suppressions(
        tmp_path,
        f"""
- fingerprint: "{"a" * 64}"
  rule_id: VG-SEC-001
  reason: temporary
  author: carol
  expires: {yesterday}
""",
    )
    finding = make_finding("a" * 64)
    outcome = apply_suppressions([finding], tmp_path, lambda _rel: "")

    assert finding.suppressed is False, "an expired waiver must not silence a finding"
    assert outcome.suppressed == 0
    assert len(outcome.expired) == 1
    assert any("expired" in warning for warning in outcome.warnings)
    # The lapsed entry is still reported, so the audit trail survives its expiry.
    assert outcome.entries == outcome.expired


def test_a_future_expiry_is_still_honoured(tmp_path: Path):
    tomorrow = (datetime.now(UTC) + timedelta(days=30)).date().isoformat()
    write_suppressions(
        tmp_path,
        f"""
- fingerprint: "{"a" * 64}"
  rule_id: VG-SEC-001
  reason: temporary
  author: carol
  expires: {tomorrow}
""",
    )
    finding = make_finding("a" * 64)
    apply_suppressions([finding], tmp_path, lambda _rel: "")
    assert finding.suppressed is True


@pytest.mark.parametrize(
    "line",
    [
        'x = 1  # vibeguard: ignore=VG-SEC-001 reason="checked, internal only"',
        "x = 1  // vibeguard: ignore=VG-SEC-001",
        "x = 1  # vibeguard: ignore=VG-SEC-004,VG-SEC-001",
    ],
)
def test_inline_suppression_on_the_finding_line(line: str):
    finding = make_finding(line=2)
    entry = inline_suppression_for(finding, lambda _rel: f"header\n{line}\nfooter\n")
    assert entry is not None
    assert entry.rule_id == "VG-SEC-001"
    assert entry.author == "inline"


def test_inline_suppression_on_the_line_above():
    source = '# vibeguard: ignore=VG-SEC-001 reason="accepted_risk"\nx = 1\n'
    finding = make_finding(line=2)
    entry = inline_suppression_for(finding, lambda _rel: source)
    assert entry is not None
    assert entry.reason is SuppressionReason.ACCEPTED_RISK


def test_inline_suppression_is_not_read_from_elsewhere_in_the_file():
    source = "# vibeguard: ignore=VG-SEC-001\n\n\n\nx = 1\n"
    finding = make_finding(line=5)
    assert inline_suppression_for(finding, lambda _rel: source) is None


def test_inline_suppression_ignores_a_different_rule():
    source = "x = 1  # vibeguard: ignore=VG-SEC-999\n"
    finding = make_finding(line=1)
    assert inline_suppression_for(finding, lambda _rel: source) is None


def test_free_text_inline_reason_becomes_a_note_not_a_bogus_enum():
    source = 'x = 1  # vibeguard: ignore=VG-SEC-001 reason="the key is a test fixture"\n'
    entry = inline_suppression_for(make_finding(line=1), lambda _rel: source)
    assert entry is not None
    assert entry.reason is SuppressionReason.ACCEPTED_RISK
    assert entry.note == "the key is a test fixture"


def test_inline_suppressions_are_applied_through_the_engine_entrypoint(tmp_path: Path):
    finding = make_finding(line=1)
    outcome = apply_suppressions(
        [finding], tmp_path, lambda _rel: "x = 1  # vibeguard: ignore=VG-SEC-001\n"
    )
    assert finding.suppressed is True
    assert outcome.suppressed == 1


def test_malformed_suppression_entries_warn_rather_than_crash(tmp_path: Path):
    write_suppressions(
        tmp_path,
        """
- rule_id: VG-SEC-001
  reason: not_a_real_reason
  author: dave
- "just a string"
- author: nobody
  reason: accepted_risk
""",
    )
    entries, warnings = load_suppressions(tmp_path)
    assert entries == []
    assert len(warnings) == 3
    assert any("not_a_real_reason" in w for w in warnings)


def test_unparseable_suppressions_file_is_reported_not_fatal(tmp_path: Path):
    write_suppressions(tmp_path, "{[bad yaml")
    entries, warnings = load_suppressions(tmp_path)
    assert entries == []
    assert warnings and SUPPRESSIONS_FILENAME in warnings[0]


def test_a_suppression_matching_nothing_is_reported(tmp_path: Path):
    write_suppressions(
        tmp_path,
        f"""
- fingerprint: "{"z" * 64}"
  rule_id: VG-SEC-001
  reason: accepted_risk
  author: erin
""",
    )
    outcome = apply_suppressions([make_finding("a" * 64)], tmp_path, lambda _rel: "")
    assert outcome.suppressed == 0
    assert any("matched no finding" in w for w in outcome.warnings)
    assert len(outcome.entries) == 1


def test_no_suppressions_file_is_silent(tmp_path: Path):
    outcome = apply_suppressions([make_finding()], tmp_path, lambda _rel: "")
    assert outcome.warnings == []
    assert outcome.entries == []


# ------------------------------------------------------------------ history


def test_history_roundtrip(tmp_path: Path):
    report = make_report(make_finding("a" * 64))
    path = write_history(report, tmp_path)

    assert path.parent == tmp_path / ".vibeguard" / "history"
    assert path.suffix == ".json"
    assert history_files(tmp_path) == [path]

    loaded = latest_history(tmp_path)
    assert loaded is not None
    assert [f.fingerprint for f in loaded.findings] == ["a" * 64]
    assert loaded.checklist == report.checklist


def test_history_entries_sort_oldest_first_and_prune(tmp_path: Path):
    for index in range(5):
        report = make_report(make_finding("a" * 64))
        report.scan_date = datetime(2026, 1, index + 1, tzinfo=UTC)
        write_history(report, tmp_path, keep=3)

    files = history_files(tmp_path)
    assert len(files) == 3
    assert files == sorted(files), "history filenames must sort chronologically"
    newest = latest_history(tmp_path)
    assert newest is not None
    assert newest.scan_date == datetime(2026, 1, 5, tzinfo=UTC)


def test_history_keep_zero_prunes_nothing(tmp_path: Path):
    for index in range(3):
        report = make_report()
        report.scan_date = datetime(2026, 2, index + 1, tzinfo=UTC)
        write_history(report, tmp_path, keep=0)
    assert len(history_files(tmp_path)) == 3


def test_unreadable_history_entries_are_skipped(tmp_path: Path):
    report = make_report(make_finding("a" * 64))
    report.scan_date = datetime(2026, 1, 1, tzinfo=UTC)
    write_history(report, tmp_path)
    (tmp_path / ".vibeguard" / "history" / "2026-06-01T00-00-00.000000Z.json").write_text(
        "garbage", encoding="utf-8"
    )
    loaded = latest_history(tmp_path)
    assert loaded is not None
    assert loaded.scan_date == datetime(2026, 1, 1, tzinfo=UTC)


# ------------------------------------------------------------------- diffing


def test_open_fingerprints_excludes_suppressed_and_fixed():
    suppressed = make_finding("a" * 64)
    suppressed.suppressed = True
    fixed = make_finding("b" * 64, fix=FixRecord(status=FixStatus.FIXED))
    unverified = make_finding("c" * 64, fix=FixRecord(status=FixStatus.UNVERIFIED))
    still_open = make_finding("d" * 64)

    assert open_fingerprints([suppressed, fixed, unverified, still_open]) == {
        "c" * 64,
        "d" * 64,
    }


def test_regression_diff_classifies_every_bucket():
    unchanged = make_finding("a" * 64)
    brand_new = make_finding("b" * 64)
    came_back = make_finding("c" * 64)

    diff = regression_diff(
        [unchanged, brand_new, came_back],
        previous={"a" * 64, "d" * 64},
        older={"c" * 64, "a" * 64},
    )

    assert diff.unchanged == 1
    assert diff.new == [brand_new.id]
    assert diff.regressed == [came_back.id]
    assert diff.resolved == ["d" * 64]


def test_regression_diff_reports_fingerprints_for_resolved_and_ids_for_present():
    """Resolved findings no longer exist, so only their fingerprint can be named."""
    diff = regression_diff([make_finding("a" * 64)], previous={"b" * 64}, older=set())
    assert diff.resolved == ["b" * 64]
    assert diff.new == ["VG-SEC-001:aaaaaaaaaaaa"]


def test_a_fixed_finding_counts_as_resolved():
    fixed = make_finding("a" * 64, fix=FixRecord(status=FixStatus.FIXED))
    diff = regression_diff([fixed], previous={"a" * 64}, older=set())
    assert diff.resolved == ["a" * 64]
    assert diff.unchanged == 0


def test_regression_against_history_walks_the_two_horizons(tmp_path: Path):
    # Run 1: the defect exists.  Run 2: it is gone.  Run 3 (now): it is back.
    first = make_report(make_finding("a" * 64))
    first.scan_date = datetime(2026, 1, 1, tzinfo=UTC)
    write_history(first, tmp_path)

    second = make_report()
    second.scan_date = datetime(2026, 1, 2, tzinfo=UTC)
    write_history(second, tmp_path)

    diff = regression_against_history([make_finding("a" * 64)], tmp_path)
    assert diff is not None
    assert diff.regressed == ["VG-SEC-001:aaaaaaaaaaaa"]
    assert diff.new == []


def test_regression_against_history_is_none_without_history(tmp_path: Path):
    assert regression_against_history([make_finding()], tmp_path) is None
