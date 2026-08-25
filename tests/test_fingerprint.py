from __future__ import annotations

from vibeguard.core.fingerprint import PROJECT_PATH, fingerprint, normalize


def test_normalize_strips_whitespace_and_lowercases():
    assert normalize("  SELECT   *\n FROM  Users ") == "select*fromusers"
    assert normalize("") == ""


def test_fingerprint_is_stable_and_hex_sha256():
    fp = fingerprint("VG-SEC-001", "app.py", "query = 'x'")
    assert fp == fingerprint("VG-SEC-001", "app.py", "query = 'x'")
    assert len(fp) == 64
    int(fp, 16)  # hex


def test_fingerprint_is_line_independent_and_format_insensitive():
    a = fingerprint("VG-SEC-001", "app.py", "cursor.execute( QUERY )")
    b = fingerprint("VG-SEC-001", "app.py", "cursor.execute(query)\n\n")
    assert a == b


def test_fingerprint_varies_with_rule_path_and_snippet():
    base = fingerprint("VG-SEC-001", "app.py", "x")
    assert base != fingerprint("VG-SEC-002", "app.py", "x")
    assert base != fingerprint("VG-SEC-001", "other.py", "x")
    assert base != fingerprint("VG-SEC-001", "app.py", "y")


def test_project_level_findings_use_dot_path():
    assert fingerprint("VG-MAINT-001", None) == fingerprint("VG-MAINT-001", PROJECT_PATH, "")
