from __future__ import annotations

from pathlib import Path

from vibeguard.core.config import DEFAULT_PACKS, VibeguardConfig
from vibeguard.core.models import Severity

TOML = """
[vibeguard]
packs = ["core", "secrets"]
exclude = ["**/vendor/**"]
local_only = true

[ai]
provider = "anthropic"
model = "claude-sonnet-4-5"
api_key_env = "ANTHROPIC_API_KEY"

[ci]
fail_on = "critical"
use_baseline = false

[fix]
allow_no_git = true
"""


def test_defaults_when_no_file(tmp_path: Path):
    config = VibeguardConfig.load(tmp_path)
    assert config.packs == DEFAULT_PACKS
    assert config.local_only is False
    assert config.ai.provider == "null"
    assert config.ci.fail_on is Severity.HIGH
    assert config.ci.use_baseline is True
    assert config.fix.allow_no_git is False
    assert "**/node_modules/**" in config.exclude
    assert config.source_path is None


def test_toml_overrides(tmp_path: Path):
    (tmp_path / ".vibeguard.toml").write_text(TOML, encoding="utf-8")
    config = VibeguardConfig.load(tmp_path)
    assert config.packs == ["core", "secrets"]
    assert config.local_only is True
    assert config.ai.provider == "anthropic"
    assert config.ai.model == "claude-sonnet-4-5"
    assert config.ci.fail_on is Severity.CRITICAL
    assert config.ci.use_baseline is False
    assert config.fix.allow_no_git is True
    assert "**/vendor/**" in config.exclude
    assert "**/node_modules/**" in config.exclude  # defaults are extended, not replaced
    assert config.source_path is not None


def test_cli_flags_override_file(tmp_path: Path):
    (tmp_path / ".vibeguard.toml").write_text(TOML, encoding="utf-8")
    config = VibeguardConfig.load(tmp_path).merge_cli(
        packs=["core"], local_only=False, fail_on=Severity.LOW
    )
    assert config.packs == ["core"]
    assert config.local_only is False
    assert config.ci.fail_on is Severity.LOW
    # untouched values survive
    assert config.fix.allow_no_git is True


def test_merge_cli_returns_a_copy(tmp_path: Path):
    config = VibeguardConfig.load(tmp_path)
    merged = config.merge_cli(local_only=True)
    assert merged is not config
    assert config.local_only is False
    assert merged.local_only is True
