"""``.vibeguard.toml`` configuration — INTERFACES.md §9."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from vibeguard.core.models import Severity

__all__ = [
    "AIConfig",
    "CIConfig",
    "FixConfig",
    "HistoryConfig",
    "VibeguardConfig",
    "CONFIG_FILENAME",
    "DEFAULT_PACKS",
    "DEFAULT_EXCLUDES",
]

CONFIG_FILENAME = ".vibeguard.toml"

DEFAULT_PACKS: list[str] = [
    "core",
    "secrets",
    "security",
    "api",
    "database",
    "reliability",
    "observability",
    "containers",
    "deployment",
    "dependencies",
    "disaster_recovery",
    "testing",
    "performance",
    "scaling",
    "cost",
    "network",
    "web",
    "devops",
    "python",
    "node",
]

DEFAULT_EXCLUDES: list[str] = [
    # VibeGuard's own memory and output. A report names every defect it found, so
    # scanning it makes "is a backup configured anywhere?" answer yes on the strength
    # of our own prose — the previous run's findings must never become this run's
    # evidence.
    "**/.vibeguard/**",
    "**/vibeguard-report.json",
    "**/vibeguard-report.md",
    "**/vibeguard-report.html",
    "**/node_modules/**",
    "**/.venv/**",
    "**/venv/**",
    "**/.git/**",
    "**/__pycache__/**",
    "**/dist/**",
    "**/build/**",
    "**/.mypy_cache/**",
    "**/.ruff_cache/**",
    "**/.pytest_cache/**",
    "**/*.egg-info/**",
]


class AIConfig(BaseModel):
    provider: Literal["null", "anthropic", "openai_compatible"] = "null"
    endpoint: str | None = None
    model: str | None = None
    api_key_env: str | None = None


class CIConfig(BaseModel):
    fail_on: Severity = Severity.HIGH
    use_baseline: bool = True


class FixConfig(BaseModel):
    allow_no_git: bool = False
    #: Run the container-build rung of the validation ladder (``fix --deep-validate``).
    deep_validate: bool = False
    #: Seconds allowed for project-wide validators (full test suite, build).
    validation_timeout_full: int = 600
    #: Seconds allowed for change-scoped validators (syntax, lint, targeted tests).
    validation_timeout_targeted: int = 120


class HistoryConfig(BaseModel):
    """``.vibeguard/history/`` persistence — the input to the regression diff."""

    enabled: bool = True
    #: How many entries to keep; older ones are pruned. 0 keeps everything.
    keep: int = 50


class VibeguardConfig(BaseModel):
    """Effective configuration. CLI flags override file values."""

    packs: list[str] = Field(default_factory=lambda: list(DEFAULT_PACKS))
    exclude: list[str] = Field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    local_only: bool = False
    ai: AIConfig = Field(default_factory=AIConfig)
    ci: CIConfig = Field(default_factory=CIConfig)
    fix: FixConfig = Field(default_factory=FixConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)
    #: Absolute path of the config file this instance was loaded from, if any.
    source_path: str | None = None

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, root: str | Path) -> VibeguardConfig:
        """Load ``.vibeguard.toml`` from ``root``; defaults when absent."""
        root_path = Path(root)
        path = root_path / CONFIG_FILENAME if root_path.is_dir() else root_path
        if not path.is_file():
            return cls()
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
        config = cls.from_dict(raw)
        config.source_path = str(path.resolve())
        return config

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> VibeguardConfig:
        """Build a config from a parsed ``.vibeguard.toml`` mapping."""
        main = dict(raw.get("vibeguard") or {})
        data: dict[str, Any] = {}
        if "packs" in main:
            data["packs"] = list(main["packs"])
        if "exclude" in main:
            # File excludes extend the built-in defaults rather than replacing them.
            data["exclude"] = list(dict.fromkeys(DEFAULT_EXCLUDES + list(main["exclude"])))
        if "local_only" in main:
            data["local_only"] = bool(main["local_only"])
        for key, model in (
            ("ai", AIConfig),
            ("ci", CIConfig),
            ("fix", FixConfig),
            ("history", HistoryConfig),
        ):
            section = raw.get(key)
            if isinstance(section, dict):
                data[key] = model(**section)
        return cls(**data)

    def merge_cli(
        self,
        *,
        packs: list[str] | None = None,
        local_only: bool | None = None,
        fail_on: Severity | None = None,
        use_baseline: bool | None = None,
        allow_no_git: bool | None = None,
        deep_validate: bool | None = None,
        history: bool | None = None,
    ) -> VibeguardConfig:
        """Return a copy with CLI overrides applied (CLI wins over file)."""
        updated = self.model_copy(deep=True)
        if packs:
            updated.packs = list(packs)
        if local_only is not None:
            updated.local_only = local_only
        if fail_on is not None:
            updated.ci.fail_on = fail_on
        if use_baseline is not None:
            updated.ci.use_baseline = use_baseline
        if allow_no_git is not None:
            updated.fix.allow_no_git = allow_no_git
        if deep_validate is not None:
            updated.fix.deep_validate = deep_validate
        if history is not None:
            updated.history.enabled = history
        return updated
