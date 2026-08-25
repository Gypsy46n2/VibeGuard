"""Private manifest parsing for the dependencies pack.

Requirements files, ``pyproject.toml``, and ``package.json`` are parsed into a
common ``Requirement`` shape. Every parser is total: malformed input yields ``[]``.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "LOCKFILES",
    "Requirement",
    "manifests",
    "node_manifests",
    "package_json",
    "pyproject_data",
    "python_manifests",
    "requirements_of",
]

LOCKFILES = frozenset(
    {
        "requirements.lock",
        "requirements.txt.lock",
        "poetry.lock",
        "uv.lock",
        "pdm.lock",
        "pipfile.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "npm-shrinkwrap.json",
    }
)

_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>.*)$"
)


@dataclass(frozen=True)
class Requirement:
    """One declared dependency."""

    name: str
    spec: str
    file: str
    line: int
    section: str = "runtime"

    @property
    def key(self) -> str:
        return self.name.lower().replace("_", "-")


def _is_named(rel: str, *names: str) -> bool:
    return PurePosixPath(rel).name.lower() in {n.lower() for n in names}


def python_manifests(ctx: ScanContext) -> list[str]:
    """``requirements*.txt`` and ``pyproject.toml`` paths."""
    out: list[str] = []
    for rel in ctx.files:
        name = PurePosixPath(rel).name.lower()
        if name == "pyproject.toml" or (name.startswith("requirements") and name.endswith(".txt")):
            out.append(rel)
    return out[:20]


def node_manifests(ctx: ScanContext) -> list[str]:
    """``package.json`` paths, excluding vendored trees."""
    return [
        rel
        for rel in ctx.files
        if _is_named(rel, "package.json") and "node_modules" not in rel.split("/")
    ][:20]


def manifests(ctx: ScanContext) -> list[str]:
    """Every dependency manifest path."""
    return python_manifests(ctx) + node_manifests(ctx)


def _parse_requirements_txt(text: str, rel: str) -> list[Requirement]:
    out: list[Requirement] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-") or line.startswith("."):
            continue
        if "://" in line or line.startswith("git+"):
            continue
        match = _REQ_LINE.match(line)
        if not match:
            continue
        spec = match.group("spec").split(";", 1)[0].strip()
        out.append(Requirement(name=match.group("name"), spec=spec, file=rel, line=index))
    return out


def pyproject_data(ctx: ScanContext, rel: str) -> dict[str, Any]:
    """Parsed ``pyproject.toml``, or ``{}`` when unreadable/malformed."""
    try:
        return tomllib.loads(ctx.read(rel))
    except Exception:
        return {}


def _line_of(text: str, needle: str) -> int:
    for index, raw in enumerate(text.splitlines(), start=1):
        if needle in raw:
            return index
    return 1


def _parse_pyproject(ctx: ScanContext, rel: str) -> list[Requirement]:
    data = pyproject_data(ctx, rel)
    if not data:
        return []
    text = ctx.read(rel)
    out: list[Requirement] = []

    def add(entry: Any, section: str) -> None:
        if not isinstance(entry, str):
            return
        cleaned = entry.split(";", 1)[0].strip()
        match = _REQ_LINE.match(cleaned)
        if not match:
            return
        out.append(
            Requirement(
                name=match.group("name"),
                spec=match.group("spec").strip(),
                file=rel,
                line=_line_of(text, match.group("name")),
                section=section,
            )
        )

    project = data.get("project")
    if isinstance(project, dict):
        for entry in project.get("dependencies") or []:
            add(entry, "runtime")
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group, entries in optional.items():
                for entry in entries or []:
                    add(entry, f"optional:{group}")

    poetry = (data.get("tool") or {}).get("poetry") if isinstance(data.get("tool"), dict) else None
    if isinstance(poetry, dict):
        deps = poetry.get("dependencies")
        if isinstance(deps, dict):
            for name, spec in deps.items():
                if str(name).lower() == "python":
                    continue
                rendered = spec if isinstance(spec, str) else ""
                out.append(
                    Requirement(
                        name=str(name),
                        spec=rendered,
                        file=rel,
                        line=_line_of(text, str(name)),
                        section="runtime",
                    )
                )
    return out


def package_json(ctx: ScanContext, rel: str) -> dict[str, Any]:
    """Parsed ``package.json``, or ``{}`` when unreadable/malformed."""
    try:
        data = json.loads(ctx.read(rel))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _parse_package_json(ctx: ScanContext, rel: str) -> list[Requirement]:
    data = package_json(ctx, rel)
    if not data:
        return []
    text = ctx.read(rel)
    out: list[Requirement] = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(spec, str):
                continue
            out.append(
                Requirement(
                    name=str(name),
                    spec=spec.strip(),
                    file=rel,
                    line=_line_of(text, f'"{name}"'),
                    section=section,
                )
            )
    return out


def requirements_of(ctx: ScanContext, rel: str) -> list[Requirement]:
    """Every dependency declared by manifest ``rel``."""
    name = PurePosixPath(rel).name.lower()
    if name == "package.json":
        return _parse_package_json(ctx, rel)
    if name == "pyproject.toml":
        return _parse_pyproject(ctx, rel)
    if name.startswith("requirements") and name.endswith(".txt"):
        return _parse_requirements_txt(ctx.read(rel), rel)
    return []
