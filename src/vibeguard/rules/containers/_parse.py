"""Private parsing helpers for the container / deployment / dependency packs.

Config parsing is the cheapest and most reliable detection tier, so these packs
parse rather than grep: a small Dockerfile instruction tokenizer, and guarded
``yaml.safe_load_all`` wrappers for compose, Kubernetes, and CI manifests.

Every helper is total: malformed, exotic, or unreadable input yields an empty
result instead of raising.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "COMPOSE_NAMES",
    "Instruction",
    "compose_files",
    "compose_services",
    "dockerfiles",
    "final_stage",
    "image_ref",
    "is_dockerfile",
    "k8s_documents",
    "parse_dockerfile",
    "pod_containers",
    "pod_spec",
    "stages",
    "tag_is_mutable",
    "workload_documents",
    "workload_name",
    "yaml_documents",
]

COMPOSE_NAMES = frozenset(
    {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
)

_WORKLOAD_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet"})

_MAX_FILES = 60


# ------------------------------------------------------------------- Dockerfile


@dataclass(frozen=True)
class Instruction:
    """One logical Dockerfile instruction (continuations already joined)."""

    name: str
    value: str
    line: int

    @property
    def upper(self) -> str:
        return self.name.upper()


def is_dockerfile(relpath: str) -> bool:
    """``Dockerfile``, ``Dockerfile.<suffix>``, or ``*.dockerfile``."""
    name = PurePosixPath(relpath).name.lower()
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")


def dockerfiles(ctx: ScanContext) -> list[str]:
    """Every Dockerfile-like path in the repository (capped)."""
    return [rel for rel in ctx.files if is_dockerfile(rel)][:_MAX_FILES]


def compose_files(ctx: ScanContext) -> list[str]:
    """Every docker-compose / compose file path (capped)."""
    return [rel for rel in ctx.files if PurePosixPath(rel).name.lower() in COMPOSE_NAMES][
        :_MAX_FILES
    ]


def parse_dockerfile(text: str) -> list[Instruction]:
    """Tokenize a Dockerfile into logical instructions.

    Comment lines and blank lines are dropped; backslash continuations are joined
    and the reported line number is that of the first physical line.
    """
    instructions: list[Instruction] = []
    if not text:
        return instructions
    try:
        lines = text.splitlines()
    except Exception:  # pragma: no cover - defensive
        return instructions

    buffer: list[str] = []
    start = 0
    for index, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if not buffer:
            if not stripped or stripped.startswith("#"):
                continue
            start = index
        elif stripped.startswith("#"):
            # Comment inside a continuation: docker ignores it.
            continue
        if stripped.endswith("\\"):
            buffer.append(stripped[:-1])
            continue
        buffer.append(stripped)
        joined = " ".join(part.strip() for part in buffer if part.strip())
        buffer = []
        parts = joined.split(None, 1)
        if not parts:
            continue
        name = parts[0]
        if not name.isalpha():
            continue
        instructions.append(
            Instruction(name=name, value=parts[1].strip() if len(parts) > 1 else "", line=start)
        )
    if buffer:
        joined = " ".join(part.strip() for part in buffer if part.strip())
        parts = joined.split(None, 1)
        if parts and parts[0].isalpha():
            instructions.append(
                Instruction(
                    name=parts[0], value=parts[1].strip() if len(parts) > 1 else "", line=start
                )
            )
    return instructions


def stages(instructions: list[Instruction]) -> list[list[Instruction]]:
    """Split instructions into build stages, one per ``FROM``."""
    out: list[list[Instruction]] = []
    current: list[Instruction] = []
    for ins in instructions:
        if ins.upper == "FROM":
            if current:
                out.append(current)
            current = [ins]
        elif current:
            current.append(ins)
    if current:
        out.append(current)
    return out


def final_stage(instructions: list[Instruction]) -> list[Instruction]:
    """The last build stage, or ``[]`` when the file declares no ``FROM``."""
    found = stages(instructions)
    return found[-1] if found else []


@dataclass(frozen=True)
class ImageRef:
    """A parsed ``FROM`` operand."""

    image: str
    tag: str
    digest: str
    alias: str


def image_ref(value: str) -> ImageRef | None:
    """Parse the operand of a ``FROM`` instruction, or None when unparsable."""
    if not value:
        return None
    tokens = value.split()
    # Drop flags such as --platform=linux/amd64.
    tokens = [tok for tok in tokens if not tok.startswith("--")]
    if not tokens:
        return None
    ref = tokens[0]
    alias = ""
    if len(tokens) >= 3 and tokens[1].lower() == "as":
        alias = tokens[2]
    digest = ""
    if "@" in ref:
        ref, _, digest = ref.partition("@")
    tag = ""
    # A colon after the last slash is a tag; before it, a registry port.
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, _, tag = last.rpartition(":")
        ref = ref[: len(ref) - len(last)] + name
    return ImageRef(image=ref, tag=tag, digest=digest, alias=alias)


# -------------------------------------------------------------------------- YAML


def yaml_documents(ctx: ScanContext, relpath: str) -> list[Any]:
    """Every YAML document in ``relpath``; ``[]`` when it cannot be parsed."""
    text = ctx.read(relpath)
    if not text.strip():
        return []
    try:
        return [doc for doc in yaml.safe_load_all(text) if doc is not None]
    except Exception:
        return []


def compose_services(ctx: ScanContext, relpath: str) -> dict[str, dict[str, Any]]:
    """``{service name: definition}`` for a compose file (empty when malformed)."""
    out: dict[str, dict[str, Any]] = {}
    for doc in yaml_documents(ctx, relpath):
        if not isinstance(doc, dict):
            continue
        services = doc.get("services")
        if not isinstance(services, dict):
            continue
        for name, definition in services.items():
            if isinstance(definition, dict):
                out[str(name)] = definition
    return out


def _is_k8s_candidate(relpath: str) -> bool:
    if PurePosixPath(relpath).suffix.lower() not in {".yml", ".yaml"}:
        return False
    posix = PurePosixPath(relpath)
    parts = {part.lower() for part in posix.parts[:-1]}
    return not ({".github", ".gitlab", ".circleci"} & parts)


def k8s_documents(ctx: ScanContext) -> list[tuple[str, dict[str, Any]]]:
    """Every YAML document carrying both ``apiVersion`` and ``kind``."""
    out: list[tuple[str, dict[str, Any]]] = []
    for rel in ctx.files:
        if not _is_k8s_candidate(rel):
            continue
        text = ctx.read(rel)
        if "apiVersion" not in text or "kind" not in text:
            continue
        for doc in yaml_documents(ctx, rel):
            if isinstance(doc, dict) and "apiVersion" in doc and "kind" in doc:
                out.append((rel, doc))
        if len(out) >= 200:
            break
    return out


def workload_documents(ctx: ScanContext) -> list[tuple[str, dict[str, Any]]]:
    """Kubernetes Deployment / StatefulSet / DaemonSet documents."""
    return [
        (rel, doc) for rel, doc in k8s_documents(ctx) if str(doc.get("kind")) in _WORKLOAD_KINDS
    ]


def pod_spec(doc: dict[str, Any]) -> dict[str, Any]:
    """``spec.template.spec`` of a workload, or ``{}``."""
    spec = doc.get("spec")
    if not isinstance(spec, dict):
        return {}
    template = spec.get("template")
    if not isinstance(template, dict):
        return {}
    inner = template.get("spec")
    return inner if isinstance(inner, dict) else {}


def pod_containers(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Every app container (``containers``, not init containers) of a workload."""
    spec = pod_spec(doc)
    entries = spec.get("containers")
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def workload_name(doc: dict[str, Any]) -> str:
    """``metadata.name`` of a manifest, or ``"<unnamed>"``."""
    metadata = doc.get("metadata")
    if isinstance(metadata, dict):
        name = metadata.get("name")
        if name:
            return str(name)
    return "<unnamed>"


# ------------------------------------------------------------------------ shared

_MUTABLE_TAGS = frozenset(
    {"latest", "stable", "edge", "main", "master", "dev", "develop", "nightly", "current"}
)
#: A tag pinning at least ``major.minor`` (``3.12``, ``18.20-alpine``) is treated as pinned.
_PINNED_TAG = re.compile(r"^\d+\.\d+")


def tag_is_mutable(tag: str) -> bool:
    """True when ``tag`` does not pin at least a minor version."""
    if not tag:
        return True
    base = tag.lower()
    if base in _MUTABLE_TAGS:
        return True
    if _PINNED_TAG.match(base):
        return False
    # A bare major such as `3`, `18`, `18-alpine` still floats.
    return bool(re.match(r"^\d+(\D|$)", base)) or base.split("-")[0] in _MUTABLE_TAGS
