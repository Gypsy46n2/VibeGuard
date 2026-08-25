"""VG-COST-003 — oversized container base image."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    Patch,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._fixes import (
    finding_snippet,
    line_at,
    locate_line,
    replace_line,
    whole_file_patch,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["OversizedBaseImageRule"]

_MAX_FINDINGS = 5

_FROM_RE = re.compile(r"^\s*FROM\s+(\S+)(?:\s+AS\s+(\S+))?", re.IGNORECASE)

#: Base images that ship a full distribution userland.
_FAT_BASE = re.compile(
    r"^(?:docker\.io/)?(?:library/)?"
    r"(python:\d[\w.]*|node:\d[\w.]*|ruby:\d[\w.]*|golang:\d[\w.]*|openjdk:\d[\w.]*|"
    r"ubuntu(?::[\w.]+)?|debian(?::[\w.]+)?|centos(?::[\w.]+)?|fedora(?::[\w.]+)?)$",
    re.IGNORECASE,
)
_SLIM = re.compile(
    r"-(?:slim|alpine|bookworm-slim|bullseye-slim)|:alpine|distroless", re.IGNORECASE
)

#: Toolchains that leave compilers or dev packages behind in the runtime image.
#: Deliberately excludes a bare `pip install`/`poetry install`, which a Python
#: runtime image needs anyway — a slim single-stage Python build is idiomatic.
_BUILD_TOOLING = re.compile(
    r"apt-get\s+install|apk\s+add|yum\s+install|dnf\s+install|npm\s+(?:ci|install)|"
    r"yarn\s+install|pnpm\s+install|go\s+build|mvn\s+package|gradle\s+build|"
    r"build-essential|\bgcc\b|\bg\+\+\b|\bmake\b|webpack|\btsc\b|cargo\s+build",
    re.IGNORECASE,
)

#: Workloads that legitimately need a full distribution.
_NEEDS_FAT = re.compile(
    r"nvidia|cuda|tensorflow|torch|opencv|libreoffice|texlive|chromium|playwright|"
    r"ffmpeg|wkhtmltopdf|imagemagick|gdal|geos|odbc",
    re.IGNORECASE,
)


def _dockerfiles(ctx: ScanContext) -> list[str]:
    out: list[str] = []
    for rel in ctx.files:
        name = PurePosixPath(rel).name.lower()
        if name == "dockerfile" or name.startswith("dockerfile."):
            out.append(rel)
        if len(out) >= 20:
            break
    return out


class OversizedBaseImageRule(Rule):
    """Full-distribution base image, or a single-stage build shipping its toolchain."""

    id: ClassVar[str] = "VG-COST-003"
    category: ClassVar[Category] = Category.COST
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Oversized container base image"
    description: ClassVar[str] = (
        "The Dockerfile builds on a full distribution image, or has no multi-stage "
        "separation, so build tooling ships to production."
    )
    why_it_matters: ClassVar[str] = (
        "A 1GB image instead of a 100MB one is paid for repeatedly: registry storage and "
        "egress on every pull, slower CI, slower autoscaling (nodes wait to download the "
        "image before serving traffic), and a much larger set of installed packages for "
        "vulnerability scanners to flag. Compilers and package managers left in the "
        "runtime image are also useful to an attacker who gets a shell."
    )
    references: ClassVar[list[str]] = [
        "https://docs.docker.com/build/building/multi-stage/",
        "https://docs.docker.com/build/building/best-practices/",
    ]
    technologies: ClassVar[set[str]] = {"docker"}
    topics: ClassVar[set[str]] = {"cost.oversized-containers", "containers.image-size"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in _dockerfiles(ctx):
            if len(findings) >= _MAX_FINDINGS:
                break
            text = ctx.read(rel)
            if not text or len(text) > 200_000:
                continue
            if _NEEDS_FAT.search(text):
                continue
            findings.extend(self._check(rel, text))
        return findings[:_MAX_FINDINGS]

    def _check(self, rel: str, text: str) -> list[Finding]:
        lines = text.splitlines()
        stages: list[tuple[int, str]] = []
        for index, line in enumerate(lines):
            match = _FROM_RE.match(line)
            if match:
                stages.append((index + 1, match.group(1)))
        if not stages:
            return []

        final_line, final_image = stages[-1]
        fat = bool(_FAT_BASE.match(final_image)) and not _SLIM.search(final_image)
        single_stage = len(stages) == 1
        tooling = bool(_BUILD_TOOLING.search(text))

        if not fat and not (single_stage and tooling):
            return []

        reasons: list[str] = []
        if fat:
            reasons.append(
                f"the final stage builds on `{final_image}`, a full distribution image "
                "rather than a `-slim`, `-alpine`, or distroless variant, and nothing in "
                "the Dockerfile suggests the workload needs the extra userland"
            )
        if single_stage and tooling:
            reasons.append(
                "the build is single-stage and installs build tooling, so compilers and "
                "package managers are shipped in the runtime image"
            )
        return [
            self.make_finding(
                file=rel,
                line=final_line,
                snippet=f"FROM {final_image}",
                description=f"In {rel}, " + "; and ".join(reasons) + ".",
                recommended_followup=(
                    f"Switch the runtime stage away from `{final_image}` to a `-slim`, "
                    "`-alpine`, or distroless variant, and split the build into a builder "
                    "stage plus a runtime stage that copies only the built artefacts — "
                    "then compare `docker image ls` before and after."
                ),
            )
        ]


    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """``FROM python:3.12`` → ``FROM python:3.12-slim`` when nothing needs the fat base.

        Refused — deliberately — whenever the project shows any sign of building
        compiled dependencies: a package that has no manylibc wheel, an ``apt-get
        install``/``gcc`` line in the Dockerfile, or one of the workload markers the
        detector already screens for. Slimming an image that needs a compiler turns a
        working build into a broken one, so the patch only lands on the plain case.
        """
        rel, line_no = finding.file, finding.line
        if not rel or not line_no:
            return None
        text = ctx.read(rel)
        target = locate_line(
            text,
            line_no,
            matches=lambda candidate: bool(_FROM_RE.match(candidate)),
            snippet=finding_snippet(finding),
        )
        line = line_at(text, target)
        if target is None or line is None:
            return None
        line_no = target
        match = _FROM_RE.match(line)
        if match is None:
            return None
        image = match.group(1)
        if not _SLIMMABLE.match(image) or _SLIM.search(image):
            return None
        if _BUILD_TOOLING.search(text) or _NEEDS_FAT.search(text):
            return None
        if _compiled_dependency(ctx):
            return None
        repaired = line.replace(image, f"{image}-slim", 1)
        return whole_file_patch(
            finding,
            rel,
            text,
            replace_line(text, line_no, repaired),
            description=(
                f"Build {rel} on `{image}-slim` instead of `{image}`; no compiled "
                "dependency or build tooling in this project needs the full image."
            ),
            scope="cost",
            summary=f"use the -slim variant of {image}",
        )


#: Only tagged CPython images are slimmed: `python:3.12` has a `-slim` variant with the
#: same interpreter, which is not true of every base image family.
_SLIMMABLE = re.compile(r"^(?:docker\.io/)?(?:library/)?python:\d[\w.]*$", re.IGNORECASE)

#: Packages that build from source on a slim image unless a wheel happens to exist.
_COMPILED_DEPENDENCIES = re.compile(
    r"(?m)^\s*(psycopg2(?!-binary)|mysqlclient|pyodbc|cx[-_]Oracle|python-ldap|pycurl|"
    r"uwsgi|pyicu|python-snappy|confluent-kafka|grpcio|pygraphviz|shapely|cartopy|"
    r"pyaudio|dbus-python|systemd-python)\b",
    re.IGNORECASE,
)
_REQUIREMENT_FILES = ("requirements.txt", "requirements/base.txt", "pyproject.toml",
                      "Pipfile", "setup.py")


def _compiled_dependency(ctx: ScanContext) -> bool:
    """True when a manifest names a package that typically needs a compiler."""
    for name in _REQUIREMENT_FILES:
        if ctx.exists(name) and _COMPILED_DEPENDENCIES.search(ctx.read(name)):
            return True
    return False


RULES: list[type[Rule]] = [OversizedBaseImageRule]
