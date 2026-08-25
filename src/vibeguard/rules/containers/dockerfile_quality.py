"""VG-CTR-002, VG-CTR-004, VG-CTR-006 — Dockerfile health, caching, and image size."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Evidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules.containers._parse import (
    Instruction,
    dockerfiles,
    image_ref,
    parse_dockerfile,
    stages,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "DockerfileNoHealthcheckRule",
    "ImageLayerBloatRule",
    "InstallAfterFullContextCopyRule",
]

_MAX = 6


class DockerfileNoHealthcheckRule(Rule):
    """A runnable image that never tells the runtime whether it is healthy."""

    id: ClassVar[str] = "VG-CTR-002"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Dockerfile without a HEALTHCHECK"
    description: ClassVar[str] = (
        "The Dockerfile declares no HEALTHCHECK, so the container runtime can only tell "
        "whether the process is alive, not whether the application is working."
    )
    why_it_matters: ClassVar[str] = (
        "A wedged process — deadlocked, out of database connections, stuck on a full "
        "queue — still counts as 'running', so nothing restarts it and load balancers keep "
        "sending it traffic. A HEALTHCHECK turns that silent outage into an automatic "
        "restart or an out-of-rotation signal within seconds."
    )
    references: ClassVar[list[str]] = [
        "https://docs.docker.com/reference/dockerfile/#healthcheck",
        "https://docs.docker.com/compose/compose-file/05-services/#healthcheck",
    ]
    topics: ClassVar[set[str]] = {"containers.health-checks", "observability.liveness-checks"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in dockerfiles(ctx):
            if len(findings) >= _MAX:
                break
            instructions = parse_dockerfile(ctx.read(rel))
            if not instructions:
                continue
            found = stages(instructions)
            if not found:
                continue
            last = found[-1]
            # A stage with no entrypoint is a builder; it does not need a healthcheck.
            if not any(ins.upper in {"CMD", "ENTRYPOINT"} for ins in last):
                continue
            if any(ins.upper == "HEALTHCHECK" for ins in instructions):
                continue
            findings.append(
                self.make_finding(
                    file=rel,
                    line=last[0].line,
                    snippet=f"FROM {last[0].value}"[:200],
                    description=(
                        f"{rel} builds a runnable image (final stage has a CMD/ENTRYPOINT) "
                        "but declares no HEALTHCHECK."
                    ),
                    recommended_followup=(
                        "Add a HEALTHCHECK that exercises the app, e.g. "
                        "`HEALTHCHECK --interval=30s --timeout=3s --start-period=10s "
                        "CMD curl -fsS http://localhost:8000/healthz || exit 1`, and back it "
                        "with a real readiness endpoint."
                    ),
                )
            )
        return findings


_FULL_COPY = re.compile(r"^(--\S+\s+)*\.\s+(\./?|/\w[\w./-]*/?)\s*$")
_INSTALL = re.compile(
    r"\b(pip3?\s+install|pipenv\s+install|poetry\s+install|uv\s+(pip\s+)?(sync|install)|"
    r"npm\s+(ci|install)|yarn\s+(install|--frozen-lockfile)|pnpm\s+(install|i)\b|"
    r"bundle\s+install|go\s+mod\s+download|composer\s+install)",
    re.IGNORECASE,
)


class InstallAfterFullContextCopyRule(Rule):
    """Dependency install placed after the whole build context is copied in."""

    id: ClassVar[str] = "VG-CTR-004"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Dependency install after COPY of the whole build context"
    description: ClassVar[str] = (
        "`COPY . .` appears before the dependency install step, so editing any source file "
        "invalidates the dependency layer and reinstalls everything."
    )
    why_it_matters: ClassVar[str] = (
        "Every build — including every CI build on every commit — redownloads and "
        "reinstalls the full dependency tree, turning a ten-second image build into "
        "minutes. That cost lands on every developer push and every deploy, and it burns "
        "CI minutes and network egress for no benefit."
    )
    references: ClassVar[list[str]] = [
        "https://docs.docker.com/build/cache/",
        "https://docs.docker.com/build/building/best-practices/",
    ]
    topics: ClassVar[set[str]] = {"containers.build-caching", "performance.build-performance"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): copy the manifest, install, then copy the source.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in dockerfiles(ctx):
            if len(findings) >= _MAX:
                break
            for stage in stages(parse_dockerfile(ctx.read(rel))):
                hit = self._offending_install(stage)
                if hit is None:
                    continue
                copy_ins, run_ins = hit
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=run_ins.line,
                        snippet=f"RUN {run_ins.value}"[:200],
                        description=(
                            f"{rel}: `{copy_ins.name} {copy_ins.value}` on line "
                            f"{copy_ins.line} precedes the dependency install on line "
                            f"{run_ins.line}, so the install layer is never cached."
                        ),
                        recommended_followup=(
                            "Copy only the manifest first (`COPY requirements.txt .` or "
                            "`COPY package*.json ./`), run the install, then `COPY . .` "
                            "afterwards so source edits reuse the cached install layer."
                        ),
                    )
                )
                break
        return findings

    @staticmethod
    def _offending_install(stage: list[Instruction]) -> tuple[Instruction, Instruction] | None:
        copy_ins: Instruction | None = None
        for ins in stage:
            if ins.upper in {"COPY", "ADD"} and copy_ins is None and _FULL_COPY.match(ins.value):
                copy_ins = ins
            elif ins.upper == "RUN" and copy_ins is not None and _INSTALL.search(ins.value):
                return copy_ins, ins
        return None


_APT = re.compile(r"apt-get\s+(-\S+\s+)*install", re.IGNORECASE)
_APT_CLEAN = re.compile(r"rm\s+-rf\s+/var/lib/apt/lists", re.IGNORECASE)
_APK = re.compile(r"\bapk\s+add\b", re.IGNORECASE)
_PIP = re.compile(r"\bpip3?\s+install\b", re.IGNORECASE)
_FAT_BASE = re.compile(r"^(python|node|ruby|openjdk)$", re.IGNORECASE)
_SLIM = re.compile(r"(slim|alpine|bookworm-slim|distroless)", re.IGNORECASE)


class ImageLayerBloatRule(Rule):
    """Package-manager caches and fat base images left in the final image."""

    id: ClassVar[str] = "VG-CTR-006"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.LOW
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Oversized or uncleaned image layers"
    description: ClassVar[str] = (
        "Package-manager caches are left behind in a layer, or a full-fat base image is "
        "used where a -slim/-alpine variant would do."
    )
    why_it_matters: ClassVar[str] = (
        "Every extra hundred megabytes is paid for on every pull: slower deploys, slower "
        "autoscaling (a new node waits on the image before it can serve traffic), and real "
        "registry storage and egress bills. A fat base image also ships hundreds of "
        "packages you never use, each one more CVE surface to triage."
    )
    references: ClassVar[list[str]] = [
        "https://docs.docker.com/build/building/best-practices/#minimize-the-number-of-layers",
        "https://pythonspeed.com/articles/base-image-python-docker-images/",
    ]
    topics: ClassVar[set[str]] = {"containers.image-size", "cost.oversized-containers"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in dockerfiles(ctx):
            for ins in parse_dockerfile(ctx.read(rel)):
                if len(findings) >= _MAX:
                    return findings
                note = self._offence(ins)
                if note is None:
                    continue
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=ins.line,
                        evidence=[
                            Evidence(
                                file=rel,
                                line=ins.line,
                                snippet=f"{ins.name} {ins.value}"[:200],
                                note=note,
                            )
                        ],
                        description=f"{rel}:{ins.line} {note}.",
                        recommended_followup=(
                            "Clean up in the same RUN layer — `apt-get install "
                            "--no-install-recommends ... && rm -rf /var/lib/apt/lists/*`, "
                            "`apk add --no-cache`, `pip install --no-cache-dir` — and pick a "
                            "`-slim` or `-alpine` base image."
                        ),
                    )
                )
        return findings

    @staticmethod
    def _offence(ins: Instruction) -> str | None:
        value = ins.value
        if ins.upper == "RUN":
            if _APT.search(value) and not (
                _APT_CLEAN.search(value) or "--no-install-recommends" in value
            ):
                return (
                    "runs `apt-get install` without `--no-install-recommends` or "
                    "`rm -rf /var/lib/apt/lists/*`, leaving the package index in the layer"
                )
            if _APK.search(value) and "--no-cache" not in value:
                return "runs `apk add` without `--no-cache`, leaving the apk index in the layer"
            if _PIP.search(value) and "--no-cache-dir" not in value:
                return "runs `pip install` without `--no-cache-dir`, leaving the wheel cache"
            return None
        if ins.upper == "FROM":
            ref = image_ref(value)
            if ref is None:
                return None
            base = ref.image.rsplit("/", 1)[-1]
            if _FAT_BASE.match(base) and not _SLIM.search(ref.tag):
                return (
                    f"uses the full `{base}` base image; the `-slim` or `-alpine` variant is "
                    "typically several hundred megabytes smaller"
                )
        return None
