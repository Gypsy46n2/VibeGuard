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
    Patch,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._fixes import insert_lines, whole_file_patch
from vibeguard.rules.containers._parse import (
    Instruction,
    dockerfiles,
    final_stage,
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

    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Add a HEALTHCHECK when the image makes the port and probe obvious.

        Requires an ``EXPOSE`` in the final stage (otherwise we would be guessing the
        port) and a Python or Node base image, so the probe can use the runtime that is
        certainly installed rather than assuming ``curl`` exists — it does not, in
        slim and distroless images. The check hits ``/`` and treats any response below
        500 as healthy, which is the most that can be assumed without knowing the app's
        routes; the finding still recommends a real readiness endpoint.
        """
        rel = finding.file
        if not rel:
            return None
        text = ctx.read(rel)
        instructions = parse_dockerfile(text)
        if any(ins.upper == "HEALTHCHECK" for ins in instructions):
            return None
        stage = final_stage(instructions)
        if not stage:
            return None
        port = _exposed_port(stage)
        entry = next((ins for ins in stage if ins.upper in {"CMD", "ENTRYPOINT"}), None)
        if port is None or entry is None:
            return None
        ref = image_ref(stage[0].value)
        probe = _health_probe(ref.image if ref else "", port)
        if probe is None:
            return None
        new_text = insert_lines(
            text,
            entry.line - 1,
            [
                "# vibeguard: report application health, not just process liveness",
                "HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \\",
                f"  CMD {probe}",
                "",
            ],
        )
        return whole_file_patch(
            finding,
            rel,
            text,
            new_text,
            description=f"Add a HEALTHCHECK probing port {port} to {rel}.",
            scope="containers",
            summary="add a container HEALTHCHECK",
        )


def _exposed_port(stage: list[Instruction]) -> int | None:
    """The single port the final stage exposes, or None when it is not unambiguous."""
    ports: list[int] = []
    for ins in stage:
        if ins.upper != "EXPOSE":
            continue
        for token in ins.value.split():
            number = token.split("/")[0]
            if number.isdigit():
                ports.append(int(number))
    return ports[0] if len(ports) == 1 else None


def _health_probe(image: str, port: int) -> str | None:
    """A probe command using a runtime the base image certainly has."""
    base = image.rsplit("/", 1)[-1].lower()
    url = f"http://127.0.0.1:{port}/"
    if base.startswith("python"):
        return (
            f'python -c "import urllib.request,sys; '
            f"sys.exit(0 if urllib.request.urlopen('{url}').status < 500 else 1)\" || exit 1"
        )
    if base.startswith("node"):
        return (
            f"node -e \"require('http').get('{url}', r => process.exit(r.statusCode < 500 "
            "? 0 : 1)).on('error', () => process.exit(1))\" || exit 1"
        )
    return None


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

    # ------------------------------------------------------------------- repair
    def fix(self, ctx: ScanContext, finding: Finding) -> Patch | None:
        """Copy the manifest, install, then copy the source — canonical shape only.

        The reorder is applied when the stage matches the textbook pattern exactly: one
        ``COPY . .`` on a single physical line, one install ``RUN`` after it, only
        layout instructions (``WORKDIR``/``ENV``/``ARG``/``LABEL``) in between, and a
        manifest file that actually exists in the repository. Anything more inventive
        is left to a human: moving a COPY past instructions with side effects can
        change what the install step sees.
        """
        rel = finding.file
        if not rel:
            return None
        text = ctx.read(rel)
        instructions = parse_dockerfile(text)
        for stage in stages(instructions):
            hit = self._offending_install(stage)
            if hit is None:
                continue
            copy_ins, run_ins = hit
            if not self._reorderable(stage, copy_ins, run_ins):
                return None
            manifest = _manifest_copy(ctx, run_ins.value)
            if manifest is None:
                return None
            lines = text.splitlines()
            copy_index = copy_ins.line - 1
            copy_line = lines[copy_index]
            if copy_line.rstrip().endswith("\\"):
                return None
            run_end = _instruction_end(lines, run_ins.line - 1)
            indent = copy_line[: len(copy_line) - len(copy_line.lstrip())]
            rebuilt = (
                lines[:copy_index]
                + [f"{indent}{manifest}"]
                + lines[copy_index + 1 : run_end + 1]
                + [f"{indent}{copy_line.strip()}"]
                + lines[run_end + 1 :]
            )
            new_text = "\n".join(rebuilt) + ("\n" if text.endswith("\n") else "")
            return whole_file_patch(
                finding,
                rel,
                text,
                new_text,
                description=(
                    f"Reorder {rel}: copy the dependency manifest, install, then copy the "
                    "source, so source edits reuse the cached install layer."
                ),
                scope="containers",
                summary="copy the manifest before installing dependencies",
            )
        return None

    @staticmethod
    def _reorderable(
        stage: list[Instruction], copy_ins: Instruction, run_ins: Instruction
    ) -> bool:
        """True when only layout instructions sit between the COPY and the install."""
        between = [
            ins
            for ins in stage
            if copy_ins.line < ins.line < run_ins.line
        ]
        if any(ins.upper not in {"WORKDIR", "ENV", "ARG", "LABEL"} for ins in between):
            return False
        full_copies = [
            ins for ins in stage if ins.upper in {"COPY", "ADD"} and _FULL_COPY.match(ins.value)
        ]
        installs = [ins for ins in stage if ins.upper == "RUN" and _INSTALL.search(ins.value)]
        return len(full_copies) == 1 and len(installs) == 1

    @staticmethod
    def _offending_install(stage: list[Instruction]) -> tuple[Instruction, Instruction] | None:
        copy_ins: Instruction | None = None
        for ins in stage:
            if ins.upper in {"COPY", "ADD"} and copy_ins is None and _FULL_COPY.match(ins.value):
                copy_ins = ins
            elif ins.upper == "RUN" and copy_ins is not None and _INSTALL.search(ins.value):
                return copy_ins, ins
        return None


#: Install command → the manifest COPY that should precede it, when the manifest exists.
_MANIFESTS: tuple[tuple[re.Pattern[str], str, tuple[str, ...]], ...] = (
    (re.compile(r"\bnpm\s+ci\b", re.IGNORECASE), "COPY package.json package-lock.json ./",
     ("package.json", "package-lock.json")),
    (re.compile(r"\bnpm\s+install\b", re.IGNORECASE), "COPY package*.json ./",
     ("package.json",)),
    (re.compile(r"\byarn\s+", re.IGNORECASE), "COPY package.json yarn.lock ./",
     ("package.json", "yarn.lock")),
    (re.compile(r"\bpnpm\s+", re.IGNORECASE), "COPY package.json pnpm-lock.yaml ./",
     ("package.json", "pnpm-lock.yaml")),
    (re.compile(r"\bpoetry\s+install\b", re.IGNORECASE), "COPY pyproject.toml poetry.lock ./",
     ("pyproject.toml", "poetry.lock")),
    (re.compile(r"\bpip3?\s+install\b.*requirements\.txt", re.IGNORECASE),
     "COPY requirements.txt ./", ("requirements.txt",)),
    (re.compile(r"\bbundle\s+install\b", re.IGNORECASE), "COPY Gemfile Gemfile.lock ./",
     ("Gemfile", "Gemfile.lock")),
    (re.compile(r"\bgo\s+mod\s+download\b", re.IGNORECASE), "COPY go.mod go.sum ./",
     ("go.mod", "go.sum")),
)


def _manifest_copy(ctx: ScanContext, run_value: str) -> str | None:
    """The COPY line to insert before an install command, when its manifests exist."""
    for pattern, copy_line, required in _MANIFESTS:
        if not pattern.search(run_value):
            continue
        if all(ctx.exists(name) for name in required):
            return copy_line
        return None
    return None


def _instruction_end(lines: list[str], start: int) -> int:
    """Index of the last physical line of an instruction beginning at ``start``."""
    index = start
    while index < len(lines) - 1 and lines[index].rstrip().endswith("\\"):
        index += 1
    return index


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
