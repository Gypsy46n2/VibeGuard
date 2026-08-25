"""VG-CTR-001, VG-CTR-003, VG-CTR-005 — Dockerfile security posture."""

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
    final_stage,
    image_ref,
    parse_dockerfile,
    tag_is_mutable,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "ContainerRunsAsRootRule",
    "SecretBakedIntoImageRule",
    "UnpinnedBaseImageRule",
]

_MAX = 8


class ContainerRunsAsRootRule(Rule):
    """A Dockerfile whose final stage never drops privileges."""

    id: ClassVar[str] = "VG-CTR-001"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Container runs as root"
    description: ClassVar[str] = (
        "The Dockerfile's final stage declares no USER instruction (or sets USER root), "
        "so the container process runs as uid 0."
    )
    why_it_matters: ClassVar[str] = (
        "A process running as root inside a container is one container-escape or one "
        "mounted host path away from owning the host. It can also write to any bind mount, "
        "silently leaving root-owned files on the host filesystem. Running as an "
        "unprivileged user turns most remote-code-execution bugs into a contained nuisance."
    )
    references: ClassVar[list[str]] = [
        "https://docs.docker.com/reference/dockerfile/#user",
        "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
    ]
    topics: ClassVar[set[str]] = {"containers.container-privileges", "containers.image-security"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): add a non-root USER and chown the app directory.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in dockerfiles(ctx):
            if len(findings) >= _MAX:
                break
            stage = final_stage(parse_dockerfile(ctx.read(rel)))
            if not stage:
                continue
            users = [ins for ins in stage if ins.upper == "USER"]
            if users and users[-1].value.split(":")[0].strip().lower() not in {"root", "0"}:
                continue
            offender = users[-1] if users else stage[0]
            reason = (
                "the final stage sets `USER root`"
                if users
                else "the final stage never declares a USER"
            )
            findings.append(
                self.make_finding(
                    file=rel,
                    line=offender.line,
                    snippet=f"{offender.name} {offender.value}".strip()[:200],
                    description=f"{rel}: {reason}, so the entrypoint runs as uid 0.",
                    recommended_followup=(
                        "Add `RUN adduser --system --no-create-home app` and `USER app` "
                        "to the final stage, and `chown` the application directory to that "
                        "user before switching."
                    ),
                )
            )
        return findings


class UnpinnedBaseImageRule(Rule):
    """A FROM line that resolves to a moving target."""

    id: ClassVar[str] = "VG-CTR-003"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Unpinned container base image"
    description: ClassVar[str] = (
        "A FROM instruction uses `:latest`, no tag at all, or a floating tag with no "
        "digest, so the image rebuilt tomorrow is not the image built today."
    )
    why_it_matters: ClassVar[str] = (
        "An unpinned base image means the build is not reproducible: a rebuild can pull a "
        "new interpreter, a new libc, or a new CVE without a single line of your code "
        "changing. Debugging 'it worked yesterday' becomes archaeology, and a rollback to "
        "an old commit does not restore the old runtime."
    )
    references: ClassVar[list[str]] = [
        "https://docs.docker.com/build/building/best-practices/#pin-base-image-versions",
        "https://slsa.dev/spec/v1.0/requirements",
    ]
    topics: ClassVar[set[str]] = {
        "containers.dependency-pinning",
        "containers.image-security",
        "deployment.build-reproducibility",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in dockerfiles(ctx):
            if len(findings) >= _MAX:
                break
            instructions = parse_dockerfile(ctx.read(rel))
            aliases = {
                ref.alias.lower()
                for ref in (image_ref(i.value) for i in instructions if i.upper == "FROM")
                if ref is not None and ref.alias
            }
            for ins in instructions:
                if ins.upper != "FROM" or len(findings) >= _MAX:
                    continue
                ref = image_ref(ins.value)
                if ref is None or ref.digest:
                    continue
                if ref.image.lower() in aliases or ref.image.lower() == "scratch":
                    continue
                if not tag_is_mutable(ref.tag):
                    continue
                shown = ref.tag or "<no tag — implicitly :latest>"
                findings.append(
                    self.make_finding(
                        file=rel,
                        line=ins.line,
                        snippet=f"FROM {ins.value}"[:200],
                        description=(
                            f"{rel}:{ins.line} pulls `{ref.image}` at the floating tag "
                            f"`{shown}`; the same Dockerfile will produce a different image "
                            "on the next build."
                        ),
                        recommended_followup=(
                            f"Pin an explicit version and digest, e.g. "
                            f"`FROM {ref.image}:<major.minor>@sha256:<digest>`, and bump it "
                            "deliberately (Renovate/Dependabot can raise the PR)."
                        ),
                    )
                )
        return findings


_CRED_NAME = re.compile(
    r"(^|_)(SECRET|SECRETS|TOKEN|PASSWORD|PASSWD|PWD|APIKEY|API_KEY|ACCESS_KEY|"
    r"PRIVATE_KEY|CREDENTIAL|CREDENTIALS|KEY|DSN)($|_)",
    re.IGNORECASE,
)
_CRED_DSN = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@/\s]+@", re.IGNORECASE)
_PLACEHOLDER = re.compile(
    r"^(|\"\"|''|\$\{?\w+\}?|<[^>]*>|xxx+|changeme|none|null)$", re.IGNORECASE
)
_SECRET_COPY = re.compile(r"(^|[/\s])(\.env(\.\w+)?|id_rsa|id_ed25519|\.npmrc|\.netrc)(\s|$)")


def _env_pairs(value: str) -> list[tuple[str, str]]:
    """Split an ENV/ARG operand into ``(name, value)`` pairs (best effort)."""
    if "=" not in value:
        return [(value.split()[0], "")] if value.split() else []
    pairs: list[tuple[str, str]] = []
    for token in re.findall(r"(\w+)=((?:\"[^\"]*\")|(?:'[^']*')|\S*)", value):
        name, raw = token
        pairs.append((name, raw.strip("\"'")))
    return pairs


class SecretBakedIntoImageRule(Rule):
    """Credentials frozen into an image layer."""

    id: ClassVar[str] = "VG-CTR-005"
    category: ClassVar[Category] = Category.CONTAINERS
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Secret baked into the image"
    description: ClassVar[str] = (
        "An ENV/ARG value or a COPY of a credential file writes a secret into an image "
        "layer, where it survives forever."
    )
    why_it_matters: ClassVar[str] = (
        "Image layers are immutable and public to anyone who can pull the image — deleting "
        "the file in a later layer does not remove it. Anyone with registry read access, "
        "and anyone who receives the image, gets the credential. Rotating it means "
        "rebuilding and repushing every affected tag."
    )
    references: ClassVar[list[str]] = [
        "https://docs.docker.com/build/building/secrets/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
    ]
    topics: ClassVar[set[str]] = {
        "containers.image-security",
        "secrets.environment-secrets",
        "iac.hardcoded-secrets",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

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
                        description=f"{rel}:{ins.line} bakes a credential into an image layer.",
                        recommended_followup=(
                            "Remove the value from the Dockerfile: inject it at runtime "
                            "(`docker run --env-file` / orchestrator secret) or, for build "
                            "time only, use `RUN --mount=type=secret`. Then rotate the "
                            "exposed credential and add the file to `.dockerignore`."
                        ),
                        redact_evidence=True,
                    )
                )
        return findings

    @staticmethod
    def _offence(ins: Instruction) -> str | None:
        if ins.upper in {"ENV", "ARG"}:
            for name, value in _env_pairs(ins.value):
                if _PLACEHOLDER.match(value.strip()):
                    continue
                if _CRED_NAME.search(name):
                    return f"{ins.upper} {name} carries a credential-shaped value"
                if _CRED_DSN.search(value):
                    return f"{ins.upper} {name} embeds a connection string with credentials"
            return None
        if ins.upper in {"COPY", "ADD"} and _SECRET_COPY.search(" " + ins.value):
            return f"{ins.upper} pulls a credential file into the image"
        return None
