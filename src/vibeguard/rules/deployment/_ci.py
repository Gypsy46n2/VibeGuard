"""Private CI-configuration helpers for the deployment pack."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from vibeguard.rules.containers._parse import yaml_documents

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = [
    "CI_FILE_NAMES",
    "ci_files",
    "github_workflows",
    "run_steps",
    "workflow_jobs",
]

#: Single-file CI configurations, by basename.
CI_FILE_NAMES = {
    ".gitlab-ci.yml": "gitlab-ci",
    ".gitlab-ci.yaml": "gitlab-ci",
    "jenkinsfile": "jenkins",
    "azure-pipelines.yml": "azure-pipelines",
    "azure-pipelines.yaml": "azure-pipelines",
    ".drone.yml": "drone",
    "bitbucket-pipelines.yml": "bitbucket-pipelines",
    "bitbucket-pipelines.yaml": "bitbucket-pipelines",
    "cloudbuild.yaml": "cloud-build",
    "buildspec.yml": "codebuild",
}


def ci_files(ctx: ScanContext) -> dict[str, str]:
    """``{relpath: ci system}`` for every CI configuration in the tree."""
    found: dict[str, str] = {}
    for rel in ctx.files:
        posix = PurePosixPath(rel)
        name = posix.name.lower()
        parts = [part.lower() for part in posix.parts]
        if rel.startswith(".github/workflows/") and posix.suffix.lower() in {".yml", ".yaml"}:
            found[rel] = "github-actions"
        elif ".circleci" in parts and name in {"config.yml", "config.yaml"}:
            found[rel] = "circleci"
        elif name in CI_FILE_NAMES:
            found[rel] = CI_FILE_NAMES[name]
        if len(found) >= 40:
            break
    return found


def github_workflows(ctx: ScanContext) -> list[tuple[str, dict[str, Any]]]:
    """``(relpath, parsed workflow)`` for each GitHub Actions workflow."""
    out: list[tuple[str, dict[str, Any]]] = []
    for rel, system in ci_files(ctx).items():
        if system != "github-actions":
            continue
        for doc in yaml_documents(ctx, rel):
            if isinstance(doc, dict):
                out.append((rel, doc))
    return out


def workflow_jobs(workflow: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """``{job id: job}`` for a parsed workflow (empty when malformed)."""
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return {}
    return {str(key): value for key, value in jobs.items() if isinstance(value, dict)}


def run_steps(job: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield each step mapping of a job."""
    steps = job.get("steps")
    if not isinstance(steps, list):
        return
    for step in steps:
        if isinstance(step, dict):
            yield step
