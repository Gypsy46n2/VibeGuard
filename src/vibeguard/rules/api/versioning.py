"""VG-API-005 — no way to evolve the API without breaking existing clients."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    ScaleClass,
    Severity,
)
from vibeguard.rules._support import ProjectRule
from vibeguard.rules.api._http import handlers, repo_matches, serves_http

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoApiVersioningRule"]

_VERSIONED_PATH = re.compile(r"/v\d+(?:[./_-]|$)|/version/\d|/api/\d+")
_VERSION_HEADER = re.compile(
    r"accept-version|api-version|x-api-version|X-Api-Version|"
    r"application/vnd\.[\w.]+\+json",
    re.IGNORECASE,
)
_ROUTER_PREFIX = re.compile(
    r"""(?:prefix|url_prefix|basePath|base_path|mountPath)\s*[=:]\s*['"]/[\w-]*v\d""",
    re.IGNORECASE,
)
_OPENAPI_NAMES = ("openapi", "swagger", "asyncapi", "api-spec", "apispec")
_OPENAPI_VERSION = re.compile(r"^\s*(?:version|info_version)\s*:\s*['\"]?\d", re.MULTILINE)


class NoApiVersioningRule(ProjectRule):
    """Routes exist but nothing declares which version of the contract they are."""

    id: ClassVar[str] = "VG-API-005"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.INFO
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No API versioning strategy"
    description: ClassVar[str] = (
        "The service exposes HTTP routes but none of them are versioned: no /v1-style path "
        "prefix, no versioned router, no Accept-Version header, and no version declared in "
        "an OpenAPI document."
    )
    why_it_matters: ClassVar[str] = (
        "Without a version marker, the first breaking change — a renamed field, a removed "
        "endpoint, a stricter validation rule — silently breaks every mobile app, "
        "integration, and script already calling you, and you have no way to keep the old "
        "behaviour alive while clients migrate. Adding versioning later is far more "
        "expensive than starting with `/v1` today."
    )
    references: ClassVar[list[str]] = [
        "https://cloud.google.com/apis/design/versioning",
        "https://swagger.io/specification/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"api.api-versioning", "api.semantic-versioning"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.INFORMATIONAL
    recommended_followup: ClassVar[str] = (
        "Mount the current routes under an explicit prefix (`/api/v1/...`) and publish an "
        "OpenAPI document that names the version, so a future v2 can ship alongside v1 "
        "instead of replacing it."
    )

    def check(self, ctx: ScanContext) -> tuple[str, str] | None:
        if not serves_http(ctx):
            return None
        found = handlers(ctx)
        if not found:
            return None
        if any(_VERSIONED_PATH.search(handler.path) for handler in found):
            return None
        if repo_matches(ctx, _VERSION_HEADER) or repo_matches(ctx, _ROUTER_PREFIX):
            return None
        if self._versioned_spec(ctx):
            return None
        sample = ", ".join(sorted({h.path for h in found if h.path})[:5]) or "(no literal paths)"
        return (
            f"{len(found)} route(s) are registered and none carry a version marker "
            f"(sample: {sample}).",
            "checked route paths for /v1-style prefixes, the repo for Accept-Version / "
            "API-Version headers and versioned router prefixes, and OpenAPI specs for a "
            "declared version",
        )

    @staticmethod
    def _versioned_spec(ctx: ScanContext) -> bool:
        for rel in ctx.files:
            name = PurePosixPath(rel).name.lower()
            if not any(hint in name for hint in _OPENAPI_NAMES):
                continue
            text = ctx.read(rel)
            if _OPENAPI_VERSION.search(text) or '"version"' in text:
                return True
        return False
