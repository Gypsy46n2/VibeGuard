"""VG-SEC-019 — privileged route without an authentication or authorization check."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, ClassVar

from vibeguard.core.models import (
    AutofixSafety,
    Category,
    Confidence,
    Finding,
    ScaleClass,
    Severity,
)
from vibeguard.core.rule import Rule
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    js_calls,
    node_text,
    source_files,
    walk,
)

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["PrivilegedRouteWithoutAuthRule"]

_MAX = 5

#: An auth mechanism existing anywhere in the project — the rule stays silent in a
#: project that has no authentication at all (that is a different, earlier problem).
_AUTH_PRESENT = re.compile(
    r"login_required|requires_auth|permission_required|user_passes_test|flask[_-]login|"
    r"passport|ensureAuthenticated|requireAuth|isAuthenticated|current_user|"
    r"jwt\.(decode|verify)|get_current_user|IsAuthenticated|authenticate\s*\(",
)
#: Auth applied to this specific handler.
_AUTH_ON_HANDLER = re.compile(
    r"login_required|requires_auth|requires_role|permission_required|user_passes_test|"
    r"permission_classes|IsAdminUser|IsAuthenticated|Depends\s*\(\s*[\w.]*"
    r"(current_user|get_current_user|require|auth)|"
    r"passport\.authenticate|requireAuth|ensureAuthenticated|isAuthenticated|"
    r"checkAuth|authorize|authGuard|verifyToken|admin_required|is_admin|"
    r"current_user|req\.user|request\.user|session\[|session\.get\(|abort\s*\(\s*40",
    re.IGNORECASE,
)
_PRIVILEGED = re.compile(
    r"admin|internal|impersonate|billing|invoice|settings|export|"
    r"delete|destroy|promote|demote|role|permission|users?/[<:{]|users?/\$\{",
    re.IGNORECASE,
)
_ROUTE_DECORATOR = re.compile(
    r"@[\w.]*\b(route|get|post|put|patch|delete)\s*\(\s*[bfru]*['\"]([^'\"]*)",
    re.IGNORECASE,
)
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "all", "use"}


class PrivilegedRouteWithoutAuthRule(Rule):
    """A privilege-shaped route with no visible auth decorator, middleware, or check."""

    id: ClassVar[str] = "VG-SEC-019"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Privileged route without an authentication check"
    description: ClassVar[str] = (
        "A route whose path or handler name signals privilege (admin, internal, delete, "
        "billing, export, a user id in the path) carries no authentication decorator, no "
        "auth middleware, and no auth or ownership check in its body, in a project that "
        "does authenticate elsewhere."
    )
    why_it_matters: ClassVar[str] = (
        "Broken access control is the most common serious web flaw: an unprotected admin "
        "or delete endpoint is exploited by simply visiting the URL, with no attack "
        "technique at all. Where the path carries someone else's id, a missing ownership "
        "check lets any logged-in user read or destroy another user's data."
    )
    references: ClassVar[list[str]] = [
        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "security.auth-bypass",
        "security.authorization-failures",
        "security.idor",
        "security.api-authentication",
        "security.iam",
        "security.oauth",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        py_files = source_files(ctx, PY_SUFFIXES)
        js_files = source_files(ctx, JS_SUFFIXES)
        if not self._project_has_auth(ctx, py_files + js_files):
            return []
        findings: list[Finding] = []
        for rel in py_files:
            if len(findings) >= _MAX:
                break
            findings.extend(self._python(ctx, rel, _MAX - len(findings)))
        for rel in js_files:
            if len(findings) >= _MAX:
                break
            findings.extend(self._javascript(ctx, rel, _MAX - len(findings)))
        return findings[:_MAX]

    def _project_has_auth(self, ctx: ScanContext, files: list[str]) -> bool:
        for rel in files[:400]:
            if _AUTH_PRESENT.search(ctx.read(rel)):
                return True
        return False

    def _python(self, ctx: ScanContext, rel: str, budget: int) -> list[Finding]:
        out: list[Finding] = []
        tree = ctx.ast(rel)
        if tree is None:
            return out
        source = ctx.read(rel).encode("utf-8")
        try:
            root = tree.root_node
        except Exception:  # pragma: no cover - defensive
            return out
        for node in walk(root):
            if len(out) >= budget:
                break
            if node.type != "decorated_definition":
                continue
            text = node_text(source, node)
            match = _ROUTE_DECORATOR.search(text)
            if match is None:
                continue
            path = match.group(2)
            name = self._def_name(source, node)
            if not _PRIVILEGED.search(path) and not _PRIVILEGED.search(name):
                continue
            if _AUTH_ON_HANDLER.search(text):
                continue
            out.append(self._finding(rel, node.start_point[0] + 1, path or name, text))
        return out

    def _def_name(self, source: bytes, node: Any) -> str:
        for child in node.children:
            if child.type == "function_definition":
                return node_text(source, child.child_by_field_name("name"))
        return ""

    def _javascript(self, ctx: ScanContext, rel: str, budget: int) -> list[Finding]:
        out: list[Finding] = []
        for call in js_calls(ctx, rel):
            if len(out) >= budget:
                break
            if call.base not in _HTTP_METHODS:
                continue
            if not re.match(r"^(app|router|server|api)\b", call.name):
                continue
            args = call.args
            path_match = re.match(r"\(\s*['\"`]([^'\"`]*)", args)
            if path_match is None:
                continue
            path = path_match.group(1)
            if not _PRIVILEGED.search(path):
                continue
            if _AUTH_ON_HANDLER.search(args):
                continue
            out.append(self._finding(rel, call.line, path, args))
        return out

    def _finding(self, rel: str, line: int, target: str, text: str) -> Finding:
        return self.make_finding(
            file=rel,
            line=line,
            snippet=text.strip().splitlines()[0][:200] if text.strip() else target,
            description=(
                f"{rel}:{line} exposes `{target}`, whose name signals privileged access, "
                "with no auth decorator, middleware, or in-body check. This is a "
                "name-and-shape heuristic: it cannot see auth applied by a wrapper it does "
                "not recognise or by a gateway outside the repository, so confirm before "
                "acting."
            ),
            recommended_followup=(
                "Add the project's auth guard to this handler (`@login_required` / "
                "`requireAuth` middleware / `Depends(get_current_user)`) and, where the "
                "path carries an id, assert the caller owns the record or holds the "
                "required role before returning it."
            ),
        )
