"""VG-SEC-003 / VG-SEC-004 — server-side and DOM cross-site scripting."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import Category, Confidence, Finding, ScaleClass, Severity
from vibeguard.core.rule import Rule
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    js_calls,
    line_at,
    node_text,
    py_calls,
    source_files,
    walk,
)
from vibeguard.rules.security._taint import first_arg, has_literal_only, is_interpolated_py

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["DomXssSinkRule", "UnescapedTemplateRenderingRule"]

_TEMPLATE_SUFFIXES = (".html", ".htm", ".jinja", ".jinja2", ".j2")
_SAFE_FILTER = re.compile(r"\{\{[^}]*\|\s*safe\b")
_AUTOESCAPE_OFF = re.compile(r"\{%\s*autoescape\s+(false|off)\s*%\}", re.IGNORECASE)
_VUE_HTML = re.compile(r"\bv-html\s*=")
_MAX = 8


class UnescapedTemplateRenderingRule(Rule):
    """Template output that bypasses auto-escaping, or a dynamically built template."""

    id: ClassVar[str] = "VG-SEC-003"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Unescaped template rendering"
    description: ClassVar[str] = (
        "A template renders a value with escaping turned off, or a template is built "
        "from a non-literal string, so attacker-controlled text reaches the page or the "
        "template engine itself."
    )
    why_it_matters: ClassVar[str] = (
        "Escaping is what stops a user's name or comment from becoming executable markup. "
        "Turn it off and any stored text becomes a script that runs in every visitor's "
        "browser, stealing sessions and acting as that user. When the template string "
        "itself is dynamic, the attacker runs code on the server instead of the browser."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "https://jinja.palletsprojects.com/en/stable/templates/#working-with-automatic-escaping",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.xss", "security.template-injection"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._templates(ctx))
        findings.extend(self._python(ctx, _MAX - len(findings)))
        return findings[:_MAX]

    def _templates(self, ctx: ScanContext) -> list[Finding]:
        out: list[Finding] = []
        for rel in source_files(ctx, _TEMPLATE_SUFFIXES):
            if len(out) >= _MAX:
                break
            for index, line in enumerate(ctx.read(rel).splitlines()):
                if len(out) >= _MAX or len(line) > 2000:
                    continue
                if not (_SAFE_FILTER.search(line) or _AUTOESCAPE_OFF.search(line)):
                    continue
                out.append(
                    self.make_finding(
                        file=rel,
                        line=index + 1,
                        snippet=line.strip()[:200],
                        description=(
                            f"{rel}:{index + 1} disables HTML escaping (`|safe` or "
                            "`autoescape false`), so the value is written to the page raw."
                        ),
                        recommended_followup=(
                            "Drop the `|safe` filter and let auto-escaping run. If the value "
                            "genuinely contains HTML, sanitise it first with a strict "
                            "allowlist (bleach/nh3) and mark only the sanitised result safe."
                        ),
                    )
                )
        return out

    def _python(self, ctx: ScanContext, budget: int) -> list[Finding]:
        out: list[Finding] = []
        if budget <= 0:
            return out
        wanted = {"render_template_string", "Markup", "mark_safe", "format_html"}
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(out) >= budget:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in py_calls(ctx, rel):
                if len(out) >= budget:
                    break
                if call.base not in wanted:
                    continue
                arg = first_arg(call.node)
                if arg is None:
                    continue
                if has_literal_only(arg) and not is_interpolated_py(source, arg):
                    continue
                if arg.type in {"string", "concatenated_string"} and not is_interpolated_py(
                    source, arg
                ):
                    continue
                out.append(
                    self.make_finding(
                        file=rel,
                        line=call.line,
                        snippet=f"{call.name}({node_text(source, arg).strip()[:180]})",
                        description=(
                            f"`{call.name}(...)` at {rel}:{call.line} wraps a non-literal "
                            "value, bypassing escaping or building the template itself from "
                            "dynamic text."
                        ),
                        recommended_followup=(
                            "Render a static template file and pass the value as a context "
                            "variable so Jinja escapes it: "
                            "`render_template('page.html', name=name)`."
                        ),
                    )
                )
        return out


_SINK_CALLS = {"write", "writeln", "insertAdjacentHTML", "eval"}
_SINK_PROPS = {"innerHTML", "outerHTML"}


class DomXssSinkRule(Rule):
    """A browser HTML/eval sink fed with something other than a literal."""

    id: ClassVar[str] = "VG-SEC-004"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "DOM XSS sink fed with dynamic data"
    description: ClassVar[str] = (
        "Dynamic data is written into an HTML-parsing or code-evaluating browser sink "
        "(innerHTML, document.write, insertAdjacentHTML, dangerouslySetInnerHTML, "
        "v-html, eval) instead of being set as text."
    )
    why_it_matters: ClassVar[str] = (
        "These sinks parse their input as markup or code. If any part of the value comes "
        "from a URL, an API response, or another user's stored content, an attacker can "
        "run script in your visitors' browsers — reading their session, submitting forms "
        "as them, and exfiltrating whatever the page can see."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
        "https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.xss"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, JS_SUFFIXES):
            if len(findings) >= _MAX:
                break
            text = ctx.read(rel)
            source = text.encode("utf-8")
            tree = ctx.ast(rel)
            if tree is None:
                continue
            try:
                root = tree.root_node
            except Exception:  # pragma: no cover - defensive
                continue
            for node in walk(root):
                if len(findings) >= _MAX:
                    break
                hit = self._assignment(source, node) or self._jsx(source, node)
                if hit is None:
                    continue
                findings.append(self._finding(rel, line_at(text, node.start_byte), hit))
            for call in js_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                if call.base not in _SINK_CALLS:
                    continue
                if call.base in {"write", "writeln"} and "document" not in call.name:
                    continue
                arg = first_arg(call.node)
                if arg is None or has_literal_only(arg):
                    continue
                findings.append(
                    self._finding(rel, call.line, f"{call.name}({node_text(source, arg)[:150]})")
                )
        for rel in source_files(ctx, (".vue", ".html", ".htm", ".svelte")):
            if len(findings) >= _MAX:
                break
            findings.extend(self._vue(ctx, rel, ctx.read(rel), _MAX - len(findings)))
        return findings[:_MAX]

    def _assignment(self, source: bytes, node: object) -> str | None:
        if getattr(node, "type", "") != "assignment_expression":
            return None
        left = node.child_by_field_name("left")  # type: ignore[attr-defined]
        right = node.child_by_field_name("right")  # type: ignore[attr-defined]
        if left is None or right is None:
            return None
        if node_text(source, left).rsplit(".", 1)[-1] not in _SINK_PROPS:
            return None
        if has_literal_only(right):
            return None
        return node_text(source, node)[:180]

    def _jsx(self, source: bytes, node: object) -> str | None:
        if getattr(node, "type", "") != "jsx_attribute":
            return None
        text = node_text(source, node)
        if not text.startswith("dangerouslySetInnerHTML"):
            return None
        value = text.split("__html", 1)[-1]
        if re.match(r"\s*:\s*['\"]", value):
            return None
        return text[:180]

    def _vue(self, ctx: ScanContext, rel: str, text: str, budget: int) -> list[Finding]:
        out: list[Finding] = []
        if budget <= 0:
            return out
        for index, line in enumerate(text.splitlines()):
            if len(out) >= budget:
                break
            if _VUE_HTML.search(line):
                out.append(self._finding(rel, index + 1, line.strip()[:180]))
        return out

    def _finding(self, rel: str, line: int, snippet: str) -> Finding:
        return self.make_finding(
            file=rel,
            line=line,
            snippet=snippet,
            description=(
                f"{rel}:{line} writes dynamic data into an HTML or code sink; the value is "
                "parsed as markup rather than inserted as text."
            ),
            recommended_followup=(
                "Use `element.textContent = value` (or React's default JSX interpolation). "
                "If the value must contain markup, run it through DOMPurify.sanitize() "
                "first; replace `eval()` with `JSON.parse()` or an explicit dispatch table."
            ),
        )
