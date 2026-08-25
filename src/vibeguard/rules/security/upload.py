"""VG-SEC-020 — unrestricted file upload."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from vibeguard.core.models import Category, Confidence, Finding, ScaleClass, Severity
from vibeguard.core.rule import Rule
from vibeguard.rules._support import (
    JS_SUFFIXES,
    PY_SUFFIXES,
    CallSite,
    js_calls,
    node_text,
    py_calls,
    source_files,
)
from vibeguard.rules.security._taint import block_text

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["UnrestrictedFileUploadRule"]

_MAX = 5

_FILE_SOURCE = re.compile(r"request\.files|\bfiles\s*\[|FileStorage|UploadFile")
_SECURE_NAME = re.compile(r"secure_filename|uuid4|token_hex|token_urlsafe")
_EXTENSION_GUARD = re.compile(
    r"ALLOWED_EXTENSIONS|allowed_extensions|\.rsplit\(\s*['\"]\.|"
    r"mimetype\s+in\b|content_type\s+in\b|imghdr|python-magic|filetype\.guess",
)
_SIZE_GUARD = re.compile(r"MAX_CONTENT_LENGTH|max_content_length|content_length\s*[<>]")
_FORMIDABLE_GUARD = re.compile(r"maxFileSize|maxTotalFileSize")


class UnrestrictedFileUploadRule(Rule):
    """An upload handler with no filename sanitisation, type allowlist, or size cap."""

    id: ClassVar[str] = "VG-SEC-020"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Unrestricted file upload"
    description: ClassVar[str] = (
        "An uploaded file is written to disk without sanitising its name and without an "
        "extension/content-type allowlist or a size limit — or a Node upload middleware "
        "is configured with no `limits`, `fileFilter`, or `maxFileSize`."
    )
    why_it_matters: ClassVar[str] = (
        "The uploader chooses the filename and the contents. Without sanitisation the name "
        "can escape the upload directory or overwrite an existing file; without a type "
        "allowlist a `.php`, `.jsp`, or `.html` file dropped into a served directory "
        "becomes code or stored XSS; and without a size cap one request fills the disk and "
        "takes the service down."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
        "https://flask.palletsprojects.com/en/stable/patterns/fileuploads/",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.file-upload", "security.path-traversal"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in source_files(ctx, PY_SUFFIXES):
            if len(findings) >= _MAX:
                break
            text = ctx.read(rel)
            source = text.encode("utf-8")
            for call in py_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                if call.base != "save":
                    continue
                context = block_text(source, call.node)
                if not _FILE_SOURCE.search(context) and not _FILE_SOURCE.search(call.name):
                    continue
                missing = self._missing_python(context, text)
                if not missing:
                    continue
                findings.append(
                    self._finding(rel, call.line, f"{call.name}{call.args}", missing)
                )
        for rel in source_files(ctx, JS_SUFFIXES):
            if len(findings) >= _MAX:
                break
            source = ctx.read(rel).encode("utf-8")
            for call in js_calls(ctx, rel):
                if len(findings) >= _MAX:
                    break
                missing = self._missing_js(call, source)
                if not missing:
                    continue
                findings.append(
                    self._finding(rel, call.line, f"{call.name}{call.args}"[:200], missing)
                )
        return findings

    def _missing_python(self, context: str, file_text: str) -> list[str]:
        missing: list[str] = []
        if not _SECURE_NAME.search(context):
            missing.append("filename sanitisation (`secure_filename`)")
        if not _EXTENSION_GUARD.search(context) and not _EXTENSION_GUARD.search(file_text):
            missing.append("an extension/content-type allowlist")
        if not _SIZE_GUARD.search(file_text):
            missing.append("a size limit (`MAX_CONTENT_LENGTH`)")
        return missing

    def _missing_js(self, call: CallSite, source: bytes) -> list[str]:
        name = call.name
        args = call.args or node_text(source, call.node)
        if call.base == "multer" or name.endswith("multer"):
            missing = []
            if not re.search(r"\blimits\s*:", args):
                missing.append("`limits` (file size/count)")
            if not re.search(r"\bfileFilter\s*:", args):
                missing.append("a `fileFilter` type allowlist")
            return missing
        if "formidable" in name.lower() or call.base in {"IncomingForm", "formidable"}:
            if not _FORMIDABLE_GUARD.search(args):
                return ["`maxFileSize`"]
        return []

    def _finding(self, rel: str, line: int, snippet: str, missing: list[str]) -> Finding:
        return self.make_finding(
            file=rel,
            line=line,
            snippet=snippet[:200],
            description=(
                f"{rel}:{line} accepts an uploaded file but is missing "
                + ", ".join(missing)
                + "."
            ),
            recommended_followup=(
                "Rename the file yourself (`secure_filename` or a generated UUID), accept "
                "only an allowlist of extensions *and* sniffed content types, cap the size "
                "(`MAX_CONTENT_LENGTH` / multer `limits`), and store uploads outside any "
                "directory the web server will execute or serve directly."
            ),
        )
