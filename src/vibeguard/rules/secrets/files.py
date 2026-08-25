"""VG-SCR-005 / VG-SCR-006 — credential *files* committed to the repository."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
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
from vibeguard.rules._support import is_generated_path, is_test_path
from vibeguard.rules.secrets._common import is_dotenv, is_env_template

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["EnvFileCommittedRule", "PrivateKeyCommittedRule"]

_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "server.key", "client.key"}
_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk")
_KEY_HEADER = re.compile(r"-----BEGIN (?:[A-Z0-9 ]*)PRIVATE KEY-----")
_KEY_FOOTER = re.compile(r"-----END |['\"`]")
_BASE64_CHARS = re.compile(r"[A-Za-z0-9+/=]")
_ESCAPES = re.compile(r"\\[nrt\"'\\]")
_MAX_SNIFF_BYTES = 200_000
#: Base64 characters that must follow the header before this counts as key material.
#: A bare header is documentation ("the file starts with ``-----BEGIN PRIVATE KEY``").
_MIN_BODY_CHARS = 20
#: In a test, spec, or fixture file the bar is a *real* key. Redaction and
#: secret-scanner unit tests are full of truncated stand-ins like
#: ``"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\n-----END..."``; a real 2048-bit
#: RSA key is well over a kilobyte of base64, so length separates them cleanly and
#: without weakening detection anywhere else (DECISIONS.md D69).
_MIN_TEST_BODY_CHARS = 400


def _body_threshold(relpath: str) -> int:
    """How much key material a file must hold before it counts."""
    return _MIN_TEST_BODY_CHARS if is_test_path(relpath) else _MIN_BODY_CHARS


def _has_key_material(text: str, *, minimum: int) -> bool:
    """True when a PEM header is followed by at least ``minimum`` base64 characters.

    Detection by *file name* (``id_rsa``, ``server.key``) is unchanged and stays
    CRITICAL wherever it is found. This only governs the inline case, where the same
    header appears in prose, in a rule's own pattern, and in the fixtures of every
    secret scanner ever written. ``\\n`` escape sequences are stripped first, so a key
    pasted into a one-line source string is measured the same as a real PEM file.
    """
    for match in _KEY_HEADER.finditer(text):
        tail = text[match.end() : match.end() + 8000]
        stop = _KEY_FOOTER.search(tail)
        body = _ESCAPES.sub("\\n", tail[: stop.start()] if stop else tail)
        if len(_BASE64_CHARS.findall(body)) >= minimum:
            return True
    return False


class PrivateKeyCommittedRule(Rule):
    """A private key file, or a PEM private-key header inside any scanned file."""

    id: ClassVar[str] = "VG-SCR-005"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.CRITICAL
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Private key material committed to the repository"
    description: ClassVar[str] = (
        "A private key file (SSH, TLS, or PKCS#12) or an inline "
        "`-----BEGIN ... PRIVATE KEY-----` block is tracked in the repository."
    )
    why_it_matters: ClassVar[str] = (
        "A private key is the one piece of a key pair that must never leave the machine "
        "that uses it. Committed, it lets anyone with repository access impersonate "
        "your server, decrypt intercepted traffic, or log into the hosts that trust the "
        "matching public key. Recovery means generating a new key and re-issuing or "
        "re-trusting it everywhere — the old one can never be un-leaked."
    )
    references: ClassVar[list[str]] = [
        "https://cwe.mitre.org/data/definitions/321.html",
        "https://docs.github.com/authentication/connecting-to-github-with-ssh",
    ]
    topics: ClassVar[set[str]] = {
        "secrets.private-keys-in-repo",
        "security.secret-leakage",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    max_total: ClassVar[int] = 5

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for rel in ctx.files:
            if len(findings) >= self.max_total:
                break
            if is_generated_path(rel):
                continue
            name = PurePosixPath(rel).name.lower()
            by_name = name in _KEY_NAMES or name.endswith(_KEY_SUFFIXES)
            reason = ""
            if by_name:
                reason = f"file name {name!r} is a private key file"
            else:
                text = ctx.read(rel)
                if not text or len(text) > _MAX_SNIFF_BYTES:
                    continue
                if _has_key_material(text, minimum=_body_threshold(rel)):
                    reason = "file contains a PEM private-key block"
            if not reason:
                continue
            findings.append(
                self.make_finding(
                    file=rel,
                    description=(
                        f"Private key material is tracked at {rel} ({reason}); the key "
                        "must be treated as compromised."
                    ),
                    evidence=[Evidence(file=rel, note=reason)],
                    recommended_followup=(
                        f"Generate a replacement key pair, re-deploy or re-trust the new "
                        f"public key, then delete `{rel}` from the working tree, add its "
                        "pattern to `.gitignore`, and purge it from git history "
                        "(`git filter-repo --path` or BFG)."
                    ),
                )
            )
        return findings


class EnvFileCommittedRule(Rule):
    """A real ``.env`` file (not a template) tracked and not covered by .gitignore."""

    id: ClassVar[str] = "VG-SCR-006"
    category: ClassVar[Category] = Category.SECRETS
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Environment file committed to the repository"
    description: ClassVar[str] = (
        "A `.env`-family file holding real configuration is present in the scanned "
        "tree and is not excluded by `.gitignore`."
    )
    why_it_matters: ClassVar[str] = (
        "`.env` is where a project keeps everything it did not want in code: database "
        "passwords, API keys, signing secrets. Committing it hands all of them to "
        "anyone with repository access at once, and to the whole internet the moment "
        "the repository is made public. It is also the single most common way a "
        "hobby project leaks production credentials."
    )
    references: ClassVar[list[str]] = [
        "https://12factor.net/config",
        "https://git-scm.com/docs/gitignore",
    ]
    topics: ClassVar[set[str]] = {
        "secrets.environment-secrets",
        "security.secret-leakage",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    max_total: ClassVar[int] = 3
    recommended_followup: ClassVar[str] = ""

    # M3 fix(): append the offending path to .gitignore (the file itself must be
    # removed from history and its secrets rotated by a human, so no autofix).
    def detect(self, ctx: ScanContext) -> list[Finding]:
        ignored = self._gitignore_entries(ctx)
        findings: list[Finding] = []
        for rel in ctx.files:
            if len(findings) >= self.max_total:
                break
            if not is_dotenv(rel) or is_env_template(rel):
                continue
            name = PurePosixPath(rel).name
            if name in ignored or rel in ignored:
                continue
            findings.append(
                self.make_finding(
                    file=rel,
                    description=(
                        f"`{rel}` is tracked in the repository and no `.gitignore` entry "
                        "covers it."
                    ),
                    evidence=[
                        Evidence(
                            file=rel,
                            note="environment file present in the scanned tree",
                        )
                    ],
                    recommended_followup=(
                        f"Add `{name}` to `.gitignore`, run `git rm --cached {rel}`, "
                        f"commit a redacted `{name}.example` documenting the keys, and "
                        "rotate every credential the file contained."
                    ),
                )
            )
        return findings

    @staticmethod
    def _gitignore_entries(ctx: ScanContext) -> set[str]:
        text = ctx.read(".gitignore")
        entries: set[str] = set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "!")):
                continue
            entries.add(line.lstrip("/").rstrip("/"))
        return entries
