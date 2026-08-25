"""VG-SEC-010 / VG-SEC-011 — weak primitives and unsafe randomness."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

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
    CallSite,
    ancestors,
    js_calls,
    node_text,
    py_calls,
    source_files,
)
from vibeguard.rules.security._taint import block_text

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["UnsafeRandomnessRule", "WeakCryptographyRule"]

_MAX = 8

_WEAK_HASHES = {"md5", "sha1", "md4", "sha", "ripemd"}
_WEAK_CIPHER_TEXT = re.compile(
    r"\b(DES3?|TripleDES|ARC4|RC4|Blowfish|CAST5|IDEA)\b|MODE_ECB|\bECB\b|"
    r"algorithms\.(TripleDES|ARC4|Blowfish|IDEA|CAST5)",
)
_CIPHER_CALL = re.compile(r"cipher|crypto|\bAES\b|encrypt|decrypt|algorithms\.", re.IGNORECASE)
_WEAK_IV = re.compile(r"\b(iv|IV|nonce)\s*=\s*(random\.|Math\.random|str\(random)")
_SENSITIVE_CONTEXT = re.compile(r"password|passwd|pwd|secret|token|credential|api_?key", re.I)
_STRONG_KDF = re.compile(r"bcrypt|scrypt|argon2|pbkdf2|passlib|werkzeug\.security", re.I)


class WeakCryptographyRule(Rule):
    """MD5/SHA-1 digests, legacy ciphers, ECB mode, or predictable IVs."""

    id: ClassVar[str] = "VG-SEC-010"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.HIGH
    title: ClassVar[str] = "Weak cryptographic primitive"
    description: ClassVar[str] = (
        "A broken or obsolete cryptographic primitive is in use: an MD5/SHA-1 digest, a "
        "legacy cipher (DES, RC4, Blowfish), AES in ECB mode, or an IV taken from a "
        "non-cryptographic random source."
    )
    why_it_matters: ClassVar[str] = (
        "MD5 and SHA-1 collide on commodity hardware and, used for passwords, fall to "
        "off-the-shelf GPU cracking at billions of guesses per second; ECB mode leaks the "
        "shape of your plaintext straight through the ciphertext. When one of these "
        "protects credentials or tokens, a stolen database is a solved database."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.weak-cryptography", "security.encryption-at-rest"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        for suffixes, extractor in ((PY_SUFFIXES, py_calls), (JS_SUFFIXES, js_calls)):
            for rel in source_files(ctx, suffixes):
                if len(findings) >= _MAX:
                    break
                source = ctx.read(rel).encode("utf-8")
                for call in extractor(ctx, rel):
                    if len(findings) >= _MAX:
                        break
                    label = self._weak_call(call)
                    if label is None or (rel, call.line) in seen:
                        continue
                    seen.add((rel, call.line))
                    context = block_text(source, call.node)
                    sensitive = bool(_SENSITIVE_CONTEXT.search(context))
                    if sensitive and _STRONG_KDF.search(context):
                        continue
                    findings.append(self._finding(rel, call.line, label, call.name, sensitive))
        findings.extend(self._text_scan(ctx, _MAX - len(findings)))
        return findings[:_MAX]

    def _weak_call(self, call: CallSite) -> str | None:
        name = call.name
        base = call.base.lower()
        if base in _WEAK_HASHES and ("hashlib" in name or "crypto" in name.lower()):
            return f"{call.base.upper()} digest"
        if base in {"new", "createhash"} or call.base in {"createHash", "new"}:
            arg = call.args.lower()
            for weak in _WEAK_HASHES:
                if f"'{weak}'" in arg or f'"{weak}"' in arg:
                    return f"{weak.upper()} digest"
        if _WEAK_CIPHER_TEXT.search(name):
            return "legacy cipher or ECB mode"
        # Arguments are only consulted for calls that are plausibly cipher construction,
        # so a regex or a docstring merely mentioning "DES" is not a finding.
        if _CIPHER_CALL.search(name) and _WEAK_CIPHER_TEXT.search(call.args):
            return "legacy cipher or ECB mode"
        return None

    def _text_scan(self, ctx: ScanContext, budget: int) -> list[Finding]:
        out: list[Finding] = []
        if budget <= 0:
            return out
        for rel in source_files(ctx, PY_SUFFIXES + JS_SUFFIXES):
            if len(out) >= budget:
                break
            for index, line in enumerate(ctx.read(rel).splitlines()):
                if len(out) >= budget or len(line) > 500:
                    continue
                stripped = line.strip()
                if stripped.startswith(("#", "//", "*")):
                    continue
                if not _WEAK_IV.search(line):
                    continue
                out.append(self._finding(rel, index + 1, "predictable IV/nonce", stripped, True))
        return out

    def _finding(self, rel: str, line: int, label: str, snippet: str, sensitive: bool) -> Finding:
        return self.make_finding(
            file=rel,
            line=line,
            severity=Severity.HIGH if sensitive else Severity.MEDIUM,
            snippet=snippet[:200],
            description=(
                f"{rel}:{line} uses a {label}"
                + (
                    " in code that handles passwords, secrets, or tokens."
                    if sensitive
                    else " (no credential handling detected nearby)."
                )
            ),
            recommended_followup=(
                "Use SHA-256/SHA-3 for integrity digests, AES-GCM (never ECB) with a "
                "random per-message IV from `os.urandom`/`crypto.randomBytes` for "
                "encryption, and argon2id/bcrypt/scrypt — never a bare hash — for "
                "passwords."
            ),
        )


_RANDOM_FUNCS = {"random", "randint", "randrange", "choice", "choices", "sample", "shuffle",
                 "uniform", "getrandbits"}
_SECURITY_NAMES = re.compile(
    r"token|secret|session|otp|nonce|password|passwd|api_?key|apikey|reset|csrf|uuid|salt|"
    r"verification|invite|voucher|coupon_code",
    re.IGNORECASE,
)


class UnsafeRandomnessRule(Rule):
    """A security-sensitive value generated from a non-cryptographic RNG."""

    id: ClassVar[str] = "VG-SEC-011"
    category: ClassVar[Category] = Category.SECURITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Cryptographically unsafe randomness for a security value"
    description: ClassVar[str] = (
        "A token, session id, OTP, nonce, or password is built with `random`/"
        "`Math.random()`, which is a predictable pseudo-random generator."
    )
    why_it_matters: ClassVar[str] = (
        "These generators are built for simulations, not secrets: their output follows "
        "from internal state an attacker can reconstruct after seeing a handful of "
        "values. Once reconstructed, every future password-reset link, session id, or "
        "one-time code is predictable, and accounts can be taken over without any "
        "password ever being guessed."
    )
    references: ClassVar[list[str]] = [
        "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation",
        "https://docs.python.org/3/library/secrets.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"security.unsafe-randomness"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    # M3 fix(): secrets.token_urlsafe() / crypto.randomBytes().
    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for suffixes, extractor in ((PY_SUFFIXES, py_calls), (JS_SUFFIXES, js_calls)):
            for rel in source_files(ctx, suffixes):
                if len(findings) >= _MAX:
                    break
                source = ctx.read(rel).encode("utf-8")
                for call in extractor(ctx, rel):
                    if len(findings) >= _MAX:
                        break
                    if not self._is_weak_rng(call):
                        continue
                    context = self._context(source, call.node)
                    if not _SECURITY_NAMES.search(context):
                        continue
                    findings.append(
                        self.make_finding(
                            file=rel,
                            line=call.line,
                            snippet=context.strip()[:200],
                            description=(
                                f"`{call.name}(...)` at {rel}:{call.line} produces a value "
                                "whose name marks it as security-sensitive, but the source "
                                "is a predictable pseudo-random generator."
                            ),
                            recommended_followup=(
                                "Generate the value with a CSPRNG: "
                                "`secrets.token_urlsafe(32)` / `secrets.choice(...)` in "
                                "Python, `crypto.randomBytes(32).toString('hex')` or "
                                "`crypto.randomUUID()` in Node."
                            ),
                        )
                    )
        return findings

    def _is_weak_rng(self, call: CallSite) -> bool:
        name = call.name
        if name in {"Math.random", "random.random"}:
            return True
        if call.base in _RANDOM_FUNCS and name.startswith(("random.", "np.random.", "rng.")):
            return True
        return call.base in _RANDOM_FUNCS and "." not in name

    def _context(self, source: bytes, node: object) -> str:
        """Statement text plus the enclosing function's signature line."""
        header = block_text(source, node).splitlines()
        return f"{header[0] if header else ''}\n{self._statement_text(source, node)}"

    def _statement_text(self, source: bytes, node: object) -> str:
        wanted = {
            "assignment",
            "expression_statement",
            "variable_declarator",
            "return_statement",
            "function_definition",
            "pair",
        }
        for parent in ancestors(node):
            if parent.type in wanted:
                text = node_text(source, parent)
                if len(text) < 400:
                    return text
                break
        return block_text(source, node)[:400]
