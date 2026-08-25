"""VibeGuard security rule pack — VG-SEC-001 … VG-SEC-020.

Injection, XSS, SSRF, access control, cryptography, transport, and configuration
defects. Anything that reasons about code semantics is tree-sitter based (see
:mod:`vibeguard.rules.security._taint` for the shared taint and interpolation
heuristics); regex is reserved for configuration-shaped checks.
"""

from __future__ import annotations

from vibeguard.core.rule import Rule
from vibeguard.rules.security.auth import UnsafeJwtHandlingRule
from vibeguard.rules.security.authz import PrivilegedRouteWithoutAuthRule
from vibeguard.rules.security.cookies import InsecureSessionCookieRule
from vibeguard.rules.security.crypto import UnsafeRandomnessRule, WeakCryptographyRule
from vibeguard.rules.security.csrf import MissingCsrfProtectionRule
from vibeguard.rules.security.deserialization import InsecureDeserializationRule
from vibeguard.rules.security.headers import MissingSecurityHeadersRule, PermissiveCorsRule
from vibeguard.rules.security.injection import CommandInjectionRule, PathTraversalRule
from vibeguard.rules.security.sql import SqlInjectionJavaScriptRule, SqlInjectionPythonRule
from vibeguard.rules.security.ssrf import OpenRedirectRule, ServerSideRequestForgeryRule
from vibeguard.rules.security.transport import DebugModeEnabledRule, TlsVerificationDisabledRule
from vibeguard.rules.security.upload import UnrestrictedFileUploadRule
from vibeguard.rules.security.xss import DomXssSinkRule, UnescapedTemplateRenderingRule

#: Registry order == rule id order.
RULES: list[type[Rule]] = [
    SqlInjectionPythonRule,  # VG-SEC-001
    SqlInjectionJavaScriptRule,  # VG-SEC-002
    UnescapedTemplateRenderingRule,  # VG-SEC-003
    DomXssSinkRule,  # VG-SEC-004
    ServerSideRequestForgeryRule,  # VG-SEC-005
    MissingCsrfProtectionRule,  # VG-SEC-006
    CommandInjectionRule,  # VG-SEC-007
    PathTraversalRule,  # VG-SEC-008
    InsecureDeserializationRule,  # VG-SEC-009
    WeakCryptographyRule,  # VG-SEC-010
    UnsafeRandomnessRule,  # VG-SEC-011
    DebugModeEnabledRule,  # VG-SEC-012
    OpenRedirectRule,  # VG-SEC-013
    MissingSecurityHeadersRule,  # VG-SEC-014
    PermissiveCorsRule,  # VG-SEC-015
    InsecureSessionCookieRule,  # VG-SEC-016
    UnsafeJwtHandlingRule,  # VG-SEC-017
    TlsVerificationDisabledRule,  # VG-SEC-018
    PrivilegedRouteWithoutAuthRule,  # VG-SEC-019
    UnrestrictedFileUploadRule,  # VG-SEC-020
]

__all__ = [
    "RULES",
    "CommandInjectionRule",
    "DebugModeEnabledRule",
    "DomXssSinkRule",
    "InsecureDeserializationRule",
    "InsecureSessionCookieRule",
    "MissingCsrfProtectionRule",
    "MissingSecurityHeadersRule",
    "OpenRedirectRule",
    "PathTraversalRule",
    "PermissiveCorsRule",
    "PrivilegedRouteWithoutAuthRule",
    "ServerSideRequestForgeryRule",
    "SqlInjectionJavaScriptRule",
    "SqlInjectionPythonRule",
    "TlsVerificationDisabledRule",
    "UnescapedTemplateRenderingRule",
    "UnrestrictedFileUploadRule",
    "UnsafeJwtHandlingRule",
    "UnsafeRandomnessRule",
    "WeakCryptographyRule",
]
