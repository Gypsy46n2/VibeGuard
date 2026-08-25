"""Scale heuristics — the anti-overengineering gate (ARCHITECTURE.md §5)."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path, PurePosixPath

import yaml

from vibeguard.core.models import ScaleClass, ScaleProfile, TechProfile
from vibeguard.discovery.files import SOURCE_EXTENSIONS

__all__ = ["detect_scale", "count_loc", "count_services"]

Reader = Callable[[str], str]

#: Keywords that suggest the app handles regulated or personal data.
_SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "credit_card",
    "creditcard",
    "card_number",
    "cardnumber",
    "cvv",
    "iban",
    "ssn",
    "social_security",
    "date_of_birth",
    "dateofbirth",
    "national_id",
    "passport",
    "medical",
    "diagnosis",
    "patient",
    "stripe",
    "paypal",
    "braintree",
    "payment",
    "invoice",
    "billing",
    "pii",
    "gdpr",
    "hipaa",
)

_SENSITIVE_RE = re.compile("|".join(re.escape(k) for k in _SENSITIVE_KEYWORDS))
_MAX_SENSITIVE_SCAN_FILES = 400

_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


def count_loc(files: list[str], read: Reader) -> int:
    """Total non-empty lines across recognised source files."""
    total = 0
    for rel in files:
        if PurePosixPath(rel).suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        text = read(rel)
        total += sum(1 for line in text.splitlines() if line.strip())
    return total


def count_services(files: list[str], read: Reader) -> int:
    """Number of deployable services, from compose files and k8s manifests."""
    services = 0
    for rel in files:
        name = PurePosixPath(rel).name.lower()
        if name in _COMPOSE_NAMES:
            try:
                doc = yaml.safe_load(read(rel)) or {}
            except yaml.YAMLError:
                continue
            if isinstance(doc, dict) and isinstance(doc.get("services"), dict):
                services += len(doc["services"])
    k8s_workloads = 0
    for rel in files:
        if PurePosixPath(rel).suffix.lower() not in {".yml", ".yaml"}:
            continue
        if rel.startswith(".github/"):
            continue
        text = read(rel)
        if "apiVersion" not in text:
            continue
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError:
            continue
        for doc in docs:
            if isinstance(doc, dict) and doc.get("kind") in {
                "Deployment",
                "StatefulSet",
                "DaemonSet",
                "CronJob",
                "Job",
            }:
                k8s_workloads += 1
    return max(1, services, k8s_workloads)


def _has_sensitive_data(
    files: list[str], read: Reader, tech: TechProfile
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if tech.auth:
        reasons.append(f"auth stack present ({', '.join(sorted(tech.auth))})")
    if tech.databases:
        reasons.append(f"persistent datastore ({', '.join(sorted(tech.databases))})")
    scanned = 0
    for rel in files:
        if PurePosixPath(rel).suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        if scanned >= _MAX_SENSITIVE_SCAN_FILES:
            break
        scanned += 1
        match = _SENSITIVE_RE.search(read(rel).lower())
        if match:
            reasons.append(f"sensitive-data keyword {match.group(0)!r} in {rel}")
            break
    sensitive = bool(tech.auth) or len(reasons) >= 2 or any("keyword" in r for r in reasons)
    return sensitive, reasons


def detect_scale(
    root: Path, files: list[str], read: Reader, tech: TechProfile
) -> ScaleProfile:
    """Classify project size from LOC, service count, and infrastructure signals."""
    loc = count_loc(files, read)
    services = count_services(files, read)
    sensitive, sensitive_reasons = _has_sensitive_data(files, read, tech)

    if loc >= 50_000 or services >= 5:
        scale = ScaleClass.LARGE
    elif loc >= 10_000 or services >= 3 or "k8s" in tech.containers:
        scale = ScaleClass.MEDIUM
    elif loc >= 1_000 or services >= 2 or bool(tech.databases) or bool(tech.ci_cd):
        scale = ScaleClass.SMALL
    else:
        scale = ScaleClass.TOY

    bits = [f"{loc} LOC", f"{services} service(s)"]
    if tech.containers:
        bits.append("containers: " + ", ".join(sorted(tech.containers)))
    if tech.ci_cd:
        bits.append("ci: " + ", ".join(sorted(tech.ci_cd)))
    bits.extend(sensitive_reasons)
    rationale = f"classified {scale.value}: " + "; ".join(bits)

    return ScaleProfile(
        scale=scale,
        loc=loc,
        service_count=services,
        has_sensitive_data=sensitive,
        rationale=rationale,
    )
