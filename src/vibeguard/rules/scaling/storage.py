"""VG-SCALE-002 — uploaded files written to the local filesystem."""

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
from vibeguard.rules._support import JS_SUFFIXES, PY_SUFFIXES, RegexRule
from vibeguard.rules.scaling._signals import grep_repo

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["LocalUploadStorageRule"]

#: Any object-storage client anywhere in the project makes this rule stand down.
_OBJECT_STORAGE = re.compile(
    r"\bboto3\b|botocore|@aws-sdk/client-s3|\bS3Client\b|\bs3\.upload|put_object\(|"
    r"upload_fileobj\(|google-cloud-storage|from google\.cloud import storage|"
    r"@google-cloud/storage|azure-storage-blob|BlobServiceClient|\bminio\b|"
    r"cloudinary|uploadthing|@vercel/blob|django-storages|flask-s3|multer-s3|"
    r"aws_s3_bucket|google_storage_bucket|azurerm_storage_container",
    re.IGNORECASE,
)

_UPLOAD_DIR = r"(?:uploads?|static|media|files|/tmp|tmp|public|attachments|avatars)"

_PATTERNS = (
    # Flask/Django/Werkzeug: file.save("uploads/...")
    re.compile(rf"\.save\(\s*[^)]*{_UPLOAD_DIR}", re.IGNORECASE),
    re.compile(r"\.save\(\s*os\.path\.join\(\s*[A-Z_]*UPLOAD", re.IGNORECASE),
    re.compile(r"^\s*UPLOAD_FOLDER\s*=|app\.config\[[\"']UPLOAD_FOLDER[\"']\]\s*="),
    # shutil / raw writes of an uploaded file
    re.compile(rf"shutil\.(?:copyfile|copyfileobj|move)\(\s*[^)]*{_UPLOAD_DIR}", re.IGNORECASE),
    re.compile(rf"open\(\s*[^)]*{_UPLOAD_DIR}[^)]*[\"']wb?[\"']", re.IGNORECASE),
    # Node: multer disk storage / fs writes into an upload directory
    re.compile(r"multer\s*\(\s*\{[^}]*dest\s*:", re.IGNORECASE),
    re.compile(r"multer\.diskStorage\s*\(", re.IGNORECASE),
    re.compile(rf"fs\.(?:promises\.)?(?:writeFile|createWriteStream|rename|copyFile)"
               rf"(?:Sync)?\(\s*[^)]*{_UPLOAD_DIR}", re.IGNORECASE),
)


class LocalUploadStorageRule(RegexRule):
    """User uploads persisted to the instance's own disk."""

    id: ClassVar[str] = "VG-SCALE-002"
    category: ClassVar[Category] = Category.SCALABILITY
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Uploads written to the local filesystem"
    description: ClassVar[str] = (
        "Uploaded files are written into a local directory and no object-storage client "
        "(S3, GCS, Azure Blob, MinIO) was found anywhere in the project."
    )
    why_it_matters: ClassVar[str] = (
        "Local disk belongs to one instance and disappears with it. Every redeploy or "
        "container restart deletes the uploads, and while several instances are running "
        "an image uploaded through one of them 404s on all the others — so users see "
        "broken avatars and missing documents that nobody can reproduce. Filling the "
        "instance's disk can also take the whole service down."
    )
    references: ClassVar[list[str]] = [
        "https://12factor.net/processes",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/upload-objects.html",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"scaling.shared-storage"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    patterns: ClassVar[tuple[re.Pattern[str], ...]] = _PATTERNS
    suffixes: ClassVar[tuple[str, ...]] = PY_SUFFIXES + JS_SUFFIXES
    max_per_file: ClassVar[int] = 2
    max_total: ClassVar[int] = 5
    skip_non_code: ClassVar[bool] = True
    recommended_followup: ClassVar[str] = (
        "Write uploads to object storage instead of disk — `boto3.client(\"s3\")."
        "upload_fileobj(file, BUCKET, key)` on Python, `multer-s3` or a presigned PUT on "
        "Node — and store only the resulting key in the database."
    )

    # M3 fix(): none — swapping local writes for an S3 client changes deployment config.
    def detect(self, ctx: ScanContext) -> list[Finding]:
        if grep_repo(ctx, _OBJECT_STORAGE, skip_tests=False) is not None:
            return []
        return super().detect(ctx)

    def describe(self, ctx: ScanContext, relpath: str, line_no: int, line: str) -> str:
        return (
            f"{relpath}:{line_no} writes an uploaded file into a local directory, and no "
            "object-storage client (boto3/S3, Google Cloud Storage, Azure Blob, MinIO) "
            "appears anywhere in the project. Files written here live on a single "
            "instance's ephemeral disk."
        )


RULES: list[type[Rule]] = [LocalUploadStorageRule]
