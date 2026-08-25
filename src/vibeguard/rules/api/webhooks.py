"""VG-API-006 / VG-API-007 — unverified webhooks and non-idempotent money routes."""

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
from vibeguard.rules.api._http import Handler, handlers

if TYPE_CHECKING:  # pragma: no cover
    from vibeguard.discovery.context import ScanContext

__all__ = ["NoIdempotencyKeyRule", "UnverifiedWebhookRule"]

_MAX_FINDINGS = 6

_WEBHOOK_NAME = re.compile(r"webhook|web_hook|callback|(?:^|[/_-])hook|notify|notification|ipn")
_SIGNATURE = re.compile(
    r"hmac\.compare_digest|compare_digest|crypto\.timingSafeEqual|timingSafeEqual|"
    r"X-Hub-Signature|x-hub-signature|Stripe-Signature|stripe-signature|"
    r"X-Signature|x-signature|X-Slack-Signature|X-Twilio-Signature|X-Shopify-Hmac|"
    r"constructEvent|construct_event|verify_signature|verifySignature|verify_webhook|"
    r"check_signature|signature_valid|Webhook\s*\(\s*secret|svix",
    re.IGNORECASE,
)

_MONEY_NAME = re.compile(
    r"payment|pay\b|charge|checkout|order|purchase|subscribe|subscription|refund|"
    r"transfer|payout|invoice|billing|provision|topup|top_up|withdraw"
)
_IDEMPOTENCY = re.compile(
    r"idempotency[-_ ]?key|Idempotency-Key|idempotent|request[-_]?id|client[-_]?token|"
    r"dedup|de-dup|nonce|transaction_id|external_id|reference_id|"
    r"unique\s*=\s*True|UniqueConstraint|ON CONFLICT|upsert",
    re.IGNORECASE,
)


def _post_handlers(ctx: ScanContext, name_re: re.Pattern[str]) -> list[Handler]:
    return [
        handler
        for handler in handlers(ctx)
        if name_re.search(handler.signature) and handler.accepts("post")
    ]


class UnverifiedWebhookRule(Rule):
    """A webhook receiver that trusts whatever POSTs to it."""

    id: ClassVar[str] = "VG-API-006"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.HIGH
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "Webhook endpoint without signature verification"
    description: ClassVar[str] = (
        "A webhook/callback route accepts POST but the handler performs no HMAC or "
        "signature verification of the request."
    )
    why_it_matters: ClassVar[str] = (
        "Webhook URLs are not secrets — they leak through logs, browser history, and error "
        "reports, and anyone can POST to them. Without verifying the provider's signature, "
        "an attacker can forge a `payment.succeeded` event and get goods for free, mark "
        "invoices paid, or flip account state at will. Signature checks are the only thing "
        "that proves the event really came from the provider."
    )
    references: ClassVar[list[str]] = [
        "https://docs.stripe.com/webhooks#verify-events",
        "https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {"api.webhooks", "security.api-authentication"}
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.MANUAL_CHANGE_REQUIRED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for handler in _post_handlers(ctx, _WEBHOOK_NAME):
            if len(findings) >= _MAX_FINDINGS:
                break
            if _SIGNATURE.search(handler.text):
                continue
            findings.append(
                self.make_finding(
                    file=handler.file,
                    line=handler.line,
                    snippet=(handler.decorator or handler.path or handler.name)[:400],
                    description=(
                        f"Webhook handler {handler.name}() at {handler.file}:{handler.line} "
                        f"(path {handler.path or 'unknown'}) accepts POST without verifying "
                        "a request signature."
                    ),
                    recommended_followup=(
                        "Verify the provider signature over the raw request body before "
                        "doing anything else, comparing with `hmac.compare_digest(...)` "
                        "(Python) or `crypto.timingSafeEqual(...)` (Node), and reject the "
                        "request with 400 when it does not match."
                    ),
                )
            )
        return findings


class NoIdempotencyKeyRule(Rule):
    """A money or provisioning POST route with no duplicate-request protection."""

    id: ClassVar[str] = "VG-API-007"
    category: ClassVar[Category] = Category.API
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[Confidence] = Confidence.MEDIUM
    title: ClassVar[str] = "No idempotency protection on a state-changing endpoint"
    description: ClassVar[str] = (
        "A POST route that moves money or provisions resources neither reads an "
        "Idempotency-Key header nor deduplicates on a client-supplied identifier."
    )
    why_it_matters: ClassVar[str] = (
        "Networks retry. A user double-clicks, a mobile client resends after a timeout, or "
        "a load balancer replays a request whose response was lost — and the charge, order, "
        "or transfer happens twice. Customers get billed twice and support has to unpick it "
        "by hand; at scale, duplicate provisioning also quietly doubles infrastructure "
        "cost."
    )
    references: ClassVar[list[str]] = [
        "https://docs.stripe.com/api/idempotent_requests",
        "https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header",
    ]
    technologies: ClassVar[set[str]] = set()
    topics: ClassVar[set[str]] = {
        "api.idempotency",
        "api.request-deduplication",
        "performance.duplicate-requests",
    }
    min_scale: ClassVar[ScaleClass] = ScaleClass.TOY
    autofix_safety: ClassVar[AutofixSafety] = AutofixSafety.REVIEW_RECOMMENDED

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for handler in _post_handlers(ctx, _MONEY_NAME):
            if len(findings) >= _MAX_FINDINGS:
                break
            if _IDEMPOTENCY.search(handler.text):
                continue
            findings.append(
                self.make_finding(
                    file=handler.file,
                    line=handler.line,
                    snippet=(handler.decorator or handler.path or handler.name)[:400],
                    description=(
                        f"State-changing handler {handler.name}() at "
                        f"{handler.file}:{handler.line} (path {handler.path or 'unknown'}) "
                        "accepts POST with no idempotency key or deduplication, so a "
                        "retried request runs the operation twice."
                    ),
                    recommended_followup=(
                        "Require an `Idempotency-Key` header, store it with the result "
                        "under a unique constraint, and return the stored response when the "
                        "same key arrives again instead of re-running the operation."
                    ),
                )
            )
        return findings
