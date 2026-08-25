from __future__ import annotations

import pytest

from vibeguard.core.redact import MASK, mask_token, redact

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


@pytest.mark.parametrize(
    "text, secret",
    [
        (f"aws_access_key_id = {AWS_KEY}", AWS_KEY),
        ('api_key="sk-live-abcdefghijklmnop1234"', "sk-live-abcdefghijklmnop1234"),
        (f"Authorization: Bearer {JWT}", JWT),
        ("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", None),
        ("DATABASE_URL=postgres://user:sup3rs3cret@db:5432/app", "sup3rs3cret"),
    ],
)
def test_secrets_are_masked(text: str, secret: str | None):
    out = redact(text)
    assert MASK in out
    if secret:
        assert secret not in out


def test_mask_keeps_four_leading_and_trailing_chars():
    out = redact(f"api_key = {AWS_KEY}")
    assert AWS_KEY[:4] in out
    assert AWS_KEY[-4:] in out
    assert AWS_KEY not in out


def test_short_tokens_are_fully_masked():
    assert mask_token("abcd") == MASK


def test_ordinary_text_is_untouched():
    text = "def get_user(user_id):\n    return db.query(User).get(user_id)\n"
    assert redact(text) == text
    assert redact("") == ""


def test_redaction_is_idempotent():
    once = redact(f"api_key = {AWS_KEY}")
    assert redact(once) == once


def test_private_key_block_is_masked():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK\n-----END RSA PRIVATE KEY-----"
    out = redact(pem)
    assert MASK in out
    assert "MIIEowIBAAK" not in out
