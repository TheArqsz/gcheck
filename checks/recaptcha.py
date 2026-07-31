"""Validate a Google reCAPTCHA secret key via siteverify."""

from __future__ import annotations

from ._common import Result, Status, http_post

RECAPTCHA_SITEVERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"


def check_recaptcha_secret(secret: str) -> list[Result]:
    code, body, parsed = http_post(
        RECAPTCHA_SITEVERIFY_URL,
        data={"secret": secret, "response": "dummy-response-token"},
    )
    error_codes = parsed.get("error-codes", [])

    if code == 200 and "invalid-input-secret" in error_codes:
        return [
            Result(
                service="reCAPTCHA secret (siteverify)",
                status=Status.INVALID,
                detail="invalid-input-secret (key rejected)",
                http_code=code,
                endpoint=RECAPTCHA_SITEVERIFY_URL,
                data=parsed,
            )
        ]
    if code == 200 and (
        parsed.get("success") is True or "invalid-input-response" in error_codes
    ):
        return [
            Result(
                service="reCAPTCHA secret (siteverify)",
                status=Status.VALID,
                detail="secret accepted; dummy response token rejected as expected",
                http_code=code,
                endpoint=RECAPTCHA_SITEVERIFY_URL,
                data=parsed,
            )
        ]
    return [
        Result(
            service="reCAPTCHA secret (siteverify)",
            status=Status.UNKNOWN,
            detail=f"HTTP {code} body[:120]={body[:120]!r}",
            http_code=code,
            endpoint=RECAPTCHA_SITEVERIFY_URL,
            data=parsed,
        )
    ]
