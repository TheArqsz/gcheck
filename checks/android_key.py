"""Probe API keys with mock Android headers to detect Android restrictions."""

from __future__ import annotations

from ._common import Result, Status, detect_google_service_disabled, http_get

ANDROID_PACKAGE_HEADER = "X-Android-Package"
ANDROID_CERT_HEADER = "X-Android-Cert"

MOCK_PACKAGE = "com.example.test"
MOCK_CERT_SHA1 = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"

PROBE_URL = "https://maps.googleapis.com/maps/api/geocode/json"
ANDROID_KEY_TEST_SERVICE = "Android Key Test"

_INVALID_KEY_HINTS = (
    "invalid api key",
    "api_key_invalid",
    "not a valid api key",
)
_ANDROID_RESTRICTION_HINTS = (
    "api_key_android_app_blocked",
    "android app not found",
    "certificate is not recognized",
)


def _matches_any_hint(text: str, error_text: str, hints: tuple[str, ...]) -> bool:
    return any(hint in text or hint in error_text for hint in hints)


def _extract_probe_signals(body: str, parsed: dict) -> tuple[str, str | None, str]:
    body_lower = body.lower()
    status_field = parsed.get("status") if isinstance(parsed, dict) else None
    error_message = (
        str(parsed.get("error_message", "")).lower() if isinstance(parsed, dict) else ""
    )
    return body_lower, status_field, error_message


def probe_android_headers(api_key: str) -> Result:
    """Probe API key with mock Android headers."""
    headers = {
        ANDROID_PACKAGE_HEADER: MOCK_PACKAGE,
        ANDROID_CERT_HEADER: MOCK_CERT_SHA1,
    }
    code, body, parsed = http_get(
        PROBE_URL,
        params={"address": "test", "key": api_key},
        headers=headers,
        timeout=10,
    )

    if code is None:
        return Result(
            service=ANDROID_KEY_TEST_SERVICE,
            status=Status.ERROR,
            detail=body,
        )

    body_lower, status_field, error_message = _extract_probe_signals(body, parsed)

    if _matches_any_hint(body_lower, error_message, _INVALID_KEY_HINTS):
        return Result(
            service=ANDROID_KEY_TEST_SERVICE,
            status=Status.INVALID,
            detail="API key rejected",
            http_code=code,
        )

    if _matches_any_hint(body_lower, error_message, _ANDROID_RESTRICTION_HINTS):
        return Result(
            service=ANDROID_KEY_TEST_SERVICE,
            status=Status.DENIED,
            detail="Valid key; Android-app-restricted (needs matching bundle+cert)",
            http_code=code,
        )

    disabled_marker = detect_google_service_disabled(body, error_message)
    if disabled_marker:
        return Result(
            service=ANDROID_KEY_TEST_SERVICE,
            status=Status.DISABLED,
            detail=("service disabled/not enabled: " f"{disabled_marker}"),
            http_code=code,
        )

    if status_field in ("OK", "ZERO_RESULTS", "OVER_QUERY_LIMIT"):
        return Result(
            service=ANDROID_KEY_TEST_SERVICE,
            status=Status.VALID,
            detail="Key is valid (no Android restrictions detected)",
            http_code=code,
        )

    return Result(
        service=ANDROID_KEY_TEST_SERVICE,
        status=Status.UNKNOWN,
        detail=f"HTTP {code} (unclassified response)",
        http_code=code,
    )
