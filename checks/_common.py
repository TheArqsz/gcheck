"""Shared HTTP, result, and output helpers."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import requests

DEFAULT_TIMEOUT = 10
USER_AGENT = "gcheck/1.0 (+pentest credential validator)"
_DEFAULT_REQUEST_HEADERS: dict[str, str] = {}

RECOMMENDATION_REGISTRY: dict[str, dict[str, Any]] = {
    "API_KEY_HTTP_REFERRER_BLOCKED": {
        "hint_code": "HINT_REFERRER_REQUIRED",
        "recommended_flags": [
            "--referer",
            "--referer-wordlist",
            "--referer-template",
        ],
        "recommended_command": "gcheck --api-key <API_KEY> --referer <allowed-origin>",
        "alternate_recommended_commands": [
            "gcheck --api-key <API_KEY> --referer-wordlist <wordlist.txt>",
            (
                "gcheck --api-key <API_KEY> --referer-wordlist <wordlist.txt> "
                "--referer-template https://FUZZ.example.com/"
            ),
        ],
        "confidence": "high",
        "recommendation_source": "reason-registry",
    },
    "API_KEY_ANDROID_APP_BLOCKED": {
        "hint_code": "HINT_ANDROID_APP_REQUIRED",
        "recommended_flags": ["--android-package", "--android-cert"],
        "recommended_command": (
            "gcheck --api-key <API_KEY> --android-package <package> "
            "--android-cert <sha1>"
        ),
        "confidence": "high",
        "recommendation_source": "reason-registry",
    },
    "API_KEY_IOS_APP_BLOCKED": {
        "hint_code": "HINT_IOS_BUNDLE_REQUIRED",
        "recommended_flags": ["--ios-bundle"],
        "recommended_command": "gcheck --api-key <API_KEY> --ios-bundle <bundle-id>",
        "confidence": "high",
        "recommendation_source": "reason-registry",
    },
}

_CONFIDENCE_SCORE = {"low": 1, "medium": 2, "high": 3}

_GOOGLE_DISABLED_HINTS: tuple[tuple[str, str], ...] = (
    ("you must enable billing", "GOOGLE_BILLING_DISABLED"),
    ("billingnotenabled", "GOOGLE_BILLING_DISABLED"),
    ("service_disabled", "GOOGLE_API_NOT_ENABLED"),
    ("service disabled", "GOOGLE_API_NOT_ENABLED"),
    ("accessnotconfigured", "GOOGLE_API_NOT_ENABLED"),
    ("access_not_configured", "GOOGLE_API_NOT_ENABLED"),
    ("has not been used in project", "GOOGLE_API_NOT_ENABLED"),
    ("api has not been used in project", "GOOGLE_API_NOT_ENABLED"),
    ("not enabled for your project", "GOOGLE_API_NOT_ENABLED"),
    ("legacy api, which is not enabled", "GOOGLE_API_NOT_ENABLED"),
    ("this api is not activated", "GOOGLE_API_NOT_ENABLED"),
    ("api not activated", "GOOGLE_API_NOT_ENABLED"),
    ("project_denied", "GOOGLE_API_NOT_ENABLED"),
)


def _normalize_text_fragments(values: tuple[Any, ...]) -> list[str]:
    normalized: list[str] = []
    for value in values:
        if value is None:
            continue
        text = value if isinstance(value, str) else str(value)
        normalized.append(text.lower())
    return normalized


def _first_matching_reason(candidate_blob: str) -> str | None:
    for reason in RECOMMENDATION_REGISTRY:
        if reason.lower() in candidate_blob:
            return reason
    return None


class Status(str, Enum):
    VALID = "VALID"
    DENIED = "DENIED"
    INVALID = "INVALID"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


def detect_google_service_disabled(*texts: Any) -> str | None:
    """Return stable disabled reason code for Google API/service disablement.

    Accepts mixed inputs and scans them case-insensitively for known disabled
    or not-enabled indicators.
    """
    normalized = _normalize_text_fragments(texts)
    if not normalized:
        return None

    haystack = "\n".join(normalized)
    for needle, canonical in _GOOGLE_DISABLED_HINTS:
        if needle in haystack:
            return canonical
    return None


@dataclass
class Result:
    service: str
    status: Status
    detail: str = ""
    data: dict = field(default_factory=dict)
    http_code: Optional[int] = None
    endpoint: str = ""

    def to_dict(self) -> dict:
        return {
            "service": self.service,
            "status": self.status.value,
            "detail": self.detail,
            "http_code": self.http_code,
            "endpoint": self.endpoint,
            "data": self.data,
        }


def detect_key_restriction(results: list[Result], min_hits: int = 3) -> str | None:
    """Return likely key restriction class based on repeated denial patterns."""
    counts = {
        "android": 0,
        "ios": 0,
        "referrer": 0,
    }
    for result in results:
        detail = (result.detail or "").lower()
        if "api_key_android_app_blocked" in detail:
            counts["android"] += 1
        if "api_key_ios_app_blocked" in detail:
            counts["ios"] += 1
        if (
            "api_key_http_referrer_blocked" in detail
            or "requests-from-referer" in detail
            or "referer restrictions" in detail
        ):
            counts["referrer"] += 1

    threshold = max(1, int(min_hits or 1))
    for restriction, value in counts.items():
        if value >= threshold:
            return restriction
    return None


def apply_indicator_recommendations(
    detail: str,
    indicator_to_recommendation: dict[str, str],
    *,
    recommendation_prefix: str = "recommendation:",
) -> tuple[str, list[str]]:
    """Append recommendation text when indicators are found in detail.

    Matching is case-insensitive. Returned recommendations preserve map order
    and are deduplicated.
    """
    if not detail or not indicator_to_recommendation:
        return detail, []

    detail_l = detail.lower()
    matched: list[str] = []
    for indicator, recommendation in indicator_to_recommendation.items():
        if indicator.lower() in detail_l and recommendation not in matched:
            matched.append(recommendation)

    if not matched:
        return detail, []

    joined = " ; ".join(matched)
    return f"{detail} | {recommendation_prefix} {joined}", matched


def build_recommendation_metadata(
    *,
    raw_reasons: list[str] | None = None,
    detail: str = "",
) -> dict[str, Any]:
    """Build structured recommendation metadata from known reason indicators."""
    candidates = [r for r in (raw_reasons or []) if isinstance(r, str) and r]
    if detail:
        candidates.append(detail)
    if not candidates:
        return {}

    candidate_blob = "\n".join(candidates).lower()
    primary_reason = _first_matching_reason(candidate_blob)
    if not primary_reason:
        return {}

    payload = dict(RECOMMENDATION_REGISTRY[primary_reason])
    payload["raw_reasons"] = list(dict.fromkeys(raw_reasons or [primary_reason]))
    return payload


def append_recommendation_to_detail(detail: str, metadata: dict[str, Any]) -> str:
    """Append a concise recommendation text to detail when metadata exists."""
    command = (
        metadata.get("recommended_command") if isinstance(metadata, dict) else None
    )
    if not command:
        return detail
    if "recommendation:" in (detail or "").lower():
        return detail
    return f"{detail} | recommendation: try {command}"


def select_top_recommendation(results: list[Result]) -> dict[str, Any] | None:
    """Pick the highest-confidence recommendation from current run results."""
    best: dict[str, Any] | None = None
    best_score = -1
    for result in results:
        data = result.data if isinstance(result.data, dict) else {}
        command = data.get("recommended_command")
        if not command:
            continue
        score = _CONFIDENCE_SCORE.get(str(data.get("confidence", "")).lower(), 0)
        if score > best_score:
            best = data
            best_score = score
    return best


def set_default_request_headers(headers: dict[str, str] | None) -> None:
    """Set process-wide default headers merged into all HTTP requests."""
    global _DEFAULT_REQUEST_HEADERS
    _DEFAULT_REQUEST_HEADERS = dict(headers or {})


# ----- HTTP -----


def http_get(
    url: str,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[Optional[int], str, dict]:
    """GET wrapper. Returns (status_code or None, text, parsed_json_or_empty_dict)."""
    h = {"User-Agent": USER_AGENT}
    h.update(_DEFAULT_REQUEST_HEADERS)
    if headers:
        h.update(headers)
    try:
        r = requests.get(url, params=params, headers=h, timeout=timeout)
    except requests.RequestException as exc:
        return None, f"request-error: {exc.__class__.__name__}: {exc}", {}
    body = r.text or ""
    parsed = _parse_response_json(r, body)
    return r.status_code, body, parsed


def http_post(
    url: str,
    json_body: Any = None,
    data: Any = None,
    headers: dict | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    params: dict | None = None,
) -> tuple[Optional[int], str, dict]:
    h = {"User-Agent": USER_AGENT}
    h.update(_DEFAULT_REQUEST_HEADERS)
    if headers:
        h.update(headers)
    try:
        r = requests.post(
            url, json=json_body, data=data, headers=h, timeout=timeout, params=params
        )
    except requests.RequestException as exc:
        return None, f"request-error: {exc.__class__.__name__}: {exc}", {}
    body = r.text or ""
    parsed = _parse_response_json(r, body)
    return r.status_code, body, parsed


def _parse_response_json(response: requests.Response, body: str) -> dict:
    if not body:
        return {}
    try:
        parsed = response.json()
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {"_root": parsed}


class C:
    R = "\033[0m"
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    BLU = "\033[34m"
    MAG = "\033[35m"
    CYN = "\033[36m"
    DIM = "\033[2m"
    B = "\033[1m"


_STATUS_COLOR = {
    Status.VALID: C.GRN + C.B,
    Status.DENIED: C.YEL,
    Status.INVALID: C.RED,
    Status.DISABLED: C.DIM,
    Status.UNKNOWN: C.MAG,
    Status.ERROR: C.RED,
}


def print_result(r: Result, no_color: bool = False, mode: str = "standard") -> None:
    col = "" if no_color else _STATUS_COLOR.get(r.status, "")
    reset = "" if no_color else C.R
    code = f" [{r.http_code}]" if r.http_code is not None else ""
    line = f"  {col}{r.status.value:<8}{reset} {r.service}{code}"
    if r.detail and mode != "hunter":
        recommendation_sep = " | recommendation:"
        sep_idx = r.detail.lower().find(recommendation_sep)
        display_detail = r.detail if sep_idx == -1 else r.detail[:sep_idx]
        line += f"  -- {display_detail}"
    print(line)
    next_step = r.data.get("recommended_command") if isinstance(r.data, dict) else None
    if next_step:
        hint_col = "" if no_color else C.DIM
        hint_reset = "" if no_color else C.R
        prefix = f"    {hint_col}Hint:{hint_reset}"
        print(f"{prefix} {next_step}")


def print_header(title: str, no_color: bool = False) -> None:
    col = "" if no_color else C.B + C.CYN
    reset = "" if no_color else C.R
    print(f"\n{col}== {title} =={reset}")


def print_warn(msg: str, no_color: bool = False) -> None:
    col = "" if no_color else C.YEL
    reset = "" if no_color else C.R
    print(f"{col}[!] {msg}{reset}", file=sys.stderr)


def print_info(msg: str, no_color: bool = False) -> None:
    col = "" if no_color else C.DIM
    reset = "" if no_color else C.R
    print(f"{col}[*] {msg}{reset}", file=sys.stderr)


def dump_json(results: list[Result]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2, default=str)
