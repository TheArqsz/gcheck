"""Detect Google credential types from raw input or JSON structure."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

RE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")

RE_FCM_LEGACY = re.compile(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b")

RE_OAUTH_ACCESS = re.compile(r"\bya29\.[A-Za-z0-9_\-\.]{20,}\b")

RE_OAUTH_REFRESH = re.compile(r"(?<!http:)(?<!https:)\b1//[0-9A-Za-z_\-]{40,}\b")

RE_OAUTH_CLIENT_ID = re.compile(r"\b\d+-[A-Za-z0-9_]+\.apps\.googleusercontent\.com\b")

RE_OAUTH_CLIENT_SECRET = re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{20,}\b")

RE_JWT = re.compile(
    r"\b(eyJ[A-Za-z0-9_\-]+)\.(eyJ[A-Za-z0-9_\-]+)\.([A-Za-z0-9_\-]+)\b"
)

RE_RECAPTCHA_SECRET = re.compile(r"\b6[0-9A-Za-z_\-]{39}\b")


@dataclass
class Detected:
    kind: str
    value: str = ""
    parsed: dict | None = None
    source: str = ""

    def __str__(self) -> str:
        suffix = f" ({self.source})" if self.source else ""
        return f"{self.kind}{suffix}"


def detect_from_string(s: str) -> list[Detected]:
    """Scan a raw string and return detected credentials."""
    found: list[Detected] = []
    s = s.strip()

    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
            j = _detect_from_json(obj)
            if j:
                found.extend(j)
                if any(
                    d.kind
                    in (
                        "service_account",
                        "google_services_json",
                        "firebase_config",
                        "oauth_client_secrets_file",
                    )
                    for d in found
                ):
                    return found
        except json.JSONDecodeError:
            pass

    for m in RE_FCM_LEGACY.finditer(s):
        found.append(Detected("fcm_legacy", m.group(0), source="regex"))

    for m in RE_API_KEY.finditer(s):
        if any(d.value == m.group(0) for d in found):
            continue
        found.append(Detected("api_key", m.group(0), source="regex"))

    for m in RE_OAUTH_ACCESS.finditer(s):
        found.append(Detected("oauth_access", m.group(0), source="regex"))

    for m in RE_OAUTH_REFRESH.finditer(s):
        found.append(Detected("oauth_refresh", m.group(0), source="regex"))

    for m in RE_OAUTH_CLIENT_ID.finditer(s):
        found.append(Detected("oauth_client_id", m.group(0), source="regex"))

    for m in RE_OAUTH_CLIENT_SECRET.finditer(s):
        found.append(Detected("oauth_client_secret", m.group(0), source="regex"))

    for m in RE_JWT.finditer(s):
        found.append(Detected("jwt", m.group(0), source="regex"))

    for m in RE_RECAPTCHA_SECRET.finditer(s):
        found.append(Detected("recaptcha_secret", m.group(0), source="regex"))

    return found


def detect_from_file(path: str | Path) -> list[Detected]:
    """Read a file and detect credentials."""
    p = Path(path)
    raw = p.read_text(errors="replace")

    structural: list[Detected] = []
    try:
        obj = json.loads(raw)
        structural = _detect_from_json(obj)
    except json.JSONDecodeError:
        pass

    if structural:
        regex_hits = detect_from_string(raw)
        keys = {(d.kind, d.value) for d in structural}
        for d in regex_hits:
            if (d.kind, d.value) not in keys:
                structural.append(d)
        return structural

    return detect_from_string(raw)


def _detect_from_json(obj: dict) -> list[Detected]:
    """Recognize common GCP/Firebase JSON shapes."""
    if not isinstance(obj, dict):
        return []
    found: list[Detected] = []

    if (
        obj.get("type") == "service_account"
        and "private_key" in obj
        and "client_email" in obj
    ):
        found.append(
            Detected(
                "service_account",
                value=obj.get("client_email", ""),
                parsed=obj,
                source="json shape",
            )
        )
        return found

    if "project_info" in obj and "client" in obj:
        found.append(Detected("google_services_json", parsed=obj, source="json shape"))
        return found

    fb_required = {"apiKey", "projectId"}
    if fb_required.issubset(obj.keys()):
        found.append(Detected("firebase_config", parsed=obj, source="json shape"))
        return found

    for k in ("web", "installed"):
        if k in obj and isinstance(obj[k], dict) and "client_id" in obj[k]:
            found.append(
                Detected("oauth_client_secrets_file", parsed=obj, source="json shape")
            )
            return found

    if obj.get("type") == "authorized_user" and "refresh_token" in obj:
        found.append(Detected("authorized_user", parsed=obj, source="json shape"))
        return found

    if "API_KEY" in obj and "GOOGLE_APP_ID" in obj:
        found.append(Detected("firebase_config", parsed=obj, source="ios plist-like"))
        return found

    return found
