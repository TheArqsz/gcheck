"""Validate an OAuth refresh token by exchanging it for an access token."""

from __future__ import annotations

from ._common import Result, Status, http_post
from . import oauth_token as ot

TOKEN_URL = "https://oauth2.googleapis.com/token"


def exchange(
    client_id: str, client_secret: str, refresh_token: str
) -> tuple[str | None, Result]:
    code, _, parsed = http_post(
        TOKEN_URL,
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if code == 200 and isinstance(parsed, dict) and parsed.get("access_token"):
        at = parsed["access_token"]
        return at, Result(
            service="OAuth: refresh token exchange",
            status=Status.VALID,
            detail=(
                f"access_token issued, expires_in="
                f"{parsed.get('expires_in','?')}s "
                f"scope={parsed.get('scope','-')}"
            ),
            http_code=code,
            endpoint=TOKEN_URL,
            data={
                "scope": parsed.get("scope"),
                "expires_in": parsed.get("expires_in"),
                "id_token_present": bool(parsed.get("id_token")),
            },
        )
    err = ""
    if isinstance(parsed, dict):
        err = parsed.get("error_description") or parsed.get("error") or ""
    status = Status.INVALID if code == 400 else Status.ERROR
    return None, Result(
        service="OAuth: refresh token exchange",
        status=status,
        detail=(err or f"HTTP {code}")[:300],
        http_code=code,
        endpoint=TOKEN_URL,
        data=parsed if isinstance(parsed, dict) else {},
    )


def check_refresh_token(
    client_id: str,
    client_secret: str,
    refresh_token: str,
    perms: list[str] | None = None,
    project_ids: list[str] | None = None,
) -> list[Result]:
    results: list[Result] = []
    at, exch = exchange(client_id, client_secret, refresh_token)
    results.append(exch)
    if not at:
        return results
    results.append(ot.introspect(at))
    results.extend(ot.probe_with_access_token(at, perms=perms, project_ids=project_ids))
    return results
