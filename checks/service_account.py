"""Validate GCP service account JSON credentials."""

from __future__ import annotations

import base64
import json
import time

from ._common import Result, Status, http_post
from . import oauth_token as ot

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
DEFAULT_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
SERVICE_ACCOUNT_PARSE = "Service Account: parse"
SERVICE_ACCOUNT_EXCHANGE = "Service Account: token exchange"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _have_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


def _sign_rs256(message: bytes, pem_private_key: str) -> bytes:
    """RS256 sign. Requires the `cryptography` library."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    key = serialization.load_pem_private_key(
        pem_private_key.encode("utf-8"), password=None
    )
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("service account private key is not RSA")
    return key.sign(message, padding.PKCS1v15(), hashes.SHA256())


def parse_sa(sa: dict) -> Result:
    """Parse identity fields without contacting Google."""
    needed = (
        "type",
        "project_id",
        "private_key_id",
        "private_key",
        "client_email",
        "client_id",
        "token_uri",
    )
    missing = [k for k in needed if k not in sa]
    if missing:
        return Result(
            service=SERVICE_ACCOUNT_PARSE,
            status=Status.INVALID,
            detail=f"missing fields: {','.join(missing)}",
        )
    if sa.get("type") != "service_account":
        return Result(
            service=SERVICE_ACCOUNT_PARSE,
            status=Status.INVALID,
            detail=f"type={sa.get('type')!r} (expected service_account)",
        )
    return Result(
        service=SERVICE_ACCOUNT_PARSE,
        status=Status.VALID,
        detail=(
            f"email={sa['client_email']} project={sa['project_id']} "
            f"key_id={sa.get('private_key_id','')[:12]}…"
        ),
        data={
            "client_email": sa.get("client_email"),
            "project_id": sa.get("project_id"),
            "private_key_id": sa.get("private_key_id"),
            "client_id": sa.get("client_id"),
            "token_uri": sa.get("token_uri"),
            "universe_domain": sa.get("universe_domain", "googleapis.com"),
        },
    )


def exchange_for_access_token(
    sa: dict, scope: str = DEFAULT_SCOPE
) -> tuple[str | None, Result]:
    """Exchange a JWT-bearer assertion for a Google access token."""
    if not _have_cryptography():
        return None, Result(
            service=SERVICE_ACCOUNT_EXCHANGE,
            status=Status.UNKNOWN,
            detail=(
                "`cryptography` not installed; cannot sign RS256. "
                "Install with `pip install cryptography`, or run "
                "`gcloud auth activate-service-account --key-file=...` "
                "and re-run gcheck with the resulting access token."
            ),
        )

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": sa.get("private_key_id")}
    claims = {
        "iss": sa["client_email"],
        "scope": scope,
        "aud": sa.get("token_uri", GOOGLE_TOKEN_URL),
        "iat": now,
        "exp": now + 3600,
    }
    h_b = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    c_b = _b64url(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b}.{c_b}".encode("ascii")
    try:
        sig = _sign_rs256(signing_input, sa["private_key"])
    except Exception as exc:
        return None, Result(
            service="Service Account: JWT sign",
            status=Status.ERROR,
            detail=f"signing failed: {exc.__class__.__name__}: {exc}",
        )
    assertion = f"{h_b}.{c_b}.{_b64url(sig)}"

    token_url = sa.get("token_uri", GOOGLE_TOKEN_URL)
    code, _, parsed = http_post(
        token_url,
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if code == 200 and isinstance(parsed, dict) and parsed.get("access_token"):
        at = parsed["access_token"]
        return at, Result(
            service=SERVICE_ACCOUNT_EXCHANGE,
            status=Status.VALID,
            detail=f"got access token, expires_in={parsed.get('expires_in','?')}s",
            http_code=code,
            endpoint=token_url,
            data={
                "token_type": parsed.get("token_type"),
                "expires_in": parsed.get("expires_in"),
            },
        )
    detail = "auth failed"
    if isinstance(parsed, dict):
        detail = parsed.get("error_description") or parsed.get("error") or detail
    return None, Result(
        service=SERVICE_ACCOUNT_EXCHANGE,
        status=Status.INVALID if code == 400 else Status.ERROR,
        detail=str(detail)[:300],
        http_code=code,
        endpoint=token_url,
        data=parsed if isinstance(parsed, dict) else {},
    )


def check_service_account(
    sa: dict,
    perms: list[str] | None = None,
    extra_project_ids: list[str] | None = None,
) -> list[Result]:
    """Run parse, token exchange, and access probes."""
    results: list[Result] = []
    parse_res = parse_sa(sa)
    results.append(parse_res)
    if parse_res.status != Status.VALID:
        return results

    project_ids = [sa.get("project_id")] if sa.get("project_id") else []
    if extra_project_ids:
        project_ids.extend(p for p in extra_project_ids if p not in project_ids)
    project_ids = [project_id for project_id in project_ids if project_id]

    at, exchange_res = exchange_for_access_token(sa)
    results.append(exchange_res)
    if not at:
        return results

    results.append(ot.introspect(at))
    results.extend(ot.probe_with_access_token(at, perms=perms, project_ids=project_ids))
    return results
