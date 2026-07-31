"""Introspect OAuth access/ID tokens and probe reachable Google resources."""

from __future__ import annotations

import base64
import json

from ._common import Result, Status, http_get, http_post

TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
CRM_PROJECTS_LIST = "https://cloudresourcemanager.googleapis.com/v1/projects"
CRM_TESTIAM_V3 = (
    "https://cloudresourcemanager.googleapis.com/v3/projects/{pid}:testIamPermissions"
)
STORAGE_BUCKETS_LIST = "https://storage.googleapis.com/storage/v1/b"
COMPUTE_ZONES = "https://compute.googleapis.com/compute/v1/projects/{pid}/zones"
IAM_SAS = "https://iam.googleapis.com/v1/projects/{pid}/serviceAccounts"


# Keep this list bounded to reduce audit-log noise while preserving signal.
DEFAULT_PERMS_TO_TEST = [
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "resourcemanager.projects.setIamPolicy",
    "iam.serviceAccounts.list",
    "iam.serviceAccounts.actAs",
    "iam.serviceAccounts.getAccessToken",
    "iam.serviceAccountKeys.create",
    "storage.buckets.list",
    "storage.buckets.get",
    "storage.objects.list",
    "storage.objects.get",
    "storage.objects.create",
    "compute.instances.list",
    "compute.instances.get",
    "compute.instances.setMetadata",
    "compute.projects.get",
    "compute.projects.setCommonInstanceMetadata",
    "container.clusters.list",
    "container.clusters.get",
    "cloudfunctions.functions.list",
    "cloudfunctions.functions.call",
    "secretmanager.secrets.list",
    "secretmanager.versions.access",
    "cloudkms.cryptoKeys.list",
    "cloudkms.cryptoKeyVersions.useToDecrypt",
    "logging.logEntries.list",
    "monitoring.timeSeries.list",
    "bigquery.datasets.get",
    "bigquery.jobs.create",
    "pubsub.topics.list",
    "pubsub.subscriptions.list",
    "cloudsql.instances.list",
    "spanner.databases.list",
    "appengine.applications.get",
    "dns.managedZones.list",
    "run.services.list",
]


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(token: str) -> tuple[dict, dict] | None:
    """Decode JWT header and payload without signature verification."""
    try:
        h, p, _ = token.split(".")
        header = json.loads(_b64url_decode(h))
        payload = json.loads(_b64url_decode(p))
        return header, payload
    except Exception:
        return None


def introspect(token: str) -> Result:
    """Hit the tokeninfo endpoint. Works for access tokens AND id_tokens."""
    code, body, parsed = http_get(TOKENINFO_URL, params={"access_token": token})
    if code == 200 and isinstance(parsed, dict) and "scope" in parsed:
        return Result(
            service="tokeninfo (access_token)",
            status=Status.VALID,
            detail=_summarise_tokeninfo(parsed),
            http_code=code,
            endpoint=TOKENINFO_URL,
            data=parsed,
        )
    code2, body2, parsed2 = http_get(TOKENINFO_URL, params={"id_token": token})
    if (
        code2 == 200
        and isinstance(parsed2, dict)
        and ("aud" in parsed2 or "email" in parsed2)
    ):
        return Result(
            service="tokeninfo (id_token)",
            status=Status.VALID,
            detail=_summarise_tokeninfo(parsed2),
            http_code=code2,
            endpoint=TOKENINFO_URL,
            data=parsed2,
        )

    if code == 400 and "invalid" in (body or "").lower():
        return Result(
            service="tokeninfo",
            status=Status.INVALID,
            detail="token rejected by tokeninfo",
            http_code=code,
            endpoint=TOKENINFO_URL,
            data=parsed if isinstance(parsed, dict) else {},
        )
    return Result(
        service="tokeninfo",
        status=Status.UNKNOWN,
        detail=f"unexpected response (got {code} and {code2})",
        http_code=code,
        endpoint=TOKENINFO_URL,
        data=parsed if isinstance(parsed, dict) else {},
    )


def _summarise_tokeninfo(info: dict) -> str:
    parts: list[str] = []
    if info.get("email"):
        parts.append(f"identity={info['email']}")
    if info.get("scope"):
        scopes = info["scope"].split()
        if len(scopes) <= 3:
            parts.append(f"scopes={info['scope']}")
        else:
            parts.append(f"scopes=({len(scopes)}) {' '.join(scopes[:3])}…")
    if info.get("aud"):
        parts.append(f"aud={info['aud']}")
    if info.get("expires_in"):
        parts.append(f"expires_in={info['expires_in']}s")
    return " ".join(parts) or "(no fields)"


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def probe_with_access_token(
    token: str, perms: list[str] | None = None, project_ids: list[str] | None = None
) -> list[Result]:
    """After introspection succeeds, map out actual access."""
    results: list[Result] = []
    perms = perms or DEFAULT_PERMS_TO_TEST

    code, _, parsed = http_get(USERINFO_URL, headers=_bearer(token))
    if code == 200:
        results.append(
            Result(
                service="OIDC userinfo",
                status=Status.VALID,
                detail=f"sub={parsed.get('sub','?')} email={parsed.get('email','-')}",
                http_code=code,
                endpoint=USERINFO_URL,
                data=parsed,
            )
        )
    elif code in (401, 403):
        results.append(
            Result(
                service="OIDC userinfo",
                status=Status.DENIED,
                detail=f"HTTP {code}",
                http_code=code,
                endpoint=USERINFO_URL,
            )
        )
    else:
        results.append(
            Result(
                service="OIDC userinfo",
                status=Status.UNKNOWN,
                detail=f"HTTP {code}",
                http_code=code,
                endpoint=USERINFO_URL,
            )
        )

    code, _, parsed = http_get(
        CRM_PROJECTS_LIST, headers=_bearer(token), params={"pageSize": "200"}
    )
    discovered_projects: list[str] = []
    if code == 200 and isinstance(parsed, dict):
        projs = parsed.get("projects", []) or []
        discovered_projects = [p.get("projectId") for p in projs if p.get("projectId")]
        results.append(
            Result(
                service="Resource Manager: list projects",
                status=Status.VALID,
                detail=f"{len(discovered_projects)} project(s) visible",
                http_code=code,
                endpoint=CRM_PROJECTS_LIST,
                data={"projects": discovered_projects},
            )
        )
    elif code in (401, 403):
        results.append(
            Result(
                service="Resource Manager: list projects",
                status=Status.DENIED,
                detail=f"HTTP {code}",
                http_code=code,
                endpoint=CRM_PROJECTS_LIST,
            )
        )
    else:
        results.append(
            Result(
                service="Resource Manager: list projects",
                status=Status.UNKNOWN,
                detail=f"HTTP {code}",
                http_code=code,
                endpoint=CRM_PROJECTS_LIST,
            )
        )

    seen: set[str] = set()
    all_projects: list[str] = []
    for p in (project_ids or []) + discovered_projects:
        if p and p not in seen:
            seen.add(p)
            all_projects.append(p)

    for pid in all_projects:
        results.extend(_test_permissions(token, pid, perms))
        results.extend(_probe_project_services(token, pid))

    if not all_projects:
        code, _, parsed = http_get(
            STORAGE_BUCKETS_LIST,
            params={"project": "_"},
            headers=_bearer(token),
        )
        det = "(no project id provided; supply --project for fuller probe)"
        if code == 400:
            det += " | storage rejected request as expected"
        results.append(
            Result(
                service="GCS buckets (no project)",
                status=Status.UNKNOWN,
                detail=det,
                http_code=code,
                endpoint=STORAGE_BUCKETS_LIST,
            )
        )

    return results


def _test_permissions(token: str, project_id: str, perms: list[str]) -> list[Result]:
    """Call testIamPermissions in batches of 100 perms."""
    out: list[Result] = []
    granted: list[str] = []
    url = CRM_TESTIAM_V3.format(pid=project_id)
    for i in range(0, len(perms), 100):
        chunk = perms[i : i + 100]
        code, _, parsed = http_post(
            url, headers=_bearer(token), json_body={"permissions": chunk}
        )
        if code == 200 and isinstance(parsed, dict):
            granted.extend(parsed.get("permissions", []) or [])
        elif code in (401, 403):
            out.append(
                Result(
                    service=f"testIamPermissions[{project_id}]",
                    status=Status.DENIED,
                    detail=f"HTTP {code} on chunk starting {chunk[0]}",
                    http_code=code,
                    endpoint=url,
                )
            )
            return out
        else:
            out.append(
                Result(
                    service=f"testIamPermissions[{project_id}]",
                    status=Status.UNKNOWN,
                    detail=f"HTTP {code} (chunk {i})",
                    http_code=code,
                    endpoint=url,
                )
            )
    out.append(
        Result(
            service=f"testIamPermissions[{project_id}]",
            status=Status.VALID if granted else Status.DENIED,
            detail=(
                f"{len(granted)}/{len(perms)} permissions held: " + ", ".join(granted)
                if granted
                else f"0/{len(perms)} permissions held"
            ),
            http_code=200,
            endpoint=url,
            data={"granted": granted},
        )
    )
    return out


def _probe_project_services(token: str, pid: str) -> list[Result]:
    """A few cheap "are you allowed to list X" probes on a single project."""
    out: list[Result] = []
    probes = [
        ("GCS: list buckets", STORAGE_BUCKETS_LIST, {"project": pid}),
        ("Compute: list zones", COMPUTE_ZONES.format(pid=pid), None),
        ("IAM: list service accounts", IAM_SAS.format(pid=pid), None),
    ]
    for name, url, params in probes:
        code, _, parsed = http_get(url, headers=_bearer(token), params=params)
        if code == 200:
            count = 0
            if isinstance(parsed, dict):
                for key in ("items", "accounts"):
                    if isinstance(parsed.get(key), list):
                        count = len(parsed[key])
                        break
            out.append(
                Result(
                    service=f"{name} ({pid})",
                    status=Status.VALID,
                    detail=f"{count} item(s)",
                    http_code=code,
                    endpoint=url,
                )
            )
        elif code in (401, 403):
            out.append(
                Result(
                    service=f"{name} ({pid})",
                    status=Status.DENIED,
                    detail=f"HTTP {code}",
                    http_code=code,
                    endpoint=url,
                )
            )
        else:
            out.append(
                Result(
                    service=f"{name} ({pid})",
                    status=Status.UNKNOWN,
                    detail=f"HTTP {code}",
                    http_code=code,
                    endpoint=url,
                )
            )
    return out


def inspect_jwt(token: str) -> Result:
    """Local decode of a JWT (no signature verification)."""
    decoded = decode_jwt(token)
    if not decoded:
        return Result(
            service="JWT decode",
            status=Status.INVALID,
            detail="not a 3-segment base64url JWT",
        )
    header, payload = decoded
    bits = []
    if payload.get("iss"):
        bits.append(f"iss={payload['iss']}")
    if payload.get("aud"):
        bits.append(f"aud={payload['aud']}")
    if payload.get("email"):
        bits.append(f"email={payload['email']}")
    if payload.get("sub"):
        bits.append(f"sub={payload['sub']}")
    if payload.get("exp"):
        bits.append(f"exp={payload['exp']}")
    if payload.get("scope"):
        bits.append(f"scope={payload['scope']}")
    return Result(
        service="JWT decode (local, unverified)",
        status=Status.VALID,
        detail=" ".join(bits),
        data={"header": header, "payload": payload},
    )
