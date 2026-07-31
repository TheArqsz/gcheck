"""Validate legacy FCM server keys via dry-run send."""

from __future__ import annotations

from ._common import Result, Status, http_post

FCM_LEGACY_URL = "https://fcm.googleapis.com/fcm/send"


def check_fcm_legacy(server_key: str) -> list[Result]:
    code, body, parsed = http_post(
        FCM_LEGACY_URL,
        json_body={"registration_ids": ["INVALID_REG_ID"], "dry_run": True},
        headers={
            "Authorization": f"key={server_key}",
            "Content-Type": "application/json",
        },
    )
    if code == 200 and isinstance(parsed, dict) and "results" in parsed:
        return [
            Result(
                service="FCM legacy send (AAAA key, dry_run)",
                status=Status.VALID,
                detail=(
                    "key accepted; FCM evaluated registration_ids "
                    "(returns InvalidRegistration as expected)"
                ),
                http_code=code,
                endpoint=FCM_LEGACY_URL,
                data={
                    "multicast_id": parsed.get("multicast_id"),
                    "results_count": len(parsed.get("results", [])),
                },
            )
        ]
    if code == 401:
        return [
            Result(
                service="FCM legacy send (AAAA key)",
                status=Status.INVALID,
                detail="HTTP 401 (key rejected)",
                http_code=code,
                endpoint=FCM_LEGACY_URL,
            )
        ]
    if code in (403, 404):
        return [
            Result(
                service="FCM legacy send (AAAA key)",
                status=Status.DENIED,
                detail=f"HTTP {code} (likely API discontinued or "
                "key disabled; legacy FCM was sunset 2024-06-20)",
                http_code=code,
                endpoint=FCM_LEGACY_URL,
            )
        ]
    return [
        Result(
            service="FCM legacy send (AAAA key)",
            status=Status.UNKNOWN,
            detail=f"HTTP {code} body[:120]={body[:120]!r}",
            http_code=code,
            endpoint=FCM_LEGACY_URL,
        )
    ]
