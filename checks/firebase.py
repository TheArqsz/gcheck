"""Firebase credential probes.

Default probes are read-only. ACTIVE mode may create Authentication users.
"""

from __future__ import annotations

import secrets

from ._common import (
    Result,
    Status,
    append_recommendation_to_detail,
    build_recommendation_metadata,
    http_get,
    http_post,
)

JSON_CONTENT_TYPE = "application/json"


def _dedupe_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def extract_from_google_services(j: dict) -> dict:
    """Return {project_id, project_number, api_keys[], package_names[],
    storage_bucket, firebase_url, app_ids[]}."""
    out: dict = {"api_keys": [], "package_names": [], "app_ids": []}
    pi = j.get("project_info", {}) or {}
    out["project_id"] = pi.get("project_id")
    out["project_number"] = pi.get("project_number")
    out["storage_bucket"] = pi.get("storage_bucket")
    out["firebase_url"] = pi.get("firebase_url")
    for c in j.get("client", []) or []:
        ci = c.get("client_info", {}) or {}
        if ci.get("mobilesdk_app_id"):
            out["app_ids"].append(ci["mobilesdk_app_id"])
        and_info = ci.get("android_client_info", {}) or {}
        if and_info.get("package_name"):
            out["package_names"].append(and_info["package_name"])
        for ak in c.get("api_key", []) or []:
            if ak.get("current_key"):
                out["api_keys"].append(ak["current_key"])
    out["api_keys"] = _dedupe_strings(out["api_keys"])
    out["package_names"] = _dedupe_strings(out["package_names"])
    out["app_ids"] = _dedupe_strings(out["app_ids"])
    return out


def extract_from_web_config(j: dict) -> dict:
    out: dict = {"api_keys": []}
    if j.get("apiKey"):
        out["api_keys"].append(j["apiKey"])
    out["project_id"] = j.get("projectId")
    out["storage_bucket"] = j.get("storageBucket")
    out["firebase_url"] = j.get("databaseURL")
    out["project_number"] = j.get("messagingSenderId")
    out["app_ids"] = [j["appId"]] if j.get("appId") else []
    out["auth_domain"] = j.get("authDomain")
    if "API_KEY" in j:
        out["api_keys"].append(j["API_KEY"])
        out["project_id"] = out["project_id"] or j.get("PROJECT_ID")
        out["storage_bucket"] = out["storage_bucket"] or j.get("STORAGE_BUCKET")
        out["firebase_url"] = out["firebase_url"] or j.get("DATABASE_URL")
        out["project_number"] = out["project_number"] or j.get("GCM_SENDER_ID")
        if j.get("GOOGLE_APP_ID"):
            out["app_ids"].append(j["GOOGLE_APP_ID"])
    out["api_keys"] = _dedupe_strings(out["api_keys"])
    out["app_ids"] = _dedupe_strings(out["app_ids"])
    return out


def probe_rtdb(firebase_url: str | None, project_id: str | None) -> list[Result]:
    """Try GET /.json on common Realtime Database URLs."""
    out: list[Result] = []
    urls: list[str] = []
    if firebase_url:
        u = firebase_url.rstrip("/")
        if not u.startswith("http"):
            u = "https://" + u
        urls.append(f"{u}/.json")
    if project_id:
        urls.extend(
            [
                f"https://{project_id}.firebaseio.com/.json",
                f"https://{project_id}-default-rtdb.firebaseio.com/.json",
                f"https://{project_id}-default-rtdb.europe-west1.firebasedatabase.app/.json",
                f"https://{project_id}-default-rtdb.asia-southeast1.firebasedatabase.app/.json",
            ]
        )
    seen: set[str] = set()
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        code, body, _ = http_get(url)
        name = f"RTDB GET {url}"
        if code is None:
            out.append(
                Result(
                    service=name, status=Status.ERROR, detail=body[:120], endpoint=url
                )
            )
            continue
        if code == 200:
            preview = body.strip()
            preview_short = (preview[:200] + "…") if len(preview) > 200 else preview
            out.append(
                Result(
                    service=name,
                    status=Status.VALID,
                    detail=f"publicly readable; body[:200]={preview_short!r}",
                    http_code=code,
                    endpoint=url,
                )
            )
        elif code == 401:
            out.append(
                Result(
                    service=name,
                    status=Status.DENIED,
                    detail="401 (security rules enforced)",
                    http_code=code,
                    endpoint=url,
                )
            )
        elif code == 404:
            out.append(
                Result(
                    service=name,
                    status=Status.UNKNOWN,
                    detail="404 (no such DB at this URL)",
                    http_code=code,
                    endpoint=url,
                )
            )
        elif code in (403, 423):
            out.append(
                Result(
                    service=name,
                    status=Status.DENIED,
                    detail=f"HTTP {code}",
                    http_code=code,
                    endpoint=url,
                )
            )
        else:
            out.append(
                Result(
                    service=name,
                    status=Status.UNKNOWN,
                    detail=f"HTTP {code}",
                    http_code=code,
                    endpoint=url,
                )
            )
    return out


def probe_storage(storage_bucket: str | None, project_id: str | None) -> list[Result]:
    out: list[Result] = []
    candidates: list[str] = []
    if storage_bucket:
        candidates.append(storage_bucket)
    if project_id:
        candidates.extend(
            [f"{project_id}.appspot.com", f"{project_id}.firebasestorage.app"]
        )
    seen: set[str] = set()
    for b in candidates:
        if b in seen:
            continue
        seen.add(b)
        url = f"https://firebasestorage.googleapis.com/v0/b/{b}/o"
        code, _, parsed = http_get(url)
        name = f"Firebase Storage list {b}"
        if code == 200:
            items = parsed.get("items", []) if isinstance(parsed, dict) else []
            out.append(
                Result(
                    service=name,
                    status=Status.VALID,
                    detail=f"listing allowed, {len(items)} item(s)",
                    http_code=code,
                    endpoint=url,
                )
            )
        elif code in (401, 403):
            out.append(
                Result(
                    service=name,
                    status=Status.DENIED,
                    detail=f"HTTP {code}",
                    http_code=code,
                    endpoint=url,
                )
            )
        elif code == 404:
            out.append(
                Result(
                    service=name,
                    status=Status.UNKNOWN,
                    detail="bucket not found",
                    http_code=code,
                    endpoint=url,
                )
            )
        else:
            out.append(
                Result(
                    service=name,
                    status=Status.UNKNOWN,
                    detail=f"HTTP {code}",
                    http_code=code,
                    endpoint=url,
                )
            )
    return out


def probe_remote_config(
    project_number: str | None,
    api_key: str | None,
    app_id: str | None = None,
    namespaces: list[str] | None = None,
) -> list[Result]:
    """Probe the Remote Config fetch endpoint."""
    out: list[Result] = []
    if not api_key or not project_number:
        return out
    namespaces = namespaces or ["firebase"]
    for ns in namespaces:
        url = (
            f"https://firebaseremoteconfig.googleapis.com/v1/projects/"
            f"{project_number}/namespaces/{ns}:fetch"
        )
        endpoint = url
        body_json = {
            "appId": app_id or f"1:{project_number}:android:0000000000000000",
            "appInstanceId": "PROD",
        }
        code, _, parsed = http_post(
            url,
            json_body=body_json,
            headers={"Content-Type": JSON_CONTENT_TYPE},
        )
        if code is None or code in (401, 403):
            url_keyed = f"{url}?key={api_key}"
            endpoint = url_keyed
            code, _, parsed = http_post(
                url_keyed,
                json_body=body_json,
                headers={"Content-Type": JSON_CONTENT_TYPE},
            )
        name = f"Remote Config fetch (ns={ns})"
        if code == 200 and isinstance(parsed, dict):
            entries = parsed.get("entries") or parsed.get("parameters") or {}
            state = parsed.get("state")
            out.append(
                Result(
                    service=name,
                    status=Status.VALID,
                    detail=(f"state={state} entries={len(entries) if entries else 0}"),
                    http_code=code,
                    endpoint=endpoint,
                    data=parsed,
                )
            )
        elif code in (401, 403):
            out.append(
                Result(
                    service=name,
                    status=Status.DENIED,
                    detail=f"HTTP {code}",
                    http_code=code,
                    endpoint=endpoint,
                )
            )
        else:
            out.append(
                Result(
                    service=name,
                    status=Status.UNKNOWN,
                    detail=f"HTTP {code}",
                    http_code=code,
                    endpoint=endpoint,
                )
            )
    return out


def _as_non_empty_text(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _iter_identitytoolkit_error_parts(error_obj: dict) -> list[str]:
    parts = [_as_non_empty_text(error_obj.get(key)) for key in ("status", "message")]

    details = error_obj.get("details")
    if not isinstance(details, list):
        return [p for p in parts if p]

    for item in details:
        if not isinstance(item, dict):
            continue
        parts.append(_as_non_empty_text(item.get("reason")))
        parts.append(_as_non_empty_text(item.get("message")))

    return [p for p in parts if p]


def _extract_identitytoolkit_reasons(parsed: dict) -> list[str]:
    if not isinstance(parsed, dict):
        return []
    error_obj = parsed.get("error")
    if not isinstance(error_obj, dict):
        return []
    return list(dict.fromkeys(_iter_identitytoolkit_error_parts(error_obj)))


def probe_identitytoolkit_active(api_key: str, signup_email: str) -> list[Result]:
    """ACTIVE probe: create a Firebase Auth email user."""
    out: list[Result] = []
    url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp"
    url_keyed = f"{url}?key={api_key}"
    generated_password = secrets.token_urlsafe(12)
    code, _, parsed = http_post(
        url_keyed,
        json_body={
            "email": signup_email,
            "password": generated_password,
            "returnSecureToken": True,
        },
        headers={"Content-Type": JSON_CONTENT_TYPE},
    )
    name = "Firebase Auth: email signUp (ACTIVE)"
    if code == 200 and isinstance(parsed, dict) and parsed.get("idToken"):
        out.append(
            Result(
                service=name,
                status=Status.VALID,
                detail=(
                    f"created user email={signup_email} uid={parsed.get('localId')} "
                    f"idToken_len={len(parsed['idToken'])}"
                ),
                http_code=code,
                endpoint=url_keyed,
                data={
                    "email": signup_email,
                    "localId": parsed.get("localId"),
                    "refreshToken_present": bool(parsed.get("refreshToken")),
                },
            )
        )
    elif code in (400, 403):
        raw_reasons = _extract_identitytoolkit_reasons(parsed)
        err = " | ".join(raw_reasons)
        detail = f"HTTP {code}" + (f" {err}" if err else "")
        recommendation_metadata = build_recommendation_metadata(
            raw_reasons=raw_reasons,
            detail=detail,
        )
        detail = append_recommendation_to_detail(detail, recommendation_metadata)
        err_upper = err.upper()
        if "EMAIL_EXISTS" in err_upper:
            result_data = {
                "email": signup_email,
                "raw_reasons": raw_reasons,
            }
            result_data.update(recommendation_metadata)
            out.append(
                Result(
                    service=name,
                    status=Status.VALID,
                    detail=(
                        "endpoint reachable and key accepted; "
                        f"target email already exists ({detail})"
                    ),
                    http_code=code,
                    endpoint=url_keyed,
                    data=result_data,
                )
            )
        elif "INVALID_EMAIL" in err_upper:
            out.append(
                Result(
                    service=name,
                    status=Status.INVALID,
                    detail=f"invalid signup email provided ({detail})",
                    http_code=code,
                    endpoint=url_keyed,
                )
            )
        else:
            result_data = {"raw_reasons": raw_reasons}
            result_data.update(recommendation_metadata)
            out.append(
                Result(
                    service=name,
                    status=Status.DENIED,
                    detail=detail,
                    http_code=code,
                    endpoint=url_keyed,
                    data=result_data,
                )
            )
    else:
        out.append(
            Result(
                service=name,
                status=Status.UNKNOWN,
                detail=f"HTTP {code}",
                http_code=code,
                endpoint=url_keyed,
            )
        )
    return out


def check_firebase(
    extracted: dict,
    active: bool = False,
    namespaces: list[str] | None = None,
    signup_email: str | None = None,
) -> list[Result]:
    """Run Firebase probes against an extracted config dict."""
    out: list[Result] = []
    bits = []
    if extracted.get("project_id"):
        bits.append(f"project_id={extracted['project_id']}")
    if extracted.get("project_number"):
        bits.append(f"project_number={extracted['project_number']}")
    if extracted.get("api_keys"):
        bits.append(f"api_keys={len(extracted['api_keys'])}")
    if extracted.get("storage_bucket"):
        bits.append(f"storage_bucket={extracted['storage_bucket']}")
    if extracted.get("firebase_url"):
        bits.append(f"databaseURL={extracted['firebase_url']}")
    out.append(
        Result(
            service="Firebase config: parsed",
            status=Status.VALID,
            detail=" ".join(bits),
            data=extracted,
        )
    )

    out.extend(probe_rtdb(extracted.get("firebase_url"), extracted.get("project_id")))
    out.extend(
        probe_storage(extracted.get("storage_bucket"), extracted.get("project_id"))
    )

    for ak in extracted.get("api_keys", []) or []:
        out.extend(
            probe_remote_config(
                extracted.get("project_number"),
                ak,
                app_id=(extracted.get("app_ids") or [None])[0],
                namespaces=namespaces,
            )
        )
        if active:
            if signup_email:
                out.extend(probe_identitytoolkit_active(ak, signup_email))
            else:
                out.append(
                    Result(
                        service="Firebase Auth: email signUp (ACTIVE)",
                        status=Status.UNKNOWN,
                        detail="skipped: provide --signup-email for due-diligence active signUp probe",
                    )
                )
    return out
