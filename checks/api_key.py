"""Validate a Google API key (AIza...) against selected high-signal services."""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import time
from typing import Optional

from . import android_key
from ._common import (
    DEFAULT_TIMEOUT,
    Result,
    Status,
    append_recommendation_to_detail,
    build_recommendation_metadata,
    detect_google_service_disabled,
    http_get,
    http_post,
)

_API_KEY_PATTERN = re.compile(r"^AIza[0-9A-Za-z_-]{35}$")


def _looks_like_api_key(value: str) -> bool:
    return bool(_API_KEY_PATTERN.fullmatch((value or "").strip()))


def _maps_geocode(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/geocode/json",
        "method": "GET",
        "params": {"address": "Mountain+View,CA", "key": k},
    }


def _maps_places_textsearch(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/place/textsearch/json",
        "method": "GET",
        "params": {"query": "cafe", "key": k},
    }


def _maps_places_nearbysearch(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/place/nearbysearch/json",
        "method": "GET",
        "params": {"location": "37.4,-122.0", "radius": "1000", "key": k},
    }


def _places_new_text_search(k):
    return {
        "url": "https://places.googleapis.com/v1/places:searchText",
        "method": "POST",
        "headers": {
            "X-Goog-Api-Key": k,
            "X-Goog-FieldMask": "places.id,places.displayName.text",
            "Content-Type": "application/json",
        },
        "json": {"textQuery": "cafe in Mountain View", "maxResultCount": 1},
    }


def _routes_compute_routes(k):
    return {
        "url": "https://routes.googleapis.com/directions/v2:computeRoutes",
        "method": "POST",
        "headers": {
            "X-Goog-Api-Key": k,
            "X-Goog-FieldMask": "routes.distanceMeters,routes.duration",
            "Content-Type": "application/json",
        },
        "json": {
            "origin": {
                "location": {"latLng": {"latitude": 37.4221, "longitude": -122.0841}}
            },
            "destination": {
                "location": {"latLng": {"latitude": 37.3318, "longitude": -122.0312}}
            },
            "travelMode": "DRIVE",
        },
    }


def _maps_directions(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/directions/json",
        "method": "GET",
        "params": {"origin": "Berlin", "destination": "Paris", "key": k},
    }


def _maps_distance_matrix(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/distancematrix/json",
        "method": "GET",
        "params": {
            "origins": "40.6655101,-73.89188969999998",
            "destinations": "40.6905615,-73.9976592",
            "key": k,
        },
    }


def _maps_elevation(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/elevation/json",
        "method": "GET",
        "params": {"locations": "39.7391536,-104.9847034", "key": k},
    }


def _maps_timezone(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/timezone/json",
        "method": "GET",
        "params": {
            "location": "39.6034810,-119.6822510",
            "timestamp": "1331161200",
            "key": k,
        },
    }


def _maps_static(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/staticmap",
        "method": "GET",
        "params": {"center": "Berlin", "zoom": "10", "size": "100x100", "key": k},
    }


def _maps_streetview(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/streetview",
        "method": "GET",
        "params": {"location": "40.720032,-73.988354", "size": "100x100", "key": k},
    }


def _maps_js_check(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/js",
        "method": "GET",
        "params": {"key": k},
        "headers": {"Referer": "https://example.com/"},
    }


def _ios_restriction_probe(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/geocode/json",
        "method": "GET",
        "params": {"address": "test", "key": k},
        "headers": {"X-Ios-Bundle-Identifier": "com.example.test"},
    }


def _referrer_restriction_probe(k):
    return {
        "url": "https://maps.googleapis.com/maps/api/geocode/json",
        "method": "GET",
        "params": {"address": "test", "key": k},
        "headers": {"Referer": "https://attacker.example/"},
    }


def _fcm_legacy_via_key(k):
    return {
        "url": "https://fcm.googleapis.com/fcm/send",
        "method": "POST",
        "headers": {"Authorization": f"key={k}", "Content-Type": "application/json"},
        "json": {"registration_ids": ["INVALID_REG_ID"], "dry_run": True},
    }


def _referer_candidate_variants(raw: str) -> list[str]:
    value = (raw or "").strip()
    if not value:
        return []

    if "://" in value:
        return [value]

    host = value
    if host.startswith("*."):
        host = host[2:]
    host = host.strip("/")
    if not host:
        return []

    return [f"https://{host}/", f"http://{host}/"]


def _append_unique_referer_variants(
    expanded: list[str],
    seen: set[str],
    raw_value: str,
) -> None:
    for candidate in _referer_candidate_variants(raw_value):
        if candidate in seen:
            continue
        seen.add(candidate)
        expanded.append(candidate)


def _normalize_probe_timeout(timeout_seconds: float) -> float:
    return max(0.1, float(timeout_seconds or DEFAULT_TIMEOUT))


def _youtube_search(k):
    return {
        "url": "https://www.googleapis.com/youtube/v3/search",
        "method": "GET",
        "params": {"part": "snippet", "q": "test", "maxResults": "1", "key": k},
    }


def _youtube_videos(k):
    return {
        "url": "https://www.googleapis.com/youtube/v3/videos",
        "method": "GET",
        "params": {
            "part": "snippet,statistics",
            "chart": "mostPopular",
            "maxResults": "1",
            "key": k,
        },
    }


def _translate_v2(k):
    return {
        "url": "https://translation.googleapis.com/language/translate/v2",
        "method": "GET",
        "params": {"q": "hello", "target": "es", "key": k},
    }


def _safebrowsing_lists(k):
    return {
        "url": "https://safebrowsing.googleapis.com/v4/threatLists",
        "method": "GET",
        "params": {"key": k},
    }


def _webrisk_search(k):
    return {
        "url": "https://webrisk.googleapis.com/v1/uris:search",
        "method": "GET",
        "params": {
            "uri": "http://testsafebrowsing.appspot.com/s/malware.html",
            "threatTypes": "MALWARE",
            "key": k,
        },
    }


def _gemini_list_models(k):
    return {
        "url": "https://generativelanguage.googleapis.com/v1beta/models",
        "method": "GET",
        "params": {"key": k},
    }


def _gemini_generate_content(k):
    return {
        "url": "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
        "method": "POST",
        "params": {"key": k},
        "json": {"contents": [{"parts": [{"text": "ping"}]}]},
    }


def _firebase_identitytoolkit_lookup(k):
    return {
        "url": "https://identitytoolkit.googleapis.com/v1/accounts:lookup",
        "method": "POST",
        "params": {"key": k},
        "json": {},
    }


def _firebase_createauth_uri(k):
    return {
        "url": "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri",
        "method": "POST",
        "params": {"key": k},
        "json": {"identifier": "test@example.com", "continueUri": "http://localhost"},
    }


def _firestore_documents(k, project_id: str):
    return {
        "url": f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents",
        "method": "GET",
        "params": {"pageSize": "1", "key": k},
    }


def _maps_roads_nearest(k):
    return {
        "url": "https://roads.googleapis.com/v1/nearestRoads",
        "method": "GET",
        "params": {"points": "60.170880,24.942795|60.170879,24.942796", "key": k},
    }


def _base_services() -> list[dict]:
    return [
        {"name": "Maps: Geocoding", "build": _maps_geocode},
        {"name": "Maps: Roads (nearestRoads)", "build": _maps_roads_nearest},
        {"name": "Maps: Places (Text)", "build": _maps_places_textsearch},
        {"name": "Maps: Places (Nearby)", "build": _maps_places_nearbysearch},
        {"name": "Places API (New): Search Text", "build": _places_new_text_search},
        {"name": "Routes API: computeRoutes", "build": _routes_compute_routes},
        {"name": "Maps: Directions", "build": _maps_directions},
        {"name": "Maps: Distance Matrix", "build": _maps_distance_matrix},
        {"name": "Maps: Elevation", "build": _maps_elevation},
        {"name": "Maps: Timezone", "build": _maps_timezone},
        {"name": "Maps: Static Maps", "build": _maps_static, "bytes": True},
        {"name": "Maps: Street View", "build": _maps_streetview, "bytes": True},
        {"name": "Maps: JavaScript API", "build": _maps_js_check},
        {"name": "Android Key Validation", "probe": android_key.probe_android_headers},
        {"name": "iOS Key Validation", "build": _ios_restriction_probe},
        {"name": "Referrer Key Validation", "build": _referrer_restriction_probe},
        {"name": "FCM legacy send (API key)", "build": _fcm_legacy_via_key},
        {"name": "YouTube Data: search", "build": _youtube_search},
        {"name": "YouTube Data: videos", "build": _youtube_videos},
        {"name": "Translate v2", "build": _translate_v2},
        {"name": "Safe Browsing v4", "build": _safebrowsing_lists},
        {"name": "Web Risk v1", "build": _webrisk_search},
        {
            "name": "Gemini / Generative Lang",
            "build": _gemini_list_models,
            "ambiguous_invalid_note": _GEMINI_INVALID_AMBIGUITY_NOTE,
        },
        {
            "name": "Firebase Auth: lookup",
            "build": _firebase_identitytoolkit_lookup,
            "allow_400_valid": True,
        },
        {
            "name": "Firebase Auth: createAuthUri",
            "build": _firebase_createauth_uri,
            "allow_400_valid": True,
        },
    ]


def _build_services(
    active: bool,
    project_ids: list[str] | None,
) -> list[dict]:
    services = _base_services()

    if active:
        services.append(
            {
                "name": "Gemini: generateContent (active)",
                "build": _gemini_generate_content,
                "ambiguous_invalid_note": _GEMINI_INVALID_AMBIGUITY_NOTE,
            }
        )
    for project_id in project_ids or []:
        services.append(
            {
                "name": f"Firestore REST (project={project_id})",
                "build": lambda key, pid=project_id: _firestore_documents(key, pid),
            }
        )
    return services


def list_api_key_services() -> list[str]:
    return [
        *[svc["name"] for svc in _base_services()],
        "Gemini: generateContent (active)",
        "Firestore REST (project=<project-id>)",
    ]


def planned_api_key_service_names(
    only: list[str] | None = None,
    *,
    active: bool = False,
    project_ids: list[str] | None = None,
    maps_js_runtime: bool = False,
) -> list[str]:
    services = _build_services(active=active, project_ids=project_ids)
    selected = [svc for svc in services if _service_matches_filter(svc["name"], only)]

    names: list[str] = []
    for svc in selected:
        name = svc["name"]
        if maps_js_runtime and name == "Maps: JavaScript API":
            name = f"{name} (runtime probe enabled)"
        names.append(name)
    return names


_INVALID_KEY_HINTS = (
    "API key not valid",
    "API_KEY_INVALID",
    "Invalid API key",
    "The provided API key is invalid",
    "InvalidKey",
    "gm_authfailure",
)
_RESTRICTED_HINTS = (
    "API_KEY_HTTP_REFERRER_BLOCKED",
    "API_KEY_IP_ADDRESS_BLOCKED",
    "API_KEY_ANDROID_APP_BLOCKED",
    "API_KEY_IOS_APP_BLOCKED",
    "API_KEY_SERVICE_BLOCKED",
    "requests-from-referer",
    "API keys with referer restrictions",
)
_DENIED_HINTS = (
    "PERMISSION_DENIED",
    "request_denied",
    "REQUEST_DENIED",
    "Forbidden",
)
_GEMINI_INVALID_AMBIGUITY_NOTE = (
    "Generative Language API returns this same message for a dead key "
    "and for a valid key whose project hasn't enabled the API; this "
    "response alone can't tell you which. Check whether other DISABLED "
    "results in this scan resolved a consumer project before assuming "
    "the key is dead."
)


def _service_matches_filter(service_name: str, only: list[str] | None) -> bool:
    if not only:
        return True
    name_lower = service_name.lower()
    return any(token.lower() in name_lower for token in only)


def _extract_error_info_metadata(parsed: dict) -> dict:
    """Extract useful fields from google.rpc.ErrorInfo metadata."""
    if not isinstance(parsed, dict):
        return {}
    error_obj = parsed.get("error")
    if not isinstance(error_obj, dict):
        return {}
    details = error_obj.get("details")
    if not isinstance(details, list):
        return {}
    out: dict = {}
    for item in details:
        if not isinstance(item, dict):
            continue
        type_url = item.get("@type", "")
        if "ErrorInfo" not in type_url:
            continue
        metadata = item.get("metadata")
        if not isinstance(metadata, dict):
            continue
        consumer = metadata.get("consumer")
        if not isinstance(consumer, str) or not consumer:
            continue
        out["consumer_raw"] = consumer
        if consumer.startswith("projects/"):
            value = consumer[len("projects/") :]
            if value.isdigit():
                out["project_number"] = value
            else:
                out["project_id"] = value
        break
    return out


def _extract_error_text(parsed: dict) -> str:
    parts: list[str] = []
    if not isinstance(parsed, dict):
        return ""

    for key in ("error_message", "error_description", "message", "status"):
        value = parsed.get(key)
        if isinstance(value, str):
            parts.append(value)

    error_obj = parsed.get("error")
    if isinstance(error_obj, dict):
        for key in ("message", "status"):
            value = error_obj.get(key)
            if isinstance(value, str):
                parts.append(value)

    return " | ".join(parts)


def _maps_js_runtime_recommendation_data() -> dict[str, object]:
    return {
        "recommended_command": "gcheck --api-key <API_KEY> --maps-js-runtime",
        "alternate_recommended_commands": [
            "gcheck --api-key <API_KEY> --maps-js-runtime --maps-js-timeout 20"
        ],
        "confidence": "high",
        "recommendation_source": "maps-js-runtime-probe",
    }


def _contains_any_hint(haystack: str, hints: tuple[str, ...]) -> str | None:
    haystack_l = haystack.lower()
    for hint in hints:
        if hint.lower() in haystack_l:
            return hint
    return None


def _classify_maps_js_bootstrap(
    api_key: str,
    service: dict,
    *,
    name: str,
    code: int,
    body: str,
    url: str,
) -> Result:
    lowered = body.lower()
    if "gm_authfailure" in lowered or "invalidkey" in lowered:
        return Result(
            service=name,
            status=Status.INVALID,
            detail="Maps JS auth failure marker in response",
            http_code=code,
            endpoint=url,
        )

    if bool(service.get("maps_js_runtime")):
        runtime_timeout = int(service.get("maps_js_runtime_timeout", 12) or 12)
        runtime_referer = service.get("maps_js_runtime_referer")
        from .maps_js_runtime import probe_maps_js_runtime

        runtime = probe_maps_js_runtime(
            api_key,
            referer=runtime_referer,
            timeout_seconds=runtime_timeout,
        )
        runtime.service = name
        if runtime.http_code is None:
            runtime.http_code = code
        if not runtime.endpoint:
            runtime.endpoint = url
        return runtime

    return Result(
        service=name,
        status=Status.UNKNOWN,
        detail="HTTP 200 bootstrap served; runtime verification recommended",
        data=_maps_js_runtime_recommendation_data(),
        http_code=code,
        endpoint=url,
    )


def _classify(
    http_code: Optional[int],
    body: str,
    parsed: dict,
    *,
    allow_400_valid: bool = False,
    ambiguous_invalid_note: Optional[str] = None,
) -> tuple[Status, str]:
    if http_code is None:
        return Status.ERROR, body[:200]

    error_text = _extract_error_text(parsed)
    body_l = (body[:4000] + "\n" + error_text).lower()

    invalid_hint = _contains_any_hint(body_l, _INVALID_KEY_HINTS)
    if invalid_hint:
        if ambiguous_invalid_note:
            return Status.UNKNOWN, f"{invalid_hint}: {ambiguous_invalid_note}"
        return Status.INVALID, invalid_hint

    restricted_hint = _contains_any_hint(body_l, _RESTRICTED_HINTS)
    if restricted_hint:
        return Status.DENIED, f"restricted: {restricted_hint}"

    disabled_marker = detect_google_service_disabled(body, error_text)
    if disabled_marker:
        return Status.DISABLED, f"service disabled/not enabled: {disabled_marker}"

    if isinstance(parsed, dict):
        status_field = parsed.get("status")
        if status_field == "REQUEST_DENIED":
            msg = parsed.get("error_message") or status_field
            if isinstance(msg, str) and any(
                h.lower() in msg.lower() for h in _INVALID_KEY_HINTS
            ):
                return Status.INVALID, msg[:200]
            return Status.DENIED, str(msg)[:200]
        if status_field in ("OK", "ZERO_RESULTS", "NOT_FOUND"):
            return Status.VALID, status_field

    if 200 <= http_code < 300:
        return Status.VALID, "HTTP 2xx"
    if http_code == 400:
        if allow_400_valid:
            return Status.VALID, "HTTP 400 (request rejected, key accepted)"
        return Status.UNKNOWN, "HTTP 400"
    if http_code == 401:
        return Status.DENIED, "HTTP 401 (OAuth required?)"
    if http_code == 403:
        denied_hint = _contains_any_hint(body_l, _DENIED_HINTS)
        if denied_hint:
            return Status.DENIED, denied_hint
        return Status.DENIED, "HTTP 403"
    if http_code == 404:
        return Status.UNKNOWN, "HTTP 404 (endpoint not found?)"
    if http_code == 429:
        return Status.DENIED, "HTTP 429 (rate-limited; key likely valid but throttled)"
    return Status.UNKNOWN, f"HTTP {http_code}"


def _run_service(api_key: str, service: dict) -> Result:
    name = service["name"]

    if "probe" in service:
        return service["probe"](api_key)

    spec = service["build"](api_key)
    method = spec.get("method", "GET")
    headers = spec.get("headers")
    params = spec.get("params")
    json_body = spec.get("json")
    url = spec["url"]

    if method == "GET":
        code, body, parsed = http_get(url, params=params, headers=headers)
    else:
        code, body, parsed = http_post(
            url,
            json_body=json_body,
            headers=headers,
            timeout=DEFAULT_TIMEOUT,
            params=params,
        )

    if name == "FCM legacy send (API key)" and code in (403, 404):
        return Result(
            service=name,
            status=Status.DENIED,
            detail=(
                f"HTTP {code} (likely API discontinued or key disabled; "
                "legacy FCM was sunset 2024-06-20)"
            ),
            http_code=code,
            endpoint=url,
        )

    if name == "Maps: JavaScript API" and code == 200:
        return _classify_maps_js_bootstrap(
            api_key,
            service,
            name=name,
            code=code,
            body=body,
            url=url,
        )

    if service.get("bytes") and code is not None and 200 <= code < 300:
        status, detail = Status.VALID, "image returned"
    else:
        status, detail = _classify(
            code,
            body,
            parsed,
            allow_400_valid=bool(service.get("allow_400_valid")),
            ambiguous_invalid_note=service.get("ambiguous_invalid_note"),
        )

    recommendation_metadata = build_recommendation_metadata(detail=detail)
    detail = append_recommendation_to_detail(detail, recommendation_metadata)

    result_data: dict = {}
    if not service.get("bytes") and isinstance(parsed, dict):
        result_data = parsed

    error_info_metadata = _extract_error_info_metadata(parsed)
    if error_info_metadata:
        result_data = dict(result_data)
        result_data["inferred"] = error_info_metadata
        project_hint = error_info_metadata.get(
            "project_number"
        ) or error_info_metadata.get("project_id")
        if project_hint:
            detail = f"{detail} | consumer project: {project_hint}"

    if recommendation_metadata:
        result_data = dict(result_data)
        result_data.update(recommendation_metadata)

    return Result(
        service=name,
        status=status,
        detail=detail,
        http_code=code,
        endpoint=url,
        data=result_data,
    )


def _probe_referer_candidate(
    api_key: str,
    referer_value: str,
    *,
    timeout_seconds: float = DEFAULT_TIMEOUT,
) -> Result:
    spec = _maps_geocode(api_key)
    url = spec["url"]
    headers = {"Referer": referer_value}
    code, body, parsed = http_get(
        url,
        params=spec.get("params"),
        headers=headers,
        timeout=_normalize_probe_timeout(timeout_seconds),
    )
    status, detail = _classify(code, body, parsed)

    recommendation_metadata = build_recommendation_metadata(detail=detail)
    detail = append_recommendation_to_detail(detail, recommendation_metadata)

    result_data: dict = {
        "referer": referer_value,
    }
    if isinstance(parsed, dict):
        result_data["response"] = parsed
    if recommendation_metadata:
        result_data.update(recommendation_metadata)

    return Result(
        service=f"Referrer bruteforce: {referer_value}",
        status=status,
        detail=detail,
        http_code=code,
        endpoint=url,
        data=result_data,
    )


def build_referrer_candidates(
    candidates: list[str],
    *,
    template: str | None = None,
) -> list[str]:
    expanded: list[str] = []
    seen: set[str] = set()

    for raw in candidates:
        token = (raw or "").strip()
        if not token:
            continue
        value = template.replace("FUZZ", token) if template else token
        _append_unique_referer_variants(expanded, seen, value)
    return expanded


def iter_referrer_candidates(
    api_key: str,
    candidates: list[str],
    *,
    template: str | None = None,
    expanded_candidates: list[str] | None = None,
    max_workers: int = 20,
    timeout_seconds: float = DEFAULT_TIMEOUT,
    delay_seconds: float = 0.0,
) -> Iterator[Result]:
    if not _looks_like_api_key(api_key):
        yield Result(
            service="Referrer bruteforce",
            status=Status.INVALID,
            detail="Malformed key (expected AIza + 35 chars)",
        )
        return

    expanded = (
        list(expanded_candidates)
        if expanded_candidates is not None
        else build_referrer_candidates(candidates, template=template)
    )
    if not expanded:
        yield Result(
            service="Referrer bruteforce",
            status=Status.UNKNOWN,
            detail="No valid referer candidates after normalization",
        )
        return

    workers = max(1, int(max_workers or 1))
    delay = max(0.0, float(delay_seconds or 0.0))

    if delay > 0.0:
        workers = 1

    if workers == 1 or len(expanded) <= 1:
        for idx, value in enumerate(expanded):
            if delay > 0.0 and idx > 0:
                time.sleep(delay)
            yield _probe_referer_candidate(
                api_key,
                value,
                timeout_seconds=timeout_seconds,
            )
        return

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                _probe_referer_candidate,
                api_key,
                value,
                timeout_seconds=timeout_seconds,
            )
            for value in expanded
        ]
        for future in as_completed(futures):
            yield future.result()


def check_referrer_candidates(
    api_key: str,
    candidates: list[str],
    *,
    template: str | None = None,
    expanded_candidates: list[str] | None = None,
    max_workers: int = 20,
    timeout_seconds: float = DEFAULT_TIMEOUT,
    delay_seconds: float = 0.0,
) -> list[Result]:
    return list(
        iter_referrer_candidates(
            api_key,
            candidates,
            template=template,
            expanded_candidates=expanded_candidates,
            max_workers=max_workers,
            timeout_seconds=timeout_seconds,
            delay_seconds=delay_seconds,
        )
    )


def iter_api_key_checks(
    api_key: str,
    only: list[str] | None = None,
    *,
    active: bool = False,
    project_ids: list[str] | None = None,
    maps_js_runtime: bool = False,
    maps_js_runtime_timeout: int = 12,
    maps_js_runtime_referer: str | None = None,
    max_workers: int = 8,
) -> Iterator[Result]:
    if not _looks_like_api_key(api_key):
        yield Result(
            service="API key format",
            status=Status.INVALID,
            detail="Malformed key (expected AIza + 35 chars)",
        )
        return

    services = _build_services(
        active=active,
        project_ids=project_ids,
    )
    selected = [svc for svc in services if _service_matches_filter(svc["name"], only)]

    if maps_js_runtime:
        for svc in selected:
            if svc.get("name") != "Maps: JavaScript API":
                continue
            svc["maps_js_runtime"] = True
            svc["maps_js_runtime_timeout"] = maps_js_runtime_timeout
            svc["maps_js_runtime_referer"] = maps_js_runtime_referer
            break

    workers = max(1, int(max_workers or 1))
    if workers == 1 or len(selected) <= 1:
        for svc in selected:
            yield _run_service(api_key, svc)
        return

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_run_service, api_key, svc) for svc in selected]
        for future in as_completed(futures):
            yield future.result()


def check_api_key(
    api_key: str,
    only: list[str] | None = None,
    *,
    active: bool = False,
    project_ids: list[str] | None = None,
    maps_js_runtime: bool = False,
    maps_js_runtime_timeout: int = 12,
    maps_js_runtime_referer: str | None = None,
    max_workers: int = 8,
) -> list[Result]:
    return list(
        iter_api_key_checks(
            api_key,
            only=only,
            active=active,
            project_ids=project_ids,
            maps_js_runtime=maps_js_runtime,
            maps_js_runtime_timeout=maps_js_runtime_timeout,
            maps_js_runtime_referer=maps_js_runtime_referer,
            max_workers=max_workers,
        )
    )
