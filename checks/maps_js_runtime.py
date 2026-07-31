"""Optional browser-runtime verification for Google Maps JavaScript API keys."""

from __future__ import annotations

from typing import Optional

from ._common import Result, Status

_MAPS_JS_ENDPOINT = "https://maps.googleapis.com/maps/api/js"
_MAPS_JS_ROUTE_GLOB = "**/maps.googleapis.com/maps/api/js**"

_INVALID_MARKERS = (
    "invalidkeymaperror",
    "the provided api key is invalid",
    "gm_authfailure",
)
_DENIED_MARKERS = (
    "referernotallowedmaperror",
    "api_key_http_referrer_blocked",
    "api_key_android_app_blocked",
    "api_key_ios_app_blocked",
    "for development purposes only",
)
_DISABLED_MARKERS = (
    "apinotactivatedmaperror",
    "billingnotenabledmaperror",
    "project_denied",
    "service_disabled",
)


def _find_marker(raw: str, markers: tuple[str, ...]) -> str | None:
    for marker in markers:
        if marker in raw:
            return marker
    return None


def _classify_runtime(messages: list[str], runtime_state: dict) -> tuple[Status, str]:
    raw = "\n".join(messages + [str(runtime_state)]).lower()

    if runtime_state.get("authFailure"):
        return Status.INVALID, "gm_authFailure triggered during runtime"

    marker = _find_marker(raw, _INVALID_MARKERS)
    if marker:
        return Status.INVALID, f"runtime marker: {marker}"

    marker = _find_marker(raw, _DENIED_MARKERS)
    if marker:
        return Status.DENIED, f"runtime marker: {marker}"

    marker = _find_marker(raw, _DISABLED_MARKERS)
    if marker:
        return Status.DISABLED, f"runtime marker: {marker}"

    if runtime_state.get("mapOk"):
        return Status.VALID, "runtime map initialization succeeded"

    error_text = (runtime_state.get("error") or "").strip()
    if error_text:
        return Status.UNKNOWN, f"runtime script error: {error_text[:200]}"

    return Status.UNKNOWN, "runtime inconclusive"


def probe_maps_js_runtime(
    api_key: str,
    *,
    referer: Optional[str] = None,
    timeout_seconds: int = 12,
) -> Result:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return Result(
            service="Maps: JavaScript API (runtime)",
            status=Status.UNKNOWN,
            detail=(
                "Playwright runtime probe requested but dependency is unavailable. "
                "Install with: pip install playwright && playwright install chromium"
            ),
        )

    captured_messages: list[str] = []
    runtime_state: dict = {}
    bootstrap_http_code: Optional[int] = None
    endpoint = _MAPS_JS_ENDPOINT
    script_src = f"{_MAPS_JS_ENDPOINT}?key={api_key}&callback=gcheckInit"

    html = f"""
<!doctype html>
<html>
  <head>
    <meta charset=\"utf-8\" />
    <title>gcheck maps runtime probe</title>
    <style>
      html, body, #map {{
        margin: 0;
        padding: 0;
        width: 100%;
        height: 100%;
      }}
    </style>
    <script>
      window.__gcheck = {{ mapOk: false, authFailure: false, error: "", callbackCalled: false }};
      window.gm_authFailure = function () {{
        window.__gcheck.authFailure = true;
        console.error("gm_authFailure");
      }};
      window.gcheckInit = function () {{
        window.__gcheck.callbackCalled = true;
        try {{
          new google.maps.Map(document.getElementById("map"), {{
            center: {{ lat: 37.4221, lng: -122.0841 }},
            zoom: 10,
            disableDefaultUI: true,
          }});
          window.__gcheck.mapOk = true;
          console.log("gcheck-map-ok");
        }} catch (err) {{
          window.__gcheck.error = String(err);
          console.error("gcheck-init-error", String(err));
        }}
      }};
      window.gcheckScriptError = function () {{
        window.__gcheck.error = "maps-script-load-failed";
        console.error("maps-script-load-failed");
      }};
    </script>
  </head>
  <body>
    <div id=\"map\"></div>
        <script async defer onerror=\"gcheckScriptError()\" src=\"{script_src}\"></script>
  </body>
</html>
"""

    timeout_ms = max(1, int(timeout_seconds or 1)) * 1000

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context()

            if referer:

                def _set_referer(route):
                    headers = dict(route.request.headers)
                    headers["referer"] = referer
                    route.continue_(headers=headers)

                context.route(_MAPS_JS_ROUTE_GLOB, _set_referer)

            page = context.new_page()

            page.on("console", lambda msg: captured_messages.append(msg.text))
            page.on("pageerror", lambda err: captured_messages.append(str(err)))

            def _capture_response(response):
                nonlocal bootstrap_http_code
                if "maps.googleapis.com/maps/api/js" in response.url:
                    bootstrap_http_code = response.status

            page.on("response", _capture_response)

            page.set_content(html, wait_until="domcontentloaded")
            try:
                page.wait_for_function(
                    """
                    () => {
                        const s = window.__gcheck || {};
                        return Boolean(s.mapOk || s.authFailure || s.error);
                    }
                    """,
                    timeout=timeout_ms,
                )
            except Exception:
                captured_messages.append("runtime-timeout")

            runtime_state = page.evaluate("() => window.__gcheck || {}")
            context.close()
            browser.close()
    except Exception as exc:
        if "Executable doesn't exist" in str(exc):
            return Result(
                service="Maps: JavaScript API (runtime)",
                status=Status.UNKNOWN,
                detail=(
                    "Playwright runtime probe requested but the Chromium browser "
                    "is not installed. Install with: playwright install chromium"
                ),
                endpoint=endpoint,
                http_code=bootstrap_http_code,
            )
        return Result(
            service="Maps: JavaScript API (runtime)",
            status=Status.ERROR,
            detail=f"runtime probe failure: {exc.__class__.__name__}: {exc}",
            endpoint=endpoint,
            http_code=bootstrap_http_code,
        )

    status, detail = _classify_runtime(captured_messages, runtime_state)
    if captured_messages and status == Status.UNKNOWN:
        detail = f"{detail}; console={'; '.join(captured_messages[:3])[:240]}"

    data = {}
    if captured_messages:
        data["console"] = captured_messages[:10]
    if runtime_state:
        data["runtime_state"] = runtime_state

    return Result(
        service="Maps: JavaScript API (runtime)",
        status=status,
        detail=detail,
        data=data,
        http_code=bootstrap_http_code,
        endpoint=endpoint,
    )
