#!/usr/bin/env python3
"""gcheck - validate leaked Google and Firebase credentials.

Default mode is read-only. Use --active only with explicit authorization.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import textwrap
import time
from collections import Counter
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from checks._common import (
    Result,
    Status,
    build_recommendation_metadata,
    print_header,
    print_info,
    print_result,
    print_warn,
    dump_json,
    detect_key_restriction,
    select_top_recommendation,
    set_default_request_headers,
    C,
)
from checks import (
    api_key as ak_mod,
    oauth_token as ot_mod,
    refresh_token as rt_mod,
    service_account as sa_mod,
    firebase as fb_mod,
    fcm_legacy as fcm_mod,
    recaptcha as recaptcha_mod,
    detect,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gcheck",
        description="Probe Google and Firebase credentials for validity and access scope.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Read-only by default. --active enables probes that create artefacts on the target; use only with explicit authorization.",
    )

    inp = p.add_argument_group("input (provide one or more)")
    inp.add_argument("--value", help="A raw secret string (autodetect type)")
    inp.add_argument(
        "--file", help="Path to a file containing the secret(s) (autodetect type)"
    )
    inp.add_argument("--api-key", dest="api_key", help="Google API key (AIzaSy...)")
    inp.add_argument(
        "--access-token", dest="access_token", help="OAuth2 access token (ya29...)"
    )
    inp.add_argument(
        "--refresh-token",
        dest="refresh_token",
        help="OAuth2 refresh token (requires --client-id and --client-secret)",
    )
    inp.add_argument(
        "--client-id", help="OAuth2 client ID (required with --refresh-token)"
    )
    inp.add_argument(
        "--client-secret", help="OAuth2 client secret (required with --refresh-token)"
    )
    inp.add_argument(
        "--service-account-file",
        dest="sa_file",
        help="Path to a GCP service account JSON",
    )
    inp.add_argument(
        "--fcm-server-key", dest="fcm_key", help="Legacy FCM server key (AAAA...)"
    )
    inp.add_argument("--jwt", help="A bare JWT to decode locally")
    inp.add_argument(
        "--recaptcha-secret",
        dest="recaptcha_secret",
        help="Google reCAPTCHA secret key (6...)",
    )

    ctx = p.add_argument_group("context (improves coverage)")
    ctx.add_argument(
        "--project-number", help="Firebase project number (for Remote Config)"
    )
    ctx.add_argument("--firebase-url", help="Realtime Database URL")
    ctx.add_argument("--storage-bucket", help="Firebase storage bucket name")
    ctx.add_argument("--app-id", help="Firebase App ID")
    ctx.add_argument(
        "--namespaces",
        default="firebase",
        help="Comma-separated Remote Config namespaces (default: firebase)",
    )
    ctx.add_argument(
        "--android-package",
        help="Android package name used for X-Android-Package",
    )
    ctx.add_argument(
        "--android-cert",
        help="Android signing cert SHA1 for X-Android-Cert",
    )
    ctx.add_argument(
        "--ios-bundle",
        help="iOS bundle id used for X-Ios-Bundle-Identifier",
    )
    ctx.add_argument(
        "--referer",
        help="Referer header value for browser-restricted API keys",
    )
    ctx.add_argument(
        "--signup-email",
        help="Email address for the Firebase Auth sign-up probe (--active only; use an address you control)",
    )

    scope = p.add_argument_group("scope control")
    scope.add_argument(
        "--project",
        action="append",
        default=[],
        dest="project_ids",
        metavar="PROJECT",
        help="GCP project ID for project-scoped probes (repeatable or comma-separated)",
    )
    scope.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="SUBSTR",
        help="Substring filter on API-key service names only (repeatable or comma-separated; case-insensitive)",
    )
    scope.add_argument(
        "--active",
        action="store_true",
        help="Enable destructive probes (creates artefacts on target; use only with authorisation)",
    )
    scope.add_argument(
        "--maps-js-runtime",
        action="store_true",
        help=(
            "Run an optional Playwright browser probe for Maps JavaScript API "
            "to disambiguate runtime-only key restrictions"
        ),
    )
    scope.add_argument(
        "--maps-js-timeout",
        type=int,
        default=12,
        metavar="SECONDS",
        help="Timeout for --maps-js-runtime browser check (default: 12)",
    )
    scope.add_argument(
        "--perms-file",
        help="Path to a newline-delimited list of IAM permissions to test (overrides the built-in list)",
    )

    ref_attack = p.add_argument_group("referrer dictionary attack")
    ref_attack.add_argument(
        "--referer-wordlist",
        help=(
            "Path to newline-delimited referer/domain list for bruteforce mode "
            "(accepts full referers like https://a.example/ or bare domains)"
        ),
    )
    ref_attack.add_argument(
        "--referer-template",
        help=(
            "Candidate template using FUZZ placeholder, e.g. "
            "https://FUZZ.example.com/"
        ),
    )
    ref_attack.add_argument(
        "--referer-workers",
        type=int,
        default=20,
        metavar="N",
        help="Parallel workers for dictionary probes (default: 20)",
    )
    ref_attack.add_argument(
        "--referer-timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="HTTP timeout per dictionary probe request (default: 10)",
    )
    ref_attack.add_argument(
        "--referer-delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="Delay between dictionary checks; when >0, probes run sequentially",
    )

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="Output JSON only on stdout")
    out.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colour output"
    )
    out.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose diagnostic logs (timings, dispatch, collapse decisions)",
    )
    out.add_argument(
        "--show-all-results",
        dest="show_all_results",
        action="store_true",
        help=(
            "Always print full per-service results even when a restriction "
            "profile can be inferred"
        ),
    )
    out.add_argument(
        "--list-services",
        action="store_true",
        help="Print available API-key service names (for use with --only) and exit",
    )
    out.add_argument(
        "--list-perms",
        action="store_true",
        help="Print the built-in IAM permissions list and exit",
    )
    out.add_argument(
        "--finding-report",
        action="store_true",
        help=("Print findings report (severity, issue, evidence, docs links)"),
    )
    return p


def _load_perms_file(path: str | None) -> list[str] | None:
    if not path:
        return None
    permissions: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        permissions.append(value)
    return permissions


def _normalize_repeatable_csv(values: list[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        for bit in (raw or "").split(","):
            value = bit.strip()
            if not value or value in seen:
                continue
            seen.add(value)
            out.append(value)
    return out


def _firebase_namespaces(raw_namespaces: str | None) -> list[str]:
    return [n.strip() for n in (raw_namespaces or "").split(",") if n.strip()]


def _apply_firebase_cli_context(args: argparse.Namespace, extracted: dict) -> dict:
    updated = dict(extracted)
    overrides = {
        "firebase_url": args.firebase_url,
        "storage_bucket": args.storage_bucket,
        "project_number": args.project_number,
    }
    for key, value in overrides.items():
        if value:
            updated[key] = value
    if args.project_ids and not updated.get("project_id"):
        updated["project_id"] = args.project_ids[0]
    if args.app_id:
        app_ids = list(updated.get("app_ids") or [])
        if args.app_id not in app_ids:
            app_ids.append(args.app_id)
        updated["app_ids"] = app_ids
    return updated


def _run_firebase_checks(
    args: argparse.Namespace,
    extracted: dict,
    results: list[Result],
    *,
    header: str | None = None,
) -> None:
    if header:
        print_header(header, args.no_color)
    results.extend(
        fb_mod.check_firebase(
            _apply_firebase_cli_context(args, extracted),
            active=args.active,
            namespaces=_firebase_namespaces(args.namespaces),
            signup_email=args.signup_email,
        )
    )


def _looks_like_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value or ""))


def _load_referer_wordlist(path: str | None) -> list[str]:
    if not path:
        return []

    loaded: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        loaded.append(value)
    return loaded


_DICT_PROGRESS_STEP_PERCENT = 5


def _maybe_print_dictionary_progress(
    *,
    done: int,
    total: int,
    next_percent: int,
    no_color: bool,
    json_mode: bool,
) -> int:
    if json_mode or total <= 0:
        return next_percent

    progress_percent = int((done * 100) / total)
    should_print = done == total or progress_percent >= next_percent
    if not should_print:
        return next_percent

    print_info(
        f"dictionary progress: {done}/{total} ({progress_percent}%)",
        no_color,
    )

    updated = next_percent
    while updated <= progress_percent:
        updated += _DICT_PROGRESS_STEP_PERCENT
    return updated


def _verbose_info(args: argparse.Namespace, msg: str) -> None:
    if args.verbose and not args.json:
        print_info(msg, args.no_color)


def _verbose_probe_diagnostics(args: argparse.Namespace, results: list[Result]) -> None:
    if not args.verbose or args.json:
        return
    for result in results:
        code = result.http_code if result.http_code is not None else "-"
        endpoint = result.endpoint or "(no endpoint)"
        detail = (result.detail or "").split(" | recommendation:", 1)[0]
        if len(detail) > 90:
            detail = detail[:87] + "..."
        print_info(
            f"probe diag: status={result.status.value} code={code} "
            f"service={result.service} endpoint={endpoint} detail={detail}",
            args.no_color,
        )


def _verbose_collapse_decision(
    args: argparse.Namespace,
    key_results: list[Result],
    *,
    min_hits: int,
    phase: str,
) -> None:
    if not args.verbose or args.json:
        return

    if args.show_all_results:
        _verbose_info(
            args,
            f"collapse decision ({phase}): disabled because --show-all-results was set",
        )
        return

    restriction = detect_key_restriction(key_results, min_hits=min_hits)
    if restriction and _has_actionable_valid_signals(key_results):
        _verbose_info(
            args,
            f"collapse decision ({phase}): restriction and actionable VALID signal(s) "
            "present, using hybrid output",
        )
        return

    if _has_actionable_valid_signals(key_results):
        _verbose_info(
            args,
            f"collapse decision ({phase}): actionable VALID probe(s) present, "
            "keeping full results",
        )
        return

    if not restriction:
        _verbose_info(
            args,
            f"collapse decision ({phase}): no dominant restriction pattern "
            f"(min_hits={min_hits})",
        )
        return

    if _restriction_context_present(args, restriction):
        _verbose_info(
            args,
            f"collapse decision ({phase}): restriction '{restriction}' detected but "
            "context override present, keeping full results",
        )
        return

    _verbose_info(
        args,
        f"collapse decision ({phase}): restriction '{restriction}' detected, "
        "collapsing output",
    )


def _run_referrer_dictionary_attack(
    api_key: str,
    args: argparse.Namespace,
    key_results: list[Result],
) -> None:
    if not args.referer_wordlist:
        return

    wordlist_values = _load_referer_wordlist(args.referer_wordlist)
    bruteforce_candidates = ak_mod.build_referrer_candidates(
        wordlist_values,
        template=args.referer_template,
    )
    total_candidates = len(bruteforce_candidates)
    if not args.json:
        print_info(
            f"dictionary mode: loaded {len(wordlist_values)} entries, "
            f"expanded to {total_candidates} referer candidates",
            args.no_color,
        )

    done = 0
    next_progress_percent = _DICT_PROGRESS_STEP_PERCENT
    for result in ak_mod.iter_referrer_candidates(
        api_key,
        wordlist_values,
        template=args.referer_template,
        expanded_candidates=bruteforce_candidates,
        max_workers=args.referer_workers,
        timeout_seconds=args.referer_timeout,
        delay_seconds=args.referer_delay,
    ):
        key_results.append(result)
        done += 1
        next_progress_percent = _maybe_print_dictionary_progress(
            done=done,
            total=total_candidates,
            next_percent=next_progress_percent,
            no_color=args.no_color,
            json_mode=args.json,
        )


def _validate_referrer_dictionary_args(args: argparse.Namespace) -> int:
    if args.referer_workers < 1:
        print_warn("--referer-workers must be >= 1", args.no_color)
        return 2

    if args.referer_timeout <= 0:
        print_warn("--referer-timeout must be > 0", args.no_color)
        return 2

    if args.referer_delay < 0:
        print_warn("--referer-delay must be >= 0", args.no_color)
        return 2

    if args.referer_wordlist and not Path(args.referer_wordlist).is_file():
        print_warn("--referer-wordlist must point to an existing file", args.no_color)
        return 2

    if args.referer_template and "FUZZ" not in args.referer_template:
        print_warn("--referer-template must contain FUZZ placeholder", args.no_color)
        return 2

    if args.referer_template and not args.referer_wordlist:
        print_warn("--referer-template requires --referer-wordlist", args.no_color)
        return 2

    if args.referer_delay > 0 and args.referer_workers > 1 and not args.json:
        print_info(
            "referrer dictionary delay enabled; running sequentially to preserve spacing",
            args.no_color,
        )

    return 0


def _run_api_key_checks(
    api_key: str,
    args: argparse.Namespace,
    results: list[Result],
    *,
    project_ids: list[str] | None = None,
    source_label: str | None = None,
) -> int:
    key_start = time.perf_counter()
    header = f"API key {api_key[:8]}..."
    if source_label:
        header += f" (from {source_label})"
    print_header(header, args.no_color)
    _verbose_info(
        args,
        "api-key check start: "
        f"active={args.active} only={bool(args.only)} project_ids={len(project_ids or [])} "
        f"maps_js_runtime={args.maps_js_runtime}",
    )

    if _should_preflight_restriction_collapse(args):
        preflight_start = time.perf_counter()
        preflight_results = ak_mod.check_api_key(
            api_key,
            only=["Key Validation"],
            active=False,
            project_ids=project_ids,
        )
        preflight_ms = (time.perf_counter() - preflight_start) * 1000.0
        _verbose_info(
            args,
            f"preflight probe completed: services={len(preflight_results)} "
            f"elapsed_ms={preflight_ms:.1f}",
        )
        _verbose_probe_diagnostics(args, preflight_results)
        _verbose_collapse_decision(
            args,
            preflight_results,
            min_hits=1,
            phase="preflight",
        )
        restriction = detect_key_restriction(preflight_results, min_hits=1)
        if _print_collapsed_key_result(args, preflight_results, min_hits=1):
            results.append(_collapsed_result_from_restriction(restriction))
            total_ms = (time.perf_counter() - key_start) * 1000.0
            _verbose_info(
                args,
                f"api-key check end (preflight-collapsed): elapsed_ms={total_ms:.1f}",
            )
            return 1

    full_start = time.perf_counter()
    if args.verbose and not args.json:
        planned_services = ak_mod.planned_api_key_service_names(
            args.only or None,
            active=args.active,
            project_ids=project_ids,
            maps_js_runtime=args.maps_js_runtime,
        )
        _verbose_info(
            args,
            f"probe plan: {len(planned_services)} service(s) selected",
        )
        for service_name in planned_services:
            _verbose_info(args, f"  - {service_name}")

    key_results = ak_mod.check_api_key(
        api_key,
        only=args.only or None,
        active=args.active,
        project_ids=project_ids,
        maps_js_runtime=args.maps_js_runtime,
        maps_js_runtime_timeout=args.maps_js_timeout,
        maps_js_runtime_referer=args.referer,
    )
    full_ms = (time.perf_counter() - full_start) * 1000.0
    _verbose_info(
        args,
        f"full api-key probes completed: services={len(key_results)} elapsed_ms={full_ms:.1f}",
    )
    _verbose_probe_diagnostics(args, key_results)

    dict_start = time.perf_counter()
    _run_referrer_dictionary_attack(api_key, args, key_results)
    if args.referer_wordlist:
        dict_ms = (time.perf_counter() - dict_start) * 1000.0
        _verbose_info(
            args,
            f"dictionary probes completed: total_results_now={len(key_results)} "
            f"elapsed_ms={dict_ms:.1f}",
        )

    results.extend(key_results)
    if args.json:
        return 0

    _verbose_collapse_decision(
        args,
        key_results,
        min_hits=3,
        phase="full-run",
    )
    if _print_hybrid_key_result(args, key_results, min_hits=3):
        total_ms = (time.perf_counter() - key_start) * 1000.0
        _verbose_info(args, f"api-key check end (hybrid): elapsed_ms={total_ms:.1f}")
        return len(key_results)
    if _print_collapsed_key_result(args, key_results):
        total_ms = (time.perf_counter() - key_start) * 1000.0
        _verbose_info(args, f"api-key check end (collapsed): elapsed_ms={total_ms:.1f}")
        return len(key_results)

    _print_results_table(key_results, args.no_color)
    total_ms = (time.perf_counter() - key_start) * 1000.0
    _verbose_info(args, f"api-key check end (full-table): elapsed_ms={total_ms:.1f}")
    return len(key_results)


def _run_detected_api_keys(
    api_keys: list[str],
    args: argparse.Namespace,
    results: list[Result],
    source_label: str,
    *,
    project_ids: list[str] | None = None,
) -> int:
    streamed = 0
    for api_key in api_keys:
        streamed += _run_api_key_checks(
            api_key,
            args,
            results,
            project_ids=project_ids,
            source_label=source_label,
        )
    return streamed


def _should_preflight_restriction_collapse(args: argparse.Namespace) -> bool:
    has_custom_context = any(
        (
            args.android_package,
            args.android_cert,
            args.ios_bundle,
            args.referer,
            args.maps_js_runtime,
        )
    )
    return not args.json and not args.show_all_results and not has_custom_context


_NON_ACTIONABLE_VALID_SERVICES = {
    "Android Key Validation",
    "iOS Key Validation",
    "Referrer Key Validation",
}


def _restriction_context_present(
    args: argparse.Namespace, restriction: str | None
) -> bool:
    if restriction == "android":
        return bool(args.android_package and args.android_cert)
    if restriction == "ios":
        return bool(args.ios_bundle)
    if restriction == "referrer":
        return bool(args.referer)
    return False


def _is_actionable_valid_signal(result: Result) -> bool:
    if result.status != Status.VALID:
        return False
    if result.service.startswith("API key restriction profile"):
        return False
    if result.service in _NON_ACTIONABLE_VALID_SERVICES:
        return False
    return True


def _has_actionable_valid_signals(key_results: list[Result]) -> bool:
    """Return True when collapse would hide meaningful confirmed access."""
    return any(_is_actionable_valid_signal(result) for result in key_results)


def _collect_actionable_valid_signals(key_results: list[Result]) -> list[Result]:
    """Return VALID results that represent meaningful confirmed access."""
    return [result for result in key_results if _is_actionable_valid_signal(result)]


def _iter_hint_commands(
    data: dict,
    *,
    include_alternates: bool = True,
) -> list[str]:
    commands: list[str] = []

    cmd = data.get("recommended_command")
    if isinstance(cmd, str) and cmd:
        commands.append(cmd)

    if include_alternates:
        alt_cmds = data.get("alternate_recommended_commands")
        if isinstance(alt_cmds, list):
            for alt_cmd in alt_cmds:
                if isinstance(alt_cmd, str) and alt_cmd:
                    commands.append(alt_cmd)

    return commands


def _print_result_hints(
    results: list[Result],
    no_color: bool,
    *,
    skip_commands: set[str] | None = None,
    include_alternates: bool = True,
    leading_newline: bool = True,
    section_label: str | None = None,
) -> None:
    skip = skip_commands or set()
    hints: dict[str, None] = {}
    for result in results:
        if not isinstance(result.data, dict):
            continue
        for cmd in _iter_hint_commands(
            result.data,
            include_alternates=include_alternates,
        ):
            if cmd not in skip:
                hints[cmd] = None

    if not hints:
        return

    dim = "" if no_color else C.DIM
    reset = "" if no_color else C.R
    if leading_newline:
        print()
    if section_label:
        print(f"  {dim}{section_label}{reset}")
    for cmd in hints:
        print(f"    {dim}Hint:{reset} {cmd}")


def _collapsed_result_from_restriction(restriction: str | None) -> Result:
    details = {
        "android": ("API key appears valid but Android-restricted"),
        "ios": "API key appears valid but iOS-restricted",
        "referrer": ("API key appears valid but referrer-restricted"),
    }
    name = restriction or "unknown"
    reason_map = {
        "android": "API_KEY_ANDROID_APP_BLOCKED",
        "ios": "API_KEY_IOS_APP_BLOCKED",
        "referrer": "API_KEY_HTTP_REFERRER_BLOCKED",
    }
    metadata = build_recommendation_metadata(
        raw_reasons=[reason_map[name]] if name in reason_map else []
    )
    return Result(
        service=f"API key restriction profile ({name})",
        status=Status.VALID,
        detail=details.get(name, "API key appears restricted"),
        data=metadata,
    )


def _print_hybrid_key_result(
    args: argparse.Namespace,
    key_results: list[Result],
    *,
    min_hits: int = 3,
) -> bool:
    """Print collapsed restriction profile plus compact confirmed access section."""
    if args.show_all_results:
        return False

    restriction = detect_key_restriction(key_results, min_hits=min_hits)
    if not restriction:
        return False

    if _restriction_context_present(args, restriction):
        return False

    actionable_valids = _collect_actionable_valid_signals(key_results)
    if not actionable_valids:
        return False

    collapsed = _collapsed_result_from_restriction(restriction)
    print_result(collapsed, args.no_color)

    col = "" if args.no_color else C.B + C.CYN
    reset = "" if args.no_color else C.R
    print(f"\n  {col}Confirmed access:{reset}")
    for result in actionable_valids:
        code = result.http_code if result.http_code is not None else "-"
        detail = (result.detail or "").split(" | recommendation:", 1)[0]
        print(f"  - {result.service} [{code}] {detail}")

    primary_hint = (
        collapsed.data.get("recommended_command")
        if isinstance(collapsed.data, dict)
        else None
    )
    skip_commands = (
        {primary_hint} if isinstance(primary_hint, str) and primary_hint else set()
    )
    _print_result_hints(
        key_results,
        args.no_color,
        skip_commands=skip_commands,
        include_alternates=False,
        leading_newline=True,
        section_label="Additional hints:",
    )
    return True


def _print_collapsed_key_result(
    args: argparse.Namespace,
    key_results: list[Result],
    *,
    min_hits: int = 3,
) -> bool:
    if args.show_all_results:
        return False
    if _has_actionable_valid_signals(key_results):
        return False
    restriction = detect_key_restriction(key_results, min_hits=min_hits)
    if not restriction:
        return False

    if _restriction_context_present(args, restriction):
        return False

    collapsed = _collapsed_result_from_restriction(restriction)
    print_result(collapsed, args.no_color)

    primary_hint = (
        collapsed.data.get("recommended_command")
        if isinstance(collapsed.data, dict)
        else None
    )
    skip_commands = (
        {primary_hint} if isinstance(primary_hint, str) and primary_hint else set()
    )
    _print_result_hints(
        key_results,
        args.no_color,
        skip_commands=skip_commands,
        include_alternates=False,
        leading_newline=True,
        section_label="Additional hints:",
    )
    return True


def _dispatch(
    kind: str,
    value: str,
    parsed: dict | None,
    args: argparse.Namespace,
    results: list[Result],
) -> int:
    """Run the validator appropriate for the detected secret kind."""
    perms = _load_perms_file(args.perms_file)
    project_ids = list(args.project_ids or [])
    streamed = 0

    if kind == "api_key":
        streamed = _run_api_key_checks(
            value,
            args,
            results,
            project_ids=project_ids,
        )
        if (
            args.firebase_url
            or args.storage_bucket
            or args.project_ids
            or args.project_number
        ):
            _run_firebase_checks(
                args,
                {
                    "project_id": project_ids[0] if project_ids else None,
                    "project_number": args.project_number,
                    "firebase_url": args.firebase_url,
                    "storage_bucket": args.storage_bucket,
                    "api_keys": [value],
                    "app_ids": [args.app_id] if args.app_id else [],
                },
                results,
                header="Firebase context probes",
            )

    elif kind == "oauth_access":
        print_header(f"Access token ya29...{value[-6:]}", args.no_color)
        results.append(ot_mod.introspect(value))
        results.extend(
            ot_mod.probe_with_access_token(
                value,
                perms=perms,
                project_ids=project_ids,
            )
        )

    elif kind == "jwt":
        print_header("JWT", args.no_color)
        results.append(ot_mod.inspect_jwt(value))
        results.append(ot_mod.introspect(value))

    elif kind == "service_account":
        parsed_obj = parsed or {}
        print_header(
            f"Service account {parsed_obj.get('client_email','?')}", args.no_color
        )
        results.extend(
            sa_mod.check_service_account(
                parsed_obj,
                perms=perms,
                extra_project_ids=project_ids,
            )
        )

    elif kind == "authorized_user":
        print_header("Authorized user credentials (gcloud ADC file)", args.no_color)
        parsed_obj = parsed or {}
        cid = parsed_obj.get("client_id")
        csec = parsed_obj.get("client_secret")
        rt = parsed_obj.get("refresh_token")
        if cid and csec and rt:
            results.extend(
                rt_mod.check_refresh_token(
                    cid,
                    csec,
                    rt,
                    perms=perms,
                    project_ids=project_ids,
                )
            )
        else:
            print_warn("authorized_user JSON missing required fields", args.no_color)

    elif kind == "google_services_json":
        print_header("google-services.json (Android)", args.no_color)
        extracted = fb_mod.extract_from_google_services(parsed or {})
        _run_firebase_checks(args, extracted, results)
        extracted_project_id = extracted.get("project_id")
        streamed += _run_detected_api_keys(
            extracted.get("api_keys", []),
            args,
            results,
            "google-services.json",
            project_ids=(
                [extracted_project_id]
                if isinstance(extracted_project_id, str) and extracted_project_id
                else []
            ),
        )

    elif kind == "firebase_config":
        print_header("Firebase config", args.no_color)
        extracted = fb_mod.extract_from_web_config(parsed or {})
        _run_firebase_checks(args, extracted, results)
        extracted_project_id = extracted.get("project_id")
        streamed += _run_detected_api_keys(
            extracted.get("api_keys", []),
            args,
            results,
            "firebase config",
            project_ids=(
                [extracted_project_id]
                if isinstance(extracted_project_id, str) and extracted_project_id
                else []
            ),
        )

    elif kind == "oauth_client_secrets_file":
        print_header("OAuth client_secrets.json", args.no_color)
        parsed_obj = parsed or {}
        section = parsed_obj.get("web") or parsed_obj.get("installed") or {}
        print_info(
            f"client_id={section.get('client_id','?')} "
            f"client_secret_present={bool(section.get('client_secret'))}",
            args.no_color,
        )
        if args.refresh_token:
            results.extend(
                rt_mod.check_refresh_token(
                    section["client_id"],
                    section["client_secret"],
                    args.refresh_token,
                    perms=perms,
                    project_ids=project_ids,
                )
            )
        else:
            print_warn(
                "client_secrets file alone is not validatable; "
                "provide --refresh-token to exchange it",
                args.no_color,
            )
            results.append(
                Result(
                    service="OAuth client_secrets file",
                    status=Status.UNKNOWN,
                    detail=(
                        "identity disclosed but cannot be validated without "
                        "a refresh token or user consent flow"
                    ),
                    data={"client_id": section.get("client_id")},
                )
            )

    elif kind == "fcm_legacy":
        print_header(f"FCM legacy key {value[:10]}...", args.no_color)
        results.extend(fcm_mod.check_fcm_legacy(value))

    elif kind == "recaptcha_secret":
        print_header(f"reCAPTCHA secret {value[:10]}...", args.no_color)
        results.extend(recaptcha_mod.check_recaptcha_secret(value))

    elif kind == "oauth_refresh":
        print_header(
            "OAuth refresh token (need --client-id/--client-secret)", args.no_color
        )
        if args.client_id and args.client_secret:
            results.extend(
                rt_mod.check_refresh_token(
                    args.client_id,
                    args.client_secret,
                    value,
                    perms=perms,
                    project_ids=project_ids,
                )
            )
        else:
            results.append(
                Result(
                    service="OAuth refresh token",
                    status=Status.UNKNOWN,
                    detail="provide --client-id and --client-secret to exchange",
                )
            )

    elif kind in ("oauth_client_id", "oauth_client_secret"):
        results.append(
            Result(
                service=f"OAuth {kind}",
                status=Status.UNKNOWN,
                detail=(
                    "identity-only; pair with a refresh token "
                    "and the matching counterpart to validate"
                ),
            )
        )

    else:
        results.append(
            Result(
                service=f"Unknown kind {kind!r}",
                status=Status.UNKNOWN,
                detail="no validator for this credential shape",
            )
        )

    return streamed


def _collect_inputs(args: argparse.Namespace) -> list[detect.Detected]:
    """Translate CLI flags into detected items."""
    items: list[detect.Detected] = []
    if args.api_key:
        items.append(detect.Detected("api_key", args.api_key, source="cli"))
    if args.access_token:
        items.append(detect.Detected("oauth_access", args.access_token, source="cli"))
    if args.refresh_token:
        items.append(detect.Detected("oauth_refresh", args.refresh_token, source="cli"))
    if args.fcm_key:
        items.append(detect.Detected("fcm_legacy", args.fcm_key, source="cli"))
    if args.recaptcha_secret:
        items.append(
            detect.Detected("recaptcha_secret", args.recaptcha_secret, source="cli")
        )
    if args.jwt:
        items.append(detect.Detected("jwt", args.jwt, source="cli"))
    if args.sa_file:
        try:
            obj = json.loads(Path(args.sa_file).read_text())
        except Exception as exc:
            print_warn(f"failed to read {args.sa_file}: {exc}", args.no_color)
        else:
            items.append(
                detect.Detected(
                    "service_account",
                    value=obj.get("client_email", ""),
                    parsed=obj,
                    source="cli",
                )
            )
    if args.value:
        items.extend(detect.detect_from_string(args.value))
    if args.file:
        items.extend(detect.detect_from_file(args.file))
    return items


def _build_default_headers(args: argparse.Namespace) -> dict[str, str]:
    headers: dict[str, str] = {}
    if args.android_package:
        headers["X-Android-Package"] = args.android_package
    if args.android_cert:
        headers["X-Android-Cert"] = args.android_cert
    if args.ios_bundle:
        headers["X-Ios-Bundle-Identifier"] = args.ios_bundle
    if args.referer:
        headers["Referer"] = args.referer
    return headers


def _has_marker(result: Result, marker: str) -> bool:
    return marker.lower() in (result.detail or "").lower()


def _is_api_key_result(result: Result) -> bool:
    service = result.service or ""
    return ":" in service and not service.startswith("OAuth ")


def _build_finding_report(results: list[Result]) -> list[dict[str, str | list[str]]]:
    """Build findings from probe results."""
    api_like = [
        r
        for r in results
        if _is_api_key_result(r) and not (r.service or "").startswith("Service account")
    ]
    if not api_like:
        return []

    runtime_maps_valid = any(
        r.service == "Maps: JavaScript API"
        and r.status == Status.VALID
        and "runtime map initialization succeeded" in (r.detail or "").lower()
        for r in api_like
    )
    invalid_hits = sum(1 for r in api_like if r.status == Status.INVALID)
    disabled_hits = sum(1 for r in api_like if r.status == Status.DISABLED)
    denied_hits = sum(1 for r in api_like if r.status == Status.DENIED)
    referrer_blocked_hits = sum(
        1 for r in api_like if _has_marker(r, "API_KEY_HTTP_REFERRER_BLOCKED")
    )

    valid_services = [r for r in api_like if r.status == Status.VALID]
    non_maps_valid = [r for r in valid_services if r.service != "Maps: JavaScript API"]
    firebase_auth_denied = any(
        (r.service or "").startswith("Firebase Auth:") and r.status == Status.DENIED
        for r in api_like
    )

    findings: list[dict[str, str | list[str]]] = []

    if runtime_maps_valid:
        severity = "INFO"
        danger = "Key is usable in browser runtime. Exposure is operational."
        issue = "Browser key exposure may be acceptable with strict referrer and API restrictions."
        if not referrer_blocked_hits:
            severity = "MEDIUM"
            danger = "Browser-usable key without restriction evidence may allow abuse and billing impact."
            issue = "Restrictions look weak or were not proven in this run."
        findings.append(
            {
                "id": "F-APIKEY-MAPSJS-RUNTIME",
                "severity": severity,
                "title": "Maps JavaScript key is runtime-usable",
                "danger": danger,
                "issue": issue,
                "evidence": (
                    "Maps: JavaScript API returned VALID with runtime initialization"
                ),
                "recommendation": (
                    "Verify allowed origins with --referer, then enforce API restrictions and quotas."
                ),
                "docs": [
                    "https://developers.google.com/maps/documentation/javascript/error-messages",
                    "https://developers.google.com/maps/documentation/javascript/maps-app-check",
                    "https://developers.google.com/maps/api-security-best-practices",
                    "https://hackerone.com/reports/1321830",
                ],
            }
        )

    if firebase_auth_denied:
        findings.append(
            {
                "id": "F-FIREBASE-APIKEY-CONTEXT",
                "severity": "INFO",
                "title": "Firebase endpoints recognize key but enforce auth/rules",
                "danger": (
                    "Firebase keys are often public by design. Risk depends on Security Rules, App Check, and quotas."
                ),
                "issue": (
                    "Auth probes were denied; review abuse and brute-force exposure."
                ),
                "evidence": "Firebase Auth probes returned PERMISSION_DENIED",
                "recommendation": (
                    "Review key allowlists, Security Rules, App Check enforcement, and identitytoolkit quotas."
                ),
                "docs": [
                    "https://firebase.google.com/docs/projects/api-keys",
                    "https://firebase.google.com/docs/rules/insecure-rules",
                    "https://firebase.google.com/docs/app-check",
                    "https://hackerone.com/reports/1066410",
                    "https://hackerone.com/reports/1065134",
                ],
            }
        )

    if referrer_blocked_hits > 0:
        findings.append(
            {
                "id": "F-APIKEY-REFERRER-RESTRICTED",
                "severity": "INFO",
                "title": "HTTP referrer restrictions detected",
                "danger": (
                    "Abuse appears constrained for tested endpoints, but the exact allowlist is unknown."
                ),
                "issue": (
                    "Restrictions may still be bypassable if wildcards or broad domains are used."
                ),
                "evidence": (
                    f"API_KEY_HTTP_REFERRER_BLOCKED observed in {referrer_blocked_hits} probes"
                ),
                "recommendation": (
                    "Test known origins with --referer and confirm exact console restriction rules."
                ),
                "docs": [
                    "https://docs.cloud.google.com/docs/authentication/api-keys#websites",
                    "https://developers.google.com/maps/documentation/javascript/error-messages",
                    "https://developers.google.com/maps/api-security-best-practices",
                ],
            }
        )

    if len(non_maps_valid) >= 1:
        findings.append(
            {
                "id": "F-APIKEY-MULTISERVICE-USABLE",
                "severity": "MEDIUM",
                "title": "Key usable beyond Maps JS",
                "danger": (
                    "More usable APIs increase abuse surface and potential cost impact."
                ),
                "issue": (
                    f"{len(non_maps_valid)} non-Maps-JS service(s) returned VALID"
                ),
                "evidence": ", ".join(r.service for r in non_maps_valid[:4]),
                "recommendation": (
                    "Restrict keys to required APIs and set quotas and budget alerts."
                ),
                "docs": [
                    "https://docs.cloud.google.com/docs/authentication/api-keys#api_key_restrictions",
                    "https://cloud.google.com/billing/docs/how-to/budgets",
                    "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/",
                    "https://hackerone.com/reports/1065041",
                    "https://hackerone.com/reports/1321830",
                    "https://blogs.dsu.edu/digforce/2023/07/27/exploiting-google-maps-unrestricted-api-key/",
                ],
            }
        )

    if any(
        r.service == "FCM legacy send (API key)"
        and r.status == Status.DENIED
        and r.http_code in (403, 404)
        for r in api_like
    ):
        findings.append(
            {
                "id": "F-FCM-LEGACY-SUNSET",
                "severity": "INFO",
                "title": "Legacy FCM endpoint is denied/sunset",
                "danger": "Legacy path likely non-usable as an attack vector.",
                "issue": "FCM legacy API has been deprecated and turned down.",
                "evidence": "FCM legacy send probe denied",
                "recommendation": "Focus on HTTP v1 credentials and IAM roles.",
                "docs": [
                    "https://firebase.google.com/docs/cloud-messaging/send/v1-api",
                    "https://firebase.google.com/docs/cloud-messaging/server-environment",
                    "https://firebase.google.com/docs/cloud-messaging/error-codes",
                ],
            }
        )

    if denied_hits > 0 and not findings:
        findings.append(
            {
                "id": "F-APIKEY-CONSTRAINED",
                "severity": "INFO",
                "title": "Key recognized but currently constrained",
                "danger": "No direct high-impact abuse path demonstrated in this run.",
                "issue": "Denied responses dominate tested services.",
                "evidence": f"DENIED={denied_hits} DISABLED={disabled_hits}",
                "recommendation": "Capture the allowed execution context and retest with realistic headers.",
                "docs": [
                    "https://docs.cloud.google.com/docs/authentication/api-keys#api_key_restrictions",
                    "https://developers.google.com/maps/api-security-best-practices",
                ],
            }
        )

    return findings


_TABLE_STATUS_ORDER = [
    Status.VALID,
    Status.INVALID,
    Status.ERROR,
    Status.UNKNOWN,
    Status.DENIED,
    Status.DISABLED,
]

_TABLE_STATUS_COLOR = {
    Status.VALID: C.GRN + C.B,
    Status.DENIED: C.YEL,
    Status.INVALID: C.RED,
    Status.DISABLED: C.DIM,
    Status.UNKNOWN: C.MAG,
    Status.ERROR: C.RED,
}


def _trim_recommendation_suffix(detail: str) -> str:
    marker = " | recommendation:"
    marker_idx = detail.lower().find(marker)
    if marker_idx == -1:
        return detail
    return detail[:marker_idx]


def _wrap_table_detail(detail: str, width: int) -> list[str]:
    return textwrap.wrap(detail, width=width) or [""]


def _record_hint_commands(hints: dict[str, None], data: dict) -> None:
    for cmd in _iter_hint_commands(data, include_alternates=True):
        hints[cmd] = None


def _print_results_table(results: list[Result], no_color: bool) -> None:
    if not results:
        return

    unknown_rank = 99
    order = {status: idx for idx, status in enumerate(_TABLE_STATUS_ORDER)}
    rows = sorted(results, key=lambda result: order.get(result.status, unknown_rank))

    svc_width = min(max(len(r.service) for r in rows), 42)
    terminal_width = shutil.get_terminal_size(fallback=(120, 20)).columns
    prefix_for_width = f"  {'':<8}  {'':<{svc_width}}  {'':>4}  "
    detail_width = max(24, terminal_width - len(prefix_for_width))
    bold = "" if no_color else C.B
    reset = "" if no_color else C.R
    dim = "" if no_color else C.DIM

    print(
        f"\n  {bold}{'STATUS':<8}  {'SERVICE':<{svc_width}}  {'CODE':>4}  DETAIL{reset}"
    )

    hints: dict[str, None] = {}
    prev_status: Status | None = None

    for r in rows:
        if prev_status is not None and r.status != prev_status:
            print()
        prev_status = r.status

        detail = _trim_recommendation_suffix(r.detail or "")
        wrapped_detail = _wrap_table_detail(detail, detail_width)

        code = f"{r.http_code:>4}" if r.http_code is not None else "    "
        svc = r.service[:svc_width]
        status_text = f"{r.status.value:<8}"
        continuation_prefix = f"  {'':<8}  {'':<{svc_width}}  {'':>4}  "

        if r.status == Status.DISABLED and not no_color:
            print(
                f"  {dim}{status_text}  {svc:<{svc_width}}  {code}  {wrapped_detail[0]}{reset}"
            )
            for continuation_line in wrapped_detail[1:]:
                print(f"  {dim}{continuation_prefix}{continuation_line}{reset}")
        else:
            status_color = "" if no_color else _TABLE_STATUS_COLOR.get(r.status, "")
            print(
                f"  {status_color}{status_text}{reset}  {svc:<{svc_width}}  {code}  {wrapped_detail[0]}"
            )
            for continuation_line in wrapped_detail[1:]:
                print(f"{continuation_prefix}{continuation_line}")

        if isinstance(r.data, dict):
            _record_hint_commands(hints, r.data)

    if hints:
        print()
        for cmd in hints:
            print(f"  {dim}Hint:{reset} {cmd}")


def _print_finding_report(results: list[Result], no_color: bool) -> None:
    findings = _build_finding_report(results)
    if not findings:
        return

    severity_counts = Counter(str(f.get("severity", "INFO")) for f in findings)
    col = "" if no_color else C.B + C.CYN
    reset = "" if no_color else C.R
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_summary = " ".join(
        f"{sev}:{severity_counts[sev]}" for sev in sev_order if severity_counts[sev]
    )

    print(f"\n{col}Findings report:{reset} {sev_summary}")
    is_first = True
    for finding in findings:
        if not is_first:
            print()
        is_first = False
        print(f"  [{finding['severity']}] {finding['id']} - {finding['title']}")
        print(f"    impact:         {finding['danger']}")
        print(f"    context:        {finding['issue']}")
        print(f"    evidence:       {finding['evidence']}")
        print(f"    recommendation: {finding['recommendation']}")
        docs = finding.get("docs", [])
        if docs:
            print("    references:")
            for doc in docs:
                print(f"      {doc}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.project_ids = _normalize_repeatable_csv(args.project_ids)
    args.only = _normalize_repeatable_csv(args.only)

    if args.list_services:
        for svc in ak_mod.list_api_key_services():
            print(svc)
        return 0

    if args.list_perms:
        for perm in ot_mod.DEFAULT_PERMS_TO_TEST:
            print(perm)
        return 0

    if bool(args.android_package) != bool(args.android_cert):
        print_warn(
            "--android-package and --android-cert must be provided together",
            args.no_color,
        )
        return 2

    if args.signup_email and not _looks_like_email(args.signup_email):
        print_warn(
            "--signup-email must look like a valid email address",
            args.no_color,
        )
        return 2

    if args.maps_js_timeout < 1:
        print_warn("--maps-js-timeout must be >= 1", args.no_color)
        return 2

    referrer_args_exit = _validate_referrer_dictionary_args(args)
    if referrer_args_exit:
        return referrer_args_exit

    default_headers = _build_default_headers(args)
    set_default_request_headers(default_headers)

    if args.verbose and not args.json:
        print_info("verbose mode enabled (--verbose received)", args.no_color)
        if default_headers:
            print_info(
                f"default headers enabled: {', '.join(sorted(default_headers.keys()))}",
                args.no_color,
            )

    if args.active and not args.json:
        print_warn(
            "ACTIVE mode enabled. Probes will create artefacts on the "
            "target (Firebase signUp etc.).",
            args.no_color,
        )

    items = _collect_inputs(args)
    if not items:
        print_warn("no inputs provided. Use --help for usage.", args.no_color)
        return 2

    if not args.json:
        print_info(f"Detected {len(items)} credential(s):", args.no_color)
        for d in items:
            preview = d.value[:20] + "…" if d.value and len(d.value) > 20 else d.value
            print_info(f"  - {d.kind}: {preview}", args.no_color)

    results: list[Result] = []
    for d in items:
        _verbose_info(
            args,
            f"dispatch start: kind={d.kind} source={d.source}",
        )
        before_count = len(results)
        streamed_count = 0
        dispatch_start = time.perf_counter()
        try:
            streamed_count = _dispatch(d.kind, d.value, d.parsed, args, results)
        except KeyboardInterrupt:
            print_warn("interrupted", args.no_color)
            break
        except Exception as exc:
            results.append(
                Result(
                    service=f"Validator for {d.kind}",
                    status=Status.ERROR,
                    detail=f"{exc.__class__.__name__}: {exc}",
                )
            )
        finally:
            elapsed_ms = (time.perf_counter() - dispatch_start) * 1000.0
            added = len(results) - before_count
            _verbose_info(
                args,
                f"dispatch end: kind={d.kind} elapsed_ms={elapsed_ms:.1f} "
                f"results_added={added} streamed_inline={streamed_count}",
            )

        if not args.json:
            for r in results[before_count + streamed_count :]:
                print_result(r, args.no_color)

    if args.json:
        print(dump_json(results))
    else:
        counts: dict[Status, int] = {}
        for r in results:
            counts[r.status] = counts.get(r.status, 0) + 1
        col = "" if args.no_color else C.B
        reset = "" if args.no_color else C.R
        summary = "  ".join(f"{k.value}:{v}" for k, v in counts.items())
        print(f"\n{col}Summary:{reset} {summary}")
        if args.finding_report:
            _print_finding_report(results, args.no_color)

    return 0 if results else 1


if __name__ == "__main__":
    sys.exit(main())
