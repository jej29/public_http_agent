from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse, urlsplit

import httpx
from agent.candidates import generate_candidates
from agent.finding_identity import stable_key
from agent.common import log, now_utc_iso, run_id_utc, save_json
from agent.crawler import (
    discover_endpoints,
    extract_navigation,
    extract_js_style_endpoints,
    classify_url_kind,
)
from agent.features import extract_features
from agent.finding_store import (
    ensure_output_dirs,
    merge_finding,
    persist_finding_map,
    save_raw_capture,
    seed_bucket_candidate,
)
from agent.llm_probe_planner import build_observation_summary, generate_llm_probes
from agent.probes import (
    RequestSpec,
    build_probe_plan,
    build_access_control_replay_plan,
    build_authenticated_request_replay_plan,
    build_object_access_control_replay_plan,
    build_authenticated_business_probe_plan,
)
from agent.report_generator import generate_reports
from agent.scan_engine import (
    _build_request_meta,
    _finalize_candidate,
    _store_with_verdict_precedence,
    maybe_authenticate,
    process_plan,
    _sanitize_request_headers_and_cookie_jar,
)

from agent.verification_policy import (
    verify_auth_bypass,
    verify_protected_resource_access,
    verify_session_controls,
    verify_session_fixation,
)

from agent.scope import (
    disclosure_scope_url,
    host_scope_url,
    misconfig_scope_url,
    normalize_url_for_dedup,
    resource_scope_url,
    route_scope_url,
)
from agent.severity_engine import apply_base_severity_to_candidates


OWASP_ONLY_NO_CWE_MAPPING = "OWASP_ONLY_NO_CWE_MAPPING"

LOW_VALUE_FILE_HINTS = (
    "readme",
    "changelog",
    "license",
    "copying",
    "authors",
    "contributing",
)

LOW_VALUE_EXTS = (
    ".md",
    ".rst",
    ".txt",
)

INFORMATION_DISCLOSURE_TYPES = {
    "HTTP_ERROR_INFO_EXPOSURE",
    "HTTP_SYSTEM_INFO_EXPOSURE",
    "DIRECTORY_LISTING_ENABLED",
    "DEFAULT_FILE_EXPOSED",
    "PHPINFO_EXPOSURE",
    "HTTP_CONFIG_FILE_EXPOSURE",
    "LOG_VIEWER_EXPOSURE",
    "FILE_PATH_HANDLING_ANOMALY",
}

SECURITY_MISCONFIGURATION_TYPES = {
    "SECURITY_HEADERS_MISSING",
    "CORS_MISCONFIG",
    "COOKIE_HTTPONLY_MISSING",
    "COOKIE_SECURE_MISSING",
    "COOKIE_SAMESITE_MISSING",
    "TRACE_ENABLED",
    "RISKY_HTTP_METHODS_ENABLED",
    "HTTPS_REDIRECT_MISSING",
    "HSTS_MISSING",
    "OPEN_REDIRECT",
    "CLICKJACKING",
    "CSP_MISSING",
    "CONTENT_TYPE_SNIFFING",
    "REFERRER_POLICY_MISSING",
    "PERMISSIONS_POLICY_MISSING",
}

AMBIGUOUS_TYPES = {
    "HTTP_ERROR_INFO_EXPOSURE",
    "HTTP_SYSTEM_INFO_EXPOSURE",
    "PHPINFO_EXPOSURE",
    "HTTP_CONFIG_FILE_EXPOSURE",
    "LOG_VIEWER_EXPOSURE",
    "FILE_PATH_HANDLING_ANOMALY",
}

DETERMINISTIC_TYPES = {
    "DIRECTORY_LISTING_ENABLED",
    "DEFAULT_FILE_EXPOSED",
    "CORS_MISCONFIG",
    "COOKIE_HTTPONLY_MISSING",
    "COOKIE_SECURE_MISSING",
    "COOKIE_SAMESITE_MISSING",
    "TRACE_ENABLED",
    "RISKY_HTTP_METHODS_ENABLED",
    "HTTPS_REDIRECT_MISSING",
    "HSTS_MISSING",
    "CLICKJACKING",
    "CSP_MISSING",
    "CONTENT_TYPE_SNIFFING",
    "REFERRER_POLICY_MISSING",
    "PERMISSIONS_POLICY_MISSING",
}

SESSION_COOKIE_NAMES = {
    "jsessionid",
    "phpsessid",
    "session",
    "sessionid",
    "sid",
    "asp.net_sessionid",
    "connect.sid",
}

def _preferred_cookie_path(url: str) -> str:
    path = urlsplit(str(url or "")).path or "/"
    segs = [s for s in path.split("/") if s]
    if segs:
        return "/" + segs[0]
    return "/"

def _clear_cookie_name_from_client(client: httpx.AsyncClient, cookie_name: str) -> None:
    jar = getattr(client.cookies, "jar", None)
    if jar is None:
        return

    to_clear = []
    try:
        for c in list(jar):
            if str(getattr(c, "name", "")).lower() == cookie_name.lower():
                to_clear.append((
                    getattr(c, "domain", None),
                    getattr(c, "path", None),
                    getattr(c, "name", None),
                ))
    except Exception:
        return

    for domain, path, name in to_clear:
        try:
            jar.clear(domain, path, name)
        except Exception:
            pass

def _store_verified_findings(
    *,
    findings: List[Dict[str, Any]],
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    stable_key_fn,
) -> None:
    for finding in findings:
        key = stable_key_fn(finding)
        verdict = (finding.get("verification") or {}).get("verdict")
        _store_with_verdict_precedence(
            key=key,
            cand=finding,
            verdict=verdict,
            confirmed_map=confirmed_map,
            informational_map=informational_map,
            false_positive_map=false_positive_map,
        )

def _base_origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _cookie_domain_candidates(url: str) -> List[str]:
    host = (urlparse(url).hostname or "").strip()
    if not host:
        return []

    out = [host]
    if "." in host and not host.replace(".", "").isdigit():
        out.append("." + host)
    return out

def _build_effective_seed_urls(
    *,
    target: str,
    auth_landing_url: str | None,
    seed_urls: List[str] | None,
) -> List[str]:
    effective_seed_urls: List[str] = []

    for candidate in [target, auth_landing_url, *(seed_urls or [])]:
        s = str(candidate or "").strip()
        if not s:
            continue
        if s not in effective_seed_urls:
            effective_seed_urls.append(s)

    return effective_seed_urls


async def _discover_authenticated_endpoints(
    *,
    client: httpx.AsyncClient,
    target: str,
    auth_landing_url: str | None,
    seed_urls: List[str] | None,
    timeout_s: float,
    crawl_depth: int,
    crawl_max_pages: int,
    crawl_enable_js: bool,
) -> List[Dict[str, Any]]:
    effective_seed_urls = _build_effective_seed_urls(
        target=target,
        auth_landing_url=auth_landing_url,
        seed_urls=seed_urls,
    )

    log("CRAWL", f"Authenticated crawl seeds: {effective_seed_urls}")
    log("CRAWL", "Re-running discovery with authenticated session")

    return await discover_endpoints(
        client=client,
        seed_url=target,
        timeout_s=timeout_s,
        max_depth=crawl_depth,
        max_pages=crawl_max_pages,
        include_js_string_paths=crawl_enable_js,
        extra_seed_urls=effective_seed_urls,
        crawl_state="authenticated",
    )

async def _run_plan_and_merge(
    *,
    client: httpx.AsyncClient,
    plan: List[Any],
    timeout_s: float,
    retries: int,
    run_dir: Path,
    raw_index: List[Dict[str, Any]],
    coverage: Dict[str, Dict[str, Any]],
    seq_start: int,
    authenticated: bool,
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    shared_unhealthy_scopes: set[str] | None = None,
) -> int:
    process_result = await process_plan(
        client=client,
        plan=plan,
        timeout_s=timeout_s,
        retries=retries,
        run_dir=run_dir,
        raw_index=raw_index,
        coverage=coverage,
        seq_start=seq_start,
        log_fn=log,
        llm_judge_if_enabled_fn=llm_judge_if_enabled,
        stable_key_fn=stable_key,
        update_coverage_from_candidate_fn=update_coverage_from_candidate,
        mark_attempted_for_spec_fn=mark_attempted_for_spec,
        update_cookie_observation_fn=update_cookie_observation,
        request_auth_state="authenticated" if authenticated else "anonymous",
        shared_unhealthy_scopes=shared_unhealthy_scopes,
    )

    _merge_process_result(
        process_result=process_result,
        confirmed_map=confirmed_map,
        informational_map=informational_map,
        false_positive_map=false_positive_map,
        request_failures=request_failures,
    )

    return process_result["next_seq"]


def _apply_manual_auth_to_client(
    *,
    client: httpx.AsyncClient,
    target: str,
) -> Dict[str, Any]:
    applied_cookie_names: List[str] = []
    applied_header_names: List[str] = []

    manual_cookie_raw = str(os.getenv("MANUAL_AUTH_COOKIE", "") or "").strip()
    manual_headers_raw = str(os.getenv("MANUAL_AUTH_HEADERS", "") or "").strip()

    def _preferred_cookie_path(url: str) -> str:
        path = urlsplit(str(url or "")).path or "/"
        segs = [s for s in path.split("/") if s]
        if segs:
            return "/" + segs[0]
        return "/"

    def _clear_cookie_name_from_client(cookie_name: str) -> None:
        jar = getattr(client.cookies, "jar", None)
        if jar is None:
            return

        to_clear: List[tuple[Any, Any, Any]] = []
        try:
            for c in list(jar):
                if str(getattr(c, "name", "") or "").lower() == cookie_name.lower():
                    to_clear.append((
                        getattr(c, "domain", None),
                        getattr(c, "path", None),
                        getattr(c, "name", None),
                    ))
        except Exception:
            return

        for domain, path, name in to_clear:
            try:
                jar.clear(domain, path, name)
            except Exception:
                pass

    preferred_path = _preferred_cookie_path(target)
    host = (urlparse(target).hostname or "").strip() or None

    if manual_cookie_raw:
        cookie_parts = [x.strip() for x in manual_cookie_raw.split(";") if x.strip()]

        for part in cookie_parts:
            if "=" not in part:
                continue

            ck, cv = part.split("=", 1)
            cookie_name = ck.strip()
            cookie_value = cv.strip()

            if not cookie_name:
                continue

            _clear_cookie_name_from_client(cookie_name)

            try:
                if host:
                    client.cookies.set(
                        cookie_name,
                        cookie_value,
                        domain=host,
                        path=preferred_path,
                    )
                else:
                    client.cookies.set(
                        cookie_name,
                        cookie_value,
                        path=preferred_path,
                    )
            except Exception:
                pass

            applied_cookie_names.append(cookie_name)

    if manual_headers_raw:
        for chunk in manual_headers_raw.split("|||"):
            piece = str(chunk or "").strip()
            if not piece or ":" not in piece:
                continue

            hk, hv = piece.split(":", 1)
            header_name = hk.strip()
            header_value = hv.strip()

            if not header_name:
                continue

            # Cookie는 절대 header로 넣지 않고 jar만 사용한다.
            if header_name.lower() == "cookie":
                continue

            client.headers[header_name] = header_value
            applied_header_names.append(header_name)

    manual_auth_enabled = bool(applied_cookie_names or applied_header_names)

    if applied_cookie_names:
        log("AUTH", f"Applied manual auth cookies: {sorted(set(applied_cookie_names))}")
    if applied_header_names:
        log("AUTH", f"Applied manual auth headers: {sorted(set(applied_header_names))}")

    return {
        "manual_auth_enabled": manual_auth_enabled,
        "manual_cookie_names": sorted(set(applied_cookie_names)),
        "manual_header_names": sorted(set(applied_header_names)),
    }

def _build_anonymous_replay_client(
    *,
    limits: httpx.Limits,
    client_timeout: httpx.Timeout,
    follow_redirects: bool,
) -> httpx.AsyncClient:
    anonymous_transport = httpx.AsyncHTTPTransport(
        retries=0,
        verify=False,
        http2=False,
    )

    anonymous_limits = httpx.Limits(
        max_connections=limits.max_connections,
        max_keepalive_connections=max(0, min(1, limits.max_connections or 1)),
        keepalive_expiry=2.0,
    )

    anonymous_timeout = httpx.Timeout(
        client_timeout.read if client_timeout.read is not None else 10.0,
        connect=client_timeout.connect if client_timeout.connect is not None else 3.0,
        read=client_timeout.read if client_timeout.read is not None else 10.0,
        write=client_timeout.write if client_timeout.write is not None else 10.0,
        pool=client_timeout.pool if client_timeout.pool is not None else 3.0,
    )

    return httpx.AsyncClient(
        limits=anonymous_limits,
        timeout=anonymous_timeout,
        transport=anonymous_transport,
        verify=False,
        trust_env=False,
        http2=False,
        follow_redirects=follow_redirects,
    )

def _merge_bucket_maps(
    src: Dict[str, Dict[str, Any]],
    dst: Dict[str, Dict[str, Any]],
) -> None:
    for k, v in src.items():
        dst[k] = merge_finding(dst[k], v) if k in dst else v


def _merge_process_result(
    *,
    process_result: Dict[str, Any],
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
) -> None:
    _merge_bucket_maps(process_result["confirmed_map"], confirmed_map)
    _merge_bucket_maps(process_result["informational_map"], informational_map)
    _merge_bucket_maps(process_result["false_positive_map"], false_positive_map)
    request_failures.extend(process_result["request_failures"])

def _path_prefixes_from_url(url: str) -> List[str]:
    path = urlsplit(url).path or "/"
    path = re.sub(r"/+", "/", path)

    if path == "/":
        return ["/"]

    segments = [seg for seg in path.split("/") if seg]
    prefixes: List[str] = []

    # /common/portal/ndaMain.do -> /common, /common/portal
    current = ""
    for seg in segments[:-1]:
        current += "/" + seg
        prefixes.append(current)

    # 마지막 segment가 파일처럼 보여도, 디렉토리 path 자체도 고려
    if not prefixes and segments:
        prefixes.append("/" + segments[0])

    return prefixes or ["/"]

async def _process_auth_snapshots(
    *,
    auth_result: Dict[str, Any],
    seq_start: int,
    client: httpx.AsyncClient,
    run_dir: Path,
    raw_index: List[Dict[str, Any]],
    coverage: Dict[str, Dict[str, Any]],
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    timeout_s: float,
    retries: int,
    stable_key_fn,
) -> int:
    auth_snaps_raw = auth_result.get("auth_snapshots") or []
    if not isinstance(auth_snaps_raw, list) or not auth_snaps_raw:
        return seq_start

    def _normalize_auth_snapshot_items(raw_items: Any) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not isinstance(raw_items, list):
            return out

        for entry in raw_items:
            if isinstance(entry, dict):
                spec = entry.get("spec")
                snap = entry.get("snapshot")

                if isinstance(spec, list) and spec:
                    spec = spec[0]
                if isinstance(snap, list) and snap:
                    snap = snap[0]

                if spec is not None and isinstance(snap, dict):
                    out.append({"spec": spec, "snapshot": snap})
                continue

            if isinstance(entry, list) and len(entry) >= 2:
                spec = entry[0]
                snap = entry[1]

                if isinstance(spec, list) and spec:
                    spec = spec[0]
                if isinstance(snap, list) and snap:
                    snap = snap[0]

                if spec is not None and isinstance(snap, dict):
                    out.append({"spec": spec, "snapshot": snap})

        return out

    auth_snaps = _normalize_auth_snapshot_items(auth_snaps_raw)
    if not auth_snaps:
        return seq_start

    raw_dir = run_dir / "raw"
    seq = seq_start

    for item in auth_snaps:
        spec = item.get("spec")
        snap = item.get("snapshot") or {}

        if not spec or not isinstance(snap, dict) or not snap:
            continue

        try:
            mark_attempted_for_spec(spec, coverage)
        except Exception:
            pass

        try:
            update_cookie_observation(snap, coverage)
        except Exception:
            pass

        raw_path = save_raw_capture(raw_dir, seq, spec, snap)

        snap_headers = snap.get("headers") or {}
        if not isinstance(snap_headers, dict):
            snap_headers = {}

        body_text = str(snap.get("body_text") or snap.get("body_snippet") or "")
        final_url = str(snap.get("final_url") or "")

        raw_index.append(
            {
                "seq": seq,
                "request_name": getattr(spec, "name", None),
                "method": getattr(spec, "method", None),
                "url": getattr(spec, "url", None),
                "raw_ref": str(raw_path),
                "status_code": snap.get("status_code"),
                "ok": snap.get("ok"),
                "source": getattr(spec, "source", None),
                "family": getattr(spec, "family", None),
                "scope_key": getattr(spec, "url", None),
                "auth_state": "authenticated",
                "content_type": str(snap_headers.get("content-type") or ""),
                "body_len": len(body_text),
                "body_text": body_text,
                "final_url": final_url,
                "comparison_group": getattr(spec, "comparison_group", None),
                "replay_key": getattr(spec, "replay_key", None),
                "replay_source_url": getattr(spec, "replay_source_url", None),
                "replay_source_state": getattr(spec, "replay_source_state", None),
                "replay_priority": getattr(spec, "replay_priority", None),
                "expected_signal": getattr(spec, "expected_signal", None),
                "mutation_class": getattr(spec, "mutation_class", None),
            }
        )
        seq += 1

        if not snap.get("ok"):
            request_failures.append(
                {
                    "trigger": getattr(spec, "name", None),
                    "method": getattr(spec, "method", None),
                    "url": getattr(spec, "url", None),
                    "error": snap.get("error"),
                    "raw_ref": str(raw_path),
                    "source": getattr(spec, "source", None),
                    "family": getattr(spec, "family", None),
                    "auth_state": "authenticated",
                }
            )
            continue

        req_meta = _build_request_meta(spec)
        feats = extract_features(req_meta, snap)
        candidates = apply_base_severity_to_candidates(generate_candidates(req_meta, snap, feats))

        for cand in candidates:
            update_coverage_from_candidate(cand, coverage)

        for cand in candidates:
            cand["raw_ref"] = str(raw_path)

            finalized = await _finalize_candidate(
                client=client,
                spec=spec,
                snap=snap,
                cand=cand,
                timeout_s=timeout_s,
                retries=retries,
                llm_judge_if_enabled_fn=llm_judge_if_enabled,
                stable_key_fn=stable_key_fn,
            )

            finalized_items = finalized if isinstance(finalized, list) else [finalized]

            for one in finalized_items:
                if not isinstance(one, dict):
                    continue

                key = stable_key_fn(one)
                verdict = (one.get("verification") or {}).get("verdict")

                _store_with_verdict_precedence(
                    key=key,
                    cand=one,
                    verdict=verdict,
                    confirmed_map=confirmed_map,
                    informational_map=informational_map,
                    false_positive_map=false_positive_map,
                )

    return seq


def _extract_authenticated_endpoints_from_auth_snapshots(
    *,
    auth_result: Dict[str, Any],
    target: str,
) -> List[Dict[str, Any]]:
    from agent.crawler import _is_session_destructive_url

    auth_snaps_raw = auth_result.get("auth_snapshots") or []
    if not isinstance(auth_snaps_raw, list) or not auth_snaps_raw:
        return []

    def _normalize_auth_snapshot_items(raw_items: Any) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not isinstance(raw_items, list):
            return out

        for entry in raw_items:
            if isinstance(entry, dict):
                spec = entry.get("spec")
                snap = entry.get("snapshot")

                if isinstance(spec, list) and spec:
                    spec = spec[0]
                if isinstance(snap, list) and snap:
                    snap = snap[0]

                if spec is not None and isinstance(snap, dict):
                    out.append({"spec": spec, "snapshot": snap})
                continue

            if isinstance(entry, list) and len(entry) >= 2:
                spec = entry[0]
                snap = entry[1]

                if isinstance(spec, list) and spec:
                    spec = spec[0]
                if isinstance(snap, list) and snap:
                    snap = snap[0]

                if spec is not None and isinstance(snap, dict):
                    out.append({"spec": spec, "snapshot": snap})

        return out

    def _mk_endpoint(
        url: str,
        *,
        kind: str,
        source: str | None,
        method: str = "GET",
        field_names: List[str] | None = None,
    ) -> Dict[str, Any]:
        normalized_url = str(url or "").strip()
        return {
            "url": normalized_url,
            "kind": kind,
            "source": source,
            "depth": 1,
            "method": str(method or "GET").upper(),
            "field_names": list(field_names or []),
            "query_param_names": [],
            "is_redirect_target": False,
            "is_session_destructive": _is_session_destructive_url(normalized_url),
            "score": 0,
            "state": "authenticated",
            "states": ["authenticated"],
        }

    auth_snaps = _normalize_auth_snapshot_items(auth_snaps_raw)
    out_by_url: Dict[str, Dict[str, Any]] = {}

    for item in auth_snaps:
        snap = item.get("snapshot") or {}
        if not isinstance(snap, dict):
            continue

        final_url = str(snap.get("final_url") or "").strip()
        body_text = str(snap.get("body_text") or snap.get("body_snippet") or "")

        if not final_url or not body_text:
            continue
        if not _same_origin(final_url, target):
            continue

        nav = extract_navigation(final_url, body_text)
        js_links = extract_js_style_endpoints(final_url, body_text)

        for link in sorted(set(nav.get("links") or set()).union(js_links)):
            if not link:
                continue
            if not _same_origin(link, target):
                continue

            ep = _mk_endpoint(
                link,
                kind=classify_url_kind(link),
                source=final_url,
                method="GET",
            )
            out_by_url[ep["url"]] = ep

        for src in sorted(set(nav.get("scripts") or set())):
            if not src:
                continue
            if not _same_origin(src, target):
                continue

            ep = _mk_endpoint(
                src,
                kind=classify_url_kind(src, "asset_js"),
                source=final_url,
                method="GET",
            )
            out_by_url[ep["url"]] = ep

        for form_def in nav.get("forms") or []:
            form_url = str(form_def.get("url") or "").strip()
            if not form_url:
                continue
            if not _same_origin(form_url, target):
                continue

            ep = _mk_endpoint(
                form_url,
                kind="form",
                source=final_url,
                method=form_def.get("method", "GET"),
                field_names=form_def.get("field_names") or [],
            )
            out_by_url[ep["url"]] = ep

    harvested = list(out_by_url.values())
    if harvested:
        log("CRAWL", f"Authenticated endpoints harvested from auth snapshots: {len(harvested)}")

    return harvested

def _build_static_plan_from_endpoints(
    *,
    target: str,
    discovered_endpoints: List[Dict[str, Any]],
    allowed_app_prefixes: List[str],
) -> List[RequestSpec]:
    static_plan: List[RequestSpec] = []
    seen_plan_keys = set()

    for idx, ep in enumerate(discovered_endpoints):
        ep_url = endpoint_url(ep)
        ep_kind = endpoint_kind(ep)
        intensity = choose_probe_intensity_for_endpoint(idx, ep)

        if is_session_destructive_endpoint(ep):
            log(
                "CRAWL",
                f"Skipping session-destructive endpoint from static plan: {ep_url} "
                f"states={endpoint_states(ep)}"
            )
            continue

        endpoint_plan = build_probe_plan(ep_url, intensity=intensity)

        log(
            "CRAWL",
            f"Probe intensity for endpoint[{idx + 1}] {ep_url} "
            f"kind={ep_kind} states={ep.get('states', []) if isinstance(ep, dict) else []} "
            f"score={ep.get('score', 0) if isinstance(ep, dict) else 0} "
            f"-> {intensity} ({len(endpoint_plan)} probes)"
        )

        for spec in endpoint_plan:
            key = (
                spec.method,
                spec.url,
                tuple(sorted((spec.headers or {}).items())),
                spec.body,
                spec.probe,
                spec.trace_marker,
                spec.family,
            )
            if key in seen_plan_keys:
                continue
            seen_plan_keys.add(key)
            static_plan.append(spec)

    log("INIT", f"Static probes planned after prioritized crawl expansion: {len(static_plan)}")

    static_plan = _filter_request_specs_by_app_scope(
        static_plan,
        base_target=target,
        allowed_prefixes=allowed_app_prefixes,
    )

    log("INIT", f"Static probes planned after app-scope filter: {len(static_plan)}")
    return static_plan

def _filter_out_session_destructive_authenticated_endpoints(
    endpoints: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    removed = 0

    for ep in endpoints or []:
        if is_session_destructive_endpoint(ep):
            removed += 1
            continue
        out.append(ep)

    if removed:
        log("CRAWL", f"Skipping session-destructive authenticated endpoints: {removed}")

    return out

def _prepare_discovered_endpoints(
    *,
    target: str,
    anonymous_endpoints: List[Dict[str, Any]],
    authenticated_endpoints: List[Dict[str, Any]],
    allowed_app_prefixes: List[str],
    max_endpoints: int,
) -> tuple[List[Dict[str, Any]], int, List[Dict[str, Any]], List[Dict[str, Any]]]:
    filtered_anonymous_endpoints = _filter_endpoints_by_app_scope(
        anonymous_endpoints,
        base_target=target,
        allowed_prefixes=allowed_app_prefixes,
    )

    filtered_authenticated_endpoints = _filter_endpoints_by_app_scope(
        authenticated_endpoints,
        base_target=target,
        allowed_prefixes=allowed_app_prefixes,
    )

    filtered_authenticated_endpoints = _filter_out_session_destructive_authenticated_endpoints(
        filtered_authenticated_endpoints
    )

    log("CRAWL", f"Anonymous endpoints in app scope: {len(filtered_anonymous_endpoints)} / {len(anonymous_endpoints)}")
    log("CRAWL", f"Authenticated endpoints in app scope: {len(filtered_authenticated_endpoints)} / {len(authenticated_endpoints)}")

    discovered_endpoints = merge_discovered_endpoints(
        filtered_anonymous_endpoints,
        filtered_authenticated_endpoints,
    )

    if not discovered_endpoints:
        discovered_endpoints = [{
            "url": target,
            "kind": "page",
            "source": None,
            "depth": 0,
            "method": "GET",
            "field_names": [],
            "query_param_names": [],
            "is_redirect_target": False,
            "is_session_destructive": False,
            "score": 0,
            "state": "anonymous",
            "states": ["anonymous"],
        }]

    original_discovered_count = len(discovered_endpoints)
    log("CRAWL", f"Discovered endpoints before pruning: {original_discovered_count}")

    discovered_endpoints = [ep for ep in discovered_endpoints if not should_drop_low_value_endpoint(ep)]
    log("CRAWL", f"Endpoints after low-value filtering: {len(discovered_endpoints)}")

    discovered_endpoint_map = {
        endpoint_url(ep): ep for ep in discovered_endpoints if endpoint_url(ep)
    }

    pruned_urls = prune_discovered_endpoints(
        list(discovered_endpoint_map.keys()),
        max_endpoints=max_endpoints,
    )

    if target not in pruned_urls:
        pruned_urls = [target] + pruned_urls
        pruned_urls = pruned_urls[:max_endpoints]

    discovered_endpoints = [
        discovered_endpoint_map.get(
            url,
            {
                "url": url,
                "kind": "page",
                "source": None,
                "depth": 0,
                "method": "GET",
                "field_names": [],
                "query_param_names": [],
                "is_redirect_target": False,
                "is_session_destructive": False,
                "score": 0,
                "state": "anonymous",
                "states": ["anonymous"],
            },
        )
        for url in pruned_urls
    ]

    log("CRAWL", f"Endpoints after pruning: {len(discovered_endpoints)}")

    return (
        discovered_endpoints,
        original_discovered_count,
        filtered_anonymous_endpoints,
        filtered_authenticated_endpoints,
    )


async def _run_llm_planner_round(
    *,
    round_name: str,
    seq_start: int,
    client: httpx.AsyncClient,
    target: str,
    timeout_s: float,
    retries: int,
    run_dir: Path,
    raw_index: List[Dict[str, Any]],
    coverage: Dict[str, Dict[str, Any]],
    discovered_endpoints: List[Dict[str, Any]],
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    allowed_app_prefixes: List[str],
    authenticated: bool,
) -> int:
    try:
        log("LLM", f"Generating additional probes with LLM planner ({round_name})...")
        observation_summary = build_observation_summary(
            target=target,
            raw_index=raw_index,
            findings_confirmed=list(confirmed_map.values()),
            findings_informational=list(informational_map.values()),
            discovered_endpoints=discovered_endpoints,
        )
        llm_plan_raw = generate_llm_probes(target, observation_summary)
        llm_plan = _filter_request_specs_by_app_scope(
            llm_plan_raw,
            base_target=target,
            allowed_prefixes=allowed_app_prefixes,
        )
        log("LLM", f"Generated probes ({round_name}): raw={len(llm_plan_raw)} filtered={len(llm_plan)}")
    except Exception as e:
        log("LLM", f"Planner failed ({round_name}), continuing: {type(e).__name__}: {e}")
        return seq_start

    if not llm_plan:
        return seq_start

    p = await process_plan(
        client=client,
        plan=llm_plan,
        timeout_s=timeout_s,
        retries=retries,
        run_dir=run_dir,
        raw_index=raw_index,
        coverage=coverage,
        seq_start=seq_start,
        log_fn=log,
        llm_judge_if_enabled_fn=llm_judge_if_enabled,
        stable_key_fn=stable_key,
        update_coverage_from_candidate_fn=update_coverage_from_candidate,
        mark_attempted_for_spec_fn=mark_attempted_for_spec,
        update_cookie_observation_fn=update_cookie_observation,
        request_auth_state="authenticated" if authenticated else "anonymous",
    )

    _merge_process_result(
        process_result=p,
        confirmed_map=confirmed_map,
        informational_map=informational_map,
        false_positive_map=false_positive_map,
        request_failures=request_failures,
    )
    return p["next_seq"]

def _derive_allowed_app_prefixes(
    *,
    target: str,
    auth_landing_url: str | None,
    seed_urls: List[str] | None,
) -> List[str]:
    def _first_path_prefix(url: str | None) -> str | None:
        if not url:
            return None

        path = urlsplit(url).path or "/"
        path = re.sub(r"/+", "/", path)

        if path == "/":
            return "/"

        segments = [seg for seg in path.split("/") if seg]
        if not segments:
            return "/"

        return "/" + segments[0]

    prefixes: List[str] = []

    for candidate in [target, auth_landing_url, *(seed_urls or [])]:
        prefix = _first_path_prefix(candidate)
        if prefix:
            prefixes.append(prefix)

    cleaned: List[str] = []
    seen = set()

    for p in prefixes:
        p = re.sub(r"/+", "/", p).rstrip("/")
        if not p:
            p = "/"
        if p not in seen:
            seen.add(p)
            cleaned.append(p)

    cleaned.sort(key=lambda x: (len(x), x))
    return cleaned or ["/"]

def _same_origin(url_a: str, url_b: str) -> bool:
    pa = urlsplit(url_a)
    pb = urlsplit(url_b)
    return (
        pa.scheme.lower(),
        pa.netloc.lower(),
    ) == (
        pb.scheme.lower(),
        pb.netloc.lower(),
    )


def _url_in_allowed_app_scope(url: str, allowed_prefixes: List[str], base_target: str) -> bool:
    if not url:
        return False

    if not _same_origin(url, base_target):
        return False

    path = re.sub(r"/+", "/", urlsplit(url).path or "/").rstrip("/")
    if not path:
        path = "/"

    normalized_prefixes: List[str] = []
    for prefix in allowed_prefixes or []:
        px = re.sub(r"/+", "/", str(prefix or "")).rstrip("/")
        normalized_prefixes.append(px or "/")

    for px in normalized_prefixes:
        if px == "/":
            return True
        if path == px or path.startswith(px + "/"):
            return True

    return False


def _filter_endpoints_by_app_scope(
    endpoints: List[Dict[str, Any]],
    *,
    base_target: str,
    allowed_prefixes: List[str],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for ep in endpoints or []:
        if not isinstance(ep, dict):
            continue

        url = endpoint_url(ep)
        if not url:
            continue

        if not _same_origin(url, base_target):
            continue

        if _url_in_allowed_app_scope(url, allowed_prefixes, base_target):
            out.append(ep)

    return out



def _filter_request_specs_by_app_scope(
    plan: List[RequestSpec],
    *,
    base_target: str,
    allowed_prefixes: List[str],
) -> List[RequestSpec]:
    out: List[RequestSpec] = []

    for spec in plan or []:
        spec_url = str(getattr(spec, "url", "") or "")
        if not spec_url:
            continue

        if not _same_origin(spec_url, base_target):
            continue

        if _url_in_allowed_app_scope(spec_url, allowed_prefixes, base_target):
            out.append(spec)

    return out

def normalize_target_name(name: str) -> str:
    name = name.strip().lower()
    name = re.sub(r"[^\w]+", "_", name)
    name = re.sub(r"_+", "_", name)
    return name.strip("_")


def prepare_output_path(base_out_dir: str, target_name: str) -> str:
    base = Path(base_out_dir) / target_name
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "results.json")


def endpoint_url(ep: Any) -> str:
    if isinstance(ep, dict):
        return str(ep.get("url") or "")
    return str(ep or "")


def endpoint_kind(ep: Any) -> str:
    if isinstance(ep, dict):
        return str(ep.get("kind") or "page")
    return "page"

def endpoint_states(ep: Any) -> List[str]:
    if isinstance(ep, dict):
        states = ep.get("states") or []
        out: List[str] = []
        seen = set()
        for s in states:
            v = str(s or "").strip().lower()
            if not v or v in seen:
                continue
            seen.add(v)
            out.append(v)
        state = str(ep.get("state") or "").strip().lower()
        if state and state not in seen:
            out.append(state)
        return out
    return []


def is_authenticated_only_endpoint(ep: Any) -> bool:
    states = set(endpoint_states(ep))
    return "authenticated" in states and "anonymous" not in states


def is_session_destructive_endpoint(ep: Any) -> bool:
    if not isinstance(ep, dict):
        return False
    return bool(ep.get("is_session_destructive"))

def discovered_endpoint_urls(endpoints: List[Any]) -> List[str]:
    out: List[str] = []
    for ep in endpoints or []:
        if isinstance(ep, dict):
            url = str(ep.get("url") or "")
            if url:
                out.append(url)
        elif isinstance(ep, str):
            out.append(ep)
    return out


def choose_probe_intensity_for_rank(rank: int) -> str:
    full_count = int(os.getenv("CRAWL_FULL_ENDPOINTS", "1"))
    medium_count = int(os.getenv("CRAWL_MEDIUM_ENDPOINTS", "2"))

    if rank < full_count:
        return "full"
    if rank < full_count + medium_count:
        return "medium"
    return "light"

def choose_probe_intensity_for_endpoint(rank: int, ep: Dict[str, Any]) -> str:
    kind = endpoint_kind(ep)
    score = int(ep.get("score", 0) or 0)
    url = endpoint_url(ep).lower()
    path = urlsplit(url).path or "/"
    query = urlsplit(url).query or ""

    states = {str(x).strip().lower() for x in (ep.get("states") or [])}
    auth_only = "authenticated" in states and "anonymous" not in states
    has_query = bool(query)

    if kind == "static":
        return "static"

    if is_session_destructive_endpoint(ep):
        return "static"

    if path in {"", "/"}:
        return "medium"

    if kind == "asset_js":
        return "light"

    high_signal_tokens = (
        "phpinfo",
        "config",
        "compose",
        "log",
        "backup",
        ".env",
        ".git",
        "debug",
        "actuator",
        "server-status",
        "server-info",
    )
    if any(tok in url for tok in high_signal_tokens):
        return "medium"

    if auth_only and has_query and any(tok in path for tok in (".do", ".action", ".php", "/api/", "/rest/")):
        return "medium"

    low_yield_targets = ("/login", "/signin", "/logout")
    if any(tok in url for tok in low_yield_targets):
        return "light"

    medium_value_tokens = (
        "/api/",
        "/rest/",
        "/admin",
        "/upload",
        "/fi/",
        "include.php",
        "/setup",
        "/security",
        "/instructions",
    )
    if any(tok in url for tok in medium_value_tokens):
        return "medium"

    if auth_only:
        if kind == "form":
            return "medium"
        if has_query:
            return "medium"

    if kind == "form":
        if score >= 50:
            return "medium"
        return "light"

    if score >= 70:
        return "medium"

    return choose_probe_intensity_for_rank(rank)

def merge_discovered_endpoints(*endpoint_lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    for endpoints in endpoint_lists:
        for ep in endpoints or []:
            if not isinstance(ep, dict):
                continue

            url = endpoint_url(ep)
            if not url:
                continue

            existing = merged.get(url)
            if existing is None:
                merged[url] = dict(ep)
                states = ep.get("states") or []
                if ep.get("state") and ep["state"] not in states:
                    states = list(states) + [ep["state"]]
                merged[url]["states"] = sorted(set(states))
                merged[url]["is_session_destructive"] = bool(ep.get("is_session_destructive"))
                continue

            existing["score"] = max(existing.get("score", 0), ep.get("score", 0))
            existing["depth"] = min(existing.get("depth", 9999), ep.get("depth", 9999))

            if ep.get("kind") == "form":
                existing["kind"] = "form"
            elif existing.get("kind") != "form" and ep.get("kind") == "page":
                existing["kind"] = "page"

            existing["field_names"] = list(
                dict.fromkeys((existing.get("field_names") or []) + (ep.get("field_names") or []))
            )
            existing["query_param_names"] = list(
                dict.fromkeys((existing.get("query_param_names") or []) + (ep.get("query_param_names") or []))
            )

            existing_states = set(existing.get("states") or [])
            incoming_states = set(ep.get("states") or [])
            if ep.get("state"):
                incoming_states.add(ep["state"])
            existing["states"] = sorted(existing_states.union(incoming_states))

            if ep.get("is_redirect_target"):
                existing["is_redirect_target"] = True

            if ep.get("is_session_destructive"):
                existing["is_session_destructive"] = True

            if not existing.get("source") and ep.get("source"):
                existing["source"] = ep["source"]

    ranked = list(merged.values())
    ranked.sort(
        key=lambda ep: (
            bool(ep.get("is_session_destructive")),
            -ep.get("score", 0),
            ep.get("kind") == "static",
            len(urlsplit(ep["url"]).path),
            urlsplit(ep["url"]).path,
            urlsplit(ep["url"]).query,
        )
    )
    return ranked


async def _run_authenticated_business_probes(
    *,
    client: httpx.AsyncClient,
    target: str,
    allowed_app_prefixes: List[str],
    authenticated: bool,
    authenticated_endpoints: List[Dict[str, Any]],
    anonymous_endpoints: List[Dict[str, Any]],
    timeout_s: float,
    retries: int,
    run_dir: Path,
    raw_index: List[Dict[str, Any]],
    coverage: Dict[str, Dict[str, Any]],
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    seq_start: int,
    shared_unhealthy_scopes: set[str] | None = None,
) -> int:
    safe_authenticated_endpoints = [
        ep for ep in (authenticated_endpoints or [])
        if not is_session_destructive_endpoint(ep)
    ]

    plan_raw = build_authenticated_business_probe_plan(
        authenticated_endpoints=safe_authenticated_endpoints,
        anonymous_endpoints=anonymous_endpoints,
        max_targets=int(os.getenv("AUTHENTICATED_BUSINESS_PROBE_MAX_TARGETS", "20")),
    )

    plan = _filter_request_specs_by_app_scope(
        plan_raw,
        base_target=target,
        allowed_prefixes=allowed_app_prefixes,
    )

    if not plan:
        log("AUTH", "Authenticated business probes skipped: no safe in-scope targets")
        return seq_start

    log("AUTH", f"Authenticated business probes planned: raw={len(plan_raw)} filtered={len(plan)}")

    return await _run_plan_and_merge(
        client=client,
        plan=plan,
        timeout_s=timeout_s,
        retries=retries,
        run_dir=run_dir,
        raw_index=raw_index,
        coverage=coverage,
        seq_start=seq_start,
        authenticated=authenticated,
        confirmed_map=confirmed_map,
        informational_map=informational_map,
        false_positive_map=false_positive_map,
        request_failures=request_failures,
        shared_unhealthy_scopes=shared_unhealthy_scopes,
    )



def should_drop_low_value_endpoint(ep: Dict[str, Any]) -> bool:
    url = endpoint_url(ep).lower()
    path = urlsplit(url).path.lower()
    filename = path.split("/")[-1]

    if filename.endswith(LOW_VALUE_EXTS):
        return True
    if filename.startswith("readme"):
        return True
    if any(x in filename for x in LOW_VALUE_FILE_HINTS):
        return True

    return False

def _endpoint_bucket(url: str) -> str:
    p = urlsplit(url)
    path = p.path or "/"

    parts = []
    for seg in path.split("/"):
        if not seg:
            continue
        if re.fullmatch(r"\d+", seg):
            parts.append("{id}")
        elif re.fullmatch(r"[a-f0-9]{8,}", seg, re.I):
            parts.append("{token}")
        else:
            parts.append(seg)

    norm = "/" + "/".join(parts)
    return f"{p.scheme}://{p.netloc}{norm}"

def prune_discovered_endpoints(urls: List[str], max_endpoints: int = 30) -> List[str]:
    unique_urls: List[str] = []
    seen_exact = set()

    for url in urls:
        u = str(url or "").strip()
        if not u or u in seen_exact:
            continue
        seen_exact.add(u)
        unique_urls.append(u)

    def score(url: str) -> tuple[int, int, int, str]:
        parts = urlsplit(url)
        path = (parts.path or "/").lower()
        query = parts.query or ""

        priority = 0

        if any(x in path for x in (".mvc", ".do", ".action", ".php", "/api/", "/rest/", "/admin")):
            priority += 4

        if query:
            priority += 3

        if any(x in path for x in (
            "/setup",
            "/instructions",
            "/config",
            "/debug",
            "/actuator",
            "/upload",
            "/downloads",
            "/account",
            "/profile",
            "/user",
            "/order",
            "/payment",
            "/wallet",
            "/admin",
            "/api/",
            "/rest/",
        )):
            priority += 4

        if path.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
            priority -= 3

        depth = len([seg for seg in path.split("/") if seg])
        return (-priority, -int(bool(query)), depth, url)

    ranked = sorted(unique_urls, key=score)

    out: List[str] = []
    seen_buckets: Dict[str, int] = {}

    for url in ranked:
        bucket = _endpoint_bucket(url)
        count = seen_buckets.get(bucket, 0)

        has_query = bool(urlsplit(url).query)
        path = (urlsplit(url).path or "/").lower()
        dynamic_like = any(x in path for x in (".do", ".action", ".php", "/api/", "/rest/"))

        allow_per_bucket = 1
        if has_query or dynamic_like:
            allow_per_bucket = 2

        if count >= allow_per_bucket:
            continue

        seen_buckets[bucket] = count + 1
        out.append(url)

        if len(out) >= max_endpoints:
            break

    return out

def finding_group(finding: Dict[str, Any]) -> str:
    ftype = str(finding.get("type") or "")

    if ftype in INFORMATION_DISCLOSURE_TYPES:
        return "information_disclosure"

    if ftype in SECURITY_MISCONFIGURATION_TYPES:
        return "security_misconfiguration"

    return "other"


def _host_scope(url: str) -> str:
    if not url:
        return ""
    try:
        return normalize_url_for_dedup(host_scope_url(url))
    except Exception:
        return ""


def _finding_identity_url(f: Dict[str, Any]) -> str:
    evidence = f.get("evidence") or {}
    return (
        str(f.get("normalized_url") or "")
        or str(evidence.get("final_url") or "")
        or str((f.get("trigger") or {}).get("url") or "")
    )


def _same_identity(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    return _finding_identity_url(a) == _finding_identity_url(b)


def _is_concrete_exposure_type(ftype: str) -> bool:
    return ftype in {
        "PHPINFO_EXPOSURE",
        "HTTP_CONFIG_FILE_EXPOSURE",
        "LOG_VIEWER_EXPOSURE",
    }


def _drop_shadowed_false_positives(
    false_positive_map: Dict[str, Dict[str, Any]],
    concrete_findings: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    def _evidence_url(f: Dict[str, Any]) -> str:
        evidence = f.get("evidence") or {}
        return str(
            f.get("normalized_url")
            or evidence.get("final_url")
            or (f.get("trigger") or {}).get("url")
            or ""
        ).strip()

    def _route_path(url: str) -> str:
        try:
            path = urlsplit(str(url or "")).path or "/"
            path = re.sub(r"/+", "/", path)
            return path.rstrip("/") or "/"
        except Exception:
            return "/"

    def _base_error_route(path: str) -> str:
        p = str(path or "").strip()
        if not p:
            return "/"

        p = re.sub(r"/missing/[^/]+(?:\.[A-Za-z0-9]+)?$", "", p)
        p = re.sub(r"/__nonexistent_[^/]+$", "", p)
        p = re.sub(r"/[^/]*nonexistent[^/]*$", "", p)
        p = re.sub(r"/[^/]*missing[^/]*$", "", p)

        p = re.sub(r"/+", "/", p).rstrip("/")
        return p or "/"

    def _is_phpinfo_route(f: Dict[str, Any]) -> bool:
        u = (_evidence_url(f) + " " + str((f.get("trigger") or {}).get("url") or "")).lower()
        return any(tok in u for tok in ("phpinfo.php", "/phpinfo", "/info.php"))

    def _is_low_value_doc_route(f: Dict[str, Any]) -> bool:
        u = (_evidence_url(f) + " " + str((f.get("trigger") or {}).get("url") or "")).lower()
        return any(tok in u for tok in (
            "/instructions",
            "/readme",
            "/license",
            "/changelog",
            "/copying",
            "/authors",
            "/contributing",
            "/about",
            "/help",
            "/faq",
            ".md",
            ".rst",
            ".txt",
        ))

    def _is_synthetic_error_fp(f: Dict[str, Any]) -> bool:
        trigger = f.get("trigger") or {}
        name = str(trigger.get("name") or "").lower()
        subtype = str(f.get("subtype") or "")
        ftype = str(f.get("type") or "")

        if ftype != "HTTP_ERROR_INFO_EXPOSURE":
            return False
        if subtype not in {"stack_trace", "file_path", "db_error", "debug_error_page"}:
            return False

        trig_url = str(trigger.get("url") or "").lower()

        return (
            "notfound_" in name
            or "missing_" in name
            or "__nonexistent_" in trig_url
            or "/missing/" in trig_url
        )

    confirmed_by_base: Dict[tuple[str, str, str], Dict[str, Any]] = {}
    for f in concrete_findings or []:
        if not isinstance(f, dict):
            continue

        ftype = str(f.get("type") or "")
        subtype = str(f.get("subtype") or "")
        path = _base_error_route(_route_path(_evidence_url(f)))
        confirmed_by_base[(ftype, subtype, path)] = f

    for key, finding in list(false_positive_map.items()):
        if not isinstance(finding, dict):
            continue

        ftype = str(finding.get("type") or "")
        subtype = str(finding.get("subtype") or "")
        path = _route_path(_evidence_url(finding))
        base_path = _base_error_route(path)

        # phpinfo 계열 weak error false positive 제거
        if ftype == "HTTP_ERROR_INFO_EXPOSURE" and _is_phpinfo_route(finding):
            false_positive_map.pop(key, None)
            continue

        # instructions/readme/help/about 같은 문서성 페이지의 synthetic error fp 제거
        if ftype == "HTTP_ERROR_INFO_EXPOSURE" and _is_low_value_doc_route(finding):
            false_positive_map.pop(key, None)
            continue

        # 같은 base route에 concrete finding이 있으면 파생 synthetic fp 제거
        if (ftype, subtype, base_path) in confirmed_by_base and _is_synthetic_error_fp(finding):
            false_positive_map.pop(key, None)
            continue

        # 기존 rule 유지
        if ftype in {"DEFAULT_FILE_EXPOSED", "PHPINFO_EXPOSURE", "HTTP_CONFIG_FILE_EXPOSURE"}:
            if any(_same_identity(finding, concrete) for concrete in concrete_findings):
                false_positive_map.pop(key, None)
                continue

    return false_positive_map

def _bucket_identity_for_dedup(f: Dict[str, Any]) -> str:
    evidence = f.get("evidence") or {}

    final_url = str(
        f.get("normalized_url")
        or evidence.get("final_url")
        or (f.get("trigger") or {}).get("url")
        or ""
    ).strip()

    return "||".join([
        str(f.get("type") or ""),
        str(f.get("subtype") or ""),
        str(f.get("policy_object") or ""),
        str(f.get("root_cause_signature") or ""),
        str(f.get("template_fingerprint") or evidence.get("error_template_fingerprint") or ""),
        final_url,
    ])


def _reconcile_bucket_precedence(
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
) -> tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    confirmed_identities = {
        _bucket_identity_for_dedup(f): k
        for k, f in confirmed_map.items()
    }

    informational_identities = {
        _bucket_identity_for_dedup(f): k
        for k, f in informational_map.items()
    }

    # confirmed 와 semantic duplicate 인 informational 제거
    for key, finding in list(informational_map.items()):
        ident = _bucket_identity_for_dedup(finding)
        if ident in confirmed_identities:
            informational_map.pop(key, None)

    # confirmed 또는 informational 과 semantic duplicate 인 false_positive 제거
    surviving_info_identities = {
        _bucket_identity_for_dedup(f): k
        for k, f in informational_map.items()
    }

    for key, finding in list(false_positive_map.items()):
        ident = _bucket_identity_for_dedup(finding)
        if ident in confirmed_identities or ident in surviving_info_identities:
            false_positive_map.pop(key, None)

    return confirmed_map, informational_map, false_positive_map

def _consolidate_generic_vs_concrete(
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
) -> tuple[Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    concrete_confirmed = [
        f for f in confirmed_map.values()
        if _is_concrete_exposure_type(str(f.get("type") or ""))
    ]
    concrete_all = concrete_confirmed + [
        f for f in informational_map.values()
        if _is_concrete_exposure_type(str(f.get("type") or ""))
    ]

    for key, finding in list(confirmed_map.items()):
        if str(finding.get("type") or "") != "DEFAULT_FILE_EXPOSED":
            continue
        if any(_same_identity(finding, concrete) for concrete in concrete_all):
            confirmed_map.pop(key, None)

    for key, finding in list(informational_map.items()):
        if str(finding.get("type") or "") != "DEFAULT_FILE_EXPOSED":
            continue
        if any(_same_identity(finding, concrete) for concrete in concrete_all):
            informational_map.pop(key, None)

    for key, finding in list(informational_map.items()):
        if str(finding.get("type") or "") != "PHPINFO_EXPOSURE":
            continue

        if any(_same_identity(finding, concrete) for concrete in concrete_confirmed):
            upgraded = dict(finding)
            upgraded.setdefault("verification", {})
            upgraded["verification"]["verdict"] = "CONFIRMED"
            upgraded["verification"]["reason"] = (
                "Concrete phpinfo() diagnostic exposure directly observed on a reachable resource."
            )
            if str(upgraded.get("severity") or "Info") == "Info":
                upgraded["severity"] = "Medium"

            informational_map.pop(key, None)
            confirmed_map[key] = upgraded

    return confirmed_map, informational_map


def _normalize_type_cwe_consistency(candidate: Dict[str, Any]) -> Dict[str, Any]:
    ctype = str(candidate.get("type") or "")
    cwe = candidate.get("cwe")

    if ctype == "HTTP_ERROR_INFO_EXPOSURE":
        if cwe not in {"CWE-209", None}:
            candidate["cwe"] = "CWE-209"

    elif ctype == "HTTP_SYSTEM_INFO_EXPOSURE":
        if cwe not in {"CWE-497", None}:
            candidate["cwe"] = "CWE-497"

    elif ctype == "DIRECTORY_LISTING_ENABLED":
        candidate["cwe"] = "CWE-548"

    elif ctype == "DEFAULT_FILE_EXPOSED":
        if cwe not in {"CWE-552", None}:
            candidate["cwe"] = None
            candidate["cwe_mapping_status"] = OWASP_ONLY_NO_CWE_MAPPING
            candidate["cwe_mapping_reason"] = (
                "OWASP category is applicable, but the resource was not directly exposed "
                "with a precise single CWE mapping in the current response."
            )

    elif ctype == "HTTP_CONFIG_FILE_EXPOSURE":
        if cwe not in {"CWE-200", None}:
            candidate["cwe"] = "CWE-200"

    elif ctype == "PHPINFO_EXPOSURE":
        if cwe not in {"CWE-200", None}:
            candidate["cwe"] = "CWE-200"

    elif ctype == "LOG_VIEWER_EXPOSURE":
        if cwe not in {"CWE-532", None}:
            candidate["cwe"] = "CWE-532"

    elif ctype == "FILE_PATH_HANDLING_ANOMALY":
        if cwe not in {"CWE-200", None}:
            candidate["cwe"] = "CWE-200"

    elif ctype == "CORS_MISCONFIG":
        candidate["cwe"] = "CWE-942"

    elif ctype == "COOKIE_HTTPONLY_MISSING":
        candidate["cwe"] = "CWE-1004"

    elif ctype == "COOKIE_SECURE_MISSING":
        candidate["cwe"] = "CWE-614"

    elif ctype in {
        "COOKIE_SAMESITE_MISSING",
        "TRACE_ENABLED",
        "RISKY_HTTP_METHODS_ENABLED",
        "SECURITY_HEADERS_MISSING",
        "CLICKJACKING",
        "CSP_MISSING",
        "CONTENT_TYPE_SNIFFING",
        "REFERRER_POLICY_MISSING",
        "PERMISSIONS_POLICY_MISSING",
    }:
        if not candidate.get("cwe"):
            candidate["cwe_mapping_status"] = OWASP_ONLY_NO_CWE_MAPPING
            candidate["cwe_mapping_reason"] = (
                "OWASP category is applicable, but no precise single CWE mapping is used for this finding."
            )

    elif ctype in {"HTTPS_REDIRECT_MISSING", "HSTS_MISSING"}:
        candidate["cwe"] = "CWE-319"

    return candidate


def _sanitize_llm_title(candidate: Dict[str, Any], llm_title: str | None) -> str | None:
    if not llm_title:
        return None

    ctype = str(candidate.get("type") or "")
    subtype = str(candidate.get("subtype") or "")
    title = str(llm_title).strip()
    if not title:
        return None

    if ctype not in AMBIGUOUS_TYPES:
        return None

    allowed_title_keywords = {
        "HTTP_ERROR_INFO_EXPOSURE": {
            "stack_trace": {"stack", "trace", "exception"},
            "file_path": {"file", "path"},
            "db_error": {"database", "sql", "db"},
            "debug_error_page": {"debug", "error"},
        },
        "HTTP_SYSTEM_INFO_EXPOSURE": {
            "server_header": {"server", "header", "version"},
            "x_powered_by": {"x-powered-by", "powered", "php", "framework"},
            "via_header": {"via", "proxy"},
            "x_aspnet_version": {"aspnet", "asp.net", "version"},
            "x_aspnetmvc_version": {"aspnetmvc", "asp.net mvc", "mvc"},
            "product_version_in_body": {"version", "product", "server"},
            "framework_hint_in_body": {"framework", "hint"},
            "debug_marker_in_body": {"debug"},
            "internal_ip_in_body": {"internal", "ip", "network"},
        },
        "PHPINFO_EXPOSURE": {"phpinfo": {"phpinfo", "php", "diagnostic"}},
        "HTTP_CONFIG_FILE_EXPOSURE": {"exposed_config_file": {"config", "configuration", "file"}},
        "LOG_VIEWER_EXPOSURE": {"log_content": {"log"}},
        "FILE_PATH_HANDLING_ANOMALY": {"file_path_parameter": {"file", "path", "parameter"}},
    }

    by_type = allowed_title_keywords.get(ctype)
    if not by_type:
        return None

    expected = by_type.get(subtype)
    if not expected:
        return None

    title_l = title.lower()
    if any(token in title_l for token in expected):
        return title
    return None


def _sanitize_llm_exposed_information(candidate: Dict[str, Any], raw_items: List[Any]) -> List[str] | None:
    if not isinstance(raw_items, list) or not raw_items:
        return None

    ctype = str(candidate.get("type") or "")
    subtype = str(candidate.get("subtype") or "")
    if ctype not in AMBIGUOUS_TYPES:
        return None

    cleaned = [str(x).strip() for x in raw_items if str(x).strip()]
    if not cleaned:
        return None

    def _contains_any(text: str, needles: set[str]) -> bool:
        t = text.lower()
        return any(n in t for n in needles)

    if ctype == "HTTP_ERROR_INFO_EXPOSURE":
        if subtype == "file_path":
            keep: List[str] = []
            reject_tokens = {
                "server version",
                "server header",
                "apache/",
                "nginx/",
                "x-powered-by",
                "php version",
                "framework",
                "debug hint",
                "internal ip",
                "database error",
                "sql",
                "stack trace",
            }

            for item in cleaned:
                item_l = item.lower()

                has_path_marker = (
                    "file path" in item_l
                    or "path:" in item_l
                    or "file:" in item_l
                    or "/" in item
                    or "\\" in item
                )

                if not has_path_marker:
                    continue
                if _contains_any(item_l, reject_tokens):
                    continue

                keep.append(item)

            return keep or None

        if subtype == "stack_trace":
            keep = [item for item in cleaned if _contains_any(item, {"stack", "trace", "exception"})]
            return keep or None

        if subtype == "db_error":
            keep = [item for item in cleaned if _contains_any(item, {"database", "sql", "mysql", "oracle", "postgres", "sqlite"})]
            return keep or None

        if subtype == "debug_error_page":
            keep = [item for item in cleaned if _contains_any(item, {"debug", "error"})]
            return keep or None

        return None

    if ctype == "HTTP_SYSTEM_INFO_EXPOSURE":
        subtype_rules = {
            "server_header": {"server", "header", "version"},
            "x_powered_by": {"x-powered-by", "php", "powered"},
            "via_header": {"via"},
            "x_aspnet_version": {"aspnet", "asp.net"},
            "x_aspnetmvc_version": {"aspnetmvc", "asp.net mvc", "mvc"},
            "product_version_in_body": {"version", "product", "server"},
            "framework_hint_in_body": {"framework"},
            "debug_marker_in_body": {"debug"},
            "internal_ip_in_body": {"internal ip", "internal", "ip"},
        }

        expected = subtype_rules.get(subtype)
        if not expected:
            return None

        keep = [item for item in cleaned if _contains_any(item, expected)]
        return keep or None

    if ctype == "PHPINFO_EXPOSURE":
        keep = [item for item in cleaned if _contains_any(item, {"php", "phpinfo", "runtime", "module"})]
        return keep or None

    if ctype == "HTTP_CONFIG_FILE_EXPOSURE":
        keep = [item for item in cleaned if _contains_any(item, {"config", "database", "password", "secret", "key", "connection"})]
        return keep or None

    if ctype == "LOG_VIEWER_EXPOSURE":
        keep = [item for item in cleaned if _contains_any(item, {"log", "request", "entry"})]
        return keep or None

    if ctype == "FILE_PATH_HANDLING_ANOMALY":
        keep = [item for item in cleaned if _contains_any(item, {"file", "path", "parameter", "include", "template"})]
        return keep or None

    return None


async def llm_judge_if_enabled(candidate: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
    candidate = _normalize_type_cwe_consistency(candidate)

    if os.getenv("LLM_MODE", "off").lower() != "on":
        return candidate

    if str(candidate.get("type") or "") not in AMBIGUOUS_TYPES:
        return candidate

    from agent.llm_client import judge_candidate, normalize_exposure_with_llm

    locked_fields = {
        "type": candidate.get("type"),
        "family": candidate.get("family"),
        "subtype": candidate.get("subtype"),
        "scope_hint": candidate.get("scope_hint"),
        "policy_object": candidate.get("policy_object"),
        "root_cause_signature": candidate.get("root_cause_signature"),
        "template_fingerprint": candidate.get("template_fingerprint"),
    }

    original_title = candidate.get("title")
    original_severity = candidate.get("severity")
    original_cwe = candidate.get("cwe")
    original_exposed = list(candidate.get("exposed_information") or [])

    try:
        judged = await asyncio.to_thread(judge_candidate, candidate, snapshot)
    except Exception as e:
        log("LLM", f"Judge failed, falling back to rule-based result: {type(e).__name__}: {e}")
        candidate.setdefault("verification", {})
        if not candidate["verification"].get("verdict"):
            candidate["verification"]["verdict"] = "INCONCLUSIVE"
            candidate["verification"]["reason"] = f"LLM judge failed: {type(e).__name__}"
        return candidate

    candidate["llm_judgement"] = judged

    verdict = judged.get("verdict")
    if verdict in {"CONFIRMED", "INCONCLUSIVE", "FALSE_POSITIVE", "INFORMATIONAL"}:
        normalized_verdict = "INFORMATIONAL" if verdict == "INCONCLUSIVE" else verdict
        candidate["verification"] = {
            "verdict": normalized_verdict,
            "reason": judged.get("reason", ""),
        }

    sanitized_title = _sanitize_llm_title(candidate, judged.get("title"))

    candidate_type = str(candidate.get("type") or "")
    llm_title_raw = str(judged.get("title") or "").strip().lower()

    negative_title_markers = (
        "not disclosed",
        "not exposed",
        "no exposure",
        "not vulnerable",
        "not found",
        "does not disclose",
        "does not expose",
    )

    if candidate_type in {"HTTP_CONFIG_FILE_EXPOSURE", "HTTP_ERROR_INFO_EXPOSURE"}:
        if any(tok in llm_title_raw for tok in negative_title_markers):
            candidate["title"] = original_title
        else:
            candidate["title"] = sanitized_title or original_title
    else:
        candidate["title"] = sanitized_title or original_title

    if judged.get("severity") in {"Info", "Low", "Medium", "High"}:
        candidate["severity"] = judged["severity"]
    else:
        candidate["severity"] = original_severity

    allowed_cwe_by_type = {
        "HTTP_ERROR_INFO_EXPOSURE": {"CWE-209", None},
        "HTTP_SYSTEM_INFO_EXPOSURE": {"CWE-497", None},
        "DIRECTORY_LISTING_ENABLED": {"CWE-548"},
        "DEFAULT_FILE_EXPOSED": {"CWE-552", None},
        "HTTP_CONFIG_FILE_EXPOSURE": {"CWE-200", None},
        "PHPINFO_EXPOSURE": {"CWE-200", None},
        "LOG_VIEWER_EXPOSURE": {"CWE-532", None},
        "FILE_PATH_HANDLING_ANOMALY": {"CWE-200", None},
        "CORS_MISCONFIG": {"CWE-942"},
        "COOKIE_HTTPONLY_MISSING": {"CWE-1004"},
        "COOKIE_SECURE_MISSING": {"CWE-614"},
        "COOKIE_SAMESITE_MISSING": {None},
        "SECURITY_HEADERS_MISSING": {None},
        "TRACE_ENABLED": {None},
        "RISKY_HTTP_METHODS_ENABLED": {None},
        "HTTPS_REDIRECT_MISSING": {"CWE-319"},
        "HSTS_MISSING": {"CWE-319"},
    }

    judged_cwe = judged.get("cwe")
    allowed = allowed_cwe_by_type.get(candidate_type)

    if allowed is None:
        if judged_cwe is not None or "cwe" in judged:
            candidate["cwe"] = judged_cwe
    else:
        if judged_cwe in allowed:
            candidate["cwe"] = judged_cwe
        else:
            candidate["cwe"] = original_cwe

    raw_exposed = judged.get("exposed_information", [])

    def _dedup_keep_order(items: List[Any], limit: int = 6) -> List[str]:
        out: List[str] = []
        seen = set()
        for item in items or []:
            s = str(item or "").strip()
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
            if len(out) >= limit:
                break
        return out

    def _config_priority(text: Any) -> int:
        s = str(text or "").strip()
        if not s:
            return 0
        s_l = s.lower()

        if "empty in this case" in s_l:
            return 0
        if "default security level" in s_l:
            return 0
        if "recaptcha public and private keys" in s_l and "empty" in s_l:
            return 0

        if s_l in {
            "database password disclosed",
            "database username disclosed",
            "database user disclosed",
            "database name disclosed",
            "database host disclosed",
            "database server disclosed",
            "application configuration details disclosed",
            "sensitive secret material disclosed",
            "api or access key material disclosed",
            "connection string disclosed",
        }:
            return 1

        if any(tok in s_l for tok in (
            "database password:",
            "db_password =",
            "connection string:",
            "api key:",
            "access key:",
            "secret:",
            "token:",
            "private key",
        )):
            return 5

        if any(tok in s_l for tok in (
            "database server:",
            "database host:",
            "database name:",
            "database user:",
            "database username:",
            "db_host =",
            "db_name =",
            "db_user =",
        )):
            return 4

        if " = " in s or ": " in s:
            return 3

        return 2

    def _pick_best_config_items(original_items: List[Any], judged_items: List[Any]) -> List[str]:
        merged: List[str] = []
        seen = set()

        for source_items in (judged_items or [], original_items or []):
            for item in source_items:
                s = str(item or "").strip()
                if not s or s in seen:
                    continue
                if _config_priority(s) <= 0:
                    continue
                seen.add(s)
                merged.append(s)

        merged.sort(key=_config_priority, reverse=True)

        has_concrete = any(_config_priority(x) >= 3 for x in merged)
        if has_concrete:
            merged = [x for x in merged if _config_priority(x) >= 3]

        out: List[str] = []
        seen2 = set()
        for item in merged:
            if item in seen2:
                continue
            seen2.add(item)
            out.append(item)
            if len(out) >= 6:
                break

        return out

    def _error_priority(text: Any) -> int:
        s = str(text or "").strip()
        if not s:
            return 0
        s_l = s.lower()

        if any(tok in s_l for tok in (
            "server header",
            "x-powered-by",
            "apache/",
            "nginx/",
            "php/8",
            "php/7",
            "server version",
            "apache server version",
            "x-powered-by header",
        )):
            return 0

        if s_l in {"fatal error", "stack trace", "exception", "stack trace: fatal error"}:
            return 1

        if any(tok in s for tok in ("/var/", "/usr/", "/app/", "\\", ".php", ".py", ".java")):
            return 5

        if any(tok in s_l for tok in (
            "traceback",
            "exception",
            "warning",
            "fatal error",
            "sql",
            "oracle",
            "mysql",
            "postgres",
            "sqlite",
            "file path",
            "absolute file",
        )):
            return 4

        if ":" in s:
            return 3

        return 2

    def _normalize_error_item(text: str) -> str:
        s = str(text or "").strip()
        s_l = s.lower()

        if any(tok in s_l for tok in ("warning", "fatal error", "deprecated")) and "path" not in s_l:
            return "PHP warning/fatal error message exposed"

        return s

    def _pick_best_error_items(original_items: List[Any], judged_items: List[Any]) -> List[str]:
        original_clean = [str(x).strip() for x in (original_items or []) if str(x).strip()]
        judged_clean = [str(x).strip() for x in (judged_items or []) if str(x).strip()]

        original_clean = [x for x in original_clean if _error_priority(x) > 0]
        judged_clean = [x for x in judged_clean if _error_priority(x) > 0]

        best_original = sorted(original_clean, key=_error_priority, reverse=True)
        best_judged = sorted(judged_clean, key=_error_priority, reverse=True)

        if best_original and best_judged:
            chosen_source = best_original if _error_priority(best_original[0]) >= _error_priority(best_judged[0]) else best_judged
        elif best_original:
            chosen_source = best_original
        else:
            chosen_source = best_judged

        normalized = [_normalize_error_item(x) for x in chosen_source]
        normalized = [x for x in normalized if _error_priority(x) > 0]
        normalized = [
            x for x in normalized
            if x.lower() not in {"full stack trace", "full stack trace showing call hierarchy", "stack trace: fatal error"}
        ]

        out: List[str] = []
        seen = set()
        for item in normalized:
            if item in seen:
                continue
            seen.add(item)
            out.append(item)
            if len(out) >= 4:
                break

        if not out:
            for item in original_clean:
                norm = _normalize_error_item(item)
                if _error_priority(norm) <= 0:
                    continue
                if norm in seen:
                    continue
                seen.add(norm)
                out.append(norm)
                if len(out) >= 4:
                    break

        return out

    if candidate_type == "HTTP_CONFIG_FILE_EXPOSURE":
        generic_only_exposure = {
            "Application configuration details disclosed",
            "Database password disclosed",
            "Database username disclosed",
            "Database user disclosed",
            "Database name disclosed",
            "Database host disclosed",
            "Database server disclosed",
            "API or access key material disclosed",
            "Sensitive secret material disclosed",
            "Connection string disclosed",
        }

        picked = _pick_best_config_items(
            original_exposed,
            raw_exposed if isinstance(raw_exposed, list) else [],
        )

        picked_set = {str(x).strip() for x in picked if str(x).strip()}
        picked_generic_only = bool(picked_set) and picked_set.issubset(generic_only_exposure)

        original_set = {str(x).strip() for x in original_exposed if str(x).strip()}
        original_generic_only = bool(original_set) and original_set.issubset(generic_only_exposure)

        if picked_generic_only and not original_generic_only:
            candidate["exposed_information"] = _dedup_keep_order(original_exposed, limit=6)
        else:
            candidate["exposed_information"] = picked

        candidate["severity_reason"] = []

    elif candidate_type == "HTTP_ERROR_INFO_EXPOSURE":
        candidate["exposed_information"] = _pick_best_error_items(
            original_exposed,
            raw_exposed if isinstance(raw_exposed, list) else [],
        )
        candidate["severity_reason"] = []

    else:
        normalize_types = {
            "DEFAULT_FILE_EXPOSED",
            "OPEN_REDIRECT",
            "PHPINFO_EXPOSURE",
            "LOG_VIEWER_EXPOSURE",
            "FILE_PATH_HANDLING_ANOMALY",
        }

        sanitized_exposed = _sanitize_llm_exposed_information(candidate, raw_exposed)

        if sanitized_exposed is not None:
            candidate["exposed_information_raw"] = raw_exposed
            candidate["exposed_information"] = sanitized_exposed[:4]
            candidate["severity_reason"] = []

        elif isinstance(raw_exposed, list) and raw_exposed:
            if candidate_type not in normalize_types:
                candidate["exposed_information"] = original_exposed
                candidate["severity_reason"] = []
            else:
                candidate["exposed_information_raw"] = raw_exposed
                try:
                    normalized = await asyncio.to_thread(
                        normalize_exposure_with_llm,
                        raw_exposed,
                        judged.get("severity"),
                        judged.get("title"),
                    )

                    normalized_items = normalized.get("exposed_information_normalized", [])
                    if isinstance(normalized_items, list) and normalized_items:
                        candidate["exposed_information"] = [
                            str(x).strip() for x in normalized_items if str(x).strip()
                        ][:4]
                    else:
                        candidate["exposed_information"] = original_exposed

                    severity_reason = normalized.get("severity_reason", [])
                    candidate["severity_reason"] = severity_reason if isinstance(severity_reason, list) else []

                except Exception as e:
                    log("LLM", f"Exposure normalization failed, using original evidence: {type(e).__name__}: {e}")
                    candidate["exposed_information"] = original_exposed
                    candidate["severity_reason"] = []
        else:
            candidate["exposed_information"] = original_exposed
            candidate["severity_reason"] = []

    if not candidate.get("exposed_information"):
        candidate["exposed_information"] = _dedup_keep_order(original_exposed, limit=6)

    if judged.get("safe_verification_requests"):
        candidate["llm_suggested_verification_requests"] = judged["safe_verification_requests"]

    if judged.get("cwe_mapping_status") is not None:
        candidate["cwe_mapping_status"] = judged["cwe_mapping_status"]

    if judged.get("cwe_mapping_reason") is not None:
        candidate["cwe_mapping_reason"] = judged["cwe_mapping_reason"]

    if judged.get("additional_cwe_candidate") is not None:
        candidate["additional_cwe_candidate"] = judged["additional_cwe_candidate"]

    if judged.get("additional_cwe_reason") is not None:
        candidate["additional_cwe_reason"] = judged["additional_cwe_reason"]

    for k, v in locked_fields.items():
        candidate[k] = v

    candidate = _normalize_type_cwe_consistency(candidate)
    return candidate


def init_coverage() -> Dict[str, Dict[str, Any]]:
    return {
        "cwe_209": {"attempted": False, "candidate_count": 0, "confirmed_count": 0, "assessment": "not_attempted"},
        "cwe_497": {"attempted": False, "candidate_count": 0, "confirmed_count": 0, "assessment": "not_attempted"},
        "cwe_548": {"attempted": False, "candidate_count": 0, "confirmed_count": 0, "assessment": "not_attempted"},
        "cwe_552": {"attempted": False, "candidate_count": 0, "confirmed_count": 0, "assessment": "not_attempted"},
        "cwe_942": {"attempted": False, "candidate_count": 0, "confirmed_count": 0, "assessment": "not_attempted"},
        "cwe_1004": {
            "attempted": False,
            "set_cookie_observed": False,
            "candidate_count": 0,
            "confirmed_count": 0,
            "assessment": "not_attempted",
        },
        "cwe_614": {
            "attempted": False,
            "set_cookie_observed": False,
            "candidate_count": 0,
            "confirmed_count": 0,
            "assessment": "not_attempted",
        },
        "cwe_319": {"attempted": False, "candidate_count": 0, "confirmed_count": 0, "assessment": "not_attempted"},
    }


def mark_attempted_for_spec(spec: RequestSpec, coverage: Dict[str, Dict[str, Any]]) -> None:
    name = (spec.name or "").lower()
    method = (spec.method or "").upper()
    url = (spec.url or "").lower()

    headers_lc = {str(k).lower(): str(v) for k, v in (spec.headers or {}).items()}
    has_origin = "origin" in headers_lc

    if (
        "notfound" in name
        or "bad" in name
        or "path_" in name
        or "qs_" in name
        or "qsx_" in name
        or "%zz" in url
        or "|" in url
        or method in {"TRACE", "PROPFIND", "SEARCH", "BREW", "FOO", "PATCH", "OPTIONS"}
    ):
        coverage["cwe_209"]["attempted"] = True

    if method in {"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "PROPFIND", "SEARCH", "BREW", "FOO", "PATCH"}:
        coverage["cwe_497"]["attempted"] = True

    if "dir_list_" in name:
        coverage["cwe_548"]["attempted"] = True

    if "default_file_" in name or "resource_probe_" in name or "resource_head_" in name:
        coverage["cwe_552"]["attempted"] = True

    if (
        has_origin
        or spec.origin is not None
        or spec.probe == "cors"
        or "cors_" in name
        or "access-control-request-method" in headers_lc
    ):
        coverage["cwe_942"]["attempted"] = True

    if method in {"GET", "HEAD"}:
        coverage["cwe_1004"]["attempted"] = True
        coverage["cwe_614"]["attempted"] = True
        coverage["cwe_319"]["attempted"] = True


def update_cookie_observation(snapshot: Dict[str, Any], coverage: Dict[str, Dict[str, Any]]) -> None:
    if snapshot.get("set_cookie_present"):
        coverage["cwe_1004"]["set_cookie_observed"] = True
        coverage["cwe_614"]["set_cookie_observed"] = True
        return

    cookie_objects = snapshot.get("set_cookie_objects") or []
    if cookie_objects:
        coverage["cwe_1004"]["set_cookie_observed"] = True
        coverage["cwe_614"]["set_cookie_observed"] = True
        return

    if snapshot.get("cookie_jar_changed") or snapshot.get("cookie_jar_observed"):
        coverage["cwe_1004"]["set_cookie_observed"] = True
        coverage["cwe_614"]["set_cookie_observed"] = True

def update_coverage_from_candidate(candidate: Dict[str, Any], coverage: Dict[str, Dict[str, Any]]) -> None:
    cwe = candidate.get("cwe")
    ctype = candidate.get("type")

    if cwe == "CWE-209" or ctype == "HTTP_ERROR_INFO_EXPOSURE":
        coverage["cwe_209"]["candidate_count"] += 1
    elif cwe == "CWE-497" or ctype == "HTTP_SYSTEM_INFO_EXPOSURE":
        coverage["cwe_497"]["candidate_count"] += 1
    elif cwe == "CWE-548" or ctype == "DIRECTORY_LISTING_ENABLED":
        coverage["cwe_548"]["candidate_count"] += 1
    elif cwe == "CWE-552" or ctype == "DEFAULT_FILE_EXPOSED":
        coverage["cwe_552"]["candidate_count"] += 1
    elif cwe == "CWE-942" or ctype == "CORS_MISCONFIG":
        coverage["cwe_942"]["candidate_count"] += 1
    elif cwe == "CWE-1004" or ctype == "COOKIE_HTTPONLY_MISSING":
        coverage["cwe_1004"]["candidate_count"] += 1
    elif cwe == "CWE-614" or ctype == "COOKIE_SECURE_MISSING":
        coverage["cwe_614"]["candidate_count"] += 1
    elif cwe == "CWE-319" or ctype in {"HTTPS_REDIRECT_MISSING", "HSTS_MISSING"}:
        coverage["cwe_319"]["candidate_count"] += 1


def add_confirmed_counts_to_coverage(results: Dict[str, Any], coverage: Dict[str, Dict[str, Any]]) -> None:
    for f in results.get("findings_confirmed", []):
        cwe = f.get("cwe")
        ctype = f.get("type")

        if cwe == "CWE-209" or ctype == "HTTP_ERROR_INFO_EXPOSURE":
            coverage["cwe_209"]["confirmed_count"] += 1
        elif cwe == "CWE-497" or ctype == "HTTP_SYSTEM_INFO_EXPOSURE":
            coverage["cwe_497"]["confirmed_count"] += 1
        elif cwe == "CWE-548" or ctype == "DIRECTORY_LISTING_ENABLED":
            coverage["cwe_548"]["confirmed_count"] += 1
        elif cwe == "CWE-552" or ctype == "DEFAULT_FILE_EXPOSED":
            coverage["cwe_552"]["confirmed_count"] += 1
        elif cwe == "CWE-942" or ctype == "CORS_MISCONFIG":
            coverage["cwe_942"]["confirmed_count"] += 1
        elif cwe == "CWE-1004" or ctype == "COOKIE_HTTPONLY_MISSING":
            coverage["cwe_1004"]["confirmed_count"] += 1
        elif cwe == "CWE-614" or ctype == "COOKIE_SECURE_MISSING":
            coverage["cwe_614"]["confirmed_count"] += 1
        elif cwe == "CWE-319" or ctype in {"HTTPS_REDIRECT_MISSING", "HSTS_MISSING"}:
            coverage["cwe_319"]["confirmed_count"] += 1

def finalize_coverage_assessment(coverage: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    for key, item in coverage.items():
        attempted = item.get("attempted", False)
        candidate_count = item.get("candidate_count", 0)
        confirmed_count = item.get("confirmed_count", 0)

        if not attempted:
            item["assessment"] = "not_attempted"
            continue

        if key in {"cwe_1004", "cwe_614"} and item.get("set_cookie_observed") is False:
            item["assessment"] = "not_yet_sufficiently_validated"
            continue

        if confirmed_count > 0:
            item["assessment"] = "confirmed"
        elif candidate_count > 0:
            item["assessment"] = "observed_but_not_confirmed"
        else:
            item["assessment"] = "not_observed_in_current_scope"

    return coverage

def _decode_response_preview(resp: httpx.Response, limit: int = 65535) -> tuple[str, bool, str | None, str | None]:
    try:
        body = resp.content[:limit]
        encoding = resp.encoding or "utf-8"
        try:
            return body.decode(encoding, errors="replace"), True, None, None
        except Exception:
            return body.decode("utf-8", errors="replace"), True, None, None
    except Exception as e:
        return "", False, f"{type(e).__name__}: {e}", type(e).__name__


async def _execute_access_control_replay_plan(
    *,
    client: httpx.AsyncClient,
    plan: List[RequestSpec],
    timeout_s: float,
    retries: int,
    run_dir: Path,
    raw_index: List[Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    seq_start: int,
) -> int:
    if not plan:
        return seq_start

    raw_dir = run_dir / "raw"
    seq = seq_start

    for spec in plan:
        request_body_text = _request_body_text_for_replay(spec)

        response, last_error = await _send_replay_request(
            client=client,
            spec=spec,
            retries=retries,
        )

        if response is not None:
            snapshot = _build_replay_success_snapshot(
                spec=spec,
                response=response,
                request_body_text=request_body_text,
            )
        else:
            snapshot = _build_replay_error_snapshot(
                spec=spec,
                request_body_text=request_body_text,
                last_error=last_error,
            )

        raw_path = save_raw_capture(raw_dir, seq, spec, snapshot)

        raw_index.append(
            _build_replay_raw_index_entry(
                seq=seq,
                spec=spec,
                raw_path=raw_path,
                snapshot=snapshot,
                request_body_text=request_body_text,
            )
        )

        if _should_record_replay_failure(snapshot):
            request_failures.append(
                _build_replay_failure_entry(
                    spec=spec,
                    raw_path=raw_path,
                    snapshot=snapshot,
                )
            )

        seq += 1

    return seq

def _request_body_text_for_replay(spec: RequestSpec) -> str:
    if spec.body is None:
        return ""
    if isinstance(spec.body, bytes):
        return spec.body.decode("utf-8", errors="replace")
    return str(spec.body)


async def _send_replay_request(
    *,
    client: httpx.AsyncClient,
    spec: RequestSpec,
    retries: int,
) -> tuple[Any | None, Exception | None]:
    last_error: Exception | None = None
    response = None

    def _preferred_cookie_path(url: str) -> str:
        path = urlsplit(str(url or "")).path or "/"
        segs = [s for s in path.split("/") if s]
        if segs:
            return "/" + segs[0]
        return "/"

    def _parse_manual_auth_cookie_pairs() -> Dict[str, str]:
        raw = str(os.getenv("MANUAL_AUTH_COOKIE", "") or "").strip()
        out: Dict[str, str] = {}

        if not raw:
            return out

        for part in raw.split(";"):
            piece = str(part or "").strip()
            if not piece or "=" not in piece:
                continue
            k, v = piece.split("=", 1)
            name = k.strip()
            value = v.strip()
            if name:
                out[name] = value
        return out

    def _clear_cookie_name_from_client(cookie_name: str) -> None:
        jar = getattr(client.cookies, "jar", None)
        if jar is None:
            return

        to_clear: List[tuple[Any, Any, Any]] = []
        try:
            for c in list(jar):
                if str(getattr(c, "name", "") or "").lower() == cookie_name.lower():
                    to_clear.append((
                        getattr(c, "domain", None),
                        getattr(c, "path", None),
                        getattr(c, "name", None),
                    ))
        except Exception:
            return

        for domain, path, name in to_clear:
            try:
                jar.clear(domain, path, name)
            except Exception:
                pass

    def _sanitize_headers_and_reseed_session(url: str, headers: Dict[str, Any]) -> Dict[str, str]:
        safe_headers: Dict[str, str] = {}
        for k, v in (headers or {}).items():
            ks = str(k or "").strip()
            if not ks:
                continue
            if ks.lower() == "cookie":
                continue
            safe_headers[ks] = "" if v is None else str(v)

        manual_pairs = _parse_manual_auth_cookie_pairs()
        preferred_path = _preferred_cookie_path(url)
        host = (urlsplit(url).hostname or "").strip() or None

        for cookie_name, cookie_value in manual_pairs.items():
            if cookie_name.lower() != "jsessionid":
                continue

            _clear_cookie_name_from_client(cookie_name)

            try:
                if host:
                    client.cookies.set(
                        cookie_name,
                        cookie_value,
                        domain=host,
                        path=preferred_path,
                    )
                else:
                    client.cookies.set(
                        cookie_name,
                        cookie_value,
                        path=preferred_path,
                    )
            except Exception:
                pass

        return safe_headers

    for _attempt in range(max(1, retries + 1)):
        try:
            safe_headers = _sanitize_headers_and_reseed_session(
                spec.url,
                dict(spec.headers or {}),
            )

            response = await client.request(
                spec.method,
                spec.url,
                headers=safe_headers,
                content=spec.body,
                follow_redirects=True,
            )
            last_error = None
            break
        except Exception as e:
            last_error = e

    return response, last_error

def _build_replay_success_snapshot(
    *,
    spec: RequestSpec,
    response: httpx.Response,
    request_body_text: str,
) -> Dict[str, Any]:
    set_cookie_values: List[str] = []
    try:
        set_cookie_values = response.headers.get_list("set-cookie")
    except Exception:
        sc = response.headers.get("set-cookie")
        if sc:
            set_cookie_values = [sc]

    body_text, body_read_ok, body_error, body_error_class = _decode_response_preview(response)
    snap_headers = dict(response.headers.items())

    return {
        "ok": True,
        "headers_received": True,
        "body_read_ok": body_read_ok,
        "error": body_error,
        "error_class": body_error_class,
        "error_phase": "body" if not body_read_ok and body_error else None,
        "status_code": response.status_code,
        "reason_phrase": getattr(response, "reason_phrase", None),
        "final_url": str(response.url),
        "headers": snap_headers,
        "content_type": response.headers.get("content-type"),
        "set_cookie_present": bool(set_cookie_values),
        "set_cookie_objects": set_cookie_values,
        "body_text": body_text,
        "body_snippet": body_text[:8000],
        "body_len": len(body_text),
        "redirect_chain": [
            {
                "url": str(h.url),
                "status_code": h.status_code,
                "headers": dict(h.headers.items()),
            }
            for h in response.history
        ],
        "request": {
            "method": str(spec.method).upper(),
            "url": str(spec.url),
            "headers": dict(spec.headers or {}),
            "body_text": request_body_text,
            "body_len": len(request_body_text),
            "has_body": bool(request_body_text),
        },
        "actual_request": {
            "method": str(getattr(response.request, "method", spec.method)).upper(),
            "url": str(getattr(response.request, "url", spec.url)),
            "headers": dict(getattr(response.request, "headers", {}) or {}),
            "body_text": request_body_text,
            "body_len": len(request_body_text),
            "has_body": bool(request_body_text),
        },
    }


def _build_replay_error_snapshot(
    *,
    spec: RequestSpec,
    request_body_text: str,
    last_error: Exception | None,
) -> Dict[str, Any]:
    return {
        "ok": False,
        "headers_received": False,
        "body_read_ok": False,
        "status_code": None,
        "reason_phrase": None,
        "final_url": spec.url,
        "headers": {},
        "content_type": None,
        "set_cookie_present": False,
        "set_cookie_objects": [],
        "body_text": "",
        "body_snippet": "",
        "body_len": 0,
        "redirect_chain": [],
        "error": f"{type(last_error).__name__}: {last_error}" if last_error else "unknown_error",
        "error_class": type(last_error).__name__ if last_error else None,
        "error_phase": "request",
        "request": {
            "method": str(spec.method).upper(),
            "url": str(spec.url),
            "headers": dict(spec.headers or {}),
            "body_text": request_body_text,
            "body_len": len(request_body_text),
            "has_body": bool(request_body_text),
        },
        "actual_request": {
            "method": str(spec.method).upper(),
            "url": str(spec.url),
            "headers": dict(spec.headers or {}),
            "body_text": request_body_text,
            "body_len": len(request_body_text),
            "has_body": bool(request_body_text),
        },
    }


def _build_replay_raw_index_entry(
    *,
    seq: int,
    spec: RequestSpec,
    raw_path: Path,
    snapshot: Dict[str, Any],
    request_body_text: str,
) -> Dict[str, Any]:
    return {
        "seq": seq,
        "request_name": spec.name,
        "method": spec.method,
        "url": spec.url,
        "raw_ref": str(raw_path),
        "status_code": snapshot.get("status_code"),
        "ok": snapshot.get("ok"),
        "source": spec.source,
        "family": spec.family,
        "scope_key": spec.url,
        "comparison_group": spec.comparison_group,
        "auth_state": spec.auth_state,
        "replay_key": spec.replay_key,
        "replay_source_url": spec.replay_source_url,
        "replay_source_state": spec.replay_source_state,
        "replay_priority": spec.replay_priority,
        "expected_signal": spec.expected_signal,
        "mutation_class": spec.mutation_class,
        "content_type": str(snapshot.get("content_type") or ""),
        "headers": dict(snapshot.get("headers") or {}),
        "body_len": int(snapshot.get("body_len") or 0),
        "body_text": str(snapshot.get("body_text") or ""),
        "body_snippet": str(snapshot.get("body_snippet") or ""),
        "final_url": str(snapshot.get("final_url") or ""),
        "request_headers": dict(spec.headers or {}),
        "request_body_len": len(request_body_text),
        "request_body_present": bool(request_body_text),
    }


def _build_replay_failure_entry(
    *,
    spec: RequestSpec,
    raw_path: Path,
    snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    snapshot_headers = snapshot.get("headers") or {}
    if not isinstance(snapshot_headers, dict):
        snapshot_headers = {}

    return {
        "trigger": spec.name,
        "method": spec.method,
        "url": spec.url,
        "error": snapshot.get("error"),
        "error_class": snapshot.get("error_class"),
        "error_phase": snapshot.get("error_phase"),
        "status_code": snapshot.get("status_code"),
        "final_url": snapshot.get("final_url"),
        "headers_received": bool(snapshot.get("headers_received")) or bool(snapshot_headers),
        "body_read_ok": snapshot.get("body_read_ok"),
        "content_type": snapshot.get("content_type"),
        "raw_ref": str(raw_path),
        "source": spec.source,
        "family": spec.family,
        "auth_state": spec.auth_state,
    }


def _should_record_replay_failure(snapshot: Dict[str, Any]) -> bool:
    return (not snapshot.get("ok")) or bool(snapshot.get("error"))

def _classify_status_bucket(
    status_code: Any,
    *,
    include_redirect_bucket: bool = False,
) -> str:
    if status_code in {200, 201, 202, 204}:
        return "2xx-success"
    if include_redirect_bucket and status_code in {301, 302, 303, 307, 308}:
        return "3xx-redirect"
    if status_code in {400, 401, 403, 404, 405, 409, 422}:
        return "4xx-client"
    if status_code is None:
        return "none"
    if isinstance(status_code, int) and status_code >= 500:
        return "5xx-server"
    return f"other:{status_code}"


async def _execute_dual_access_control_replay_plans(
    *,
    authenticated_client: httpx.AsyncClient,
    anonymous_client_limits: httpx.Limits,
    anonymous_client_timeout: httpx.Timeout,
    anonymous_follow_redirects: bool,
    auth_plan: List[Any],
    anon_plan: List[Any],
    timeout_s: float,
    retries: int,
    run_dir: Path,
    raw_index: List[Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    seq_start: int,
) -> int:
    next_seq = seq_start

    if auth_plan:
        next_seq = await _execute_access_control_replay_plan(
            client=authenticated_client,
            plan=auth_plan,
            timeout_s=timeout_s,
            retries=retries,
            run_dir=run_dir,
            raw_index=raw_index,
            request_failures=request_failures,
            seq_start=next_seq,
        )

    if anon_plan:
        async with _build_anonymous_replay_client(
            limits=anonymous_client_limits,
            client_timeout=anonymous_client_timeout,
            follow_redirects=anonymous_follow_redirects,
        ) as anonymous_client:
            next_seq = await _execute_access_control_replay_plan(
                client=anonymous_client,
                plan=anon_plan,
                timeout_s=timeout_s,
                retries=retries,
                run_dir=run_dir,
                raw_index=raw_index,
                request_failures=request_failures,
                seq_start=next_seq,
            )

    return next_seq


def _summarize_raw_index_for_request_replay(
    *,
    raw_index: List[Dict[str, Any]],
) -> Dict[str, Dict[str, int]]:
    auth_state_counts: Dict[str, int] = {}
    source_counts: Dict[str, int] = {}
    method_counts: Dict[str, int] = {}
    status_bucket_counts: Dict[str, int] = {}

    for item in raw_index:
        if not isinstance(item, dict):
            continue

        auth_state_key = str(item.get("auth_state") or "MISSING")
        source_key = str(item.get("source") or "MISSING")
        method_key = str(item.get("method") or "MISSING").upper()
        status_bucket = _classify_status_bucket(item.get("status_code"))

        auth_state_counts[auth_state_key] = auth_state_counts.get(auth_state_key, 0) + 1
        source_counts[source_key] = source_counts.get(source_key, 0) + 1
        method_counts[method_key] = method_counts.get(method_key, 0) + 1
        status_bucket_counts[status_bucket] = status_bucket_counts.get(status_bucket, 0) + 1

    return {
        "raw_index_auth_state_counts": auth_state_counts,
        "raw_index_source_counts": source_counts,
        "raw_index_method_counts": method_counts,
        "raw_index_status_buckets": status_bucket_counts,
    }


def _summarize_added_replay_entries(
    *,
    added_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    added_auth = 0
    added_anon = 0
    added_ok = 0
    added_status_buckets: Dict[str, int] = {}

    for item in added_entries:
        if not isinstance(item, dict):
            continue

        item_auth_state = str(item.get("auth_state") or "").strip().lower()
        if item_auth_state == "authenticated":
            added_auth += 1
        elif item_auth_state == "anonymous":
            added_anon += 1

        if bool(item.get("ok")):
            added_ok += 1

        bucket = _classify_status_bucket(
            item.get("status_code"),
            include_redirect_bucket=True,
        )
        added_status_buckets[bucket] = added_status_buckets.get(bucket, 0) + 1

    return {
        "raw_index_added_auth_count": added_auth,
        "raw_index_added_anon_count": added_anon,
        "raw_index_added_ok_count": added_ok,
        "raw_index_added_status_buckets": added_status_buckets,
    }


def _log_object_replay_plan(
    *,
    auth_plan: List[Any],
    anon_plan: List[Any],
    max_preview: int = 30,
) -> None:
    log(
        "AUTH",
        "Object-based access control replay targets prepared: "
        f"auth={len(auth_plan)} anon={len(anon_plan)}"
    )

    for spec in auth_plan[:max_preview]:
        log(
            "AUTH",
            "[object-replay-auth] "
            f"{spec.method} {spec.url} "
            f"key={spec.replay_key} "
            f"priority={spec.replay_priority} "
            f"source_url={spec.replay_source_url} "
            f"mutation={spec.mutation_class} "
            f"group={spec.comparison_group}"
        )

    for spec in anon_plan[:max_preview]:
        log(
            "AUTH",
            "[object-replay-anon] "
            f"{spec.method} {spec.url} "
            f"key={spec.replay_key} "
            f"priority={spec.replay_priority} "
            f"source_url={spec.replay_source_url} "
            f"mutation={spec.mutation_class} "
            f"group={spec.comparison_group}"
        )

def compute_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    confirmed = results.get("findings_confirmed", [])
    informational = results.get("findings_informational", [])
    false_positive = results.get("findings_false_positive", [])

    def by_cwe(items: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in items:
            key = f.get("cwe") or f.get("cwe_mapping_status") or "UNMAPPED"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def by_group(items: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in items:
            g = finding_group(f)
            counts[g] = counts.get(g, 0) + 1
        return counts

    summary = {
        "confirmed_count": len(confirmed),
        "informational_count": len(informational),
        "false_positive_count": len(false_positive),
        "total_findings": len(confirmed) + len(informational) + len(false_positive),
        "confirmed_by_cwe": by_cwe(confirmed),
        "informational_by_cwe": by_cwe(informational),
        "false_positive_by_cwe": by_cwe(false_positive),
        "confirmed_by_group": by_group(confirmed),
        "informational_by_group": by_group(informational),
        "false_positive_by_group": by_group(false_positive),
    }

    if any((f.get("cwe_mapping_status") == OWASP_ONLY_NO_CWE_MAPPING) for f in confirmed + informational + false_positive):
        summary["cwe_mapping_note"] = {
            OWASP_ONLY_NO_CWE_MAPPING: "OWASP category is assigned, but no precise single CWE mapping is used for this finding."
        }

    return summary


def resolve_scan_profile() -> str:
    return (os.getenv("SCAN_PROFILE") or "balanced").strip().lower()


def resolve_scan_settings() -> Dict[str, Any]:
    profile = resolve_scan_profile()

    defaults = {
        "fast": {"timeout_seconds": 4.0, "retries": 0, "concurrency": 8, "follow_redirects": False},
        "balanced": {"timeout_seconds": 6.0, "retries": 1, "concurrency": 6, "follow_redirects": False},
        "thorough": {"timeout_seconds": 10.0, "retries": 1, "concurrency": 5, "follow_redirects": False},
    }.get(profile, {
        "timeout_seconds": 6.0,
        "retries": 1,
        "concurrency": 6,
        "follow_redirects": False,
    })

    timeout_s = float(os.getenv("TIMEOUT_SECONDS", str(defaults["timeout_seconds"])))
    retries = int(os.getenv("RETRIES", str(defaults["retries"])))
    concurrency = int(os.getenv("CONCURRENCY", str(defaults["concurrency"])))
    follow_redirects = (os.getenv("HTTP_FOLLOW_REDIRECTS", str(defaults["follow_redirects"])).lower() == "true")

    return {
        "profile": profile,
        "timeout_seconds": timeout_s,
        "retries": retries,
        "concurrency": concurrency,
        "follow_redirects": follow_redirects,
    }

async def _run_endpoint_access_control_replay(
    *,
    authenticated: bool,
    client: httpx.AsyncClient,
    limits: httpx.Limits,
    client_timeout: httpx.Timeout,
    follow_redirects: bool,
    timeout_s: float,
    retries: int,
    run_dir: Path,
    raw_index: List[Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    seq_start: int,
    authenticated_endpoints: List[Dict[str, Any]],
    anonymous_endpoints: List[Dict[str, Any]],
    auth_landing_url: str | None,
) -> tuple[int, Dict[str, Any]]:
    if not authenticated:
        return seq_start, {
            "authenticated_replay_count": 0,
            "anonymous_replay_count": 0,
        }

    safe_authenticated_endpoints = [
        ep for ep in (authenticated_endpoints or [])
        if not is_session_destructive_endpoint(ep)
    ]

    endpoint_replay_plan = build_access_control_replay_plan(
        authenticated_endpoints=safe_authenticated_endpoints,
        anonymous_endpoints=anonymous_endpoints,
        auth_landing_url=auth_landing_url,
        max_targets=int(os.getenv("ACCESS_CONTROL_REPLAY_MAX_TARGETS", "20")),
    )
    auth_plan = endpoint_replay_plan.get("authenticated", [])
    anon_plan = endpoint_replay_plan.get("anonymous", [])

    next_seq = await _execute_dual_access_control_replay_plans(
        authenticated_client=client,
        anonymous_client_limits=limits,
        anonymous_client_timeout=client_timeout,
        anonymous_follow_redirects=follow_redirects,
        auth_plan=auth_plan,
        anon_plan=anon_plan,
        timeout_s=timeout_s,
        retries=retries,
        run_dir=run_dir,
        raw_index=raw_index,
        request_failures=request_failures,
        seq_start=seq_start,
    )

    return next_seq, {
        "authenticated_replay_count": len(auth_plan),
        "anonymous_replay_count": len(anon_plan),
    }

async def _run_request_access_control_replay(
    *,
    authenticated: bool,
    client: httpx.AsyncClient,
    limits: httpx.Limits,
    client_timeout: httpx.Timeout,
    follow_redirects: bool,
    timeout_s: float,
    retries: int,
    run_dir: Path,
    raw_index: List[Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    seq_start: int,
) -> tuple[int, Dict[str, Any]]:
    if not authenticated:
        return seq_start, {
            "authenticated_replay_count": 0,
            "anonymous_replay_count": 0,
            "raw_index_auth_state_counts": {},
            "raw_index_source_counts": {},
            "raw_index_method_counts": {},
            "raw_index_status_buckets": {},
        }

    raw_index_summary = _summarize_raw_index_for_request_replay(raw_index=raw_index)

    request_replay_plan = build_authenticated_request_replay_plan(
        raw_index=raw_index,
        max_targets=int(os.getenv("ACCESS_CONTROL_REQUEST_REPLAY_MAX_TARGETS", "20")),
    )
    auth_plan = request_replay_plan.get("authenticated", [])
    anon_plan = request_replay_plan.get("anonymous", [])

    next_seq = await _execute_dual_access_control_replay_plans(
        authenticated_client=client,
        anonymous_client_limits=limits,
        anonymous_client_timeout=client_timeout,
        anonymous_follow_redirects=follow_redirects,
        auth_plan=auth_plan,
        anon_plan=anon_plan,
        timeout_s=timeout_s,
        retries=retries,
        run_dir=run_dir,
        raw_index=raw_index,
        request_failures=request_failures,
        seq_start=seq_start,
    )

    return next_seq, {
        "authenticated_replay_count": len(auth_plan),
        "anonymous_replay_count": len(anon_plan),
        **raw_index_summary,
    }

async def _run_object_access_control_replay(
    *,
    authenticated: bool,
    client: httpx.AsyncClient,
    limits: httpx.Limits,
    client_timeout: httpx.Timeout,
    follow_redirects: bool,
    timeout_s: float,
    retries: int,
    run_dir: Path,
    raw_index: List[Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    seq_start: int,
    authenticated_endpoints: List[Dict[str, Any]] | None = None,
    anonymous_endpoints: List[Dict[str, Any]] | None = None,
    auth_landing_url: str | None = None,
) -> tuple[int, Dict[str, Any]]:
    authenticated_endpoints = authenticated_endpoints or []
    anonymous_endpoints = anonymous_endpoints or []

    safe_authenticated_endpoints = [
        ep for ep in authenticated_endpoints
        if not is_session_destructive_endpoint(ep)
    ]

    base_summary = {
        "input_authenticated_endpoint_count": len(safe_authenticated_endpoints),
        "input_anonymous_endpoint_count": len(anonymous_endpoints),
    }

    if not authenticated:
        return seq_start, {
            "authenticated_replay_count": 0,
            "anonymous_replay_count": 0,
            **base_summary,
            "raw_index_count_before": len(raw_index),
            "raw_index_count_after": len(raw_index),
            "raw_index_added": 0,
            "request_failures_added": 0,
        }

    object_replay_plan = build_object_access_control_replay_plan(
        raw_index=raw_index,
        authenticated_endpoints=safe_authenticated_endpoints,
        anonymous_endpoints=anonymous_endpoints,
        auth_landing_url=auth_landing_url,
        max_targets=int(os.getenv("ACCESS_CONTROL_OBJECT_REPLAY_MAX_TARGETS", "20")),
    )

    auth_plan = object_replay_plan.get("authenticated", [])
    anon_plan = object_replay_plan.get("anonymous", [])

    _log_object_replay_plan(
        auth_plan=auth_plan,
        anon_plan=anon_plan,
    )

    if not auth_plan and not anon_plan:
        log("AUTH", "Object access control replay skipped: no replay targets selected")
        return seq_start, {
            "authenticated_replay_count": 0,
            "anonymous_replay_count": 0,
            **base_summary,
            "raw_index_count_before": len(raw_index),
            "raw_index_count_after": len(raw_index),
            "raw_index_added": 0,
            "request_failures_added": 0,
        }

    raw_index_before = len(raw_index)
    request_failures_before = len(request_failures)

    next_seq = await _execute_dual_access_control_replay_plans(
        authenticated_client=client,
        anonymous_client_limits=limits,
        anonymous_client_timeout=client_timeout,
        anonymous_follow_redirects=follow_redirects,
        auth_plan=auth_plan,
        anon_plan=anon_plan,
        timeout_s=timeout_s,
        retries=retries,
        run_dir=run_dir,
        raw_index=raw_index,
        request_failures=request_failures,
        seq_start=seq_start,
    )

    raw_index_after = len(raw_index)
    request_failures_after = len(request_failures)

    added_entries = raw_index[raw_index_before:raw_index_after]
    added_summary = _summarize_added_replay_entries(added_entries=added_entries)

    return next_seq, {
        "authenticated_replay_count": len(auth_plan),
        "anonymous_replay_count": len(anon_plan),
        **base_summary,
        "raw_index_count_before": raw_index_before,
        "raw_index_count_after": raw_index_after,
        "raw_index_added": raw_index_after - raw_index_before,
        "request_failures_added": request_failures_after - request_failures_before,
        **added_summary,
    }



async def run_scan(
    target: str,
    out_file: str,
    *,
    seed_urls: List[str] | None = None,
    auth: Dict[str, str] | None = None,
) -> int:
    log("INIT", f"Target: {target}")

    scan_settings = resolve_scan_settings()
    timeout_s = scan_settings["timeout_seconds"]
    retries = scan_settings["retries"]
    concurrency = scan_settings["concurrency"]
    follow_redirects = scan_settings["follow_redirects"]

    #http_only_mode = os.getenv("HTTP_ONLY_MODE", "true").lower() == "true"
    http_only_mode = os.getenv("HTTP_ONLY_MODE", "false").lower() == "true"
    #enable_auth_business_probe = os.getenv("ENABLE_AUTHENTICATED_BUSINESS_PROBE", "off").lower() == "on"
    enable_auth_business_probe = os.getenv("ENABLE_AUTHENTICATED_BUSINESS_PROBE", "on").lower() == "on"

    run_id = run_id_utc()
    requested_out = Path(out_file)
    base_out_dir = requested_out.parent
    run_dir = base_out_dir / run_id
    ensure_output_dirs(run_dir)

    out_path = run_dir / "results.json"

    limits = httpx.Limits(
        max_connections=concurrency,
        max_keepalive_connections=max(0, min(1, concurrency)),
        keepalive_expiry=2.0,
    )
    client_timeout = httpx.Timeout(
        timeout_s,
        connect=min(3.0, timeout_s),
        read=timeout_s,
        write=timeout_s,
        pool=min(3.0, timeout_s),
    )

    transport = httpx.AsyncHTTPTransport(
        retries=0,
        verify=False,
        http2=False,
    )

    async with httpx.AsyncClient(
        limits=limits,
        timeout=client_timeout,
        transport=transport,
        verify=False,
        trust_env=False,
        http2=False,
        follow_redirects=follow_redirects,
    ) as client:
        crawl_depth = int(os.getenv("CRAWL_DEPTH", "2"))
        crawl_max_pages = int(os.getenv("CRAWL_MAX_PAGES", "20"))
        crawl_enable_js = os.getenv("CRAWL_INCLUDE_JS_PATHS", "on").lower() == "on"

        manual_auth_meta = _apply_manual_auth_to_client(
            client=client,
            target=target,
        )

        results: Dict[str, Any] = {
            "metadata": {
                "target": target,
                "target_origin": _base_origin(target),
                "run_id": run_id,
                "started_at": now_utc_iso(),
                "scan_profile": scan_settings["profile"],
                "timeout_seconds": timeout_s,
                "retries": retries,
                "concurrency": concurrency,
                "crawl_depth": crawl_depth,
                "crawl_max_pages": crawl_max_pages,
                "authenticated": False,
                "auth_landing_url": None,
                "anonymous_endpoint_count": 0,
                "authenticated_endpoint_count": 0,
                "http_only_mode": http_only_mode,
                "enable_authenticated_business_probe": enable_auth_business_probe,
                "manual_auth_enabled": manual_auth_meta["manual_auth_enabled"],
                "manual_auth_cookie_names": manual_auth_meta["manual_cookie_names"],
                "manual_auth_header_names": manual_auth_meta["manual_header_names"],
                "follow_redirects": follow_redirects,
                "allowed_app_prefixes": [],
                "external_redirect_observations": [],
            },
            "summary": {},
            "findings_confirmed": [],
            "findings_informational": [],
            "findings_false_positive": [],
            "request_failures": [],
        }

        coverage = init_coverage()
        raw_index: List[Dict[str, Any]] = []
        shared_unhealthy_scopes: set[str] = set()

        confirmed_map: Dict[str, Dict[str, Any]] = {}
        informational_map: Dict[str, Dict[str, Any]] = {}
        false_positive_map: Dict[str, Dict[str, Any]] = {}
        request_failures: List[Dict[str, Any]] = []

        next_seq = 1
        authenticated = False
        auth_landing_url = None
        auth_result: Dict[str, Any] = {}
        authenticated_endpoints: List[Dict[str, Any]] = []
        protected_resource_findings: List[Dict[str, Any]] = []

        log("CRAWL", f"Discovering anonymous endpoints from seed: {target}")
        anonymous_endpoints = await discover_endpoints(
            client=client,
            seed_url=target,
            timeout_s=timeout_s,
            max_depth=crawl_depth,
            max_pages=crawl_max_pages,
            include_js_string_paths=crawl_enable_js,
            extra_seed_urls=seed_urls or [],
            crawl_state="anonymous",
        )

        manual_auth_enabled = bool(manual_auth_meta.get("manual_auth_enabled"))

        if auth:
            try:
                auth_result = await maybe_authenticate(
                    client=client,
                    target=target,
                    timeout_s=timeout_s,
                    username=auth.get("username"),
                    password=auth.get("password"),
                )
                authenticated = bool(auth_result.get("ok"))
                auth_landing_url = auth_result.get("landing_url")

                log("AUTH", f"Authentication {'succeeded' if authenticated else 'not established'}")
                if auth_landing_url:
                    log("AUTH", f"Authenticated landing URL: {auth_landing_url}")

                bearer_token = str(auth_result.get("bearer_token") or "").strip()
                auth_headers = auth_result.get("auth_headers") or {}

                if bearer_token:
                    client.headers["Authorization"] = f"Bearer {bearer_token}"
                    log("AUTH", "Applied bearer token to authenticated client headers.")
                elif auth_headers:
                    for hk, hv in auth_headers.items():
                        if str(hk).strip() and str(hv).strip():
                            client.headers[str(hk)] = str(hv)
                    log("AUTH", f"Applied auth headers to authenticated client: {sorted(auth_headers.keys())}")

                login_url = auth_result.get("login_url") or target
                auth_mode = str(auth_result.get("auth_mode") or "").strip().lower()

                if auth_mode in {"cookie_form", "form", "session_cookie"}:
                    bypass_findings = await verify_auth_bypass(
                        client=client,
                        login_url=login_url,
                        username_field="login",
                        password_field="password",
                        valid_username=auth.get("username", ""),
                        valid_password=auth.get("password", ""),
                        timeout_s=timeout_s,
                    )

                    session_findings = await verify_session_controls(
                        target=target,
                        auth=auth,
                        timeout_s=timeout_s,
                        authenticate_fn=maybe_authenticate,
                    )

                    fixation_findings = await verify_session_fixation(
                        target=target,
                        auth=auth,
                        timeout_s=timeout_s,
                        authenticate_fn=maybe_authenticate,
                    )
                else:
                    log("AUTH", f"Skipping form/cookie session verifiers for auth_mode={auth_mode or 'unknown'}")
                    bypass_findings = []
                    session_findings = []
                    fixation_findings = []

                _store_verified_findings(
                    findings=bypass_findings + session_findings + fixation_findings,
                    confirmed_map=confirmed_map,
                    informational_map=informational_map,
                    false_positive_map=false_positive_map,
                    stable_key_fn=stable_key,
                )

                auth_snapshot_count = len(auth_result.get("auth_snapshots") or [])
                log("AUTH", f"Auth snapshots captured: {auth_snapshot_count}")
                next_seq = await _process_auth_snapshots(
                    auth_result=auth_result,
                    seq_start=next_seq,
                    client=client,
                    run_dir=run_dir,
                    raw_index=raw_index,
                    coverage=coverage,
                    confirmed_map=confirmed_map,
                    informational_map=informational_map,
                    false_positive_map=false_positive_map,
                    request_failures=request_failures,
                    timeout_s=timeout_s,
                    retries=retries,
                    stable_key_fn=stable_key,
                )

                auth_events = auth_result.get("auth_events") or []
                if not isinstance(auth_events, list):
                    auth_events = []

                auth_cookie_observations = auth_result.get("cookie_observations") or []
                if not isinstance(auth_cookie_observations, list):
                    auth_cookie_observations = []

                results["metadata"]["auth_events"] = auth_events
                results["metadata"]["auth_cookie_observations"] = auth_cookie_observations

            except Exception as e:
                log("AUTH", f"Authentication failed: {type(e).__name__}: {e}")
                authenticated = False
                auth_landing_url = None

        allowed_app_prefixes = _derive_allowed_app_prefixes(
            target=target,
            auth_landing_url=auth_landing_url,
            seed_urls=seed_urls or [],
        )
        results["metadata"]["allowed_app_prefixes"] = allowed_app_prefixes

        log("CRAWL", f"Allowed app prefixes: {allowed_app_prefixes}")

        if manual_auth_enabled:
            if not authenticated:
                authenticated = True
                auth_landing_url = (seed_urls or [target])[0] if (seed_urls or []) else target
                log("AUTH", "Manual authentication mode enabled via MANUAL_AUTH_COOKIE / MANUAL_AUTH_HEADERS")
                log("AUTH", f"Authenticated landing URL (manual): {auth_landing_url}")
            else:
                log("AUTH", "Manual authentication is also active in addition to established login flow")

        if authenticated:
            authenticated_endpoints = await _discover_authenticated_endpoints(
                client=client,
                target=target,
                auth_landing_url=auth_landing_url,
                seed_urls=seed_urls,
                timeout_s=timeout_s,
                crawl_depth=crawl_depth,
                crawl_max_pages=crawl_max_pages,
                crawl_enable_js=crawl_enable_js,
            )

        if authenticated and auth_result:
            snapshot_authenticated_endpoints = _extract_authenticated_endpoints_from_auth_snapshots(
                auth_result=auth_result,
                target=target,
            )

            if snapshot_authenticated_endpoints:
                authenticated_endpoints = merge_discovered_endpoints(
                    authenticated_endpoints,
                    snapshot_authenticated_endpoints,
                )

        if authenticated and not http_only_mode and enable_auth_business_probe:
            next_seq = await _run_authenticated_business_probes(
                client=client,
                target=target,
                allowed_app_prefixes=allowed_app_prefixes,
                authenticated=authenticated,
                authenticated_endpoints=authenticated_endpoints,
                anonymous_endpoints=anonymous_endpoints,
                timeout_s=timeout_s,
                retries=retries,
                run_dir=run_dir,
                raw_index=raw_index,
                coverage=coverage,
                confirmed_map=confirmed_map,
                informational_map=informational_map,
                false_positive_map=false_positive_map,
                request_failures=request_failures,
                seq_start=next_seq,
                shared_unhealthy_scopes=shared_unhealthy_scopes,
            )
        elif authenticated and http_only_mode:
            log("AUTH", "Authenticated business probes skipped: HTTP_ONLY_MODE=true")

        max_endpoints = int(os.getenv("MAX_ENDPOINTS", "200"))

        (
            discovered_endpoints,
            original_discovered_count,
            filtered_anonymous_endpoints,
            filtered_authenticated_endpoints,
        ) = _prepare_discovered_endpoints(
            target=target,
            anonymous_endpoints=anonymous_endpoints,
            authenticated_endpoints=authenticated_endpoints,
            allowed_app_prefixes=allowed_app_prefixes,
            max_endpoints=max_endpoints,
        )

        static_plan = _build_static_plan_from_endpoints(
            target=target,
            discovered_endpoints=discovered_endpoints,
            allowed_app_prefixes=allowed_app_prefixes,
        )

        results["metadata"]["authenticated"] = authenticated
        results["metadata"]["auth_landing_url"] = auth_landing_url
        results["metadata"]["anonymous_endpoint_count"] = len(filtered_anonymous_endpoints)
        results["metadata"]["authenticated_endpoint_count"] = len(filtered_authenticated_endpoints)

        llm_planner_enabled = os.getenv("LLM_PROBE_PLANNER_MODE", "off").lower() == "on"
        llm_midpoint_ratio = float(os.getenv("LLM_PLANNER_MIDPOINT_RATIO", "0.40"))

        if not static_plan:
            static_plan_a = []
            static_plan_b = []
        else:
            split_idx = max(1, min(len(static_plan), int(len(static_plan) * llm_midpoint_ratio)))
            static_plan_a = static_plan[:split_idx]
            static_plan_b = static_plan[split_idx:]

        next_seq = await _run_plan_and_merge(
            client=client,
            plan=static_plan_a,
            timeout_s=timeout_s,
            retries=retries,
            run_dir=run_dir,
            raw_index=raw_index,
            coverage=coverage,
            seq_start=next_seq,
            authenticated=authenticated,
            confirmed_map=confirmed_map,
            informational_map=informational_map,
            false_positive_map=false_positive_map,
            request_failures=request_failures,
            shared_unhealthy_scopes=shared_unhealthy_scopes,
        )

        async def _run_llm_planner_round(round_name: str, seq_start_val: int) -> int:
            nonlocal confirmed_map, informational_map, false_positive_map, request_failures
            try:
                log("LLM", f"Generating additional probes with LLM planner ({round_name})...")
                observation_summary = build_observation_summary(
                    target=target,
                    raw_index=raw_index,
                    findings_confirmed=list(confirmed_map.values()),
                    findings_informational=list(informational_map.values()),
                    discovered_endpoints=discovered_endpoints,
                )
                llm_plan_raw = generate_llm_probes(target, observation_summary)
                llm_plan = _filter_request_specs_by_app_scope(
                    llm_plan_raw,
                    base_target=target,
                    allowed_prefixes=allowed_app_prefixes,
                )

                log("LLM", f"Generated probes ({round_name}): raw={len(llm_plan_raw)} filtered={len(llm_plan)}")

                for spec in llm_plan:
                    log("LLM", f"[{round_name}] {spec.method} {spec.url} family={spec.family}")
            except Exception as e:
                log("LLM", f"Planner failed ({round_name}), continuing: {type(e).__name__}: {e}")
                llm_plan = []

            if not llm_plan:
                return seq_start_val

            return await _run_plan_and_merge(
                client=client,
                plan=llm_plan,
                timeout_s=timeout_s,
                retries=retries,
                run_dir=run_dir,
                raw_index=raw_index,
                coverage=coverage,
                seq_start=seq_start_val,
                authenticated=authenticated,
                confirmed_map=confirmed_map,
                informational_map=informational_map,
                false_positive_map=false_positive_map,
                request_failures=request_failures,
                shared_unhealthy_scopes=shared_unhealthy_scopes,
            )

        if llm_planner_enabled:
            next_seq = await _run_llm_planner_round("mid", next_seq)

        next_seq = await _run_plan_and_merge(
            client=client,
            plan=static_plan_b,
            timeout_s=timeout_s,
            retries=retries,
            run_dir=run_dir,
            raw_index=raw_index,
            coverage=coverage,
            seq_start=next_seq,
            authenticated=authenticated,
            confirmed_map=confirmed_map,
            informational_map=informational_map,
            false_positive_map=false_positive_map,
            request_failures=request_failures,
            shared_unhealthy_scopes=shared_unhealthy_scopes,
        )

        if llm_planner_enabled:
            next_seq = await _run_llm_planner_round("final", next_seq)

        endpoint_replay_meta = {
            "authenticated_replay_count": 0,
            "anonymous_replay_count": 0,
        }
        request_replay_meta = {
            "authenticated_replay_count": 0,
            "anonymous_replay_count": 0,
            "raw_index_auth_state_counts": {},
            "raw_index_source_counts": {},
            "raw_index_method_counts": {},
            "raw_index_status_buckets": {},
        }
        object_replay_meta = {
            "authenticated_replay_count": 0,
            "anonymous_replay_count": 0,
        }

        if authenticated:
            enable_endpoint_acl_replay = (
                not http_only_mode and
                os.getenv("ENABLE_ENDPOINT_ACL_REPLAY", "off").lower() == "on"
            )
            enable_request_acl_replay = (
                not http_only_mode and
                os.getenv("ENABLE_REQUEST_ACL_REPLAY", "off").lower() == "on"
            )
            enable_object_acl_replay = (
                not http_only_mode and
                os.getenv("ENABLE_OBJECT_ACL_REPLAY", "off").lower() == "on"
            )

            if enable_endpoint_acl_replay:
                next_seq, endpoint_replay_meta = await _run_endpoint_access_control_replay(
                    authenticated=authenticated,
                    client=client,
                    limits=limits,
                    client_timeout=client_timeout,
                    follow_redirects=follow_redirects,
                    timeout_s=timeout_s,
                    retries=retries,
                    run_dir=run_dir,
                    raw_index=raw_index,
                    request_failures=request_failures,
                    seq_start=next_seq,
                    authenticated_endpoints=authenticated_endpoints,
                    anonymous_endpoints=anonymous_endpoints,
                    auth_landing_url=auth_landing_url,
                )
            else:
                endpoint_replay_meta = {
                    "authenticated_replay_count": 0,
                    "anonymous_replay_count": 0,
                    "disabled": True,
                }
                if http_only_mode:
                    log("AUTH", "Endpoint ACL replay skipped: HTTP_ONLY_MODE=true")

            if enable_request_acl_replay:
                next_seq, request_replay_meta = await _run_request_access_control_replay(
                    authenticated=authenticated,
                    client=client,
                    limits=limits,
                    client_timeout=client_timeout,
                    follow_redirects=follow_redirects,
                    timeout_s=timeout_s,
                    retries=retries,
                    run_dir=run_dir,
                    raw_index=raw_index,
                    request_failures=request_failures,
                    seq_start=next_seq,
                )
            else:
                request_replay_meta = {
                    "authenticated_replay_count": 0,
                    "anonymous_replay_count": 0,
                    "raw_index_auth_state_counts": {},
                    "raw_index_source_counts": {},
                    "raw_index_method_counts": {},
                    "raw_index_status_buckets": {},
                    "disabled": True,
                }
                if http_only_mode:
                    log("AUTH", "Request ACL replay skipped: HTTP_ONLY_MODE=true")

            if enable_object_acl_replay:
                next_seq, object_replay_meta = await _run_object_access_control_replay(
                    authenticated=authenticated,
                    client=client,
                    limits=limits,
                    client_timeout=client_timeout,
                    follow_redirects=follow_redirects,
                    timeout_s=timeout_s,
                    retries=retries,
                    run_dir=run_dir,
                    raw_index=raw_index,
                    request_failures=request_failures,
                    seq_start=next_seq,
                    authenticated_endpoints=authenticated_endpoints,
                    anonymous_endpoints=anonymous_endpoints,
                    auth_landing_url=auth_landing_url,
                )

                try:
                    if not http_only_mode:
                        protected_resource_findings = await verify_protected_resource_access(
                            target=target,
                            authenticated_client=client,
                            authenticated_endpoints=authenticated_endpoints,
                            anonymous_endpoints=anonymous_endpoints,
                            auth_landing_url=auth_landing_url,
                            timeout_s=timeout_s,
                            raw_index=raw_index,
                        )
                        log("AUTH", f"protected_resource_findings={len(protected_resource_findings)}")
                    else:
                        protected_resource_findings = []
                        log("AUTH", "Protected resource verification skipped: HTTP_ONLY_MODE=true")
                except Exception as e:
                    log("AUTH", f"Protected resource verification failed: {type(e).__name__}: {e}")
                    protected_resource_findings = []
            else:
                object_replay_meta = {
                    "authenticated_replay_count": 0,
                    "anonymous_replay_count": 0,
                    "disabled": True,
                }
                protected_resource_findings = []
                if http_only_mode:
                    log("AUTH", "Object ACL replay skipped: HTTP_ONLY_MODE=true")

            _store_verified_findings(
                findings=protected_resource_findings,
                confirmed_map=confirmed_map,
                informational_map=informational_map,
                false_positive_map=false_positive_map,
                stable_key_fn=stable_key,
            )

        results["metadata"]["endpoint_access_control_replay"] = endpoint_replay_meta
        results["metadata"]["request_access_control_replay"] = request_replay_meta
        results["metadata"]["object_access_control_replay"] = object_replay_meta

        confirmed_map, informational_map = _consolidate_generic_vs_concrete(confirmed_map, informational_map)
        false_positive_map = _drop_shadowed_false_positives(
            false_positive_map,
            list(confirmed_map.values()) + list(informational_map.values())
        )

        confirmed_map, informational_map, false_positive_map = _reconcile_bucket_precedence(
            confirmed_map,
            informational_map,
            false_positive_map,
        )

        confirmed_list = persist_finding_map(run_dir, "confirmed", confirmed_map, log)
        informational_list = persist_finding_map(run_dir, "informational", informational_map, log)
        false_positive_list = persist_finding_map(run_dir, "false_positive", false_positive_map, log)

        results["findings_confirmed"] = confirmed_list
        results["findings_informational"] = informational_list
        results["findings_false_positive"] = false_positive_list
        results["request_failures"] = request_failures

        add_confirmed_counts_to_coverage(results, coverage)
        results["coverage"] = finalize_coverage_assessment(coverage)

        results["metadata"]["finished_at"] = now_utc_iso()
        results["metadata"]["request_count"] = len(raw_index)
        results["metadata"]["discovered_endpoint_count_before_pruning"] = original_discovered_count
        results["metadata"]["discovered_endpoint_count"] = len(discovered_endpoints)
        results["metadata"]["max_endpoints"] = max_endpoints
        results["metadata"]["discovered_endpoints_sample"] = [
            {
                "url": endpoint_url(ep),
                "kind": endpoint_kind(ep),
                "states": ep.get("states", []) if isinstance(ep, dict) else [],
                "score": ep.get("score", 0) if isinstance(ep, dict) else 0,
                "field_names": ep.get("field_names", []) if isinstance(ep, dict) else [],
            }
            for ep in discovered_endpoints[:20]
        ]

        results["summary"] = compute_summary(results)
        results["raw_index"] = raw_index

        summary = results["summary"]
        log("SUMMARY", f"Requests sent: {results['metadata']['request_count']}")
        log("SUMMARY", f"Confirmed findings: {summary['confirmed_count']}")
        log("SUMMARY", f"Informational findings: {summary['informational_count']}")
        log("SUMMARY", f"False positives: {summary['false_positive_count']}")

        save_json(out_path, results)
        generate_reports(run_dir, results)

    return 0

def build_auth_args(args: Any) -> Dict[str, str] | None:
    if getattr(args, "auth_username", None) and getattr(args, "auth_password", None):
        return {
            "username": args.auth_username,
            "password": args.auth_password,
        }
    return None

def resolve_target_name(target: str, target_name: str | None) -> str:
    if target_name:
        return normalize_target_name(target_name)
    host = urlparse(target).hostname or "target"
    return normalize_target_name(host)
