from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit

from agent.analysis.features import (
    FILE_PATH_PATTERNS,
    INTERNAL_IP_PATTERNS,
    _detect_phpinfo_indicators,
    _extract_config_values,
    _extract_phpinfo_values,
    _extract_runtime_error_messages,
    _filter_meaningful_internal_ips,
    _find_matches,
    _looks_like_local_filesystem_path,
)
from agent.core.scope import normalize_url_for_dedup


_DIFF_ROUTE_SKIP_PATTERNS = (
    "/login",
    "login.php",
    "/logout",
)


def _entry_route_key(item: Dict[str, Any]) -> str:
    final_url = str(item.get("final_url") or item.get("url") or "").strip()
    return normalize_url_for_dedup(final_url)


def _entry_is_anonymous(item: Dict[str, Any]) -> bool:
    return str(item.get("auth_state") or "").strip().lower() == "anonymous"


def _entry_is_authenticated(item: Dict[str, Any]) -> bool:
    return str(item.get("auth_state") or "").strip().lower() == "authenticated"


def _looks_like_loginish_page(url: str, body: str) -> bool:
    url_l = str(url or "").lower()
    body_l = str(body or "").lower()
    if any(token in url_l for token in ("/login", "login.php", "/signin", "/auth", "/sso")):
        return True
    return (
        "<form" in body_l
        and "password" in body_l
        and any(token in body_l for token in ("login", "sign in", "log in", "username"))
    )


def _extract_differential_exposure_values(body: str) -> List[str]:
    text = str(body or "")
    if not text.strip():
        return []

    values: List[str] = []

    for item in _extract_phpinfo_values(text):
        item_s = str(item or "").strip()
        if item_s:
            values.append(item_s)

    for item in _extract_config_values(text):
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip()
        value = str(item.get("value") or "").strip()
        if not key or not value:
            continue
        values.append(f"{key}={value}")

    for item in _extract_runtime_error_messages(text):
        item_s = " ".join(str(item or "").split())
        if len(item_s) >= 20:
            values.append(f"Runtime error: {item_s}")

    raw_paths = _find_matches(FILE_PATH_PATTERNS, text, 20)
    local_paths = []
    for path in raw_paths:
        norm = " ".join(str(path or "").split())
        if norm and _looks_like_local_filesystem_path(norm):
            local_paths.append(norm)
    for path in local_paths[:10]:
        values.append(f"File path: {path}")

    internal_ips = _filter_meaningful_internal_ips(_find_matches(INTERNAL_IP_PATTERNS, text, 10))
    for ip in internal_ips:
        values.append(f"Internal IP: {ip}")

    seen = set()
    out: List[str] = []
    for value in values:
        value = str(value or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out[:15]


def _best_route_observation(items: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    best: Dict[str, Any] | None = None
    best_score = (-1, -1, -1)

    for item in items or []:
        body = str(item.get("body_text") or "")
        extracted = _extract_differential_exposure_values(body)
        score = (
            1 if int(item.get("status_code") or 0) == 200 else 0,
            len(extracted),
            len(body),
        )
        if score > best_score:
            best = dict(item)
            best["_diff_exposed_information"] = extracted
            best_score = score

    return best


def _build_route_observation_buckets(raw_index: List[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any] | None]]:
    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for item in raw_index or []:
        if not isinstance(item, dict):
            continue
        route_key = _entry_route_key(item)
        if not route_key:
            continue
        bucket = grouped.setdefault(route_key, {"anonymous": [], "authenticated": []})
        if _entry_is_anonymous(item):
            bucket["anonymous"].append(item)
        elif _entry_is_authenticated(item):
            bucket["authenticated"].append(item)

    out: Dict[str, Dict[str, Dict[str, Any] | None]] = {}
    for route_key, bucket in grouped.items():
        out[route_key] = {
            "anonymous": _best_route_observation(bucket.get("anonymous") or []),
            "authenticated": _best_route_observation(bucket.get("authenticated") or []),
        }
    return out


def _annotate_visibility_scope(
    bucket_map: Dict[str, Dict[str, Any]],
    raw_index: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    route_buckets = _build_route_observation_buckets(raw_index)
    annotated: Dict[str, Dict[str, Any]] = {}

    for key, finding in (bucket_map or {}).items():
        updated = dict(finding)
        evidence = updated.get("evidence") or {}
        route_key = normalize_url_for_dedup(
            str(
                evidence.get("final_url")
                or evidence.get("requested_url")
                or updated.get("normalized_url")
                or ""
            )
        )
        pair = route_buckets.get(route_key) or {}
        anon_best = pair.get("anonymous")
        auth_best = pair.get("authenticated")

        visibility_scope = "unknown"
        anonymous_behavior = "not_observed"
        newly_exposed_information: List[str] = []

        if auth_best and anon_best:
            anon_values = set(anon_best.get("_diff_exposed_information") or [])
            auth_values = list(auth_best.get("_diff_exposed_information") or [])
            newly_exposed_information = [value for value in auth_values if value not in anon_values]

            anon_status = int(anon_best.get("status_code") or 0)
            anon_body = str(anon_best.get("body_text") or "")
            if anon_status in {401, 403}:
                anonymous_behavior = "blocked"
            elif _looks_like_loginish_page(str(anon_best.get("final_url") or anon_best.get("url") or ""), anon_body):
                anonymous_behavior = "login_redirect_or_auth_page"
            elif anon_values:
                anonymous_behavior = "meaningful_disclosure_observed"
            else:
                anonymous_behavior = "no_meaningful_disclosure"

            if newly_exposed_information and anonymous_behavior in {
                "blocked",
                "login_redirect_or_auth_page",
                "no_meaningful_disclosure",
            }:
                visibility_scope = "authenticated_only"
            else:
                visibility_scope = "public_or_shared"
        elif auth_best:
            visibility_scope = "authenticated_observed_only"
        elif anon_best:
            visibility_scope = "public_or_shared"

        updated["visibility_scope"] = visibility_scope
        updated["anonymous_behavior"] = anonymous_behavior
        if not updated.get("exposure_context"):
            if visibility_scope == "authenticated_only":
                updated["exposure_context"] = "differential_anonymous_vs_authenticated"
            elif visibility_scope == "authenticated_observed_only":
                updated["exposure_context"] = "authenticated"
            elif visibility_scope == "public_or_shared":
                updated["exposure_context"] = "public_or_shared"
        if newly_exposed_information:
            updated["newly_exposed_information"] = newly_exposed_information

        evidence = dict(evidence)
        if anon_best:
            evidence["anon_status_code"] = anon_best.get("status_code")
            evidence["anon_final_url"] = anon_best.get("final_url")
            evidence["anon_raw_ref"] = anon_best.get("raw_ref")
        if auth_best:
            evidence["auth_status_code"] = auth_best.get("status_code")
            evidence["auth_final_url"] = auth_best.get("final_url")
            evidence["auth_raw_ref"] = auth_best.get("raw_ref")
        evidence["visibility_scope"] = visibility_scope
        evidence["anonymous_behavior"] = anonymous_behavior
        if newly_exposed_information:
            evidence["newly_exposed_information"] = newly_exposed_information
        updated["evidence"] = evidence
        annotated[key] = updated

    return annotated


def _differential_subtype(exposed_information: List[str], auth_body: str) -> str:
    body = str(auth_body or "")
    if _detect_phpinfo_indicators(body):
        return "authenticated_phpinfo_disclosure"
    if any("=" in item and any(tok in item.lower() for tok in ("db_", "password", "secret", "token")) for item in exposed_information):
        return "authenticated_config_disclosure"
    return "authenticated_diagnostic_disclosure"


def _differential_severity(exposed_information: List[str], subtype: str) -> str:
    if subtype in {"authenticated_phpinfo_disclosure", "authenticated_config_disclosure"}:
        return "Medium"
    if any(item.lower().startswith("runtime error:") for item in exposed_information):
        return "Medium"
    return "Low"


def _differential_cwe(subtype: str) -> str:
    if subtype == "authenticated_config_disclosure":
        return "CWE-538"
    return "CWE-497"


def _build_differential_disclosure_findings(
    *,
    raw_index: List[Dict[str, Any]],
    authenticated: bool,
) -> List[Dict[str, Any]]:
    if not authenticated:
        return []

    grouped: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for item in raw_index or []:
        if not isinstance(item, dict):
            continue

        route_key = _entry_route_key(item)
        if not route_key:
            continue

        route_key_l = route_key.lower()
        if any(token in route_key_l for token in _DIFF_ROUTE_SKIP_PATTERNS):
            continue

        bucket = grouped.setdefault(route_key, {"anonymous": [], "authenticated": []})
        if _entry_is_anonymous(item):
            bucket["anonymous"].append(item)
        elif _entry_is_authenticated(item):
            bucket["authenticated"].append(item)

    findings: List[Dict[str, Any]] = []

    for route_key, bucket in grouped.items():
        anon_best = _best_route_observation(bucket.get("anonymous") or [])
        auth_best = _best_route_observation(bucket.get("authenticated") or [])

        if not anon_best or not auth_best:
            continue

        anon_values = set(anon_best.get("_diff_exposed_information") or [])
        auth_values = list(auth_best.get("_diff_exposed_information") or [])
        if not auth_values:
            continue

        new_values = [value for value in auth_values if value not in anon_values]
        if not new_values:
            continue

        anon_status = int(anon_best.get("status_code") or 0)
        auth_status = int(auth_best.get("status_code") or 0)
        anon_body = str(anon_best.get("body_text") or "")
        auth_body = str(auth_best.get("body_text") or "")

        anonymous_behavior = "same_content"
        if anon_status in {401, 403}:
            anonymous_behavior = "blocked"
        elif _looks_like_loginish_page(str(anon_best.get("final_url") or anon_best.get("url") or ""), anon_body):
            anonymous_behavior = "login_redirect_or_auth_page"
        elif not anon_values:
            anonymous_behavior = "no_meaningful_disclosure"

        if anonymous_behavior == "same_content":
            continue
        if auth_status < 200 or auth_status >= 400:
            continue

        subtype = _differential_subtype(new_values, auth_body)
        severity = _differential_severity(new_values, subtype)
        cwe = _differential_cwe(subtype)

        findings.append(
            {
                "type": "AUTHENTICATED_ONLY_INFORMATION_DISCLOSURE",
                "title": "Additional internal information disclosed only after authentication",
                "severity": severity,
                "cwe": cwe,
                "classification_source": "rule_based_differential",
                "cwe_source": "rule_based_visibility_mapping",
                "severity_source": "rule_based_differential_policy",
                "owasp": "A05:2021 Security Misconfiguration",
                "family": "HTTP_BODY_DISCLOSURE",
                "subtype": subtype,
                "scope_hint": "route-specific",
                "policy_object": "authenticated_only_information",
                "where": "response.body",
                "status_code": auth_status,
                "confidence": 0.88,
                "classification_kind": "finding",
                "signal_strength": "strong",
                "signal_repeatability": "likely_stable",
                "observation_scope": "route_behavior",
                "verification_strategy": "differential_replay",
                "signal_type": "differential_information_disclosure",
                "visibility_scope": "authenticated_only",
                "exposure_context": "differential_anonymous_vs_authenticated",
                "trigger": {
                    "name": str(auth_best.get("request_name") or "authenticated_differential_observation"),
                    "method": str(auth_best.get("method") or "GET"),
                    "url": str(auth_best.get("url") or route_key),
                },
                "verification": {
                    "verdict": "CONFIRMED",
                    "reason": "Information disclosure was observed only in the authenticated response and not in the anonymous response.",
                },
                "evidence": {
                    "final_url": str(auth_best.get("final_url") or route_key),
                    "requested_url": str(auth_best.get("url") or route_key),
                    "anon_final_url": str(anon_best.get("final_url") or anon_best.get("url") or route_key),
                    "anon_status_code": anon_status,
                    "auth_final_url": str(auth_best.get("final_url") or auth_best.get("url") or route_key),
                    "auth_status_code": auth_status,
                    "anon_raw_ref": anon_best.get("raw_ref"),
                    "auth_raw_ref": auth_best.get("raw_ref"),
                    "anonymous_behavior": anonymous_behavior,
                    "newly_exposed_information": new_values,
                    "anonymous_exposed_information": sorted(anon_values)[:10],
                    "authenticated_exposed_information": auth_values,
                    "differential_observed": True,
                },
                "exposed_information": new_values,
                "normalized_exposed_information": new_values,
                "exposed_information_raw": new_values,
                "reason": "Authenticated users can access additional internal details that were not present in the anonymous response.",
                "recommendation": [
                    "Limit internal diagnostic and operational details to the minimum required for the user role.",
                    "Review authenticated-only pages for unnecessary server, runtime, path, and configuration disclosures.",
                ],
                "root_cause_signature": f"authenticated_only_disclosure:{subtype}",
            }
        )

    return findings


def _candidate_signal_key(signal: Dict[str, Any]) -> str:
    evidence = signal.get("evidence") or {}
    final_url = str(evidence.get("final_url") or "")
    subtype = str(signal.get("subtype") or "")
    finding_type = str(signal.get("finding_type") or "")
    policy_object = str(signal.get("policy_object") or "")

    try:
        parsed = urlsplit(final_url)
        host_scope = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}/" if parsed.scheme and parsed.netloc else final_url
        route_scope = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or '/'}" if parsed.scheme and parsed.netloc else final_url
    except Exception:
        host_scope = final_url
        route_scope = final_url

    if subtype in {
        "detector_version_disclosure",
        "detector_framework_hint",
        "detector_internal_structure",
        "banner_header",
    }:
        scope = host_scope
    else:
        scope = route_scope

    return "||".join([finding_type, subtype, policy_object, scope])


def _reduce_candidate_signals(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    reduced: Dict[str, Dict[str, Any]] = {}
    for signal in signals or []:
        key = _candidate_signal_key(signal)
        existing = reduced.get(key)
        if existing is None:
            signal = dict(signal)
            signal["observation_count"] = 1
            reduced[key] = signal
            continue

        existing["observation_count"] = int(existing.get("observation_count") or 1) + 1
        existing_conf = float(existing.get("confidence") or 0.0)
        signal_conf = float(signal.get("confidence") or 0.0)
        if signal_conf > existing_conf:
            merged_count = existing["observation_count"]
            signal = dict(signal)
            signal["observation_count"] = merged_count
            reduced[key] = signal
    return list(reduced.values())


def store_verified_findings(
    *,
    findings: List[Dict[str, Any]],
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    stable_key_fn,
    store_with_verdict_precedence_fn,
) -> None:
    for finding in findings:
        key = stable_key_fn(finding)
        verdict = (finding.get("verification") or {}).get("verdict")
        store_with_verdict_precedence_fn(
            key=key,
            cand=finding,
            verdict=verdict,
            confirmed_map=confirmed_map,
            informational_map=informational_map,
            false_positive_map=false_positive_map,
        )


def _count_values(items: List[Dict[str, Any]], field: str, *, limit: int = 20) -> Dict[str, int]:
    counts = Counter()
    for item in items or []:
        value = item.get(field)
        if value is None or value == "":
            value = "<missing>"
        counts[str(value)] += 1
    return dict(counts.most_common(limit))


def _status_family(status: Any) -> str:
    try:
        code = int(status)
    except Exception:
        return "unknown"
    if code < 100:
        return "unknown"
    return f"{code // 100}xx"


def _content_family(content_type: Any) -> str:
    value = str(content_type or "").lower()
    if not value:
        return "unknown"
    if "json" in value:
        return "json"
    if "html" in value:
        return "html"
    if "javascript" in value or "ecmascript" in value:
        return "javascript"
    if "xml" in value:
        return "xml"
    if value.startswith("text/"):
        return "text"
    if any(token in value for token in ("image/", "font/", "video/", "audio/", "pdf", "zip", "octet-stream")):
        return "binary_or_static"
    return value.split(";", 1)[0]


def _path_tokens(url: str) -> List[str]:
    try:
        return [seg.lower() for seg in (urlsplit(str(url or "")).path or "/").split("/") if seg]
    except Exception:
        return []


def _is_api_like_url(url: str) -> bool:
    path = "/" + "/".join(_path_tokens(url))
    return any(token in path for token in ("/api/", "/rest/", "/graphql", "/v1/", "/v2/"))


def _is_shape_sensitive_get_url(url: str) -> bool:
    tokens = _path_tokens(url)
    joined = " ".join(tokens)
    return any(
        token in joined
        for token in (
            "upload",
            "download",
            "excel",
            "export",
            "import",
            "update",
            "delete",
            "create",
            "submit",
            "save",
            "issue",
            "approval",
        )
    )


def _build_cookie_diagnostics(raw_index: List[Dict[str, Any]], metadata: Dict[str, Any]) -> Dict[str, Any]:
    request_cookie_names = sorted({
        name
        for item in raw_index or []
        for name in (item.get("request_cookie_names") or [])
        if str(name or "").strip()
    })
    set_cookie_entries = [
        entry
        for item in raw_index or []
        for entry in (item.get("set_cookie_flag_summary") or [])
        if isinstance(entry, dict)
    ]
    set_cookie_names = sorted({str(entry.get("name") or "") for entry in set_cookie_entries if entry.get("name")})
    sensitive_set_cookie_names = sorted({
        str(entry.get("name") or "")
        for entry in set_cookie_entries
        if entry.get("name") and entry.get("sensitive")
    })

    flag_observations: Dict[str, Dict[str, Any]] = {}
    for entry in set_cookie_entries:
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        obs = flag_observations.setdefault(
            name,
            {
                "sensitive": False,
                "secure_seen": False,
                "secure_missing_seen": False,
                "httponly_seen": False,
                "httponly_missing_seen": False,
                "samesite_values": [],
                "samesite_missing_seen": False,
                "observation_count": 0,
            },
        )
        obs["observation_count"] += 1
        obs["sensitive"] = bool(obs["sensitive"] or entry.get("sensitive"))
        if entry.get("secure"):
            obs["secure_seen"] = True
        else:
            obs["secure_missing_seen"] = True
        if entry.get("httponly"):
            obs["httponly_seen"] = True
        else:
            obs["httponly_missing_seen"] = True
        samesite = str(entry.get("samesite") or "").strip()
        if samesite:
            values = obs.setdefault("samesite_values", [])
            if samesite not in values:
                values.append(samesite)
        else:
            obs["samesite_missing_seen"] = True

    notes: List[str] = []
    manual_cookie_names = metadata.get("manual_auth_cookie_names") or []
    if manual_cookie_names and not set_cookie_entries:
        notes.append(
            "manual_auth_cookie_flags_not_observable_without_set_cookie: "
            "Cookie request headers prove replay, but Secure/HttpOnly/SameSite can only be judged from Set-Cookie responses."
        )
    if request_cookie_names and not set_cookie_entries:
        notes.append("session_cookie_sent_but_server_never_reissued_cookie_in_observed_responses")

    return {
        "manual_auth_cookie_names": manual_cookie_names,
        "request_cookie_names_seen": request_cookie_names,
        "set_cookie_response_count": sum(1 for item in raw_index or [] if item.get("set_cookie_present")),
        "set_cookie_names_seen": set_cookie_names,
        "sensitive_set_cookie_names_seen": sensitive_set_cookie_names,
        "set_cookie_flag_observations": flag_observations,
        "notes": notes,
    }


def _build_probe_shape_diagnostics(raw_index: List[Dict[str, Any]]) -> Dict[str, Any]:
    business_entries = [
        item for item in raw_index or []
        if str(item.get("family") or "") == "authenticated_business_probe"
    ]
    status_families = Counter(_status_family(item.get("status_code")) for item in business_entries)
    shape_sensitive_gets = [
        item for item in business_entries
        if str(item.get("method") or "").upper() == "GET"
        and not item.get("request_body_present")
        and _is_shape_sensitive_get_url(str(item.get("url") or ""))
    ]
    api_entries = [item for item in business_entries if _is_api_like_url(str(item.get("url") or ""))]
    api_error_entries = [
        item for item in api_entries
        if _status_family(item.get("status_code")) in {"4xx", "5xx"}
    ]

    notes: List[str] = []
    if business_entries:
        error_ratio = (status_families.get("4xx", 0) + status_families.get("5xx", 0)) / max(1, len(business_entries))
        if error_ratio >= 0.6:
            notes.append(
                "high_error_ratio_on_authenticated_business_probes: selected URLs may require the original SPA method/body/CSRF headers."
            )
    if len(shape_sensitive_gets) >= max(3, len(business_entries) // 4):
        notes.append(
            "many_shape_sensitive_endpoints_called_as_plain_get: replay real browser requests for upload/download/update/export APIs when possible."
        )
    if api_entries and len(api_error_entries) / max(1, len(api_entries)) >= 0.6:
        notes.append("api_probe_replay_gap_likely: API endpoints were discovered, but most returned 4xx/5xx to generic probes.")

    return {
        "authenticated_business_probe_count": len(business_entries),
        "status_code_counts": _count_values(business_entries, "status_code"),
        "status_family_counts": dict(status_families),
        "content_family_counts": dict(Counter(_content_family(item.get("content_type")) for item in business_entries)),
        "api_like_probe_count": len(api_entries),
        "api_like_4xx_5xx_count": len(api_error_entries),
        "shape_sensitive_plain_get_count": len(shape_sensitive_gets),
        "shape_sensitive_plain_get_examples": [
            {
                "url": item.get("url"),
                "status_code": item.get("status_code"),
                "raw_ref": item.get("raw_ref"),
            }
            for item in shape_sensitive_gets[:10]
        ],
        "notes": notes,
    }


def _build_scan_diagnostics(
    *,
    results: Dict[str, Any],
    raw_index: List[Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    discovered_endpoints: List[Dict[str, Any]],
) -> Dict[str, Any]:
    metadata = results.get("metadata") or {}
    auth_landing_url = str(metadata.get("auth_landing_url") or "")
    endpoint_urls = [str(ep.get("url") or "") for ep in discovered_endpoints or [] if isinstance(ep, dict)]
    raw_urls = [str(item.get("url") or "") for item in raw_index or []]
    hash_route_present = "#" in auth_landing_url or any("#" in url for url in endpoint_urls[:50])

    notes: List[str] = []
    if hash_route_present:
        notes.append(
            "spa_hash_route_detected: URL fragments are client-side state and are not sent to the server; prioritize harvested API/XHR endpoints."
        )

    cookie_diag = _build_cookie_diagnostics(raw_index, metadata)
    probe_diag = _build_probe_shape_diagnostics(raw_index)
    notes.extend(cookie_diag.get("notes") or [])
    notes.extend(probe_diag.get("notes") or [])

    auth_state_loss_events = [
        item for item in request_failures or []
        if str(item.get("error_class") or "") == "AuthStateLoss"
    ]

    return {
        "auth": {
            "authenticated": bool(metadata.get("authenticated")),
            "manual_auth_enabled": bool(metadata.get("manual_auth_enabled")),
            "manual_auth_cookie_names": metadata.get("manual_auth_cookie_names") or [],
            "manual_auth_header_names": metadata.get("manual_auth_header_names") or [],
            "auth_landing_url": auth_landing_url or None,
            "auth_landing_has_fragment": "#" in auth_landing_url,
            "auth_state_loss_count": len(auth_state_loss_events),
        },
        "coverage_shape": {
            "raw_request_count": len(raw_index or []),
            "discovered_endpoint_count": len(discovered_endpoints or []),
            "status_code_counts": _count_values(raw_index, "status_code"),
            "status_family_counts": dict(Counter(_status_family(item.get("status_code")) for item in raw_index or [])),
            "content_family_counts": dict(Counter(_content_family(item.get("content_type")) for item in raw_index or [])),
            "auth_state_counts": _count_values(raw_index, "auth_state"),
            "family_counts": _count_values(raw_index, "family"),
            "api_like_raw_request_count": sum(1 for url in raw_urls if _is_api_like_url(url)),
            "api_like_discovered_endpoint_count": sum(1 for url in endpoint_urls if _is_api_like_url(url)),
        },
        "cookies": cookie_diag,
        "authenticated_business_probe": probe_diag,
        "diagnostic_notes": notes,
        "recommended_next_steps": [
            "If Set-Cookie is never observed, capture the real login or SSO redirect response once so cookie flags can be evaluated.",
            "For SPA/API applications, provide seed URLs or replay captures for real XHR calls with method, body, CSRF, Origin, Referer, and Authorization headers.",
            "If many authenticated probes return 403/500, prefer browser-observed API requests over generic GET probes for evidence collection.",
        ],
    }


def _error_response_marker_summary(body: str) -> Dict[str, Any]:
    text = str(body or "")
    lower = text.lower()
    oracle = re.findall(r"\bORA-\d{5}\b", text, flags=re.I)
    sql_markers = [
        marker
        for marker in (
            "sql",
            "sqlexception",
            "preparedstatement",
            "constraint",
            "jdbc",
            "hibernate",
            "mybatis",
            "psqlexception",
            "mysql",
            "postgres",
            "oracle",
        )
        if marker in lower
    ]
    stack_markers = [
        marker
        for marker in ("exception", "stack trace", "traceback", "caused by", "\tat ", "java.")
        if marker in lower
    ]
    return {
        "has_db_error_markers": bool(oracle or sql_markers),
        "has_stack_markers": bool(stack_markers),
        "oracle_error_codes": sorted(set(oracle)),
        "db_error_markers": sorted(set(sql_markers)),
        "stack_markers": sorted(set(stack_markers)),
    }


def _build_error_response_debug(raw_index: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in raw_index or []:
        try:
            status_code = int(item.get("status_code") or 0)
        except Exception:
            continue
        if status_code < 500:
            continue

        body = str(item.get("body_text") or item.get("body_snippet") or "")
        marker_summary = _error_response_marker_summary(body)
        if marker_summary["has_db_error_markers"] or marker_summary["has_stack_markers"]:
            classification_hint = "error_disclosure_candidate"
        elif body:
            classification_hint = "generic_error_response_no_sensitive_markers"
        else:
            classification_hint = "empty_error_response"

        out.append(
            {
                "request_name": item.get("request_name"),
                "method": item.get("method"),
                "url": item.get("url"),
                "status_code": status_code,
                "content_type": item.get("content_type"),
                "family": item.get("family"),
                "auth_state": item.get("auth_state"),
                "raw_ref": item.get("raw_ref"),
                "classification_hint": classification_hint,
                **marker_summary,
                "body_preview": body[:500],
            }
        )
    return out[:500]


def finalize_and_write_results(
    *,
    results: Dict[str, Any],
    coverage: Dict[str, Dict[str, Any]],
    run_dir: Path,
    out_path: Path,
    raw_index: List[Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    discovered_endpoints: List[Dict[str, Any]],
    original_discovered_count: int,
    max_endpoints: int,
    consolidate_generic_vs_concrete_fn,
    drop_shadowed_false_positives_fn,
    reconcile_bucket_precedence_fn,
    persist_finding_map_fn,
    add_confirmed_counts_to_coverage_fn,
    finalize_coverage_assessment_fn,
    compute_summary_fn,
    now_utc_iso_fn,
    endpoint_url_fn,
    endpoint_kind_fn,
    log_fn,
    save_json_fn,
    generate_reports_fn,
) -> Dict[str, Any]:
    candidate_signals: List[Dict[str, Any]] = []

    confirmed_map = _annotate_visibility_scope(confirmed_map, raw_index)
    informational_map = _annotate_visibility_scope(informational_map, raw_index)
    false_positive_map = _annotate_visibility_scope(false_positive_map, raw_index)

    differential_findings = _build_differential_disclosure_findings(
        raw_index=raw_index,
        authenticated=bool((results.get("metadata") or {}).get("authenticated")),
    )
    for finding in differential_findings:
        key = stable_key_fn(finding)
        store_with_verdict_precedence_fn(
            key=key,
            cand=finding,
            verdict=(finding.get("verification") or {}).get("verdict"),
            confirmed_map=confirmed_map,
            informational_map=informational_map,
            false_positive_map=false_positive_map,
        )

    def _split_supporting_signals(bucket_map: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        filtered: Dict[str, Dict[str, Any]] = {}
        for key, finding in bucket_map.items():
            if str(finding.get("classification_kind") or "") == "supporting_signal":
                candidate_signals.append(finding)
                continue
            filtered[key] = finding
        return filtered

    confirmed_map = _split_supporting_signals(confirmed_map)
    informational_map = _split_supporting_signals(informational_map)
    false_positive_map = _split_supporting_signals(false_positive_map)
    candidate_signals = _reduce_candidate_signals(candidate_signals)

    confirmed_map, informational_map = consolidate_generic_vs_concrete_fn(
        confirmed_map,
        informational_map,
    )
    false_positive_map = drop_shadowed_false_positives_fn(
        false_positive_map,
        list(confirmed_map.values()) + list(informational_map.values()),
    )

    confirmed_map, informational_map, false_positive_map = reconcile_bucket_precedence_fn(
        confirmed_map,
        informational_map,
        false_positive_map,
    )

    confirmed_list = persist_finding_map_fn(run_dir, "confirmed", confirmed_map, log_fn)
    informational_list = persist_finding_map_fn(run_dir, "informational", informational_map, log_fn)
    false_positive_list = persist_finding_map_fn(run_dir, "false_positive", false_positive_map, log_fn)

    results["findings_confirmed"] = confirmed_list
    results["findings_informational"] = informational_list
    results["findings_false_positive"] = false_positive_list
    results["candidate_signals"] = candidate_signals
    results["request_failures"] = request_failures

    add_confirmed_counts_to_coverage_fn(results, coverage)
    results["coverage"] = finalize_coverage_assessment_fn(coverage)

    results["metadata"]["finished_at"] = now_utc_iso_fn()
    results["metadata"]["request_count"] = len(raw_index)
    auth_state_loss_events = [
        item for item in request_failures
        if str(item.get("error_class") or "") == "AuthStateLoss"
    ]
    results["metadata"]["auth_state_loss_count"] = len(auth_state_loss_events)
    results["metadata"]["auth_state_loss_examples"] = auth_state_loss_events[:10]
    results["metadata"]["discovered_endpoint_count_before_pruning"] = original_discovered_count
    results["metadata"]["discovered_endpoint_count"] = len(discovered_endpoints)
    results["metadata"]["max_endpoints"] = max_endpoints
    results["metadata"]["discovered_endpoints_sample"] = [
        {
            "url": endpoint_url_fn(endpoint),
            "kind": endpoint_kind_fn(endpoint),
            "states": endpoint.get("states", []) if isinstance(endpoint, dict) else [],
            "score": endpoint.get("score", 0) if isinstance(endpoint, dict) else 0,
            "field_names": endpoint.get("field_names", []) if isinstance(endpoint, dict) else [],
        }
        for endpoint in discovered_endpoints[:20]
    ]

    scan_diagnostics = _build_scan_diagnostics(
        results=results,
        raw_index=raw_index,
        request_failures=request_failures,
        discovered_endpoints=discovered_endpoints,
    )
    results["metadata"]["scan_diagnostics"] = {
        "diagnostic_notes": scan_diagnostics.get("diagnostic_notes") or [],
        "cookie_notes": (scan_diagnostics.get("cookies") or {}).get("notes") or [],
        "authenticated_business_probe_notes": (
            scan_diagnostics.get("authenticated_business_probe") or {}
        ).get("notes") or [],
    }

    results["summary"] = compute_summary_fn(results)
    results["raw_index"] = raw_index

    summary = results["summary"]
    log_fn("SUMMARY", f"Requests sent: {results['metadata']['request_count']}")
    log_fn("SUMMARY", f"Confirmed findings: {summary['confirmed_count']}")
    log_fn("SUMMARY", f"Informational findings: {summary['informational_count']}")
    log_fn("SUMMARY", f"False positives: {summary['false_positive_count']}")
    log_fn("SUMMARY", f"Candidate signals: {len(candidate_signals)}")

    save_json_fn(out_path, results)
    scan_diagnostics_path = run_dir / "debug" / "scan_diagnostics.json"
    scan_diagnostics_path.parent.mkdir(parents=True, exist_ok=True)
    scan_diagnostics_path.write_text(
        json.dumps(scan_diagnostics, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    error_response_debug = _build_error_response_debug(raw_index)
    if error_response_debug:
        error_response_debug_path = run_dir / "debug" / "error_responses.json"
        error_response_debug_path.write_text(
            json.dumps(error_response_debug, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    candidate_signal_path = run_dir / "debug" / "candidate_signals.json"
    candidate_signal_path.parent.mkdir(parents=True, exist_ok=True)
    candidate_signal_path.write_text(
        json.dumps(candidate_signals, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    generate_reports_fn(run_dir, results)
    return results
