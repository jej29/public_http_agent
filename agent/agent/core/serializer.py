from __future__ import annotations
import html
from typing import Any, Dict, List
from copy import deepcopy


def normalize_risky_http_methods_for_output(finding: Dict[str, Any]) -> Dict[str, Any]:
    out = deepcopy(finding)

    if str(out.get("type") or "") != "RISKY_HTTP_METHODS_ENABLED":
        return out

    evidence = out.setdefault("evidence", {})
    verification = out.setdefault("verification", {})

    final_methods = sorted({
        str(m).upper().strip()
        for m in (evidence.get("risky_methods_enabled") or [])
        if str(m).strip() and str(m).upper().strip() != "TRACE"
    })

    evidence["risky_methods_enabled"] = final_methods
    evidence["method_capability_signals"] = list(dict.fromkeys(
        str(s) for s in (evidence.get("method_capability_signals") or [])
        if str(s).strip()
    ))
    evidence["confirmed_method_capabilities"] = sorted({
        str(m).upper().strip()
        for m in (evidence.get("confirmed_method_capabilities") or [])
        if str(m).strip() and str(m).upper().strip() != "TRACE"
    })

    out["root_cause_signature"] = "methods:" + ",".join(final_methods)

    exposed_information = [
        *[f"Allowed or handled risky method: {m}" for m in final_methods],
        f"Observed methods: {', '.join(final_methods)}" if final_methods else "Observed methods: none",
    ]

    verification["verdict"] = "INFORMATIONAL"
    verification["reason"] = (
        "Observed risky HTTP method handling without confirmed exploitability. "
        + (f"Observed methods: {', '.join(final_methods)}." if final_methods else "")
    )
    out["title"] = "Risky HTTP methods appear enabled but exploitability was not confirmed"
    out["severity"] = "Info"
    out["final_severity"] = "Info"

    out["exposed_information"] = exposed_information
    out["reason"] = verification["reason"]
    return out


def _dedup_str_list(items: List[Any], limit: int | None = None) -> List[str]:
    out: List[str] = []
    seen = set()

    for x in items or []:
        s = str(x).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if limit is not None and len(out) >= limit:
            break

    return out


def _compress_route_listing_items(finding: Dict[str, Any], items: List[str]) -> List[str]:
    if str(finding.get("type") or "") != "DIRECTORY_LISTING_ENABLED":
        return items
    evidence = finding.get("evidence") or {}
    final_url = str(evidence.get("final_url") or finding.get("normalized_url") or "").strip()
    if not final_url:
        return items[:1]
    return [f"Directory listing enabled at: {final_url}"]


def _sanitize_exposed_item(finding: Dict[str, Any], item: Any) -> str | None:
    text = html.unescape(str(item or "")).replace("\ufffd", "").strip()
    text = " ".join(text.split())
    if not text:
        return None

    ftype = str(finding.get("type") or "")

    if text.lower() in {"sqlite3.", "sqlite3", "array (", "array("}:
        return None

    if text.count("*") >= max(4, len(text) // 2):
        return None

    if ftype == "HTTP_CONFIG_FILE_EXPOSURE":
        if text.startswith("Masked configuration value present:"):
            return None
        if text == "Application configuration details disclosed":
            return None
        if text.startswith("Token: ") and len(text.removeprefix("Token: ").strip()) < 12:
            return None

    if ftype == "PHPINFO_EXPOSURE":
        if text.startswith("phpinfo indicator:"):
            return None

    return text


def _compact_trigger(trigger: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(trigger, dict):
        return {}
    out = {
        "name": trigger.get("name"),
        "method": trigger.get("method"),
        "url": trigger.get("url"),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def _event_priority(family: str, event: Dict[str, Any]) -> tuple[int, int]:
    trigger = (event or {}).get("trigger") or {}
    name = str(trigger.get("name") or "")
    method = str(trigger.get("method") or "").upper()
    url = str(trigger.get("url") or "")
    status_code = (event or {}).get("status_code")

    score = 100

    if family in {"TRANSPORT_SECURITY", "HTTP_HEADER_DISCLOSURE", "HTTP_HEADER_SECURITY"}:
        if name.startswith("baseline_get"):
            score = 1
        elif name.startswith("baseline_head"):
            score = 2
        elif name.startswith("baseline_query"):
            score = 3
        elif name.startswith("notfound"):
            score = 20
        else:
            score = 50

    elif family == "HTTP_ERROR_DISCLOSURE":
        if "path_badenc" in name or "%ZZ" in url:
            score = 1
        elif name.startswith("path_"):
            score = 2
        elif name.startswith(("qs_", "qsx_", "combo_")):
            score = 3
        elif name.startswith("resource_probe_"):
            score = 4
        elif name.startswith("notfound"):
            score = 10
        else:
            score = 30

    elif family == "COOKIE_SECURITY":
        if name.startswith("baseline_get"):
            score = 1
        elif name.startswith("baseline_head"):
            score = 2
        else:
            score = 20

    elif family == "CORS_MISCONFIG":
        if name.startswith("cors_get"):
            score = 1
        elif name.startswith("cors_head"):
            score = 2
        elif name.startswith("cors_preflight"):
            score = 3
        else:
            score = 20

    elif family == "HTTP_METHOD_SECURITY":
        if method == "PUT":
            score = 1
        elif method == "DELETE":
            score = 2
        elif method == "TRACE":
            score = 3
        elif method == "OPTIONS":
            score = 4
        else:
            score = 10

    elif family in {"DEFAULT_RESOURCE_EXPOSURE", "DIRECTORY_LISTING"}:
        if name.startswith("resource_probe_"):
            score = 1
        elif name.startswith("resource_head_"):
            score = 2
        elif name.startswith("dir_list_"):
            score = 3
        else:
            score = 20

    elif family == "HTTP_BODY_DISCLOSURE":
        if name.startswith("resource_probe_"):
            score = 1
        elif name.startswith("baseline_get"):
            score = 2
        else:
            score = 20

    else:
        if name.startswith("baseline_"):
            score = 5

    if status_code == 200:
        score -= 1
    if status_code in {201, 202, 204}:
        score -= 2

    return (score, len(name))


def select_primary_evidence(finding: Dict[str, Any], limit: int = 3) -> List[Dict[str, Any]]:
    family = str(finding.get("family") or "")
    events = finding.get("events") or []

    if not isinstance(events, list):
        return []

    sorted_events = sorted(events, key=lambda e: _event_priority(family, e))
    out: List[Dict[str, Any]] = []
    seen = set()

    for ev in sorted_events:
        trigger = _compact_trigger((ev or {}).get("trigger") or {})
        final_url = str((ev or {}).get("final_url") or "")
        raw_ref = str((ev or {}).get("raw_ref") or "")
        status_code = (ev or {}).get("status_code")

        item = {
            "trigger": trigger,
            "final_url": final_url,
            "status_code": status_code,
            "raw_ref": raw_ref,
        }
        item = {k: v for k, v in item.items() if v not in (None, "", [], {})}

        key = (
            trigger.get("name", ""),
            trigger.get("method", ""),
            trigger.get("url", ""),
            final_url,
            status_code,
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)

        if len(out) >= limit:
            break

    return out


def _refined_llm_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    llm = finding.get("llm_judgement") or {}
    refined = llm.get("refined_finding") or {}
    return refined if isinstance(refined, dict) else {}


def _best_exposed_information(finding: Dict[str, Any]) -> List[str]:
    explicit_raw = _dedup_str_list(
        finding.get("missing_security_controls")
        or finding.get("normalized_exposed_information")
        or finding.get("exposed_information")
        or [],
        limit=10,
    )
    explicit = _dedup_str_list(
        [_sanitize_exposed_item(finding, item) for item in explicit_raw if _sanitize_exposed_item(finding, item)],
        limit=10,
    )
    if explicit:
        return explicit

    refined = _refined_llm_finding(finding)
    refined_items = _dedup_str_list(
        [
            _sanitize_exposed_item(finding, item)
            for item in (refined.get("exposed_information") or [])
            if _sanitize_exposed_item(finding, item)
        ],
        limit=6,
    )
    if refined_items:
        return refined_items

    return _fallback_exposed_information_from_evidence(finding)


def _best_title(finding: Dict[str, Any]) -> str | None:
    title = finding.get("title")
    if title:
        return title

    refined = _refined_llm_finding(finding)
    return refined.get("title") or finding.get("type")


def _best_reason(finding: Dict[str, Any]) -> str | None:
    verification = finding.get("verification") or {}
    if verification.get("reason"):
        return str(verification.get("reason"))

    refined = _refined_llm_finding(finding)
    if refined.get("reason"):
        return str(refined.get("reason"))

    llm = finding.get("llm_judgement") or {}
    if llm.get("reason"):
        return str(llm.get("reason"))

    return None


def _normalize_technology_fingerprint(items: List[Any]) -> List[str]:
    ordered = _dedup_str_list(items)
    if not ordered:
        return []

    versioned: Dict[str, str] = {}
    for item in ordered:
        s = str(item).strip().lower()
        if "/" in s:
            name = s.split("/", 1)[0].strip()
            if name and name not in versioned:
                versioned[name] = str(item).strip()

    out: List[str] = []
    seen = set()

    for item in ordered:
        raw = str(item).strip()
        s = raw.lower()
        if "/" in s:
            if raw not in seen:
                out.append(raw)
                seen.add(raw)
            continue

        name = s.strip()
        if name in versioned:
            continue

        if raw not in seen:
            out.append(raw)
            seen.add(raw)

    return out[:10]


def _clean_file_paths_for_summary(items: List[Any]) -> List[str]:
    cleaned = _dedup_str_list(items)
    if not cleaned:
        return []

    strong: List[str] = []
    weak: List[str] = []

    for item in cleaned:
        s = str(item).strip()
        s_l = s.lower()

        looks_absolute_unix = s.startswith("/var/") or s.startswith("/usr/") or s.startswith("/opt/") or s.startswith("/home/")
        looks_windows = ":\\" in s or s[:2].endswith(":")
        looks_code_path = "(" in s and ")" in s and ".php" in s_l

        if looks_absolute_unix or looks_windows or looks_code_path:
            strong.append(s)
        else:
            weak.append(s)

    return (strong + weak)[:5]


def _build_compact_evidence_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    evidence = finding.get("evidence") or {}
    summary: Dict[str, Any] = {
        "final_url": evidence.get("final_url"),
        "response_kind": evidence.get("response_kind"),
        "default_error_hint": evidence.get("default_error_hint"),
        "error_exposure_class": evidence.get("error_exposure_class"),
        "body_content_type_hint": evidence.get("body_content_type_hint"),
    }

    if evidence.get("banner_headers"):
        summary["banner_headers"] = evidence.get("banner_headers")

    if evidence.get("header_version_tokens"):
        summary["header_version_tokens"] = _dedup_str_list(evidence.get("header_version_tokens") or [], limit=5)

    if evidence.get("strong_version_tokens_in_body"):
        summary["strong_version_tokens_in_body"] = _dedup_str_list(evidence.get("strong_version_tokens_in_body") or [], limit=5)

    if evidence.get("all_version_tokens"):
        summary["all_version_tokens"] = _dedup_str_list(evidence.get("all_version_tokens") or [], limit=8)

    if evidence.get("stack_traces"):
        summary["stack_traces"] = _dedup_str_list(evidence.get("stack_traces") or [], limit=3)

    if evidence.get("file_paths"):
        summary["file_paths"] = _clean_file_paths_for_summary(evidence.get("file_paths") or [])

    if evidence.get("db_errors"):
        summary["db_errors"] = _dedup_str_list(evidence.get("db_errors") or [], limit=3)
    if evidence.get("runtime_error_messages"):
        summary["runtime_error_messages"] = _dedup_str_list(evidence.get("runtime_error_messages") or [], limit=3)

    if evidence.get("internal_ips"):
        summary["internal_ips"] = _dedup_str_list(evidence.get("internal_ips") or [], limit=5)
    if evidence.get("writable_paths"):
        summary["writable_paths"] = _dedup_str_list(evidence.get("writable_paths") or [], limit=5)
    if evidence.get("setup_diagnostic_values"):
        summary["setup_diagnostic_values"] = _dedup_str_list(evidence.get("setup_diagnostic_values") or [], limit=8)
    if "direct_http_access_confirmed" in evidence:
        summary["direct_http_access_confirmed"] = bool(evidence.get("direct_http_access_confirmed"))
    if evidence.get("follow_up_constraints"):
        summary["follow_up_constraints"] = _dedup_str_list(evidence.get("follow_up_constraints") or [], limit=3)

    if evidence.get("debug_hints"):
        summary["debug_hints"] = _dedup_str_list(evidence.get("debug_hints") or [], limit=5)

    if evidence.get("framework_hints"):
        summary["framework_hints"] = _dedup_str_list(evidence.get("framework_hints") or [], limit=5)

    if evidence.get("default_file_hints"):
        summary["default_file_hints"] = _dedup_str_list(evidence.get("default_file_hints") or [], limit=5)

    if evidence.get("directory_listing_hints"):
        summary["directory_listing_hints"] = _dedup_str_list(evidence.get("directory_listing_hints") or [], limit=5)

    if evidence.get("risky_methods_enabled"):
        summary["risky_methods_enabled"] = _dedup_str_list(evidence.get("risky_methods_enabled") or [], limit=10)

    if evidence.get("allowed_methods"):
        summary["allowed_methods"] = _dedup_str_list(evidence.get("allowed_methods") or [], limit=10)

    if evidence.get("phpinfo_indicators"):
        summary["phpinfo_indicators"] = _dedup_str_list(evidence.get("phpinfo_indicators") or [], limit=5)

    if evidence.get("phpinfo_extracted_values"):
        summary["phpinfo_extracted_values"] = _dedup_str_list(
            [
                item.get("display")
                for item in (evidence.get("phpinfo_extracted_values") or [])
                if isinstance(item, dict) and item.get("display")
            ],
            limit=8,
        )

    if evidence.get("config_exposure_markers"):
        summary["config_exposure_markers"] = _dedup_str_list(evidence.get("config_exposure_markers") or [], limit=8)

    if evidence.get("log_exposure_patterns"):
        summary["log_exposure_patterns"] = _dedup_str_list(evidence.get("log_exposure_patterns") or [], limit=8)

    if evidence.get("file_path_parameter_names"):
        summary["file_path_parameter_names"] = _dedup_str_list(evidence.get("file_path_parameter_names") or [], limit=8)

    if evidence.get("redirect_parameter_names"):
        summary["redirect_parameter_names"] = _dedup_str_list(evidence.get("redirect_parameter_names") or [], limit=8)

    if evidence.get("query_param_names"):
        summary["query_param_names"] = _dedup_str_list(evidence.get("query_param_names") or [], limit=10)

    if evidence.get("confirmed_method_capabilities"):
        summary["confirmed_method_capabilities"] = _dedup_str_list(
            evidence.get("confirmed_method_capabilities") or [],
            limit=10,
        )

    if evidence.get("method_capability_signals"):
        summary["method_capability_signals"] = _dedup_str_list(
            evidence.get("method_capability_signals") or [],
            limit=10,
        )

    for field in (
        "candidate_url",
        "allow_header",
        "dav_header",
        "put_status",
        "get_status",
        "delete_status",
        "verify_delete_status",
        "marker",
        "uploaded_bytes",
        "retrieved_marker_present",
        "delete_verified_absent",
    ):
        if evidence.get(field) not in (None, "", [], {}):
            summary[field] = evidence.get(field)

    if evidence.get("notes"):
        summary["notes"] = _dedup_str_list(evidence.get("notes") or [], limit=8)

    for field in ["acao", "acac", "acam", "acah", "vary", "location", "cookie_name"]:
        if evidence.get(field) not in (None, "", [], {}):
            summary[field] = evidence.get(field)

    # protected resource exposure summary
    protected_fields = (
        "resource_url",
        "resource_kind",
        "seen_in_anonymous_crawl",
        "auth_status_code",
        "auth_final_url",
        "auth_content_type",
        "auth_is_json_like",
        "auth_body_len",
        "anon_status_code",
        "anon_final_url",
        "anon_content_type",
        "anon_is_json_like",
        "anon_body_len",
    )
    for field in protected_fields:
        if evidence.get(field) not in (None, "", [], {}):
            summary[field] = evidence.get(field)

    if evidence.get("auth_json_indicators"):
        summary["auth_json_indicators"] = _dedup_str_list(evidence.get("auth_json_indicators") or [], limit=8)

    if evidence.get("anon_json_indicators"):
        summary["anon_json_indicators"] = _dedup_str_list(evidence.get("anon_json_indicators") or [], limit=8)

    if evidence.get("decision_reasons"):
        summary["decision_reasons"] = _dedup_str_list(evidence.get("decision_reasons") or [], limit=8)

    if evidence.get("anon_body_snippet"):
        summary["anon_body_snippet"] = str(evidence.get("anon_body_snippet"))[:400]

    if finding.get("type") == "PROTECTED_RESOURCE_EXPOSURE":
        for field in (
            "resource_url",
            "resource_kind",
            "seen_in_anonymous_crawl",
            "replay_method",
            "auth_status_code",
            "auth_final_url",
            "auth_content_type",
            "auth_is_json_like",
            "auth_body_len",
            "anon_status_code",
            "anon_final_url",
            "anon_content_type",
            "anon_is_json_like",
            "anon_body_len",
        ):
            if evidence.get(field) not in (None, "", [], {}):
                summary[field] = evidence.get(field)

        if evidence.get("auth_json_indicators"):
            summary["auth_json_indicators"] = _dedup_str_list(
                evidence.get("auth_json_indicators") or [],
                limit=8,
            )

        if evidence.get("anon_json_indicators"):
            summary["anon_json_indicators"] = _dedup_str_list(
                evidence.get("anon_json_indicators") or [],
                limit=8,
            )

        if evidence.get("decision_reasons"):
            summary["decision_reasons"] = _dedup_str_list(
                evidence.get("decision_reasons") or [],
                limit=8,
            )

        if evidence.get("anon_body_snippet"):
            summary["anon_body_snippet"] = str(evidence.get("anon_body_snippet"))[:400]

    return {k: v for k, v in summary.items() if v not in (None, "", [], {})}

def _fallback_exposed_information_from_evidence(finding: Dict[str, Any]) -> List[str]:
    evidence = finding.get("evidence") or {}
    out: List[str] = []

    for x in evidence.get("all_version_tokens") or []:
        out.append(f"Version token: {x}")

    for x in evidence.get("stack_traces") or []:
        out.append(f"Stack trace: {x}")

    for x in _clean_file_paths_for_summary(evidence.get("file_paths") or []):
        out.append(f"File path: {x}")
    for x in evidence.get("writable_paths") or []:
        out.append(f"Writable path disclosed: {x}")
    for x in evidence.get("setup_diagnostic_values") or []:
        out.append(str(x))

    for x in evidence.get("db_errors") or []:
        out.append(f"Database error: {x}")
    for x in evidence.get("runtime_error_messages") or []:
        out.append(f"Error message: {x}")

    for x in evidence.get("phpinfo_indicators") or []:
        out.append(f"phpinfo indicator: {x}")

    for x in evidence.get("config_exposure_markers") or []:
        out.append(f"Config marker: {x}")

    for x in evidence.get("default_file_hints") or []:
        out.append(f"Default resource hint: {x}")

    if str(finding.get("type") or "") == "HTTP_PUT_UPLOAD_CAPABILITY":
        candidate_url = str(evidence.get("candidate_url") or "")
        if candidate_url:
            out.append(f"PUT upload succeeded at: {candidate_url}")
        if evidence.get("retrieved_marker_present"):
            out.append("Uploaded marker was retrieved successfully via GET")

    if str(finding.get("type") or "") == "HTTP_DELETE_CAPABILITY":
        candidate_url = str(evidence.get("candidate_url") or "")
        if candidate_url:
            out.append(f"DELETE succeeded at: {candidate_url}")
        if evidence.get("delete_verified_absent"):
            out.append("Deleted resource was confirmed absent after verification")

    if str(finding.get("type") or "") == "PROTECTED_RESOURCE_EXPOSURE":
        resource_url = str(evidence.get("resource_url") or "")
        if resource_url:
            out.append(f"Anonymous access path: {resource_url}")

        auth_status = evidence.get("auth_status_code")
        anon_status = evidence.get("anon_status_code")
        if auth_status not in (None, "") or anon_status not in (None, ""):
            out.append(f"Auth/anon status: {auth_status}/{anon_status}")

        for x in evidence.get("decision_reasons") or []:
            out.append(f"Decision reason: {x}")

        for x in evidence.get("auth_json_indicators") or []:
            out.append(f"Authenticated JSON indicator: {x}")

        for x in evidence.get("anon_json_indicators") or []:
            out.append(f"Anonymous JSON indicator: {x}")

    return _dedup_str_list(out, limit=6)


def serialize_compact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    finding = normalize_risky_http_methods_for_output(finding)
    primary_evidence = select_primary_evidence(finding, limit=3)

    exposed_information = _best_exposed_information(finding)
    recommendations = _dedup_str_list(finding.get("recommendation") or [], limit=4)
    severity_reason = _dedup_str_list(finding.get("severity_reason") or [], limit=4)
    technology_fingerprint = _normalize_technology_fingerprint(
        finding.get("technology_fingerprint") or []
    )
    effective_severity = str(finding.get("final_severity") or finding.get("severity") or "Info")
    classification_source = finding.get("classification_source") or "rule_based"
    cwe_source = finding.get("cwe_source") or "rule_based_mapping"
    severity_source = finding.get("severity_source") or (
        "validation_policy" if finding.get("final_severity") else "rule_based_policy"
    )

    compact: Dict[str, Any] = {
        "type": finding.get("type"),
        "title": _best_title(finding),
        "visibility_scope": finding.get("visibility_scope"),
        "exposure_context": finding.get("exposure_context"),
        "severity": effective_severity,
        "cwe": finding.get("cwe"),
        "cwe_mapping_status": finding.get("cwe_mapping_status"),
        "cwe_mapping_reason": finding.get("cwe_mapping_reason"),
        "classification_source": classification_source,
        "cwe_source": cwe_source,
        "severity_source": severity_source,
        "owasp": finding.get("owasp"),
        "family": finding.get("family"),
        "subtype": finding.get("subtype"),
        "scope_hint": finding.get("scope_hint"),
        "policy_object": finding.get("policy_object"),
        "where": finding.get("where"),
        "status_code": finding.get("status_code"),
        "normalized_url": finding.get("normalized_url"),
        "verification": finding.get("verification"),
        "confidence": finding.get("confidence"),
        "trigger_count": finding.get("trigger_count") or len(finding.get("events") or []),
        "primary_evidence": primary_evidence,
        "exposed_information": _compress_route_listing_items(finding, exposed_information),
        "normalized_exposed_information": _compress_route_listing_items(
            finding,
            _dedup_str_list(finding.get("normalized_exposed_information") or [], limit=10),
        ),
        "exposed_information_raw": _compress_route_listing_items(
            finding,
            _dedup_str_list(finding.get("exposed_information_raw") or [], limit=12),
        ),
        "llm_evidence_review": finding.get("llm_evidence_review"),
        "severity_reason": severity_reason,
        "recommendation": recommendations,
        "technology_fingerprint": technology_fingerprint,
        "template_fingerprint": finding.get("template_fingerprint"),
        "root_cause_signature": finding.get("root_cause_signature"),
        "anonymous_behavior": finding.get("anonymous_behavior"),
        "newly_exposed_information": _dedup_str_list(finding.get("newly_exposed_information") or [], limit=10),
        "evidence_summary": _build_compact_evidence_summary(finding),
    }

    best_reason = _best_reason(finding)
    if best_reason:
        compact["reason"] = best_reason

    if finding.get("llm_severity"):
        compact["llm_severity"] = finding.get("llm_severity")

    if finding.get("severity_validation_reason"):
        compact["severity_validation_reason"] = finding.get("severity_validation_reason")

    if finding.get("type") in {"RISKY_HTTP_METHODS_ENABLED", "HTTP_PUT_UPLOAD_CAPABILITY", "HTTP_DELETE_CAPABILITY"}:
        primary = compact.get("primary_evidence") or []
        compact["primary_evidence"] = sorted(primary, key=_primary_evidence_sort_key)

    return {k: v for k, v in compact.items() if v not in (None, "", [], {})}


def _primary_evidence_sort_key(ev: Dict[str, Any]) -> tuple:
    trigger = ev.get("trigger") or {}

    url = str(trigger.get("url") or "")
    method = str(trigger.get("method") or "").upper()

    try:
        status = int(ev.get("status_code") or 0)
    except (TypeError, ValueError):
        status = 0

    if status in {200, 201, 202, 204, 207, 401, 403}:
        status_rank = 0
    elif status in {301, 302, 307, 308}:
        status_rank = 1
    else:
        status_rank = 2

    normalized = url.rstrip("/")
    root_rank = 0 if normalized == "http://dvwa" else 1

    method_rank = {
        "PUT": 0,
        "DELETE": 1,
        "TRACE": 2,
        "OPTIONS": 3,
    }.get(method, 9)

    return (status_rank, method_rank, root_rank, len(url), url, method)


def serialize_debug_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    finding = normalize_risky_http_methods_for_output(finding)
    debug_finding = dict(finding)

    if debug_finding.get("technology_fingerprint"):
        debug_finding["technology_fingerprint"] = _normalize_technology_fingerprint(
            debug_finding.get("technology_fingerprint") or []
        )

    if debug_finding.get("type") in {"RISKY_HTTP_METHODS_ENABLED", "HTTP_PUT_UPLOAD_CAPABILITY", "HTTP_DELETE_CAPABILITY"}:
        primary = select_primary_evidence(debug_finding, limit=5)
        debug_finding["primary_evidence"] = sorted(primary, key=_primary_evidence_sort_key)

    evidence = debug_finding.get("evidence") or {}
    if isinstance(evidence, dict) and evidence.get("file_paths"):
        evidence = dict(evidence)
        evidence["file_paths"] = _dedup_str_list(evidence.get("file_paths") or [], limit=10)
        debug_finding["evidence"] = evidence

    return debug_finding
