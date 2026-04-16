from __future__ import annotations

from typing import Any, Dict, List

from agent.detection.extractors import extract_all_signals
from agent.detection.patterns import DisclosureSignal, DisclosureType, Severity


def _dedup(items: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items or []:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _severity_value(severity: Severity) -> str:
    mapping = {
        Severity.CRITICAL: "High",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Info",
    }
    return mapping.get(severity, "Info")


def _confidence_value(signal: DisclosureSignal) -> float:
    try:
        confidence = float(signal.confidence)
    except Exception:
        confidence = 0.5
    return max(0.0, min(confidence, 1.0))


def _base_evidence(
    *,
    signal: DisclosureSignal,
    requested_url: str,
    final_url: str,
    status_code: int | None,
) -> Dict[str, Any]:
    return {
        "requested_url": requested_url,
        "final_url": final_url or requested_url,
        "status_code": status_code,
        "detector_location": signal.location,
        "detector_context": signal.context or {},
        "detector_evidence": _dedup(signal.evidence),
    }


def _technology_fingerprint(feats: Dict[str, Any]) -> List[str]:
    return _dedup([str(x).strip() for x in (feats.get("technology_fingerprint") or []) if str(x).strip()])


def _clean_signal_evidence(items: List[str]) -> List[str]:
    out: List[str] = []
    for item in items or []:
        value = str(item or "").replace("\ufffd", "").strip()
        value = " ".join(value.split())
        if not value:
            continue
        out.append(value)
    return _dedup(out)


def _is_low_value_stack_trace(items: List[str]) -> bool:
    cleaned = _clean_signal_evidence(items)
    if not cleaned:
        return True
    meaningful_markers = (" in /", " on line ", "traceback (most recent call last)", "caused by:", "#0 ", "stack trace:")
    meaningful = [
        item for item in cleaned
        if any(marker in item.lower() for marker in meaningful_markers)
        and not any(token in item.lower() for token in ("<span", "</span>", "color:", "&lt;span"))
    ]
    return not meaningful


def _is_low_value_db_error(items: List[str]) -> bool:
    cleaned = _clean_signal_evidence(items)
    if not cleaned:
        return True
    joined = " ".join(cleaned).lower()
    if any(token in joined for token in ("<span", "</span>", "color:", "&lt;span")):
        return True
    if cleaned == ["sqlite3."] or cleaned == ["sqlite3"]:
        return True
    strong_markers = (
        "sqlstate",
        "syntax error",
        "mysqli",
        "pdoexception",
        "warning: mysql",
        "warning: mysqli",
        "postgresql",
        "sqlite error",
        "database error #",
        "database error:",
        "query failed",
        "ora-",
        "sql error",
    )
    return not any(marker in joined for marker in strong_markers)


def _is_marker_only_config_signal(items: List[str]) -> bool:
    cleaned = _clean_signal_evidence(items)
    if not cleaned:
        return True
    if len(cleaned) == 1 and cleaned[0].lower() in {"db_password", "db_user", "database", "config", "<?php\\s"}:
        return True
    return all(
        len(item) <= 32
        and ":" not in item
        and "=" not in item
        and "\n" not in item
        for item in cleaned
    )


def _classification_kind_for_detector(signal: DisclosureSignal, evidence_items: List[str]) -> str:
    if signal.disclosure_type in {
        DisclosureType.VERSION_DISCLOSURE,
        DisclosureType.FRAMEWORK_HINT,
        DisclosureType.INTERNAL_STRUCTURE,
    }:
        return "supporting_signal"
    if signal.disclosure_type == DisclosureType.STACK_TRACE and _is_low_value_stack_trace(evidence_items):
        return "supporting_signal"
    if signal.disclosure_type == DisclosureType.DB_ERROR and _is_low_value_db_error(evidence_items):
        return "supporting_signal"
    if signal.disclosure_type in {DisclosureType.CONFIG_EXPOSURE, DisclosureType.SOURCE_CODE}:
        return "supporting_signal"
    return "finding"


def _looks_like_setup_or_install_page(final_url: str, body_text: str) -> bool:
    final_url_l = str(final_url or "").lower()
    body_l = str(body_text or "").lower()
    return any(token in final_url_l for token in ("setup", "install", "installer", "instructions")) or any(
        token in body_l for token in ("setup", "installation", "installer", "instructions")
    )


def _has_strong_config_payload(feats: Dict[str, Any]) -> bool:
    extracted_values = feats.get("config_extracted_values") or []
    real_values = [
        item
        for item in extracted_values
        if isinstance(item, dict) and not bool(item.get("masked"))
    ]
    if len(real_values) >= 3:
        return True

    key_classes = set()
    for item in extracted_values:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip().lower()
        value = str(item.get("value") or "").strip()
        if not key:
            continue
        if not value or value.lower() in {"array (", "array(", "{}", "[]", "null", "none"}:
            continue
        if "password" in key:
            key_classes.add("db_password")
        if key in {"db_host", "database_host", "host"}:
            key_classes.add("db_host")
        if key in {"db_name", "database", "dbname"}:
            key_classes.add("db_name")
        if key in {"db_user", "database_user", "username", "user"}:
            key_classes.add("db_user")
        if "secret" in key or "api_key" in key or "access_key" in key:
            key_classes.add("secret")

    if len(key_classes.intersection({"db_host", "db_name", "db_user", "db_password"})) >= 3:
        return True
    if "secret" in key_classes or "db_password" in key_classes:
        return True
    return False


def _why_and_rec(disclosure_type: DisclosureType) -> tuple[str, List[str]]:
    mapping = {
        DisclosureType.STACK_TRACE: (
            "Stack trace exposure can reveal internal code structure, classes, and execution paths.",
            [
                "Return generic error pages in production.",
                "Disable verbose exception and stack trace output for end users.",
            ],
        ),
        DisclosureType.FILE_PATH: (
            "Filesystem path exposure can reveal deployment layout and sensitive server-side file locations.",
            [
                "Remove local filesystem paths from responses.",
                "Normalize file handling errors into generic messages.",
            ],
        ),
        DisclosureType.DB_ERROR: (
            "Database error details can help attackers understand schema and injection points.",
            [
                "Handle database exceptions with generic client-facing errors.",
                "Avoid returning SQL errors or driver messages in HTTP responses.",
            ],
        ),
        DisclosureType.CONFIG_EXPOSURE: (
            "Configuration exposure may leak secrets, internal endpoints, or deployment details.",
            [
                "Prevent direct access to config-like resources.",
                "Strip secrets and internal configuration values from responses.",
            ],
        ),
        DisclosureType.SOURCE_CODE: (
            "Source code disclosure may reveal implementation details, secrets, and vulnerable logic.",
            [
                "Ensure source files are never served directly.",
                "Block access to development and template artifacts in production.",
            ],
        ),
    }
    return mapping.get(
        disclosure_type,
        (
            "The response exposes internal implementation or environment details that can assist further attacks.",
            ["Reduce response verbosity and remove unnecessary internal details from production responses."],
        ),
    )


def _build_signal(
    *,
    signal: DisclosureSignal,
    finding_type: str,
    family: str,
    subtype: str,
    title: str,
    where: str,
    leak_type: str,
    leak_value: str,
    scope_hint: str,
    policy_object: str,
    root_cause_signature: str,
    cwe: str | None,
    owasp: str,
    exposed_information: List[str],
    evidence: Dict[str, Any],
    feats: Dict[str, Any],
) -> Dict[str, Any]:
    why, recommendation = _why_and_rec(signal.disclosure_type)
    return {
        "signal_type": "detector_enrichment",
        "finding_type": finding_type,
        "family": family,
        "subtype": subtype,
        "title": title,
        "severity": _severity_value(signal.severity),
        "confidence": _confidence_value(signal),
        "where": where,
        "evidence": evidence,
        "exposed_information": _dedup(exposed_information),
        "leak_type": leak_type,
        "leak_value": leak_value,
        "cwe": cwe,
        "owasp": owasp,
        "scope_hint": scope_hint,
        "policy_object": policy_object,
        "root_cause_signature": root_cause_signature,
        "technology_fingerprint": _technology_fingerprint(feats),
        "why_it_matters": why,
        "recommendation": recommendation,
        "signal_strength": "strong",
        "signal_repeatability": "likely_stable",
        "observation_scope": "route_behavior",
        "verification_strategy": "rule_based_detector",
        "classification_kind": _classification_kind_for_detector(signal, exposed_information),
        "burp_zap_aligned": True,
    }


def build_detector_disclosure_signals(
    *,
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    info_skip: bool,
) -> List[Dict[str, Any]]:
    body = str(feats.get("body_text") or snapshot.get("body_text") or snapshot.get("body_snippet") or "")
    headers = snapshot.get("headers") or {}
    requested_url = str(request_meta.get("url") or "")
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or requested_url)
    status_code = feats.get("status_code") or snapshot.get("status_code")
    setup_or_install_page = _looks_like_setup_or_install_page(final_url, body)

    if not body and not headers:
        return []

    try:
        detector_signals = extract_all_signals(
            body=body,
            headers=headers if isinstance(headers, dict) else dict(headers),
            url=final_url,
            status_code=int(status_code) if isinstance(status_code, int) else 0,
        )
    except Exception:
        return []

    out: List[Dict[str, Any]] = []

    for signal in detector_signals:
        evidence = _base_evidence(
            signal=signal,
            requested_url=requested_url,
            final_url=final_url,
            status_code=status_code,
        )

        if signal.disclosure_type == DisclosureType.STACK_TRACE:
            evidence["stack_traces"] = _dedup(signal.evidence)
            out.append(
                _build_signal(
                    signal=signal,
                    finding_type="HTTP_ERROR_INFO_EXPOSURE",
                    family="HTTP_ERROR_DISCLOSURE",
                    subtype="detector_stack_trace",
                    title="Stack Trace Exposed In HTTP Response",
                    where="response.body",
                    leak_type="stack_trace",
                    leak_value=evidence["stack_traces"][0] if evidence["stack_traces"] else "",
                    scope_hint="route-specific",
                    policy_object="error_response",
                    root_cause_signature="error:stack_trace_exposed",
                    cwe="CWE-209",
                    owasp="A05:2021 Security Misconfiguration",
                    exposed_information=evidence["stack_traces"],
                    evidence=evidence,
                    feats=feats,
                )
            )
            continue

        if signal.disclosure_type == DisclosureType.DB_ERROR:
            evidence["db_errors"] = _dedup(signal.evidence)
            out.append(
                _build_signal(
                    signal=signal,
                    finding_type="HTTP_ERROR_INFO_EXPOSURE",
                    family="HTTP_ERROR_DISCLOSURE",
                    subtype="detector_db_error",
                    title="Database Error Details Exposed",
                    where="response.body",
                    leak_type="database_error",
                    leak_value=evidence["db_errors"][0] if evidence["db_errors"] else "",
                    scope_hint="route-specific",
                    policy_object="error_response",
                    root_cause_signature="error:db_error_exposed",
                    cwe="CWE-209",
                    owasp="A05:2021 Security Misconfiguration",
                    exposed_information=evidence["db_errors"],
                    evidence=evidence,
                    feats=feats,
                )
            )
            continue

        if signal.disclosure_type == DisclosureType.FILE_PATH:
            if setup_or_install_page:
                continue
            evidence["file_paths"] = _dedup(signal.evidence)
            out.append(
                _build_signal(
                    signal=signal,
                    finding_type="FILE_PATH_HANDLING_ANOMALY",
                    family="HTTP_BODY_DISCLOSURE",
                    subtype="detector_file_path",
                    title="Filesystem Path Exposed In HTTP Response",
                    where="response.body",
                    leak_type="file_path",
                    leak_value=evidence["file_paths"][0] if evidence["file_paths"] else "",
                    scope_hint="route-specific",
                    policy_object="error_response",
                    root_cause_signature="body:file_path_exposed",
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    exposed_information=evidence["file_paths"],
                    evidence=evidence,
                    feats=feats,
                )
            )
            continue

        if signal.disclosure_type == DisclosureType.CONFIG_EXPOSURE:
            if not _has_strong_config_payload(feats):
                continue
            evidence["config_exposure_markers"] = _dedup(signal.evidence)
            if _is_marker_only_config_signal(evidence["config_exposure_markers"]):
                continue
            out.append(
                _build_signal(
                    signal=signal,
                    finding_type="HTTP_CONFIG_FILE_EXPOSURE",
                    family="HTTP_BODY_DISCLOSURE",
                    subtype="detector_config_exposure",
                    title="Configuration-Like Data Exposed",
                    where=f"response.{signal.location or 'body'}",
                    leak_type="config_exposure",
                    leak_value=evidence["config_exposure_markers"][0] if evidence["config_exposure_markers"] else "",
                    scope_hint="route-specific",
                    policy_object="response_body",
                    root_cause_signature="body:config_data_exposed",
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    exposed_information=evidence["config_exposure_markers"],
                    evidence=evidence,
                    feats=feats,
                )
            )
            continue

        if signal.disclosure_type == DisclosureType.SOURCE_CODE:
            if not _has_strong_config_payload(feats):
                continue
            evidence["source_code_markers"] = _dedup(signal.evidence)
            if _is_marker_only_config_signal(evidence["source_code_markers"]):
                continue
            out.append(
                _build_signal(
                    signal=signal,
                    finding_type="HTTP_CONFIG_FILE_EXPOSURE",
                    family="HTTP_BODY_DISCLOSURE",
                    subtype="detector_source_code",
                    title="Source Code Markers Exposed",
                    where="response.body",
                    leak_type="source_code",
                    leak_value=evidence["source_code_markers"][0] if evidence["source_code_markers"] else "",
                    scope_hint="route-specific",
                    policy_object="response_body",
                    root_cause_signature="body:source_code_marker_exposed",
                    cwe="CWE-200",
                    owasp="A05:2021 Security Misconfiguration",
                    exposed_information=evidence["source_code_markers"],
                    evidence=evidence,
                    feats=feats,
                )
            )
            continue

        if info_skip:
            continue

        if signal.disclosure_type in {
            DisclosureType.VERSION_DISCLOSURE,
            DisclosureType.FRAMEWORK_HINT,
            DisclosureType.INTERNAL_IP,
            DisclosureType.DEBUG_INFO,
            DisclosureType.VERBOSE_ERROR,
            DisclosureType.INTERNAL_STRUCTURE,
        }:
            subtype_map = {
                DisclosureType.VERSION_DISCLOSURE: "detector_version_disclosure",
                DisclosureType.FRAMEWORK_HINT: "detector_framework_hint",
                DisclosureType.INTERNAL_IP: "detector_internal_ip",
                DisclosureType.DEBUG_INFO: "detector_debug_info",
                DisclosureType.VERBOSE_ERROR: "detector_verbose_error",
                DisclosureType.INTERNAL_STRUCTURE: "detector_internal_structure",
            }
            finding_type = "HTTP_SYSTEM_INFO_EXPOSURE"
            leak_type = "system_info"
            cwe = "CWE-497"
            if signal.disclosure_type in {DisclosureType.DEBUG_INFO, DisclosureType.VERBOSE_ERROR}:
                finding_type = "HTTP_ERROR_INFO_EXPOSURE"
                leak_type = "debug_info"
                cwe = "CWE-209"

            out.append(
                _build_signal(
                    signal=signal,
                    finding_type=finding_type,
                    family="HTTP_BODY_DISCLOSURE",
                    subtype=subtype_map[signal.disclosure_type],
                    title="Internal System Information Exposed",
                    where=f"response.{signal.location or 'body'}",
                    leak_type=leak_type,
                    leak_value=_dedup(signal.evidence)[0] if _dedup(signal.evidence) else "",
                    scope_hint="route-specific",
                    policy_object="response_body",
                    root_cause_signature=f"body:{subtype_map[signal.disclosure_type]}",
                    cwe=cwe,
                    owasp="A05:2021 Security Misconfiguration",
                    exposed_information=_dedup(signal.evidence),
                    evidence=evidence,
                    feats=feats,
                )
            )

    return out
