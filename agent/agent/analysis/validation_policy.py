from __future__ import annotations

from typing import Any, Dict

from agent.core.evidence_policy import (
    has_strong_config_evidence,
    has_strong_log_evidence,
    has_strong_phpinfo_evidence,
    is_direct_200_observation,
    is_low_value_disclosure,
)
from agent.findings.types import AMBIGUOUS_TYPES, CONCRETE_EXPOSURE_TYPES, DETERMINISTIC_TYPES
from agent.llm_client import normalize_exposure_with_llm


def _evidence(candidate: Dict[str, Any]) -> Dict[str, Any]:
    ev = candidate.get("evidence") or {}
    return ev if isinstance(ev, dict) else {}


def _severity_rank(sev: str) -> int:
    order = {"Info": 1, "Low": 2, "Medium": 3, "High": 4}
    return order.get(str(sev or "Info"), 1)


def _min_severity(a: str, b: str) -> str:
    return a if _severity_rank(a) <= _severity_rank(b) else b


def _max_severity(a: str, b: str) -> str:
    return a if _severity_rank(a) >= _severity_rank(b) else b


def _ensure_verification(candidate: Dict[str, Any]) -> Dict[str, Any]:
    candidate.setdefault("verification", {})
    verification = candidate["verification"]
    if not isinstance(verification, dict):
        verification = {}
        candidate["verification"] = verification
    return verification


def _apply_final_verdict_state(candidate: Dict[str, Any]) -> Dict[str, Any]:
    raw_items = candidate.get("exposed_information_raw")
    if not isinstance(raw_items, list) or not raw_items:
        raw_items = list(candidate.get("exposed_information") or [])
    candidate["exposed_information_raw"] = [str(x).strip() for x in raw_items if str(x).strip()][:8]

    try:
        reviewed = normalize_exposure_with_llm(
            candidate["exposed_information_raw"],
            str(candidate.get("final_severity") or candidate.get("severity") or "Info"),
            str(candidate.get("title") or ""),
        )
    except Exception:
        reviewed = {
            "exposed_information_normalized": candidate["exposed_information_raw"][:5],
            "severity_reason": [],
            "evidence_review": {"mode": "fallback_error"},
        }

    normalized_items = [
        str(x).strip()
        for x in (reviewed.get("exposed_information_normalized") or [])
        if str(x).strip()
    ][:6]
    if normalized_items:
        candidate["normalized_exposed_information"] = normalized_items
    else:
        candidate.pop("normalized_exposed_information", None)

    review_meta = reviewed.get("evidence_review")
    if isinstance(review_meta, dict) and review_meta:
        candidate["llm_evidence_review"] = review_meta

    verification = _ensure_verification(candidate)
    verdict = str(verification.get("verdict") or "").upper()

    if verdict == "FALSE_POSITIVE":
        candidate["final_severity"] = "Info"
        candidate["severity"] = "Info"
        candidate["severity_validation_reason"] = "Marked as false positive after verification."
        return candidate

    if verdict == "INFORMATIONAL":
        final_sev = str(candidate.get("final_severity") or "Info")
        candidate["final_severity"] = final_sev
        candidate["severity"] = final_sev
        if not candidate.get("severity_validation_reason"):
            candidate["severity_validation_reason"] = "Informational signal retained after validation."
        return candidate

    if verdict == "CONFIRMED":
        final_sev = str(candidate.get("final_severity") or candidate.get("severity") or "Info")
        candidate["final_severity"] = final_sev
        candidate["severity"] = final_sev
        return candidate

    candidate["final_severity"] = str(candidate.get("final_severity") or candidate.get("severity") or "Info")
    candidate["severity"] = candidate["final_severity"]
    return candidate


def _has_local_file_path(candidate: Dict[str, Any]) -> bool:
    evidence = _evidence(candidate)
    file_paths = evidence.get("file_paths") or []

    for path in file_paths:
        s = str(path or "").strip().lower()
        if s.startswith(("/var/", "/usr/", "/opt/", "/home/", "/etc/", "/app/", "/workspace/")):
            return True
        if ":\\" in s:
            return True
    return False


def _meaningful_stack_trace_values(items: list[Any]) -> list[str]:
    out: list[str] = []
    for item in items or []:
        value = " ".join(str(item or "").replace("\ufffd", "").split()).strip()
        lowered = value.lower()
        if not value:
            continue
        if lowered in {"fatal error", "stack trace", "exception", "traceback", "stack trace: fatal error"}:
            continue
        if len(value) < 18:
            continue
        if any(token in lowered for token in ("<span", "</span>", "color:", "&lt;span")):
            continue
        if any(marker in lowered for marker in (" in /", " on line ", "traceback (most recent call last)", "caused by:", "#0 ", "stack trace:")):
            out.append(value)
    return out


def _meaningful_db_error_values(items: list[Any]) -> list[str]:
    out: list[str] = []
    for item in items or []:
        value = " ".join(str(item or "").replace("\ufffd", "").split()).strip()
        lowered = value.lower()
        if not value:
            continue
        if lowered in {"sqlite3.", "sqlite3", "mysql", "postgres", "oracle"}:
            continue
        if len(value) < 18:
            continue
        if any(token in lowered for token in ("<span", "</span>", "color:", "&lt;span")):
            continue
        if any(marker in lowered for marker in ("sqlstate", "syntax error", "odbc", "pdoexception", "mysqli", "postgresql", "oracle error", "sqlite error", "database error", "query failed", "sql error", "warning: mysql", "warning: mysqli", "ora-")):
            out.append(value)
    return out


def _is_concrete_error_disclosure(candidate: Dict[str, Any]) -> bool:
    evidence = _evidence(candidate)
    status_code = candidate.get("status_code") or evidence.get("status_code")

    stack_traces = _meaningful_stack_trace_values(evidence.get("stack_traces") or [])
    file_paths = evidence.get("file_paths") or []
    db_errors = _meaningful_db_error_values(evidence.get("db_errors") or [])
    debug_hints = evidence.get("debug_hints") or []
    default_error_hint = evidence.get("default_error_hint")

    if db_errors and (status_code in {400, 401, 403, 404, 405, 500, 502, 503} or stack_traces or len(debug_hints) >= 1):
        return True

    if stack_traces:
        return True

    if file_paths and _has_local_file_path(candidate):
        return True

    if status_code in {400, 401, 403, 404, 405, 500, 502, 503}:
        if file_paths or stack_traces or db_errors:
            return True

    if default_error_hint and len(debug_hints) >= 2 and (file_paths or stack_traces or db_errors):
        return True

    return False

def _has_concrete_system_info(candidate: Dict[str, Any]) -> bool:
    evidence = _evidence(candidate)

    strong_versions = evidence.get("strong_version_tokens_in_body") or []
    internal_ips = evidence.get("internal_ips") or []
    body_markers = evidence.get("body_info_markers") or []
    framework_hints = evidence.get("framework_hints") or []
    debug_hints = evidence.get("debug_hints") or []
    stack_traces = evidence.get("stack_traces") or []
    db_errors = evidence.get("db_errors") or []
    file_paths = evidence.get("file_paths") or []
    decision_reasons = evidence.get("decision_reasons") or []
    response_kind = str(evidence.get("response_kind") or "").lower()

    # HTML shell / weak document-like ?섏씠吏??concrete system info濡?蹂댁? ?딆쓬
    if response_kind == "static_asset":
        return False

    # strong version token? concrete
    if strong_versions:
        return True

    # internal IP??debug/error context媛 媛숈씠 ?덉쓣 ?뚮쭔 concrete
    if internal_ips and (framework_hints or debug_hints or stack_traces or db_errors or file_paths):
        return True

    # 媛뺥븳 ?쒗뭹/?꾨젅?꾩썙??諛곕꼫 留덉빱
    strong_body_markers = [
        x for x in body_markers
        if any(tok in str(x).lower() for tok in (
            "apache tomcat/",
            "jboss eap",
            "wildfly/",
            "undertow/",
            "weblogic",
            "websphere",
            "spring boot",
            "django ",
            "flask ",
            "laravel ",
            "asp.net",
            "wordpress",
            "drupal",
            "struts",
        ))
    ]
    if strong_body_markers:
        return True

    # classifier媛 ?대? ?ㅼ쨷 ?뚰듃濡??щ┛ 寃쎌슦留??쒗븳?곸쑝濡??몄젙
    if "multi_hint_disclosure" in [str(x) for x in decision_reasons]:
        if len(framework_hints) + len(debug_hints) >= 2:
            return True

    return False

def _has_concrete_default_resource_exposure(candidate: Dict[str, Any]) -> bool:
    evidence = _evidence(candidate)
    subtype = str(candidate.get("subtype") or "")

    phpinfo_indicators = evidence.get("phpinfo_indicators") or []
    config_markers = evidence.get("config_exposure_markers") or []
    log_patterns = evidence.get("log_exposure_patterns") or []
    default_hints = evidence.get("default_file_hints") or []
    body_snippet = str(evidence.get("body_snippet") or "").lower()

    if subtype == "phpinfo_page":
        return len(phpinfo_indicators) >= 2 or (
            "phpinfo()" in body_snippet and "php version" in body_snippet
        )

    if subtype == "env_file":
        return bool(config_markers)

    if subtype == "git_metadata":
        return (
            "[core]" in body_snippet
            or "repositoryformatversion" in body_snippet
            or "filemode =" in body_snippet
            or "bare =" in body_snippet
            or bool(default_hints)
        )

    if subtype == "server_status":
        return (
            "apache server status" in body_snippet
            or "server uptime" in body_snippet
            or "total accesses" in body_snippet
            or bool(default_hints)
        )

    if subtype == "actuator_endpoint":
        marker_count = 0
        for marker in ('"status"', '"components"', '"_links"', "/actuator"):
            if marker in body_snippet:
                marker_count += 1
        return marker_count >= 2

    if subtype == "debug_endpoint":
        marker_count = 0
        for marker in ("debug toolbar", "trace", "environment", "application config"):
            if marker in body_snippet:
                marker_count += 1
        return marker_count >= 2

    return bool(phpinfo_indicators or config_markers or log_patterns or default_hints)


def _cap_deterministic_severity(candidate: Dict[str, Any], current_sev: str) -> str:
    candidate_type = str(candidate.get("type") or "")
    policy_object = str(candidate.get("policy_object") or "").lower()

    if candidate_type == "HTTPS_REDIRECT_MISSING":
        return "Info"

    if candidate_type == "HSTS_MISSING":
        return _min_severity(current_sev, "Low")

    if candidate_type == "COOKIE_HTTPONLY_MISSING":
        return _min_severity(current_sev, "Low")

    if candidate_type == "COOKIE_SECURE_MISSING":
        return _min_severity(current_sev, "Low")

    if candidate_type == "COOKIE_SAMESITE_MISSING":
        return "Info"

    if candidate_type == "TRACE_ENABLED":
        return _min_severity(current_sev, "Medium")

    if candidate_type == "RISKY_HTTP_METHODS_ENABLED":
        return "Info"

    if candidate_type in {"HTTP_PUT_UPLOAD_CAPABILITY", "HTTP_DELETE_CAPABILITY"}:
        return _max_severity(current_sev, "Medium")

    if candidate_type == "CLICKJACKING":
        return _min_severity(current_sev, "Low")

    if candidate_type == "CSP_MISSING":
        return _min_severity(current_sev, "Low")

    if candidate_type == "CONTENT_TYPE_SNIFFING":
        return _min_severity(current_sev, "Low")

    if candidate_type in {"REFERRER_POLICY_MISSING", "PERMISSIONS_POLICY_MISSING"}:
        return "Info"

    if candidate_type == "CORS_MISCONFIG":
        return current_sev

    if candidate_type == "DIRECTORY_LISTING_ENABLED":
        return _max_severity(current_sev, "Medium")

    if candidate_type == "SECURITY_HEADERS_MISSING":
        if policy_object in {"content-security-policy", "x-frame-options", "x-content-type-options"}:
            return _min_severity(current_sev, "Low")
        return "Info"

    return current_sev

def _is_phpinfo_route_error_false_positive(candidate: Dict[str, Any]) -> bool:
    if str(candidate.get("type") or "") != "HTTP_ERROR_INFO_EXPOSURE":
        return False

    evidence = _evidence(candidate)

    final_url = str(evidence.get("final_url") or "").lower()
    requested_url = str(evidence.get("requested_url") or "").lower()
    subtype = str(candidate.get("subtype") or "")

    route_hint = any(
        tok in (final_url + " " + requested_url)
        for tok in ("phpinfo.php", "/phpinfo", "/info.php")
    )
    if not route_hint:
        return False

    stack_traces = evidence.get("stack_traces") or []
    file_paths = evidence.get("file_paths") or []
    db_errors = _meaningful_db_error_values(evidence.get("db_errors") or [])
    phpinfo_indicators = evidence.get("phpinfo_indicators") or []

    # 吏꾩쭨 stack/file path ?몄텧?대㈃ error finding ?좎? 媛??
    if _meaningful_stack_trace_values(stack_traces):
        return False
    if file_paths and _has_local_file_path(candidate):
        return False

    # phpinfo 寃쎈줈?먯꽌 db_error留??쏀븯寃?嫄몃┛ 寃쎌슦???ㅽ깘 泥섎━
    if subtype == "db_error" and (db_errors or phpinfo_indicators):
        return True

    # phpinfo ?뚰듃媛 ?덈뒗??concrete error artifact媛 ?놁쑝硫??ㅽ깘
    if phpinfo_indicators and not stack_traces and not file_paths:
        return True

    return False

def _cap_ambiguous_confirmed_severity(candidate: Dict[str, Any], current_sev: str) -> str:
    candidate_type = str(candidate.get("type") or "")

    if candidate_type in {"PHPINFO_EXPOSURE", "HTTP_CONFIG_FILE_EXPOSURE", "LOG_VIEWER_EXPOSURE"}:
        return _max_severity(current_sev, "Medium")

    if candidate_type in {"HTTP_ERROR_INFO_EXPOSURE", "FILE_PATH_HANDLING_ANOMALY"}:
        return _max_severity(current_sev, "Medium")

    if candidate_type == "HTTP_SYSTEM_INFO_EXPOSURE":
        return _max_severity(current_sev, "Low")

    if candidate_type == "DEFAULT_FILE_EXPOSED":
        return _max_severity(current_sev, "Medium") if _has_concrete_default_resource_exposure(candidate) else "Info"

    return current_sev


def _set_informational(
    candidate: Dict[str, Any],
    *,
    reason: str,
    severity: str = "Info",
) -> Dict[str, Any]:
    verification = _ensure_verification(candidate)
    candidate["final_severity"] = severity
    candidate["severity"] = severity
    candidate["severity_validation_reason"] = reason
    verification["verdict"] = "INFORMATIONAL"
    verification["reason"] = verification.get("reason") or reason
    return _apply_final_verdict_state(candidate)


def _set_confirmed(
    candidate: Dict[str, Any],
    *,
    reason: str,
    severity: str | None = None,
) -> Dict[str, Any]:
    verification = _ensure_verification(candidate)
    final_sev = severity or str(candidate.get("final_severity") or candidate.get("severity") or "Info")
    candidate["final_severity"] = final_sev
    candidate["severity"] = final_sev
    candidate["severity_validation_reason"] = reason
    verification["verdict"] = "CONFIRMED"
    verification["reason"] = verification.get("reason") or reason
    return _apply_final_verdict_state(candidate)

def validate_candidate_after_llm(candidate: Dict[str, Any]) -> Dict[str, Any]:
    candidate_type = str(candidate.get("type") or "")
    current_sev = str(candidate.get("severity") or "Info")
    candidate["llm_severity"] = current_sev

    verification = _ensure_verification(candidate)
    existing_verdict = str(verification.get("verdict") or "").upper()

    # ------------------------------------------------------------
    # actively confirmed capability findings
    # ------------------------------------------------------------
    if candidate_type == "RISKY_HTTP_METHODS_ENABLED":
        evidence = _evidence(candidate)
        observed_caps = sorted({str(x).upper() for x in (evidence.get("risky_methods_enabled") or []) if x})
        candidate["final_severity"] = "Info"
        candidate["severity"] = "Info"
        candidate["severity_validation_reason"] = (
            "Risky methods were observed or handled, but this root finding remains informational."
        )
        verification["verdict"] = "INFORMATIONAL"
        verification["reason"] = (
            "Observed risky HTTP method handling without confirmed exploitability."
            + (f" Observed methods: {', '.join(observed_caps)}." if observed_caps else "")
        )
        return _apply_final_verdict_state(candidate)

    if candidate_type in {"HTTP_PUT_UPLOAD_CAPABILITY", "HTTP_DELETE_CAPABILITY"}:
        candidate["final_severity"] = _max_severity(current_sev, "Medium")
        candidate["severity"] = candidate["final_severity"]

        if candidate_type == "HTTP_PUT_UPLOAD_CAPABILITY":
            verification["verdict"] = "CONFIRMED"
            verification["reason"] = (
                verification.get("reason")
                or "Confirmed HTTP PUT upload capability by uploading a canary resource and retrieving it successfully."
            )
            candidate["severity_validation_reason"] = (
                "Arbitrary PUT upload capability was actively confirmed with retrieval verification."
            )
        else:
            verification["verdict"] = "CONFIRMED"
            verification["reason"] = (
                verification.get("reason")
                or "Confirmed HTTP DELETE capability by deleting a canary resource and verifying that it was no longer accessible."
            )
            candidate["severity_validation_reason"] = (
                "HTTP DELETE capability was actively confirmed with post-delete absence verification."
            )

        return _apply_final_verdict_state(candidate)

    # ------------------------------------------------------------
    # explicit false positive wins
    # ------------------------------------------------------------
    if existing_verdict == "FALSE_POSITIVE":
        candidate["final_severity"] = "Info"
        candidate["severity"] = "Info"
        candidate["severity_validation_reason"] = "Marked as false positive after verification."
        return _apply_final_verdict_state(candidate)

    # ------------------------------------------------------------
    # deterministic findings
    # ------------------------------------------------------------
    if candidate_type in DETERMINISTIC_TYPES:
        candidate["final_severity"] = _cap_deterministic_severity(candidate, current_sev)
        candidate["severity"] = candidate["final_severity"]
        candidate["severity_validation_reason"] = "Deterministic HTTP finding normalized by validation policy."

        if candidate_type == "HTTPS_REDIRECT_MISSING":
            verification["verdict"] = "INFORMATIONAL"
            verification["reason"] = "Informational transport-security posture."
        else:
            verification["verdict"] = "CONFIRMED"
            verification["reason"] = verification.get("reason") or "Confirmed deterministic HTTP finding."

        return _apply_final_verdict_state(candidate)

    # ------------------------------------------------------------
    # ambiguous findings
    # ------------------------------------------------------------
    if candidate_type in AMBIGUOUS_TYPES:
        # phpinfo route?먯꽌 ?섎せ 遺숈? error disclosure ?좎젣 李⑤떒
        if _is_phpinfo_route_error_false_positive(candidate):
            verification["verdict"] = "FALSE_POSITIVE"
            verification["reason"] = (
                "phpinfo-like route produced weak DB/debug-like text without concrete stack trace or local file path disclosure."
            )
            candidate["final_severity"] = "Info"
            candidate["severity"] = "Info"
            candidate["severity_validation_reason"] = (
                "Weak phpinfo-route error signal was classified as false positive."
            )
            return _apply_final_verdict_state(candidate)

        # already confirmed -> keep, but cap sanely
        if existing_verdict == "CONFIRMED":
            if candidate_type == "DEFAULT_FILE_EXPOSED":
                if not _has_concrete_default_resource_exposure(candidate):
                    return _set_informational(
                        candidate,
                        reason="Resource-like path was reproducible, but concrete resource content exposure was not established.",
                        severity="Info",
                    )

            capped = _cap_ambiguous_confirmed_severity(candidate, current_sev)
            return _set_confirmed(
                candidate,
                reason="Ambiguous finding retained as confirmed after verification.",
                severity=capped,
            )

        if is_low_value_disclosure(candidate):
            return _set_informational(
                candidate,
                reason="Low-value or weak disclosure signal downgraded to informational.",
                severity="Info",
            )

        if candidate_type == "HTTP_ERROR_INFO_EXPOSURE":
            if _is_concrete_error_disclosure(candidate):
                capped = _cap_ambiguous_confirmed_severity(candidate, current_sev)
                return _set_confirmed(
                    candidate,
                    reason="Concrete error disclosure with internal artifacts was directly observed.",
                    severity=capped,
                )
            return _set_informational(
                candidate,
                reason="Error disclosure signal was observed, but concrete internal exposure was not strong enough to confirm.",
                severity="Info",
            )

        if candidate_type == "HTTP_SYSTEM_INFO_EXPOSURE":
            if _has_concrete_system_info(candidate):
                candidate["final_severity"] = _cap_ambiguous_confirmed_severity(candidate, current_sev)
                candidate["severity"] = candidate["final_severity"]
                candidate["severity_validation_reason"] = (
                    "Concrete body-based system information disclosure retained after validation."
                )
                if verification.get("verdict") not in {"CONFIRMED", "INFORMATIONAL"}:
                    verification["verdict"] = "INFORMATIONAL"
                    verification["reason"] = "Concrete system-information markers observed in response body."
                return _apply_final_verdict_state(candidate)

            return _set_informational(
                candidate,
                reason="Weak body fingerprint was kept informational and not escalated.",
                severity="Info",
            )

        if candidate_type in CONCRETE_EXPOSURE_TYPES and is_direct_200_observation(candidate):
            concrete_ok = (
                (candidate_type == "PHPINFO_EXPOSURE" and has_strong_phpinfo_evidence(candidate))
                or (candidate_type == "HTTP_CONFIG_FILE_EXPOSURE" and has_strong_config_evidence(candidate))
                or (candidate_type == "LOG_VIEWER_EXPOSURE" and has_strong_log_evidence(candidate))
            )

            if concrete_ok:
                candidate["final_severity"] = _cap_ambiguous_confirmed_severity(candidate, current_sev)
                candidate["severity"] = candidate["final_severity"]
                candidate["severity_validation_reason"] = (
                    "Concrete exposure was directly observed in a 200 response."
                )

                if verification.get("verdict") not in {"CONFIRMED", "INFORMATIONAL"}:
                    verification["verdict"] = "INFORMATIONAL"
                    verification["reason"] = (
                        "Concrete exposure observed directly; retained meaningfully without stronger reproduce evidence."
                    )
                return _apply_final_verdict_state(candidate)

        if candidate_type == "DEFAULT_FILE_EXPOSED":
            if _has_concrete_default_resource_exposure(candidate) and is_direct_200_observation(candidate):
                candidate["final_severity"] = _cap_ambiguous_confirmed_severity(candidate, current_sev)
                candidate["severity"] = candidate["final_severity"]
                candidate["severity_validation_reason"] = (
                    "Concrete default/sensitive resource content was directly observed."
                )

                if verification.get("verdict") not in {"CONFIRMED", "INFORMATIONAL"}:
                    verification["verdict"] = "INFORMATIONAL"
                    verification["reason"] = (
                        "Concrete default resource content was observed directly."
                    )
                return _apply_final_verdict_state(candidate)

            return _set_informational(
                candidate,
                reason="Default resource signals are kept informational unless actual resource content is proven.",
                severity="Info",
            )

        return _set_informational(
            candidate,
            reason="Ambiguous finding is kept informational unless verification confirms it more strongly.",
            severity="Info",
        )

    # ------------------------------------------------------------
    # fallback
    # ------------------------------------------------------------
    return _set_informational(
        candidate,
        reason="Unclassified or weak signal downgraded to informational.",
        severity="Info",
    )


def verdict_dirname(verdict: str) -> str:
    verdict = str(verdict or "").upper()
    if verdict == "CONFIRMED":
        return "confirmed"
    if verdict == "FALSE_POSITIVE":
        return "false_positive"
    return "informational"
