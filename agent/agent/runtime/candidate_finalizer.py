from __future__ import annotations

import re
from typing import Any, Dict, List


def _candidate_status_code(candidate: Dict[str, Any], first_snapshot: Dict[str, Any]) -> int | None:
    evidence = candidate.get("evidence") or {}
    return candidate.get("status_code") or evidence.get("status_code") or first_snapshot.get("status_code")


def _candidate_redirect_location(candidate: Dict[str, Any], first_snapshot: Dict[str, Any]) -> str:
    evidence = candidate.get("evidence") or {}
    location = str(evidence.get("location") or "")
    if location:
        return location

    headers = first_snapshot.get("headers") or {}
    for key, value in headers.items():
        if str(key).lower() == "location":
            return str(value or "")
    return ""


def _is_concrete_exposure_type(candidate_type: str) -> bool:
    return candidate_type in {
        "PHPINFO_EXPOSURE",
        "HTTP_CONFIG_FILE_EXPOSURE",
        "LOG_VIEWER_EXPOSURE",
    }


def _has_concrete_body_exposure(candidate: Dict[str, Any]) -> bool:
    evidence = candidate.get("evidence") or {}
    candidate_type = str(candidate.get("type") or "")

    if candidate_type == "PHPINFO_EXPOSURE":
        indicators = evidence.get("phpinfo_indicators") or []
        return len(indicators) >= 2

    if candidate_type == "HTTP_CONFIG_FILE_EXPOSURE":
        markers = [
            str(item).strip().lower()
            for item in (evidence.get("config_exposure_markers") or [])
            if str(item).strip()
        ]
        body_hint = str(evidence.get("body_content_type_hint") or "").lower()
        final_url = str(evidence.get("final_url") or "").lower()

        strong_tokens = {
            "db_password",
            "mysql_password",
            "db_user",
            "db_host",
            "database",
            "connection_string",
            "api_key",
            "access_key",
            "aws_access_key",
            "aws_secret",
            "private_key",
        }

        config_like_path = any(
            token in final_url
            for token in (
                ".env",
                ".ini",
                ".conf",
                ".cfg",
                ".yaml",
                ".yml",
                ".json",
                ".xml",
                ".properties",
                "config",
                "settings",
                "appsettings",
                "database",
            )
        )
        config_like_body = body_hint in {"json", "json_like", "yaml", "yaml_like", "xml", "xml_like"}

        if len(set(markers).intersection(strong_tokens)) >= 1 and (config_like_path or config_like_body):
            return True
        if len(markers) >= 3 and config_like_body:
            return True
        return False

    if candidate_type == "LOG_VIEWER_EXPOSURE":
        patterns = evidence.get("log_exposure_patterns") or []
        return len(patterns) >= 2

    if candidate_type == "FILE_PATH_HANDLING_ANOMALY":
        return any(
            evidence.get(key)
            for key in ("file_paths", "stack_traces", "db_errors", "debug_hints")
        )

    return False


def _is_direct_200_exposure(first_snapshot: Dict[str, Any]) -> bool:
    if not first_snapshot.get("ok"):
        return False
    if first_snapshot.get("status_code") != 200:
        return False

    final_url = str(first_snapshot.get("final_url") or "").lower()
    headers = first_snapshot.get("headers") or {}

    location = ""
    for key, value in headers.items():
        if str(key).lower() == "location":
            location = str(value or "").lower()
            break

    if any(token in final_url for token in ("login", "signin", "/auth", "/sso")):
        return False
    if any(token in location for token in ("login", "signin", "/auth", "/sso")):
        return False

    return True


def _body_text_from_snapshot(snapshot: Dict[str, Any]) -> str:
    return str(snapshot.get("body_text") or snapshot.get("body_snippet") or "")


def _has_error_like_exposure(candidate: Dict[str, Any], snapshot: Dict[str, Any]) -> bool:
    evidence = candidate.get("evidence") or {}
    body_l = _body_text_from_snapshot(snapshot).lower()

    if evidence.get("error_exposure_class"):
        return True
    if evidence.get("stack_traces"):
        return True
    if evidence.get("file_paths"):
        return True
    if evidence.get("db_errors"):
        return True
    if evidence.get("debug_hints"):
        return True

    return any(
        token in body_l
        for token in (
            "fatal error",
            "stack trace",
            "traceback",
            "uncaught exception",
            "exception report",
        )
    )


def _has_concrete_default_resource_exposure(candidate: Dict[str, Any], snapshot: Dict[str, Any]) -> bool:
    evidence = candidate.get("evidence") or {}
    subtype = str(candidate.get("subtype") or "")
    body = _body_text_from_snapshot(snapshot)
    body_l = body.lower()

    if not _is_direct_200_exposure(snapshot):
        return False

    if _has_error_like_exposure(candidate, snapshot):
        return False

    if subtype == "phpinfo_page":
        indicators = evidence.get("phpinfo_indicators") or []
        return len(indicators) >= 2

    if subtype == "git_metadata":
        return any(
            marker in body_l
            for marker in (
                "[core]",
                "repositoryformatversion",
                "filemode = ",
                'remote "origin"',
                "bare = ",
            )
        )

    if subtype == "server_status":
        return any(
            marker in body_l
            for marker in (
                "apache server status",
                "server uptime",
                "total accesses",
                "scoreboard",
            )
        )

    if subtype == "env_file":
        env_like_lines = 0
        for line in body.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", value):
                env_like_lines += 1
                if env_like_lines >= 2:
                    return True
        return False

    if subtype in {"actuator_endpoint", "debug_endpoint"}:
        if body_l.startswith("{") and any(key in body_l for key in ('"status"', '"_links"', '"health"', '"components"')):
            return True
        if "debug toolbar" in body_l:
            return True
        return False

    return bool(evidence.get("default_file_hints") or [])


def _should_downgrade_weak_resource_signal(candidate: Dict[str, Any], first_snapshot: Dict[str, Any]) -> bool:
    candidate_type = str(candidate.get("type") or "")
    status_code = _candidate_status_code(candidate, first_snapshot)
    location = _candidate_redirect_location(candidate, first_snapshot).lower()

    if candidate_type == "DEFAULT_FILE_EXPOSED":
        if status_code in {301, 302, 303, 307, 308, 401, 403, 404}:
            return True
        if any(token in location for token in ("login", "signin", "/auth", "/sso")):
            return True
        return not _has_concrete_default_resource_exposure(candidate, first_snapshot)

    if candidate_type == "FILE_PATH_HANDLING_ANOMALY":
        return not _has_concrete_body_exposure(candidate)

    if candidate_type in {"PHPINFO_EXPOSURE", "HTTP_CONFIG_FILE_EXPOSURE", "LOG_VIEWER_EXPOSURE"}:
        if _is_direct_200_exposure(first_snapshot) and _has_concrete_body_exposure(candidate):
            return False
        return True

    return False


def _normalize_risky_http_methods_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    if str(finding.get("type") or "") != "RISKY_HTTP_METHODS_ENABLED":
        return finding

    finding = dict(finding)
    evidence = finding.setdefault("evidence", {})
    verification = finding.setdefault("verification", {})

    final_methods = sorted({
        str(method).upper().strip()
        for method in (evidence.get("risky_methods_enabled") or [])
        if str(method).strip() and str(method).upper().strip() != "TRACE"
    })

    evidence["risky_methods_enabled"] = final_methods
    evidence["method_capability_signals"] = list(dict.fromkeys(
        str(signal).strip()
        for signal in (evidence.get("method_capability_signals") or [])
        if str(signal).strip()
    ))

    finding["root_cause_signature"] = "methods:" + ",".join(final_methods)
    finding["title"] = "Risky HTTP methods appear enabled"
    finding["severity"] = "Info"
    finding["final_severity"] = "Info"
    verification["verdict"] = "INFORMATIONAL"
    verification["reason"] = (
        "Observed risky HTTP methods in server handling or allow headers. "
        "Actual upload/delete capability is tracked as separate findings."
    )
    finding["reason"] = verification["reason"]

    finding["exposed_information"] = [
        *[f"Allowed or handled risky method: {method}" for method in final_methods],
        f"Observed methods: {', '.join(final_methods)}" if final_methods else "Observed risky methods in headers/behavior",
    ]
    return finding


def _normalize_put_upload_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    if str(finding.get("type") or "") != "HTTP_PUT_UPLOAD_CAPABILITY":
        return finding

    finding = dict(finding)
    evidence = finding.setdefault("evidence", {})
    verification = finding.setdefault("verification", {})

    finding["title"] = "HTTP PUT allows upload to a web-accessible location"
    finding["severity"] = "Medium"
    finding["final_severity"] = "Medium"
    finding["root_cause_signature"] = f"put-upload:{evidence.get('candidate_url') or finding.get('where') or ''}"

    if verification.get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE"}:
        verification["verdict"] = "CONFIRMED"
    verification["reason"] = (
        "A canary resource was uploaded with HTTP PUT and then retrieved successfully from the same location."
    )
    finding["reason"] = verification["reason"]

    finding["exposed_information"] = [
        f"PUT upload target: {evidence.get('candidate_url') or finding.get('where') or ''}",
        f"PUT status: {evidence.get('put_status')}",
        f"GET verification status: {evidence.get('get_status')}",
        "Uploaded marker was retrieved successfully.",
    ]
    return finding


def _normalize_delete_capability_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    if str(finding.get("type") or "") != "HTTP_DELETE_CAPABILITY":
        return finding

    finding = dict(finding)
    evidence = finding.setdefault("evidence", {})
    verification = finding.setdefault("verification", {})

    finding["title"] = "HTTP DELETE can remove a web-accessible resource"
    finding["severity"] = "Medium"
    finding["final_severity"] = "Medium"
    finding["root_cause_signature"] = f"delete-capability:{evidence.get('candidate_url') or finding.get('where') or ''}"

    if verification.get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE"}:
        verification["verdict"] = "CONFIRMED"
    verification["reason"] = (
        "A canary resource created by the scanner was deleted with HTTP DELETE and its removal was verified."
    )
    finding["reason"] = verification["reason"]

    finding["exposed_information"] = [
        f"DELETE target: {evidence.get('candidate_url') or finding.get('where') or ''}",
        f"DELETE status: {evidence.get('delete_status')}",
        f"Post-delete verification status: {evidence.get('verify_delete_status')}",
        "Deleted canary resource was no longer accessible.",
    ]
    return finding


def _normalize_method_capability_candidates(items: Any) -> List[Dict[str, Any]]:
    if isinstance(items, list):
        raw_items = items
    elif isinstance(items, dict):
        raw_items = [items]
    else:
        raw_items = []

    out: List[Dict[str, Any]] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue

        candidate_type = str(item.get("type") or "")
        if candidate_type == "RISKY_HTTP_METHODS_ENABLED":
            out.append(_normalize_risky_http_methods_finding(item))
        elif candidate_type == "HTTP_PUT_UPLOAD_CAPABILITY":
            out.append(_normalize_put_upload_finding(item))
        elif candidate_type == "HTTP_DELETE_CAPABILITY":
            out.append(_normalize_delete_capability_finding(item))
        else:
            out.append(item)
    return out


def try_direct_finalize_candidate(candidate: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any] | None:
    candidate = dict(candidate)
    candidate_type = str(candidate.get("type") or "")
    candidate_family = str(candidate.get("family") or "")
    evidence = candidate.get("evidence") or {}

    if candidate_type == "HTTP_SYSTEM_INFO_EXPOSURE" and candidate_family == "HTTP_HEADER_DISCLOSURE":
        candidate.setdefault("verification", {})
        if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE", "INFORMATIONAL"}:
            candidate["verification"]["verdict"] = "INFORMATIONAL"
            candidate["verification"]["reason"] = (
                "Header-based system information disclosure observed in a stable response."
            )
        candidate["reproduction_attempts"] = 1
        return candidate

    if candidate_type == "HTTP_SYSTEM_INFO_EXPOSURE" and candidate_family == "HTTP_BODY_DISCLOSURE":
        strong_versions = evidence.get("strong_version_tokens_in_body") or []
        internal_ips = evidence.get("internal_ips") or []
        if not strong_versions and not internal_ips:
            candidate.setdefault("verification", {})
            if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE", "INFORMATIONAL"}:
                candidate["verification"]["verdict"] = "INFORMATIONAL"
                candidate["verification"]["reason"] = (
                    "Weak body fingerprint was kept informational and not escalated."
                )
            candidate["reproduction_attempts"] = 1
            return candidate

    if candidate_type in {"PHPINFO_EXPOSURE", "HTTP_CONFIG_FILE_EXPOSURE", "LOG_VIEWER_EXPOSURE"}:
        if _is_direct_200_exposure(snapshot) and _has_concrete_body_exposure(candidate):
            candidate.setdefault("verification", {})
            candidate["verification"]["verdict"] = "CONFIRMED"
            candidate["verification"]["reason"] = (
                "Concrete diagnostic/config/log exposure directly observed in a 200 response."
            )
            candidate["reproduction_attempts"] = 1
            return candidate

    if candidate_type == "DEFAULT_FILE_EXPOSED":
        if _is_direct_200_exposure(snapshot) and _has_concrete_default_resource_exposure(candidate, snapshot):
            candidate.setdefault("verification", {})
            candidate["verification"]["verdict"] = "CONFIRMED"
            candidate["verification"]["reason"] = (
                "Direct default or sensitive resource exposure was observed with concrete content markers."
            )
            candidate["reproduction_attempts"] = 1
            return candidate

    if candidate_type == "HTTP_ERROR_INFO_EXPOSURE" and _has_error_like_exposure(candidate, snapshot):
        candidate.setdefault("verification", {})
        if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE", "INFORMATIONAL"}:
            candidate["verification"]["verdict"] = "INFORMATIONAL"
            candidate["verification"]["reason"] = (
                "Error disclosure indicators were directly observed in the response."
            )
        candidate["reproduction_attempts"] = 1
        return candidate

    return None


def finalize_without_reproduce(candidate: Dict[str, Any]) -> Dict[str, Any]:
    candidate = dict(candidate)
    candidate_type = str(candidate.get("type") or "")
    candidate.setdefault("verification", {})

    if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE", "INFORMATIONAL"}:
        if candidate_type in {"HTTP_SYSTEM_INFO_EXPOSURE", "HTTP_ERROR_INFO_EXPOSURE"}:
            candidate["verification"]["verdict"] = "INFORMATIONAL"
            candidate["verification"]["reason"] = (
                "Observed directly in a single response without reproduce escalation."
            )
        else:
            candidate["verification"]["verdict"] = "CONFIRMED"
            candidate["verification"]["reason"] = (
                "Confirmed from a deterministic or strong single-response signal; reproduce step skipped."
            )

    candidate["reproduction_attempts"] = 1

    if candidate_type == "HTTP_CONFIG_FILE_EXPOSURE":
        verdict = str((candidate.get("verification") or {}).get("verdict") or "").upper()
        if verdict == "CONFIRMED":
            candidate["title"] = "Configuration file exposure via HTTP parameter"
        elif verdict == "INFORMATIONAL":
            candidate["title"] = "Potential configuration file exposure via HTTP parameter"

    return candidate
