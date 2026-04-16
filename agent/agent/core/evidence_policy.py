from __future__ import annotations

import re
from typing import Any, Dict

CONCRETE_EXPOSURE_TYPES = {
    "PHPINFO_EXPOSURE",
    "HTTP_CONFIG_FILE_EXPOSURE",
    "LOG_VIEWER_EXPOSURE",
}


def evidence_dict(candidate: Dict[str, Any]) -> Dict[str, Any]:
    evidence = candidate.get("evidence") or {}
    return evidence if isinstance(evidence, dict) else {}


def joined_exposed(candidate: Dict[str, Any]) -> str:
    return " | ".join(str(x).lower() for x in (candidate.get("exposed_information") or []))


def is_https_cookie_secure_case(candidate: Dict[str, Any]) -> bool:
    if str(candidate.get("type") or "") != "COOKIE_SECURE_MISSING":
        return True
    return bool(evidence_dict(candidate).get("is_https_response"))


def has_strong_phpinfo_evidence(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    indicators = evidence.get("phpinfo_indicators") or []
    exposed = joined_exposed(candidate)
    return len(indicators) >= 2 or ("phpinfo()" in exposed and "php version" in exposed)


def has_strong_config_evidence(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    markers = evidence.get("config_exposure_markers") or []
    real_values = evidence.get("config_real_values") or []
    masked_values = evidence.get("config_masked_values") or []
    key_classes = {
        str(item.get("key_class") or "").strip().lower()
        for item in (real_values + masked_values)
        if isinstance(item, dict) and str(item.get("key_class") or "").strip()
    }

    strong_secret_markers = {
        "db_password",
        "mysql_password",
        "api_key",
        "access_key",
        "aws_access_key",
        "aws_secret",
        "private_key",
        "connection_string",
        "secret",
    }
    db_context_classes = {"db_host", "db_name", "db_user", "db_password", "db_port"}
    exposed = joined_exposed(candidate)

    if any(cls in strong_secret_markers for cls in key_classes):
        return True
    if len(key_classes.intersection(db_context_classes)) >= 3:
        return True
    if len(real_values) >= 3:
        return True
    if ":" in exposed and any(
        token in exposed
        for token in (
            "database host:",
            "database name:",
            "database user:",
            "database password:",
            "connection string:",
            "api key:",
            "secret:",
        )
    ):
        return True

    if not markers:
        return False
    return False


def has_strong_log_evidence(candidate: Dict[str, Any]) -> bool:
    patterns = evidence_dict(candidate).get("log_exposure_patterns") or []
    return len(patterns) >= 2


def has_strong_file_path_evidence(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    return bool(
        evidence.get("file_paths")
        or evidence.get("stack_traces")
        or evidence.get("db_errors")
        or evidence.get("error_exposure_class") in {"file_path", "stack_trace", "db_error"}
    )


def has_strong_error_disclosure(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    if evidence.get("stack_traces") or evidence.get("db_errors") or evidence.get("file_paths"):
        return True
    return evidence.get("error_exposure_class") == "debug_error_page" and len(evidence.get("debug_hints") or []) >= 2


def has_strong_system_info(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    strong_versions = evidence.get("strong_version_tokens_in_body") or []
    banner_headers = evidence.get("banner_headers") or {}
    framework_hints = evidence.get("framework_hints") or []
    debug_hints = evidence.get("debug_hints") or []
    internal_ips = evidence.get("internal_ips") or []

    if strong_versions or banner_headers:
        return True
    if len(framework_hints) >= 2 or len(debug_hints) >= 2:
        return True
    return bool(internal_ips and (strong_versions or banner_headers))


def has_version_signal(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    return bool(
        evidence.get("strong_version_tokens_in_body")
        or evidence.get("header_version_tokens")
        or evidence.get("all_version_tokens")
    )


def default_resource_has_error_disclosure(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    return bool(
        evidence.get("error_exposure_class")
        or evidence.get("stack_traces")
        or evidence.get("file_paths")
        or evidence.get("db_errors")
        or evidence.get("debug_hints")
    )


def default_resource_has_concrete_marker(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    subtype = str(candidate.get("subtype") or "")
    exposed = joined_exposed(candidate)

    if subtype == "phpinfo_page":
        indicators = evidence.get("phpinfo_indicators") or []
        return len(indicators) >= 2 or ("phpinfo()" in exposed and "php version" in exposed)

    if subtype == "env_file":
        return len(evidence.get("config_exposure_markers") or []) >= 2

    if subtype == "git_metadata":
        return any(x in exposed for x in ("repositoryformatversion", "[core]", 'remote "origin"', "git config"))

    if subtype == "server_status":
        return any(x in exposed for x in ("apache server status", "server uptime", "total accesses", "scoreboard"))

    if subtype == "actuator_endpoint":
        body_markers = sum(1 for x in ('"status"', '"components"', '"_links"', "/actuator") if x in exposed)
        return body_markers >= 2

    if subtype == "debug_endpoint":
        body_markers = sum(1 for x in ("debug toolbar", "trace", "environment", "application config") if x in exposed)
        return body_markers >= 2

    return False


def is_low_value_disclosure(candidate: Dict[str, Any]) -> bool:
    candidate_type = str(candidate.get("type") or "")
    subtype = str(candidate.get("subtype") or "")
    evidence = evidence_dict(candidate)
    exposed = joined_exposed(candidate)

    if candidate_type == "HTTP_SYSTEM_INFO_EXPOSURE":
        if "127.0.0.1" in exposed and not has_version_signal(candidate):
            return True
        if subtype in {"framework_hint_in_body", "debug_marker_in_body"} and not has_strong_system_info(candidate):
            return True
        if subtype == "internal_ip_in_body":
            strong_context = bool(
                evidence.get("stack_traces")
                or evidence.get("db_errors")
                or evidence.get("file_paths")
                or evidence.get("strong_version_tokens_in_body")
                or evidence.get("banner_headers")
            )
            if not strong_context:
                return True
        return not has_strong_system_info(candidate)

    if candidate_type == "HTTP_ERROR_INFO_EXPOSURE":
        return not has_strong_error_disclosure(candidate)

    if candidate_type == "FILE_PATH_HANDLING_ANOMALY":
        return not has_strong_file_path_evidence(candidate)

    if candidate_type == "LOG_VIEWER_EXPOSURE":
        return not has_strong_log_evidence(candidate)

    if candidate_type == "HTTP_CONFIG_FILE_EXPOSURE":
        return not has_strong_config_evidence(candidate)

    if candidate_type == "PHPINFO_EXPOSURE":
        return not has_strong_phpinfo_evidence(candidate)

    if candidate_type == "DEFAULT_FILE_EXPOSED":
        return default_resource_has_error_disclosure(candidate) or not default_resource_has_concrete_marker(candidate)

    return False


def is_direct_200_observation(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    status_code = candidate.get("status_code") or evidence.get("status_code")
    if status_code != 200:
        return False

    final_url = str(evidence.get("final_url") or "").lower()
    location = str(evidence.get("location") or "").lower()

    if any(x in final_url for x in ("login", "signin", "auth")):
        return False
    if any(x in location for x in ("login", "signin", "auth")):
        return False
    return True


def has_concrete_body_exposure(candidate: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    candidate_type = str(candidate.get("type") or "")

    if candidate_type == "PHPINFO_EXPOSURE":
        return has_strong_phpinfo_evidence(candidate)

    if candidate_type == "HTTP_CONFIG_FILE_EXPOSURE":
        return has_strong_config_evidence(candidate)

    if candidate_type == "LOG_VIEWER_EXPOSURE":
        return len(evidence.get("log_exposure_patterns") or []) >= 2

    if candidate_type == "FILE_PATH_HANDLING_ANOMALY":
        return any(
            evidence.get(k)
            for k in ("file_paths", "stack_traces", "db_errors", "debug_hints", "internal_ips")
        )

    return False


def is_direct_200_snapshot(snapshot: Dict[str, Any]) -> bool:
    if not snapshot.get("ok"):
        return False
    if snapshot.get("status_code") != 200:
        return False

    final_url = str(snapshot.get("final_url") or "").lower()
    headers = snapshot.get("headers") or {}
    location = ""
    for k, v in headers.items():
        if str(k).lower() == "location":
            location = str(v or "").lower()
            break

    if any(x in final_url for x in ("login", "signin", "auth")):
        return False
    if any(x in location for x in ("login", "signin", "auth")):
        return False
    return True


def has_error_like_exposure_snapshot(candidate: Dict[str, Any], snapshot: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    body_l = str(snapshot.get("body_snippet") or "").lower()

    if evidence.get("error_exposure_class") or evidence.get("stack_traces") or evidence.get("file_paths") or evidence.get("db_errors") or evidence.get("debug_hints"):
        return True

    return any(token in body_l for token in ("fatal error", "warning</b>", "uncaught error", "stack trace", "traceback"))


def has_concrete_default_resource_exposure(candidate: Dict[str, Any], snapshot: Dict[str, Any]) -> bool:
    evidence = evidence_dict(candidate)
    subtype = str(candidate.get("subtype") or "")
    body = str(snapshot.get("body_snippet") or "")
    body_l = body.lower()

    if not is_direct_200_snapshot(snapshot):
        return False
    if has_error_like_exposure_snapshot(candidate, snapshot):
        return False

    if subtype == "phpinfo_page":
        indicators = evidence.get("phpinfo_indicators") or []
        return len(indicators) >= 2 or ("phpinfo()" in body_l and "php version" in body_l)

    if subtype == "git_metadata":
        return any(marker in body_l for marker in ("[core]", "repositoryformatversion", "filemode = ", 'remote "origin"', "bare = "))

    if subtype == "server_status":
        return any(marker in body_l for marker in ("apache server status", "server uptime", "total accesses", "scoreboard", "apache status"))

    if subtype == "env_file":
        env_like_lines = 0
        for line in body.splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", s):
                env_like_lines += 1
            if env_like_lines >= 2:
                return True
        return False

    if subtype in {"actuator_endpoint", "debug_endpoint"}:
        if body_l.startswith("{") and any(k in body_l for k in ('"status"', '"_links"', '"health"')):
            return True
        return "actuator" in body_l or "debug toolbar" in body_l

    hints = evidence.get("default_file_hints") or []
    return bool(hints) and not has_error_like_exposure_snapshot(candidate, snapshot)
