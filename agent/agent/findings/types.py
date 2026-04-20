from __future__ import annotations

from typing import Dict, Optional, Set

OWASP_ONLY_NO_CWE_MAPPING = "OWASP_ONLY_NO_CWE_MAPPING"
OWASP_ONLY_NO_CWE_REASON = (
    "OWASP category is applicable, but no precise single CWE mapping is used for this finding."
)

INFORMATION_DISCLOSURE_TYPES: Set[str] = {
    "AUTHENTICATED_ONLY_INFORMATION_DISCLOSURE",
    "HTTP_ERROR_INFO_EXPOSURE",
    "HTTP_SYSTEM_INFO_EXPOSURE",
    "DIRECTORY_LISTING_ENABLED",
    "DEFAULT_FILE_EXPOSED",
    "PHPINFO_EXPOSURE",
    "HTTP_CONFIG_FILE_EXPOSURE",
    "LOG_VIEWER_EXPOSURE",
    "FILE_PATH_HANDLING_ANOMALY",
}

SECURITY_MISCONFIGURATION_TYPES: Set[str] = {
    "SECURITY_HEADERS_MISSING",
    "CORS_MISCONFIG",
    "COOKIE_HTTPONLY_MISSING",
    "COOKIE_SECURE_MISSING",
    "COOKIE_SAMESITE_MISSING",
    "TRACE_ENABLED",
    "RISKY_HTTP_METHODS_ENABLED",
    "HTTP_PUT_UPLOAD_CAPABILITY",
    "HTTP_DELETE_CAPABILITY",
    "HTTPS_REDIRECT_MISSING",
    "HSTS_MISSING",
    "CLICKJACKING",
    "CSP_MISSING",
    "CONTENT_TYPE_SNIFFING",
    "REFERRER_POLICY_MISSING",
    "PERMISSIONS_POLICY_MISSING",
}

DETERMINISTIC_TYPES: Set[str] = {
    "COOKIE_HTTPONLY_MISSING",
    "COOKIE_SECURE_MISSING",
    "COOKIE_SAMESITE_MISSING",
    "CLICKJACKING",
    "CSP_MISSING",
    "CONTENT_TYPE_SNIFFING",
    "REFERRER_POLICY_MISSING",
    "PERMISSIONS_POLICY_MISSING",
    "TRACE_ENABLED",
    "RISKY_HTTP_METHODS_ENABLED",
    "HTTP_PUT_UPLOAD_CAPABILITY",
    "HTTP_DELETE_CAPABILITY",
    "HTTPS_REDIRECT_MISSING",
    "HSTS_MISSING",
    "DIRECTORY_LISTING_ENABLED",
    "CORS_MISCONFIG",
}

AMBIGUOUS_TYPES: Set[str] = {
    "AUTHENTICATED_ONLY_INFORMATION_DISCLOSURE",
    "HTTP_ERROR_INFO_EXPOSURE",
    "HTTP_SYSTEM_INFO_EXPOSURE",
    "PHPINFO_EXPOSURE",
    "HTTP_CONFIG_FILE_EXPOSURE",
    "LOG_VIEWER_EXPOSURE",
    "FILE_PATH_HANDLING_ANOMALY",
    "DEFAULT_FILE_EXPOSED",
}

CONCRETE_EXPOSURE_TYPES: Set[str] = {
    "PHPINFO_EXPOSURE",
    "HTTP_CONFIG_FILE_EXPOSURE",
    "LOG_VIEWER_EXPOSURE",
}

PRIMARY_CWE_BY_TYPE: Dict[str, Optional[str]] = {
    "AUTHENTICATED_ONLY_INFORMATION_DISCLOSURE": "CWE-497",
    "HTTP_ERROR_INFO_EXPOSURE": "CWE-209",
    "HTTP_SYSTEM_INFO_EXPOSURE": "CWE-497",
    "DIRECTORY_LISTING_ENABLED": "CWE-548",
    "DEFAULT_FILE_EXPOSED": "CWE-552",
    "PHPINFO_EXPOSURE": "CWE-497",
    "HTTP_CONFIG_FILE_EXPOSED": None,  # backward-compat typo guard
    "HTTP_CONFIG_FILE_EXPOSURE": "CWE-538",
    "LOG_VIEWER_EXPOSURE": "CWE-532",
    "FILE_PATH_HANDLING_ANOMALY": None,
    "CORS_MISCONFIG": "CWE-942",
    "COOKIE_HTTPONLY_MISSING": "CWE-1004",
    "COOKIE_SECURE_MISSING": "CWE-614",
    "COOKIE_SAMESITE_MISSING": None,
    "TRACE_ENABLED": None,
    "RISKY_HTTP_METHODS_ENABLED": None,
    "HTTP_PUT_UPLOAD_CAPABILITY": None,
    "HTTP_DELETE_CAPABILITY": None,
    "CLICKJACKING": None,
    "CSP_MISSING": None,
    "CONTENT_TYPE_SNIFFING": None,
    "REFERRER_POLICY_MISSING": None,
    "PERMISSIONS_POLICY_MISSING": None,
    "HTTPS_REDIRECT_MISSING": "CWE-319",
    "HSTS_MISSING": "CWE-319",
    "SECURITY_HEADERS_MISSING": None,
}

ALLOWED_PRIMARY_CWES = {
    "CWE-209",
    "CWE-497",
    "CWE-548",
    "CWE-552",
    "CWE-538",
    "CWE-532",
    "CWE-319",
    "CWE-942",
    "CWE-1004",
    "CWE-614",
    "CWE-601",
    None,
}

HOST_WIDE_TYPES: Set[str] = {
    "COOKIE_HTTPONLY_MISSING",
    "COOKIE_SECURE_MISSING",
    "COOKIE_SAMESITE_MISSING",
    "CLICKJACKING",
    "CSP_MISSING",
    "CONTENT_TYPE_SNIFFING",
    "REFERRER_POLICY_MISSING",
    "PERMISSIONS_POLICY_MISSING",
    "TRACE_ENABLED",
    "RISKY_HTTP_METHODS_ENABLED",
    "HSTS_MISSING",
    "HTTPS_REDIRECT_MISSING",
}


def finding_group_from_type(finding_type: str) -> str:
    if finding_type in INFORMATION_DISCLOSURE_TYPES:
        return "information_disclosure"
    if finding_type in SECURITY_MISCONFIGURATION_TYPES:
        return "security_misconfiguration"
    return "other"


def default_cwe_for_type(finding_type: str) -> Optional[str]:
    return PRIMARY_CWE_BY_TYPE.get(finding_type)


def ensure_type_cwe_consistency(candidate: Dict[str, object]) -> Dict[str, object]:
    finding_type = str(candidate.get("type") or "")
    primary_cwe = default_cwe_for_type(finding_type)

    if primary_cwe is not None:
        candidate["cwe"] = primary_cwe
        return candidate

    if finding_type in PRIMARY_CWE_BY_TYPE:
        if not candidate.get("cwe"):
            candidate["cwe_mapping_status"] = OWASP_ONLY_NO_CWE_MAPPING
            candidate["cwe_mapping_reason"] = OWASP_ONLY_NO_CWE_REASON
            candidate["cwe_source"] = "owasp_only_no_precise_cwe"
    return candidate
