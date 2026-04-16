from __future__ import annotations

from typing import Dict, List

SEVERITY_ORDER = {
    "Info": 1,
    "Low": 2,
    "Medium": 3,
    "High": 4,
}

BASE_SEVERITY_BY_TYPE = {
    "DIRECTORY_LISTING_ENABLED": "Medium",
    "DEFAULT_FILE_EXPOSED": "Medium",
    "HTTP_ERROR_INFO_EXPOSURE": "Medium",
    "HTTP_SYSTEM_INFO_EXPOSURE": "Low",
    "PHPINFO_EXPOSURE": "Medium",
    "HTTP_CONFIG_FILE_EXPOSURE": "High",
    "LOG_VIEWER_EXPOSURE": "Medium",
    "FILE_PATH_HANDLING_ANOMALY": "Medium",
    "TRACE_ENABLED": "Medium",
    "RISKY_HTTP_METHODS_ENABLED": "Low",
    "CORS_MISCONFIG": "Medium",
    "CLICKJACKING": "Low",
    "CSP_MISSING": "Low",
    "CONTENT_TYPE_SNIFFING": "Low",
    "REFERRER_POLICY_MISSING": "Info",
    "PERMISSIONS_POLICY_MISSING": "Info",
    "COOKIE_HTTPONLY_MISSING": "Low",
    "COOKIE_SECURE_MISSING": "Low",
    "COOKIE_SAMESITE_MISSING": "Info",
    "HTTPS_REDIRECT_MISSING": "Info",
    "HSTS_MISSING": "Low",
}


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(str(sev or "Info"), 1)


def higher_severity(a: str, b: str) -> str:
    return a if severity_rank(a) >= severity_rank(b) else b


def apply_base_severity(candidate: Dict) -> Dict:
    finding_type = str(candidate.get("type") or "")
    base = BASE_SEVERITY_BY_TYPE.get(finding_type, "Info")
    existing = str(candidate.get("severity") or "Info")
    candidate["severity"] = higher_severity(existing, base)
    return candidate


def apply_base_severity_to_candidates(candidates: List[Dict]) -> List[Dict]:
    return [apply_base_severity(c) for c in candidates]


def apply_combination_severity(findings: List[Dict]) -> List[Dict]:
    if not findings:
        return findings

    has_config = any(f.get("type") == "HTTP_CONFIG_FILE_EXPOSURE" for f in findings)
    has_error = any(f.get("type") == "HTTP_ERROR_INFO_EXPOSURE" for f in findings)
    has_directory = any(f.get("type") == "DIRECTORY_LISTING_ENABLED" for f in findings)
    has_default_resource = any(f.get("type") == "DEFAULT_FILE_EXPOSED" for f in findings)

    for finding in findings:
        finding_type = str(finding.get("type") or "")
        severity = str(finding.get("severity") or "Info")

        if has_config and finding_type in {"HTTP_CONFIG_FILE_EXPOSURE", "DEFAULT_FILE_EXPOSED", "DIRECTORY_LISTING_ENABLED"}:
            finding["severity"] = higher_severity(severity, "High")
            continue

        if has_directory and has_default_resource and finding_type in {"DIRECTORY_LISTING_ENABLED", "DEFAULT_FILE_EXPOSED"}:
            finding["severity"] = higher_severity(severity, "High")

    return findings
