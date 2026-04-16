from __future__ import annotations

import re
from typing import Any, Dict, List
from urllib.parse import urlsplit

from agent.core.scope import (
    canonical_finding_url,
    disclosure_scope_url,
    host_scope_url,
    misconfig_scope_url,
    normalize_url_for_dedup,
    resource_scope_url,
    route_scope_url,
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
    "HTTP_PUT_UPLOAD_CAPABILITY",
    "HTTP_DELETE_CAPABILITY",
    "HTTPS_REDIRECT_MISSING",
    "HSTS_MISSING",
    "OPEN_REDIRECT",
    "CLICKJACKING",
    "CSP_MISSING",
    "CONTENT_TYPE_SNIFFING",
    "REFERRER_POLICY_MISSING",
    "PERMISSIONS_POLICY_MISSING",
}


def finding_group(finding: Dict[str, Any]) -> str:
    ftype = str(finding.get("type") or "")
    if ftype in INFORMATION_DISCLOSURE_TYPES:
        return "information_disclosure"
    if ftype in SECURITY_MISCONFIGURATION_TYPES:
        return "security_misconfiguration"
    return "other"


def _slugify(text: str) -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "finding"


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _host_scope(url: str) -> str:
    if not url:
        return ""
    try:
        return normalize_url_for_dedup(host_scope_url(url))
    except Exception:
        return ""


def _bucket_route_for_error(url: str) -> str:
    if not url:
        return ""

    try:
        p = urlsplit(url)
    except Exception:
        return normalize_url_for_dedup(url)

    path = p.path or "/"
    segs = [s for s in path.split("/") if s]

    if not segs:
        return normalize_url_for_dedup(route_scope_url(url))

    if len(segs) >= 2 and segs[0] == "vulnerabilities" and segs[1] == "api":
        return f"{p.scheme}://{p.netloc}/vulnerabilities/api"

    if len(segs) >= 2:
        last = segs[-1].lower()
        resource_like = (
            "." in last
            or last in {
                ".env",
                ".env.local",
                "server-status",
                "server-info",
                "phpinfo.php",
                "info.php",
                "static",
                "uploads",
                "backup",
                "logs",
            }
        )
        if resource_like:
            return f"{p.scheme}://{p.netloc}/" + "/".join(segs[:-1])

    return normalize_url_for_dedup(route_scope_url(url))


def _normalize_methods(items: List[Any]) -> str:
    methods = sorted({str(x).strip().upper() for x in (items or []) if str(x).strip()})
    return ",".join(methods)


def stable_key(finding: Dict[str, Any]) -> str:
    evidence = finding.get("evidence") or {}
    trigger = finding.get("trigger") or {}

    trigger_url = _safe_str(trigger.get("url"))
    final_url = _safe_str(evidence.get("final_url") or trigger_url)

    normalized_final_url = normalize_url_for_dedup(final_url)
    host_scope = _host_scope(final_url or trigger_url)
    disclosure_url = normalize_url_for_dedup(disclosure_scope_url(finding))
    misconfig_url = normalize_url_for_dedup(misconfig_scope_url(finding))
    route_scope = normalize_url_for_dedup(route_scope_url(final_url or trigger_url))
    resource_scope = normalize_url_for_dedup(resource_scope_url(final_url or trigger_url))

    group = finding_group(finding)
    ftype = _safe_str(finding.get("type"))
    subtype = _safe_str(finding.get("subtype"))
    cwe = _safe_str(finding.get("cwe"))
    policy_object = _safe_str(finding.get("policy_object"))
    root_cause_signature = _safe_str(finding.get("root_cause_signature"))
    template_fingerprint = _safe_str(
        finding.get("template_fingerprint")
        or evidence.get("error_template_fingerprint")
    )

    cookie_name = _safe_str(
        evidence.get("cookie_name")
        or evidence.get("cookie")
        or policy_object
    ).lower()
    cookie_prefix = _safe_str(evidence.get("cookie_prefix")).lower()
    cookie_scope = host_scope or route_scope or misconfig_url or normalized_final_url

    acao = _safe_str(evidence.get("acao")).lower()
    acac = _safe_str(evidence.get("acac")).lower()

    risky_methods = _normalize_methods(evidence.get("risky_methods_enabled") or [])
    query_param_names = ",".join(sorted(str(x) for x in (evidence.get("query_param_names") or []) if str(x)))
    file_path_param_names = ",".join(sorted(str(x) for x in (evidence.get("file_path_parameter_names") or []) if str(x)))

    if ftype in {
        "COOKIE_HTTPONLY_MISSING",
        "COOKIE_SECURE_MISSING",
        "COOKIE_SAMESITE_MISSING",
    }:
        cookie_identity = cookie_name or policy_object or root_cause_signature or "cookie"
        return "||".join([
            group,
            ftype,
            cookie_scope,
            cookie_prefix,
            cookie_identity,
        ])

    if ftype in {
        "CLICKJACKING",
        "CSP_MISSING",
        "CONTENT_TYPE_SNIFFING",
        "REFERRER_POLICY_MISSING",
        "PERMISSIONS_POLICY_MISSING",
        "SECURITY_HEADERS_MISSING",
        "TRACE_ENABLED",
        "HSTS_MISSING",
        "HTTPS_REDIRECT_MISSING",
    }:
        return "||".join([group, ftype, host_scope, policy_object or subtype])

    if ftype == "RISKY_HTTP_METHODS_ENABLED":
        return "||".join([group, ftype, host_scope or _host_scope(trigger_url), "risky_http_methods"])

    if ftype == "HTTP_PUT_UPLOAD_CAPABILITY":
        candidate_url = normalize_url_for_dedup(_safe_str(evidence.get("candidate_url") or trigger_url or final_url))
        return "||".join([group, ftype, candidate_url, "put_upload_capability"])

    if ftype == "HTTP_DELETE_CAPABILITY":
        candidate_url = normalize_url_for_dedup(_safe_str(evidence.get("candidate_url") or trigger_url or final_url))
        return "||".join([group, ftype, candidate_url, "delete_capability"])

    if ftype == "CORS_MISCONFIG":
        return "||".join([
            group,
            ftype,
            misconfig_url or route_scope or normalized_final_url,
            acao,
            acac,
        ])

    if ftype == "PROTECTED_RESOURCE_EXPOSURE":
        resource_url = normalize_url_for_dedup(
            _safe_str(
                evidence.get("resource_url")
                or evidence.get("anon_final_url")
                or evidence.get("auth_final_url")
                or final_url
                or trigger_url
            )
        )
        replay_method = _safe_str(
            evidence.get("replay_method")
            or trigger.get("method")
            or "GET"
        ).upper()

        return "||".join([
            group,
            ftype,
            resource_url,
            replay_method,
        ])

    if ftype == "DIRECTORY_LISTING_ENABLED":
        return "||".join([
            group,
            ftype,
            route_scope or normalized_final_url,
        ])

    if ftype == "DEFAULT_FILE_EXPOSED":
        return "||".join([
            group,
            ftype,
            resource_scope or normalized_final_url,
            subtype,
        ])

    if ftype == "PHPINFO_EXPOSURE":
        return "||".join([
            group,
            ftype,
            resource_scope or disclosure_url or normalized_final_url,
            subtype,
            root_cause_signature or "phpinfo",
        ])

    if ftype == "HTTP_CONFIG_FILE_EXPOSURE":
        return "||".join([
            group,
            ftype,
            resource_scope or disclosure_url or normalized_final_url,
            subtype,
            root_cause_signature or file_path_param_names or query_param_names or "config_file",
        ])

    if ftype == "LOG_VIEWER_EXPOSURE":
        return "||".join([
            group,
            ftype,
            resource_scope or disclosure_url or normalized_final_url,
            subtype,
            root_cause_signature or "log_content",
        ])

    if ftype == "FILE_PATH_HANDLING_ANOMALY":
        return "||".join([
            group,
            ftype,
            resource_scope or disclosure_url or route_scope or normalized_final_url,
            subtype,
            root_cause_signature or "file_path_parameter",
        ])

    if ftype == "HTTP_ERROR_INFO_EXPOSURE":
        error_bucket = _bucket_route_for_error(final_url or trigger_url)
        return "||".join([
            group,
            ftype,
            error_bucket or disclosure_url or route_scope or normalized_final_url,
            subtype,
            template_fingerprint or root_cause_signature or "error_template",
        ])

    if ftype == "HTTP_SYSTEM_INFO_EXPOSURE":
        if subtype == "banner_header":
            return "||".join([
                group,
                ftype,
                host_scope or _host_scope(trigger_url) or disclosure_url or normalized_final_url,
                subtype,
                policy_object or "response_headers",
            ])
        scope = disclosure_url or route_scope or host_scope or normalized_final_url
        return "||".join([
            group,
            ftype,
            scope,
            subtype,
            policy_object,
            root_cause_signature or "system_info",
        ])

    return "||".join([
        group,
        ftype,
        cwe,
        normalized_final_url,
        subtype,
        root_cause_signature,
    ])


def stable_finding_filename(finding: Dict[str, Any]) -> str:
    ftype = _safe_str(finding.get("type"))
    cwe = _safe_str(finding.get("cwe")) or _safe_str(finding.get("cwe_mapping_status")) or "UNMAPPED"

    evidence = finding.get("evidence") or {}
    trigger = finding.get("trigger") or {}
    final_url = _safe_str(evidence.get("final_url") or trigger.get("url"))

    if ftype == "HTTP_ERROR_INFO_EXPOSURE":
        bucket = _bucket_route_for_error(final_url)
        path = urlsplit(bucket).path if bucket else urlsplit(final_url).path
    elif ftype in {
        "PHPINFO_EXPOSURE",
        "HTTP_CONFIG_FILE_EXPOSURE",
        "LOG_VIEWER_EXPOSURE",
        "FILE_PATH_HANDLING_ANOMALY",
        "HTTP_SYSTEM_INFO_EXPOSURE",
    }:
        path = urlsplit(canonical_finding_url(finding)).path
    elif ftype == "RISKY_HTTP_METHODS_ENABLED":
        path = "root"
    else:
        path = urlsplit(final_url).path

    slug = _slugify(path.strip("/") or "root")
    return f"{cwe}_{ftype}_{slug}.json"
