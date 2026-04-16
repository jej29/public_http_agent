from __future__ import annotations

from typing import Any, Dict, List

from agent.analysis.verification_policy import build_signal_metadata


OWASP_ONLY_NO_CWE_REASON = (
    "OWASP category is applicable, but no precise single CWE mapping is used for this finding."
)


def compact_signal_items(items: List[str], limit: int = 4) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items or []:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out[:limit]


def signal_meta_for(family: str, subtype: str) -> Dict[str, str]:
    if family == "TRANSPORT_SECURITY":
        return build_signal_metadata(
            signal_strength="deterministic",
            signal_repeatability="stable",
            observation_scope="transport_policy",
        )
    if family == "COOKIE_SECURITY":
        return build_signal_metadata(
            signal_strength="deterministic",
            signal_repeatability="stable",
            observation_scope="cookie_policy",
        )
    if family in {"HTTP_HEADER_DISCLOSURE", "HTTP_HEADER_SECURITY"}:
        return build_signal_metadata(
            signal_strength="deterministic",
            signal_repeatability="stable",
            observation_scope="response_policy",
        )
    if family == "HTTP_METHOD_SECURITY" and subtype == "risky_methods_enabled":
        return build_signal_metadata(
            signal_strength="deterministic",
            signal_repeatability="stable",
            observation_scope="response_policy",
        )
    if family == "HTTP_METHOD_SECURITY" and subtype == "trace_reflection":
        return build_signal_metadata(
            signal_strength="strong",
            signal_repeatability="likely_stable",
            observation_scope="request_specific",
        )
    if family == "CORS_MISCONFIG":
        return build_signal_metadata(
            signal_strength="strong",
            signal_repeatability="likely_stable",
            observation_scope="request_specific",
        )
    if family in {"HTTP_ERROR_DISCLOSURE", "HTTP_BODY_DISCLOSURE", "DIRECTORY_LISTING", "DEFAULT_RESOURCE_EXPOSURE"}:
        return build_signal_metadata(
            signal_strength="strong",
            signal_repeatability="likely_stable",
            observation_scope="route_behavior",
        )
    return build_signal_metadata(
        signal_strength="weak",
        signal_repeatability="unknown",
        observation_scope="request_specific",
    )


def alignment_meta_for(finding_type: str) -> Dict[str, Any]:
    burp_zap_aligned_types = {
        "HSTS_MISSING",
        "COOKIE_HTTPONLY_MISSING",
        "COOKIE_SECURE_MISSING",
        "COOKIE_SAMESITE_MISSING",
        "TRACE_ENABLED",
        "RISKY_HTTP_METHODS_ENABLED",
        "CORS_MISCONFIG",
        "DIRECTORY_LISTING_ENABLED",
        "DEFAULT_FILE_EXPOSED",
        "HTTP_ERROR_INFO_EXPOSURE",
        "HTTP_SYSTEM_INFO_EXPOSURE",
        "PHPINFO_EXPOSURE",
        "HTTP_CONFIG_FILE_EXPOSURE",
        "LOG_VIEWER_EXPOSURE",
        "FILE_PATH_HANDLING_ANOMALY",
        "CLICKJACKING",
        "CSP_MISSING",
        "CONTENT_TYPE_SNIFFING",
        "REFERRER_POLICY_MISSING",
        "PERMISSIONS_POLICY_MISSING",
    }
    classification_kind = "supporting_signal" if finding_type == "HTTPS_REDIRECT_MISSING" else "finding"
    return {
        "classification_kind": classification_kind,
        "burp_zap_aligned": finding_type in burp_zap_aligned_types,
    }


def narrative_for_family(family: str) -> Dict[str, Any]:
    mapping = {
        "HTTP_HEADER_DISCLOSURE": {
            "why": "Response headers expose stack, product, or framework details that help attackers fingerprint the target.",
            "rec": [
                "Minimize version and product disclosure in response headers.",
                "Review reverse proxy, application server, and framework banner settings.",
            ],
        },
        "HTTP_ERROR_DISCLOSURE": {
            "why": "Verbose error handling leaks implementation details such as stack traces, file paths, or database internals.",
            "rec": [
                "Use generic production error responses.",
                "Remove stack traces, file paths, and exception details from user-facing responses.",
            ],
        },
        "HTTP_BODY_DISCLOSURE": {
            "why": "The response body reveals internal technologies, debug details, or sensitive implementation clues.",
            "rec": [
                "Remove unnecessary product, version, and debug details from response bodies.",
                "Review templates and error views for internal information leakage.",
            ],
        },
        "COOKIE_SECURITY": {
            "why": "Weak cookie attributes reduce browser-side protections for session and authentication data.",
            "rec": [
                "Set HttpOnly, Secure, and SameSite on sensitive cookies.",
                "Apply stricter defaults to session and authentication cookies first.",
            ],
        },
        "CORS_MISCONFIG": {
            "why": "Overly permissive CORS settings can allow cross-origin access to sensitive responses.",
            "rec": [
                "Avoid reflecting arbitrary Origin values.",
                "Allow credentials only for a strict allowlist of trusted origins.",
            ],
        },
        "HTTP_METHOD_SECURITY": {
            "why": "Unnecessary or risky HTTP methods broaden the exposed attack surface.",
            "rec": [
                "Allow only required methods.",
                "Disable TRACE and unnecessary write-capable methods at the proxy and application layers.",
            ],
        },
        "TRANSPORT_SECURITY": {
            "why": "Weak transport security increases the risk of downgrade, interception, or mixed access patterns.",
            "rec": [
                "Redirect HTTP to HTTPS consistently.",
                "Set HSTS on HTTPS responses where appropriate.",
            ],
        },
        "DEFAULT_RESOURCE_EXPOSURE": {
            "why": "Default resources and operational endpoints can reveal sensitive data or internal deployment details.",
            "rec": [
                "Remove or block default, debug, and operational resources from production.",
                "Review deployment artifacts so sensitive files are not published.",
            ],
        },
        "DIRECTORY_LISTING": {
            "why": "Directory listing exposes file names and internal structure that can guide further probing.",
            "rec": [
                "Disable directory listing.",
                "Return generic 403 or 404 responses for directory browsing attempts.",
            ],
        },
        "HTTP_HEADER_SECURITY": {
            "why": "Missing browser-facing security headers weakens client-side protections.",
            "rec": [
                "Define a baseline set of security headers for HTML responses.",
                "Apply the baseline consistently across the application.",
            ],
        },
    }
    return mapping.get(
        family,
        {
            "why": "Observed HTTP behavior indicates information exposure or security misconfiguration.",
            "rec": ["Reduce unnecessary exposure and harden the affected response behavior."],
        },
    )


def build_signal(
    *,
    signal_type: str,
    finding_type: str,
    family: str,
    subtype: str,
    title: str,
    severity: str,
    confidence: float,
    where: str,
    evidence: Dict[str, Any],
    exposed_information: List[str],
    leak_type: str,
    leak_value: str,
    cwe: str | None,
    owasp: str,
    scope_hint: str,
    policy_object: str,
    root_cause_signature: str,
    technology_fingerprint: List[str],
    template_fingerprint: str | None = None,
    cwe_mapping_status: str | None = None,
    cwe_mapping_reason: str | None = None,
) -> Dict[str, Any]:
    narrative = narrative_for_family(family)
    out = {
        "signal_type": signal_type,
        "finding_type": finding_type,
        "family": family,
        "subtype": subtype,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "where": where,
        "evidence": evidence,
        "exposed_information": compact_signal_items(exposed_information),
        "leak_type": leak_type,
        "leak_value": leak_value,
        "cwe": cwe,
        "owasp": owasp,
        "scope_hint": scope_hint,
        "policy_object": policy_object,
        "root_cause_signature": root_cause_signature,
        "technology_fingerprint": technology_fingerprint,
        "template_fingerprint": template_fingerprint,
        "why_it_matters": narrative["why"],
        "recommendation": narrative["rec"],
        "cwe_mapping_status": cwe_mapping_status,
        "cwe_mapping_reason": cwe_mapping_reason or (
            OWASP_ONLY_NO_CWE_REASON if cwe_mapping_status else None
        ),
        **signal_meta_for(family, subtype),
        **alignment_meta_for(finding_type),
    }
    return {key: value for key, value in out.items() if value not in (None, "", [], {})}
