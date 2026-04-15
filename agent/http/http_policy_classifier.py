from __future__ import annotations

from typing import Any, Dict, List, Set
from urllib.parse import urlsplit

from agent.http.http_signal_builder import build_signal


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


def _status_code(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> int | None:
    return feats.get("status_code") or snapshot.get("status_code")


def _redirect_location(snapshot: Dict[str, Any]) -> str:
    headers = snapshot.get("headers") or {}
    for key, value in headers.items():
        if str(key).lower() == "location":
            return str(value or "")
    return ""


def _is_redirect_status(code: int | None) -> bool:
    return code in {301, 302, 303, 307, 308}


def _is_auth_redirect(snapshot: Dict[str, Any]) -> bool:
    location = _redirect_location(snapshot).lower()
    return any(token in location for token in ("login", "signin", "auth"))


def _is_static_response(feats: Dict[str, Any]) -> bool:
    return (feats.get("response_kind") or "") == "static_asset"


def _is_baseline_probe(request_meta: Dict[str, Any]) -> bool:
    name = str(request_meta.get("name") or "").lower()
    family = str(request_meta.get("family") or "")
    return name in {"baseline_get", "baseline_head", "baseline_query_session"} or family == "baseline"


def _requested_and_final_origin(requested_url: str, final_url: str) -> tuple[tuple[str, str], tuple[str, str]]:
    requested_parts = urlsplit(requested_url)
    final_parts = urlsplit(final_url or requested_url)
    requested_origin = (requested_parts.scheme.lower(), requested_parts.netloc.lower())
    final_origin = (final_parts.scheme.lower(), final_parts.netloc.lower())
    return requested_origin, final_origin


def _is_external_auth_transition(requested_url: str, final_url: str) -> bool:
    requested_origin, final_origin = _requested_and_final_origin(requested_url, final_url)
    is_cross_origin = requested_origin != final_origin
    final_url_l = str(final_url or "").lower()
    is_auth_landing = any(token in final_url_l for token in ("login", "signin", "adfs", "/auth", "/sso"))
    return is_cross_origin and is_auth_landing


def _is_sensitive_cookie_name(name: str) -> bool:
    normalized = str(name or "").strip().lower()
    if not normalized:
        return False

    strong_exact = {
        "jsessionid", "phpsessid", "sessionid", "session_id", "sessid", "sid", "connect.sid",
        "_session", "_sessionid", "auth_token", "access_token", "refresh_token", "remember_token",
        "csrftoken", "csrf_token", "xsrf-token", "x-csrf-token", "jwt",
    }
    if normalized in strong_exact:
        return True

    strong_contains = (
        "jsession", "phpsess", "session", "sess", "auth", "token", "jwt",
        "csrf", "xsrf", "remember", "login", "sso", "oauth", "saml",
    )
    return any(token in normalized for token in strong_contains)


def _is_probably_non_sensitive_cookie_name(name: str) -> bool:
    normalized = str(name or "").strip().lower()
    if not normalized:
        return True

    exact_names = {
        "lang", "language", "locale", "theme", "timezone", "tz", "returnpath", "return_path",
        "redirect", "redirecturl", "redirect_url", "lastactivitytime", "last_activity_time",
        "visit", "visited", "menu", "menuid", "_menuid", "_menuf", "search",
        "search_arguments_data", "search_arguments_path",
    }
    if normalized in exact_names:
        return True

    weak_tokens = ("lang", "locale", "theme", "return", "redirect", "lastactivity", "menu", "search", "view", "tab", "sort", "filter", "popup")
    return any(token in normalized for token in weak_tokens)


def _build_cors_signals(
    response_kind: str,
    final_url: str,
    feats: Dict[str, Any],
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    cors = feats.get("cors") or {}
    origin = str(cors.get("request_origin") or "").strip()
    acao = str(cors.get("acao") or "").strip()
    acac_raw = str(cors.get("acac") or "").strip()
    acac = acac_raw.lower() if acac_raw else ""
    vary = str(cors.get("vary") or "").strip()

    if not (origin and acao):
        return []

    is_reflection = acao == origin
    is_wildcard = acao == "*"
    creds_true = acac == "true"
    if not (is_reflection or (is_wildcard and creds_true)):
        return []

    subtype = "origin_reflection" if is_reflection else "wildcard_with_credentials"
    severity = "High" if creds_true else "Medium"
    confidence = 0.84 if (is_reflection and creds_true) else (0.78 if is_reflection else 0.70)

    return [
        build_signal(
            signal_type="cors_policy",
            finding_type="CORS_MISCONFIG",
            family="CORS_MISCONFIG",
            subtype=subtype,
            title="Overly permissive CORS policy observed",
            severity=severity,
            confidence=confidence,
            where="response.headers",
            evidence={
                "response_kind": response_kind,
                "request_origin": origin,
                "acao": acao,
                "acac": acac_raw,
                "acam": cors.get("acam"),
                "acah": cors.get("acah"),
                "vary": vary,
                "final_url": final_url,
                "is_reflection": is_reflection,
                "is_wildcard": is_wildcard,
                "credentials_true": creds_true,
                "cors_probe_kind": "simple_origin",
            },
            exposed_information=[f"Access-Control-Allow-Origin: {acao}", f"Access-Control-Allow-Credentials: {acac_raw}"],
            leak_type="cors_policy",
            leak_value=f"ACAO={acao}, ACAC={acac_raw}",
            cwe="CWE-942",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="cors_policy",
            root_cause_signature=f"cors|acao:{acao}|acac:{acac_raw}",
            technology_fingerprint=technology_fingerprint,
        )
    ]


def _build_header_policy_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    req_method = str(request_meta.get("method") or "").upper().strip()
    req_family = str(request_meta.get("family") or "")
    code = _status_code(snapshot, feats)

    if req_method not in {"GET", "HEAD"} or code is None or code >= 400:
        return []
    if _is_static_response(feats) or req_family in {"cors_behavior", "method_behavior", "body_behavior"}:
        return []

    requested_url = str(request_meta.get("url") or "")
    if _is_external_auth_transition(requested_url, final_url):
        return []

    is_redirect = _is_redirect_status(code)
    is_auth_redirect = _is_auth_redirect(snapshot)
    if is_auth_redirect and not _is_baseline_probe(request_meta):
        return []

    common_evidence = {
        "response_kind": response_kind,
        "final_url": final_url,
        "requested_url": requested_url,
        "status_code": code,
        "is_redirect": is_redirect,
        "is_auth_redirect": is_auth_redirect,
        "is_cross_origin": _requested_and_final_origin(requested_url, final_url)[0] != _requested_and_final_origin(requested_url, final_url)[1],
        "location": _redirect_location(snapshot),
        "present": feats.get("security_headers_present") or [],
        "missing": feats.get("security_headers_missing") or [],
    }
    out: List[Dict[str, Any]] = []

    if not feats.get("clickjacking_protection_present"):
        out.append(build_signal(
            signal_type="missing_header", finding_type="CLICKJACKING", family="HTTP_HEADER_SECURITY",
            subtype="clickjacking_protection_missing", title="Missing clickjacking protection headers",
            severity="Low", confidence=0.86, where="response.headers",
            evidence={**common_evidence, "x_frame_options_present": feats.get("x_frame_options_present"), "csp_frame_ancestors_present": feats.get("csp_frame_ancestors_present")},
            exposed_information=["Missing X-Frame-Options header", "Missing CSP frame-ancestors directive"],
            leak_type="missing_clickjacking_protection", leak_value="x-frame-options/frame-ancestors missing",
            cwe="CWE-1021", owasp="A05:2021 Security Misconfiguration", scope_hint="host-wide",
            policy_object="clickjacking_protection", root_cause_signature="missing_header:clickjacking_protection",
            technology_fingerprint=technology_fingerprint,
        ))

    missing_header_checks = [
        ("csp_present", "CSP_MISSING", "csp_missing", "Missing Content-Security-Policy header", "Low", 0.82, "content-security-policy", "content-security-policy"),
        ("x_content_type_options_present", "CONTENT_TYPE_SNIFFING", "content_type_sniffing", "Missing X-Content-Type-Options header", "Low", 0.88, "x-content-type-options", "x-content-type-options"),
        ("referrer_policy_present", "REFERRER_POLICY_MISSING", "referrer_policy_missing", "Missing Referrer-Policy header", "Info", 0.80, "referrer-policy", "referrer-policy"),
        ("permissions_policy_present", "PERMISSIONS_POLICY_MISSING", "permissions_policy_missing", "Missing Permissions-Policy header", "Info", 0.78, "permissions-policy", "permissions-policy"),
    ]
    for feat_name, finding_type, subtype, title, severity, confidence, leak_value, policy_object in missing_header_checks:
        if feats.get(feat_name):
            continue
        out.append(build_signal(
            signal_type="missing_header", finding_type=finding_type, family="HTTP_HEADER_SECURITY",
            subtype=subtype, title=title, severity=severity, confidence=confidence, where="response.headers",
            evidence=common_evidence, exposed_information=[title], leak_type=f"missing_{policy_object.replace('-', '_')}",
            leak_value=leak_value, cwe=None, owasp="A05:2021 Security Misconfiguration", scope_hint="host-wide",
            policy_object=policy_object, root_cause_signature=f"missing_header:{policy_object}",
            technology_fingerprint=technology_fingerprint, cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
            cwe_mapping_reason="OWASP category is applicable, but no precise single CWE mapping is used for this finding.",
        ))

    return out


def _build_cookie_signals(
    request_meta: Dict[str, Any],
    response_kind: str,
    final_url: str,
    feats: Dict[str, Any],
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    code = feats.get("status_code")
    if _is_static_response(feats) or code is None or code >= 400:
        return out

    requested_url = str(request_meta.get("url") or "")
    if _is_external_auth_transition(requested_url, final_url):
        return out

    req_family = str(request_meta.get("family") or "")
    req_name = str(request_meta.get("name") or "").lower()
    is_https_response = str(final_url or "").lower().startswith("https://")
    final_url_l = str(final_url or "").lower()
    auth_context = req_family == "authentication" or "login" in final_url_l or "signin" in final_url_l or req_name.startswith("auth_")

    request_sensitive_cookie_names = {str(item).strip().lower() for item in (feats.get("request_sensitive_cookie_names") or []) if str(item).strip()}
    request_sensitive_cookie_names_missing_in_response = {str(item).strip().lower() for item in (feats.get("request_sensitive_cookie_names_missing_in_response") or []) if str(item).strip()}
    cookie_objects = list(feats.get("cookie_objects") or [])
    response_cookie_names = {str(cookie.get("name") or "").strip().lower() for cookie in cookie_objects if str(cookie.get("name") or "").strip()}
    seen_cookie_issue_keys: Set[tuple[str, str]] = set()

    for cookie in cookie_objects:
        name = str(cookie.get("name") or "").strip()
        raw = str(cookie.get("raw") or "").strip()
        if not name:
            continue

        name_l = name.lower()
        sensitive_cookie = bool(cookie.get("sensitive")) or _is_sensitive_cookie_name(name)
        request_sensitive_candidate = bool(cookie.get("request_sensitive_candidate")) and not _is_probably_non_sensitive_cookie_name(name)
        prefix = str(cookie.get("prefix") or "")
        target_cookie = sensitive_cookie or request_sensitive_candidate or name_l in request_sensitive_cookie_names or prefix in {"__Host-", "__Secure-"}
        if not target_cookie:
            continue

        common_evidence = {
            "response_kind": response_kind,
            "cookie": raw,
            "cookie_name": name,
            "cookie_prefix": prefix,
            "cookie_sensitive": sensitive_cookie,
            "cookie_persistent": bool(cookie.get("persistent")),
            "auth_context": auth_context,
            "request_present": bool(cookie.get("request_present")),
            "request_sensitive_candidate": request_sensitive_candidate,
            "request_sensitive_cookie_names": sorted(request_sensitive_cookie_names),
            "request_sensitive_cookie_names_missing_in_response": sorted(request_sensitive_cookie_names_missing_in_response),
            "response_cookie_names": sorted(response_cookie_names),
            "sensitive_reason": cookie.get("sensitive_reason") or [],
            "is_https_response": is_https_response,
            "final_url": final_url,
            "requested_url": requested_url,
        }

        checks = [
            (not bool(cookie.get("httponly")), "httponly_missing", "COOKIE_HTTPONLY_MISSING", f"Cookie '{name}' missing HttpOnly attribute", "Low", 0.92 if (sensitive_cookie or request_sensitive_candidate) else 0.84, "CWE-1004", None, None),
            (not bool(cookie.get("secure")), "secure_missing", "COOKIE_SECURE_MISSING", f"Cookie '{name}' missing Secure attribute", "Low" if is_https_response else "Info", 0.94 if (is_https_response and (sensitive_cookie or request_sensitive_candidate or prefix in {"__Host-", "__Secure-"})) else 0.82, "CWE-614", None, None),
            (not bool(cookie.get("samesite")), "samesite_missing", "COOKIE_SAMESITE_MISSING", f"Cookie '{name}' missing SameSite attribute", "Info", 0.86 if (sensitive_cookie or request_sensitive_candidate) else 0.80, None, "DIRECT", "Sensitive or authentication-related cookie missing SameSite attribute."),
        ]

        for enabled, subtype, finding_type, title, severity, confidence, cwe, mapping_status, mapping_reason in checks:
            dedup_key = (name.lower(), subtype)
            if not enabled or dedup_key in seen_cookie_issue_keys:
                continue
            seen_cookie_issue_keys.add(dedup_key)
            out.append(build_signal(
                signal_type="missing_cookie_attr", finding_type=finding_type, family="COOKIE_SECURITY",
                subtype=subtype, title=title, severity=severity, confidence=confidence, where="response.headers",
                evidence=common_evidence, exposed_information=[title], leak_type=f"cookie_{subtype}", leak_value=raw,
                cwe=cwe, owasp="A05:2021 Security Misconfiguration", scope_hint="cookie-specific",
                policy_object=name, root_cause_signature=f"cookie:{name}|{subtype}", technology_fingerprint=technology_fingerprint,
                cwe_mapping_status=mapping_status, cwe_mapping_reason=mapping_reason,
            ))
    return out


def _build_method_signals(request_meta: Dict[str, Any], response_kind: str, final_url: str, feats: Dict[str, Any], technology_fingerprint: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    requested_url = str(request_meta.get("url") or "")
    if _is_external_auth_transition(requested_url, final_url):
        return out

    if feats.get("trace_reflection"):
        out.append(build_signal(
            signal_type="trace_reflection", finding_type="TRACE_ENABLED", family="HTTP_METHOD_SECURITY",
            subtype="trace_reflection", title="TRACE Method Reflects Request Content", severity="Medium",
            confidence=0.94, where="response.body",
            evidence={"request_method": str(request_meta.get("method") or "").upper().strip(), "response_kind": response_kind, "final_url": final_url, "requested_url": requested_url, "trace_reflection": True},
            exposed_information=["TRACE request content reflected by the server"], leak_type="trace_reflection",
            leak_value=final_url, cwe=None, owasp="A05:2021 Security Misconfiguration", scope_hint="route-specific",
            policy_object="http_method_policy", root_cause_signature="methods:trace_reflection",
            technology_fingerprint=technology_fingerprint, cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
            cwe_mapping_reason="OWASP category is applicable, but no precise single CWE mapping is used for this finding.",
        ))

    risky_methods = [method for method in _dedup([str(item).upper() for item in (feats.get("risky_methods_enabled") or []) if str(item).strip()]) if method != "TRACE"]
    if risky_methods:
        out.append(build_signal(
            signal_type="risky_http_methods", finding_type="RISKY_HTTP_METHODS_ENABLED", family="HTTP_METHOD_SECURITY",
            subtype="risky_methods_enabled", title="Risky HTTP Methods Are Enabled Or Handled", severity="Info",
            confidence=0.90, where="response.headers",
            evidence={"response_kind": response_kind, "final_url": final_url, "requested_url": requested_url, "risky_methods_enabled": risky_methods, "allow_header": feats.get("allow_header")},
            exposed_information=[f"Risky method enabled: {method}" for method in risky_methods], leak_type="risky_http_methods",
            leak_value=",".join(risky_methods), cwe=None, owasp="A05:2021 Security Misconfiguration", scope_hint="host-wide",
            policy_object="http_method_policy", root_cause_signature="methods:" + ",".join(risky_methods),
            technology_fingerprint=technology_fingerprint, cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
            cwe_mapping_reason="OWASP category is applicable, but no precise single CWE mapping is used for this finding.",
        ))
    return out


def _build_transport_signals(request_meta: Dict[str, Any], snapshot: Dict[str, Any], feats: Dict[str, Any], response_kind: str, final_url: str, technology_fingerprint: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    requested_url = str(request_meta.get("url") or "")
    requested_scheme = urlsplit(requested_url).scheme.lower()
    final_scheme = urlsplit(final_url).scheme.lower()
    code = _status_code(snapshot, feats)

    if requested_scheme == "http" and final_scheme != "https":
        out.append(build_signal(
            signal_type="transport_policy", finding_type="HTTPS_REDIRECT_MISSING", family="TRANSPORT_SECURITY",
            subtype="https_redirect_missing", title="HTTP Endpoint Does Not Enforce HTTPS", severity="Low",
            confidence=0.88, where="response.headers",
            evidence={"response_kind": response_kind, "requested_url": requested_url, "final_url": final_url, "status_code": code},
            exposed_information=["HTTP request did not redirect to HTTPS"], leak_type="https_redirect_missing",
            leak_value=requested_url, cwe="CWE-319", owasp="A05:2021 Security Misconfiguration", scope_hint="host-wide",
            policy_object="transport_policy", root_cause_signature="transport:https_redirect_missing",
            technology_fingerprint=technology_fingerprint,
        ))

    if final_scheme == "https" and not feats.get("hsts_present"):
        out.append(build_signal(
            signal_type="transport_policy", finding_type="HSTS_MISSING", family="TRANSPORT_SECURITY",
            subtype="hsts_missing", title="HTTPS Response Missing HSTS Header", severity="Low",
            confidence=0.90, where="response.headers",
            evidence={"response_kind": response_kind, "requested_url": requested_url, "final_url": final_url, "status_code": code},
            exposed_information=["Missing Strict-Transport-Security header on HTTPS response"], leak_type="missing_hsts",
            leak_value="strict-transport-security", cwe="CWE-319", owasp="A05:2021 Security Misconfiguration", scope_hint="host-wide",
            policy_object="strict-transport-security", root_cause_signature="transport:hsts_missing",
            technology_fingerprint=technology_fingerprint,
        ))

    return out


def build_policy_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    *,
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    out.extend(_build_cors_signals(response_kind, final_url, feats, technology_fingerprint))
    out.extend(_build_header_policy_signals(request_meta, snapshot, feats, response_kind, final_url, technology_fingerprint))
    out.extend(_build_cookie_signals(request_meta, response_kind, final_url, feats, technology_fingerprint))
    out.extend(_build_method_signals(request_meta, response_kind, final_url, feats, technology_fingerprint))
    out.extend(_build_transport_signals(request_meta, snapshot, feats, response_kind, final_url, technology_fingerprint))
    return out
