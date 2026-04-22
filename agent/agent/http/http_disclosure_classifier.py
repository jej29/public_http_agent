from __future__ import annotations

import html
import re
from typing import Any, Dict, List
from urllib.parse import urlsplit

from agent.http.disclosure_enrichment import build_detector_disclosure_signals
from agent.http.http_signal_builder import build_signal as _build_signal


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


def _clean_disclosure_text(value: str) -> str:
    text = html.unescape(str(value or "")).replace("\ufffd", "").strip()
    text = re.sub(r"\s+", " ", text)
    return text


def _looks_like_meaningful_stack_trace(text: str) -> bool:
    lowered = str(text or "").strip().lower()
    if not lowered:
        return False
    if lowered in {
        "fatal error",
        "stack trace",
        "exception",
        "traceback",
        "stack trace: fatal error",
    }:
        return False
    if len(lowered) < 18:
        return False
    if any(token in lowered for token in ("<span", "</span>", "color:", "&lt;span")):
        return False
    meaningful_markers = (
        " in /",
        " on line ",
        "traceback (most recent call last)",
        " at ",
        "caused by:",
        "uncaught ",
        "warning:",
        "notice:",
        "exception:",
        "fatal error:",
        "#0 ",
        "stack trace:",
    )
    return any(marker in lowered for marker in meaningful_markers)


def _meaningful_stack_traces(items: List[str]) -> List[str]:
    out: List[str] = []
    for item in items or []:
        text = _clean_disclosure_text(item)
        if not _looks_like_meaningful_stack_trace(text):
            continue
        out.append(text)
    return _dedup(out)


def _meaningful_db_errors(items: List[str]) -> List[str]:
    out: List[str] = []
    for item in items or []:
        text = _clean_disclosure_text(item)
        if not text:
            continue
        if text.lower() in {"sqlite3.", "sqlite3", "mysql", "postgres", "oracle"}:
            continue
        if len(text) < 12:
            continue
        lowered = text.lower()
        if not any(
            marker in lowered
            for marker in (
                "sqlstate",
                "syntax error",
                "mysqli",
                "pdoexception",
                "warning: mysql",
                "warning: mysqli",
                "postgresql",
                "sqlite error",
                "database error",
                "query failed",
                "ora-",
                "sql error",
            )
        ):
            continue
        out.append(text)
    return _dedup(out)


def _meaningful_runtime_error_messages(items: List[str]) -> List[str]:
    out: List[str] = []
    for item in items or []:
        text = _clean_disclosure_text(item)
        if not text:
            continue
        if len(text) < 24:
            continue
        lowered = text.lower()
        if any(token in lowered for token in ("<span", "</span>", "color:", "&lt;span")):
            continue
        out.append(text)
    return _dedup(out)


def _meaningful_file_paths(items: List[str]) -> List[str]:
    out: List[str] = []
    for item in items or []:
        text = _clean_disclosure_text(item)
        if not text:
            continue
        out.append(text.rstrip(" '\""))
    return _dedup(out)


def _clean_htmlish_text(value: str) -> str:
    text = html.unescape(str(value or ""))
    text = re.sub(r"(?is)<br\s*/?>", "\n", text)
    text = re.sub(r"(?is)</(?:p|div|tr|li|h\d|td|th)>", "\n", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = text.replace("\xa0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def _extract_setup_diagnostic_values(
    body_text: str,
    feats: Dict[str, Any],
) -> Dict[str, List[str]]:
    plain = _clean_htmlish_text(body_text)
    if not plain:
        return {
            "diagnostic_values": [],
            "writable_paths": [],
            "filesystem_paths": [],
        }

    diagnostic_values: List[str] = []
    writable_paths: List[str] = []
    filesystem_paths: List[str] = []

    for item in (_meaningful_file_paths(feats.get("file_paths") or []) or [])[:6]:
        filesystem_paths.append(item)

    for item in (feats.get("config_extracted_values") or [])[:12]:
        key = str(item.get("key") or "").strip()
        value = str(item.get("value") or "").strip()
        if not key or not value:
            continue
        label = {
            "db_host": "Database host",
            "db_name": "Database name",
            "db_user": "Database username",
            "db_password": "Database password",
            "db_port": "Database port",
        }.get(key.lower())
        if label:
            diagnostic_values.append(f"{label}: {value}")

    for item in (feats.get("phpinfo_extracted_values") or [])[:12]:
        display = str(item.get("display") or "").strip()
        if not display:
            continue
        display_l = display.lower()
        if any(
            token in display_l
            for token in (
                "server_software:",
                "server_addr:",
                "remote_addr:",
                "document_root:",
                "script_filename:",
                "loaded configuration file:",
                "configuration file (php.ini) path:",
            )
        ):
            diagnostic_values.append(display)

    for item in (_dedup(feats.get("strong_version_tokens_in_body") or []) or [])[:4]:
        token = str(item).strip()
        if not token:
            continue
        if token.lower().startswith("php/"):
            diagnostic_values.append(f"PHP version: {token}")
        else:
            diagnostic_values.append(f"Server software: {token}")

    writable_patterns = [
        re.compile(
            r"(?im)\b(?:writable|writeable)\s+(?:folder|directory|path)\s+([A-Za-z]:\\[^\s<]+|/(?:[^/\s<]+/)*[^<:\n]+/?)[\s:=-]+(yes|no|true|false|writable|not writable)\b"
        ),
        re.compile(
            r"(?im)\b(?:folder|directory|path)\s+([A-Za-z]:\\[^\s<]+|/(?:[^/\s<]+/)*[^<:\n]+/?)\s+(?:is\s+)?(writable|writeable|readable|not writable|not writeable)\b"
        ),
    ]
    for pattern in writable_patterns:
        for path_value, state in pattern.findall(plain):
            normalized_path = _clean_disclosure_text(path_value).rstrip(" :")
            normalized_state = _clean_disclosure_text(state).lower()
            if not normalized_path:
                continue
            readable_state = {
                "yes": "writable",
                "true": "writable",
                "writable": "writable",
                "writeable": "writable",
                "no": "not writable",
                "false": "not writable",
            }.get(normalized_state, normalized_state)
            writable_paths.append(f"{normalized_path} ({readable_state})")
            filesystem_paths.append(normalized_path)

    labeled_patterns = [
        re.compile(
            r"(?im)\b(server user|web server user|process user|running as|document root|config file|configuration file|upload folder|uploads folder|temp directory|temporary directory)\s*[:=]\s*(.{1,200})$"
        ),
        re.compile(
            r"(?im)\b(php version|server software|database host|database username|database user|database name|database password)\s*[:=]\s*(.{1,200})$"
        ),
    ]
    for pattern in labeled_patterns:
        for label, value in pattern.findall(plain):
            clean_label = _clean_disclosure_text(label)
            clean_value = _clean_disclosure_text(value)
            if not clean_label or not clean_value:
                continue
            diagnostic_values.append(f"{clean_label}: {clean_value[:200]}")
            if re.search(r"(?i)(?:[A-Za-z]:\\|/(?:usr|var|etc|opt|home|srv|tmp|app|workspace)/)", clean_value):
                filesystem_paths.append(clean_value[:200])

    return {
        "diagnostic_values": _dedup(diagnostic_values)[:12],
        "writable_paths": _dedup(writable_paths)[:8],
        "filesystem_paths": _dedup(filesystem_paths)[:10],
    }


def _first(items: List[str]) -> str:
    values = _dedup(items)
    return values[0] if values else ""


def _status_code(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> int | None:
    return feats.get("status_code") or snapshot.get("status_code")


def _response_headers(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    return snapshot.get("headers") or {}


def _redirect_location(snapshot: Dict[str, Any]) -> str:
    for key, value in _response_headers(snapshot).items():
        if str(key).lower() == "location":
            return str(value or "")
    return ""


def _body_text(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> str:
    return str(
        feats.get("body_text")
        or snapshot.get("body_text")
        or snapshot.get("body_snippet")
        or ""
    )


def _is_auth_redirect(snapshot: Dict[str, Any]) -> bool:
    location = _redirect_location(snapshot).lower()
    return any(token in location for token in ("login", "signin", "auth"))


def _is_static_response(feats: Dict[str, Any]) -> bool:
    return (feats.get("response_kind") or "") == "static_asset"


def _is_static_javascript_response(
    response_kind: str,
    final_url: str,
    snapshot: Dict[str, Any],
) -> bool:
    if response_kind != "static_asset":
        return False
    path = urlsplit(final_url or "").path.lower()
    if path.endswith(".js") or path.endswith(".mjs"):
        return True
    headers = snapshot.get("headers") or {}
    if isinstance(headers, dict):
        content_type = ""
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                content_type = str(value or "").lower()
                break
        return "javascript" in content_type
    return False


def _extract_client_bundle_disclosure_markers(body: str) -> Dict[str, List[str]]:
    text = str(body or "")
    if not text:
        return {}

    source_markers = _dedup(
        re.findall(r"(?:sourceURL|sourceMappingURL)=webpack:///[^\s\"')]+", text, re.I)
        + re.findall(r"webpack:///[^\s\"')]*?/src/[^\s\"')]+", text, re.I)
    )[:5]
    all_urls = _dedup(re.findall(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", text))
    interesting_url_tokens = (
        "10.",
        "127.",
        "172.",
        "192.168.",
        "localhost",
        ".internal",
        ".corp",
        "apm.",
        "elastic",
        "samsungds",
        "/api/",
        "/rest/",
    )
    external_urls = [
        url for url in all_urls
        if any(token in url.lower() for token in interesting_url_tokens)
    ][:8]

    debug_tokens: List[str] = []
    lowered = text.lower()
    if "console.trace" in lowered:
        debug_tokens.append("console.trace")
    for token in ("productgroupid", "productid", "productphase", "rumservertype", "applicationservers", "loglevel"):
        if token in lowered:
            debug_tokens.append(token)
    debug_tokens = _dedup(debug_tokens)[:8]

    out: Dict[str, List[str]] = {}
    if source_markers:
        out["source_map_markers"] = source_markers
    if external_urls:
        out["client_side_urls"] = external_urls
    if debug_tokens and (external_urls or source_markers):
        out["debug_or_config_tokens"] = debug_tokens
    return out


def _is_auth_or_session_loss(feats: Dict[str, Any]) -> bool:
    return bool(
        feats.get("auth_required_like")
        or feats.get("session_expired_like")
        or feats.get("external_auth_redirect_like")
    )


def _requested_and_final_origin(
    requested_url: str,
    final_url: str,
) -> tuple[tuple[str, str], tuple[str, str]]:
    from urllib.parse import urlsplit

    requested_parts = urlsplit(requested_url)
    final_parts = urlsplit(final_url or requested_url)
    requested_origin = (requested_parts.scheme.lower(), requested_parts.netloc.lower())
    final_origin = (final_parts.scheme.lower(), final_parts.netloc.lower())
    return requested_origin, final_origin


def _is_external_auth_transition(requested_url: str, final_url: str) -> bool:
    requested_origin, final_origin = _requested_and_final_origin(requested_url, final_url)
    is_cross_origin = requested_origin != final_origin
    final_url_l = str(final_url or "").lower()
    is_auth_landing = any(tok in final_url_l for tok in ("login", "signin", "adfs", "/auth", "/sso"))
    return is_cross_origin and is_auth_landing


def _looks_like_generic_notfound_template(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> bool:
    status_code = _status_code(snapshot, feats)
    body_l = _body_text(snapshot, feats).lower()
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or "").lower()

    if status_code not in {404, 200}:
        return False

    generic_markers = [
        "page not found",
        "not found",
        "page could not be found",
        "the requested url was not found",
        "requested resource",
        "this system is strictly restricted to authorized users only",
    ]
    hit_count = sum(1 for marker in generic_markers if marker in body_l)
    if hit_count >= 2:
        return True

    if "<html" in body_l and "<title>page not found" in body_l and "page could not be found" in body_l:
        return True

    route_tokens = (".env", ".git/config", "phpinfo.php", "server-status", "actuator", "debug")
    return status_code == 200 and hit_count >= 1 and any(token in final_url for token in route_tokens)


def _severity_rank(severity: str) -> int:
    return {"Info": 1, "Low": 2, "Medium": 3, "High": 4}.get(str(severity or "Info"), 1)


def looks_like_setup_or_install_page(final_url: str, body_text: str) -> bool:
    url_l = str(final_url or "").lower()
    body_l = str(body_text or "").lower()
    setup_tokens = (
        "install",
        "installation",
        "setup",
        "wizard",
        "quick start",
        "getting started",
        "docker compose",
        "readme",
    )
    url_hint = any(token in url_l for token in ("/install", "/setup", "/readme", "/docs"))
    body_hint = sum(1 for token in setup_tokens if token in body_l) >= 2
    return url_hint or body_hint


def should_skip_info_disclosure(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> bool:
    requested_url = str(request_meta.get("url") or "")
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or requested_url or "")

    if _is_static_response(feats):
        return True
    if _is_external_auth_transition(requested_url, final_url):
        return True
    if _is_auth_or_session_loss(feats):
        return True

    has_strong_error_like_signal = bool(
        feats.get("error_exposure_class")
        or (feats.get("stack_traces") or [])
        or (feats.get("file_paths") or [])
        or (feats.get("db_errors") or [])
        or (feats.get("debug_hints") or [])
    )
    if has_strong_error_like_signal:
        return False

    if _is_auth_redirect(snapshot):
        return True
    if _looks_like_generic_notfound_template(snapshot, feats):
        return True
    return False


def _build_error_disclosure_signals(
    request_meta: Dict[str, Any],
    status_code: int | None,
    response_kind: str,
    final_url: str,
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    technology_fingerprint: List[str],
    tech: str,
) -> List[Dict[str, Any]]:
    if _is_static_javascript_response(response_kind, final_url, snapshot):
        return []

    error_class = str(feats.get("error_exposure_class") or "")
    stack_traces = _meaningful_stack_traces(feats.get("stack_traces") or [])
    file_paths = _meaningful_file_paths(feats.get("file_paths") or [])
    db_errors = _meaningful_db_errors(feats.get("db_errors") or [])
    runtime_error_messages = _meaningful_runtime_error_messages(feats.get("runtime_error_messages") or [])
    phpinfo_indicators = _dedup(feats.get("phpinfo_indicators") or [])
    phpinfo_extracted_values = feats.get("phpinfo_extracted_values") or []
    debug_hints = _dedup(feats.get("debug_hints") or [])
    default_error_hint = str(feats.get("default_error_hint") or "")
    template_fingerprint = str(feats.get("error_template_fingerprint") or "")

    looks_like_phpinfo_page = bool(phpinfo_extracted_values) or len(phpinfo_indicators) >= 2
    if looks_like_phpinfo_page and file_paths and not stack_traces and not db_errors:
        return []

    exposed_information: List[str] = []
    exposed_information.extend([f"Error message: {item}" for item in runtime_error_messages[:2]])
    exposed_information.extend([f"Stack trace: {_clean_disclosure_text(item)}" for item in stack_traces[:2]])
    exposed_information.extend([f"File path: {item}" for item in file_paths[:3]])
    exposed_information.extend([f"Database error: {item}" for item in db_errors[:2]])
    exposed_information.extend([f"Debug hint: {_clean_disclosure_text(item)}" for item in debug_hints[:2]])
    if default_error_hint:
        exposed_information.append(f"Default error template: {default_error_hint}")
    exposed_information = _dedup(exposed_information)
    has_concrete_error_artifact = bool(stack_traces or file_paths or db_errors or runtime_error_messages)
    if not exposed_information and not error_class:
        return []
    if not has_concrete_error_artifact and error_class in {"stack_trace", "db_error"}:
        return []
    if not has_concrete_error_artifact and default_error_hint and len(debug_hints) < 2:
        return []

    high_value_runtime = any(
        tok in msg.lower()
        for msg in runtime_error_messages
        for tok in (
            "uncaught",
            "exception",
            "sql",
            "mysqli",
            "pdo",
            "query",
            "failed to open stream",
            "headers already sent",
        )
    )
    severity = "High" if db_errors or stack_traces or (high_value_runtime and file_paths) else "Medium"
    confidence = 0.94 if db_errors or stack_traces or runtime_error_messages else 0.87

    return [
        _build_signal(
            signal_type="error_disclosure",
            finding_type="HTTP_ERROR_INFO_EXPOSURE",
            family="HTTP_ERROR_DISCLOSURE",
            subtype=error_class or "error_page",
            title="Error Response Exposes Internal Application Details",
            severity=severity,
            confidence=confidence,
            where="response.body",
            evidence={
                "final_url": final_url,
                "requested_url": str(request_meta.get("url") or ""),
                "status_code": status_code,
                "response_kind": response_kind,
                "error_exposure_class": error_class,
                "stack_traces": stack_traces,
                "file_paths": file_paths,
                "db_errors": db_errors,
                "runtime_error_messages": runtime_error_messages,
                "debug_hints": debug_hints,
                "default_error_hint": default_error_hint,
                "error_template_fingerprint": template_fingerprint,
                "technology_fingerprint": technology_fingerprint,
            },
            exposed_information=exposed_information or [error_class or "Internal error details exposed"],
            leak_type="error_details",
            leak_value=_first(stack_traces) or _first(file_paths) or _first(db_errors) or error_class or final_url,
            cwe="CWE-209",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="error_response",
            root_cause_signature=f"error:{error_class}|template:{template_fingerprint}|tech:{tech}",
            technology_fingerprint=technology_fingerprint,
            template_fingerprint=template_fingerprint or None,
        )
    ]


def _build_static_client_bundle_disclosure_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
    tech: str,
) -> List[Dict[str, Any]]:
    if not _is_static_javascript_response(response_kind, final_url, snapshot):
        return []
    body = str(feats.get("body_text") or snapshot.get("body_text") or snapshot.get("body_snippet") or "")
    markers = _extract_client_bundle_disclosure_markers(body)
    if not markers:
        return []

    source_markers = markers.get("source_map_markers") or []
    urls = markers.get("client_side_urls") or []
    debug_tokens = markers.get("debug_or_config_tokens") or []

    exposed_information: List[str] = []
    if source_markers:
        exposed_information.append("Webpack source map/sourceURL module paths are present in the client bundle")
    if urls:
        exposed_information.extend([f"Client-side URL: {item}" for item in urls[:3]])
    if debug_tokens:
        exposed_information.append("Client-side debug/config tokens are present: " + ", ".join(debug_tokens[:6]))
    exposed_information = _dedup(exposed_information)
    if not exposed_information:
        return []

    has_runtime_config = bool(urls or debug_tokens)
    return [
        _build_signal(
            signal_type="client_bundle_disclosure",
            finding_type="HTTP_SYSTEM_INFO_EXPOSURE",
            family="HTTP_BODY_DISCLOSURE",
            subtype="client_bundle_source_map_or_config",
            title="Client Bundle Discloses Source Map Or Runtime Configuration Details",
            severity="Info" if not has_runtime_config else "Low",
            confidence=0.82 if source_markers else 0.87,
            where="response.body",
            evidence={
                "final_url": final_url,
                "requested_url": str(request_meta.get("url") or ""),
                "response_kind": response_kind,
                "source_map_markers": source_markers,
                "client_side_urls": urls,
                "debug_or_config_tokens": debug_tokens,
                "technology_fingerprint": technology_fingerprint,
            },
            exposed_information=exposed_information[:6],
            leak_type="client_bundle_metadata",
            leak_value=_first(urls) or _first(source_markers) or _first(debug_tokens) or final_url,
            cwe="CWE-497",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="client_bundle",
            root_cause_signature=f"client_bundle:{tech}|markers:{','.join(sorted(markers.keys()))}",
            technology_fingerprint=technology_fingerprint,
            signal_strength="strong",
            signal_repeatability="likely_stable",
            observation_scope="route_behavior",
            verification_strategy="single_observation",
        )
    ]


def _build_header_disclosure_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
    tech: str,
) -> List[Dict[str, Any]]:
    items = feats.get("header_disclosures") or []
    if not items:
        return []

    exposed_information: List[str] = []
    banner_headers: List[Dict[str, Any]] = []
    versioned = 0
    for item in items[:8]:
        if not isinstance(item, dict):
            continue
        header = str(item.get("header") or "")
        value = str(item.get("value") or "")
        subtype = str(item.get("subtype") or "")
        if not header or not value:
            continue
        banner_headers.append({"header": header, "value": value, "subtype": subtype})
        exposed_information.append(f"{header}: {value}")
        if item.get("has_version"):
            versioned += 1

    if not exposed_information:
        return []

    severity = "Medium" if versioned >= 1 else "Low"
    confidence = 0.91 if versioned >= 1 else 0.83
    return [
        _build_signal(
            signal_type="header_disclosure",
            finding_type="HTTP_SYSTEM_INFO_EXPOSURE",
            family="HTTP_HEADER_DISCLOSURE",
            subtype="banner_header",
            title="Response Headers Disclose Server Or Framework Details",
            severity=severity,
            confidence=confidence,
            where="response.headers",
            evidence={
                "final_url": final_url,
                "requested_url": str(request_meta.get("url") or ""),
                "response_kind": response_kind,
                "banner_headers": banner_headers,
                "technology_fingerprint": technology_fingerprint,
            },
            exposed_information=_dedup(exposed_information)[:6],
            leak_type="system_info",
            leak_value=_first(exposed_information) or final_url,
            cwe="CWE-497",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="host-wide",
            policy_object="response_headers",
            root_cause_signature=f"headers:{'|'.join(str(x.get('subtype') or '') for x in banner_headers)}|tech:{tech}",
            technology_fingerprint=technology_fingerprint,
        )
    ]


def _build_non_error_body_disclosure_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
    tech: str,
) -> List[Dict[str, Any]]:
    if _status_code(snapshot, feats) != 200:
        return []
    if _is_auth_redirect(snapshot) or _is_static_response(feats):
        return []
    if _is_auth_or_session_loss(feats):
        return []
    if _looks_like_generic_notfound_template(snapshot, feats):
        return []
    if feats.get("directory_listing_hints"):
        return []

    strong_versions = _dedup(feats.get("strong_version_tokens_in_body") or [])
    framework_hints = _dedup(feats.get("framework_hints") or [])
    debug_hints = _dedup(feats.get("debug_hints") or [])
    internal_ips = _dedup(feats.get("internal_ips") or [])

    exposed_information: List[str] = []
    exposed_information.extend([f"Version token: {item}" for item in strong_versions[:3]])
    exposed_information.extend([f"Framework hint: {item}" for item in framework_hints[:3]])
    exposed_information.extend([f"Internal IP: {item}" for item in internal_ips[:2]])
    if len(debug_hints) >= 2:
        exposed_information.extend([f"Debug hint: {item}" for item in debug_hints[:2]])
    exposed_information = _dedup(exposed_information)
    if not exposed_information:
        return []

    return [
        _build_signal(
            signal_type="body_system_info_disclosure",
            finding_type="HTTP_SYSTEM_INFO_EXPOSURE",
            family="HTTP_BODY_DISCLOSURE",
            subtype="system_info",
            title="Response Body Discloses System Or Framework Details",
            severity="Low" if not internal_ips else "Medium",
            confidence=0.82 if not internal_ips else 0.88,
            where="response.body",
            evidence={
                "final_url": final_url,
                "requested_url": str(request_meta.get("url") or ""),
                "response_kind": response_kind,
                "strong_version_tokens_in_body": strong_versions,
                "framework_hints": framework_hints,
                "debug_hints": debug_hints,
                "internal_ips": internal_ips,
                "technology_fingerprint": technology_fingerprint,
            },
            exposed_information=exposed_information[:6],
            leak_type="system_info",
            leak_value=_first(strong_versions) or _first(internal_ips) or _first(framework_hints) or final_url,
            cwe="CWE-497",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="response_body",
            root_cause_signature=f"bodyinfo:{tech}|versions:{'|'.join(strong_versions[:3])}",
            technology_fingerprint=technology_fingerprint,
        )
    ]


def _build_setup_diagnostic_disclosure_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
    tech: str,
) -> List[Dict[str, Any]]:
    if _status_code(snapshot, feats) != 200:
        return []
    if _is_auth_redirect(snapshot) or _is_static_response(feats):
        return []
    if _is_auth_or_session_loss(feats):
        return []
    if _looks_like_generic_notfound_template(snapshot, feats):
        return []

    body_text = _body_text(snapshot, feats)
    diagnostics = _extract_setup_diagnostic_values(body_text, feats)
    diagnostic_values = diagnostics.get("diagnostic_values") or []
    writable_paths = diagnostics.get("writable_paths") or []
    filesystem_paths = diagnostics.get("filesystem_paths") or []
    setup_like = looks_like_setup_or_install_page(final_url, body_text)

    if not setup_like and not writable_paths:
        return []

    internal_ips = _dedup(feats.get("internal_ips") or [])
    strong_versions = _dedup(feats.get("strong_version_tokens_in_body") or [])

    exposed_information: List[str] = []
    exposed_information.extend(diagnostic_values[:8])
    exposed_information.extend([f"Writable path disclosed: {item}" for item in writable_paths[:4]])
    exposed_information.extend([f"File path: {item}" for item in filesystem_paths[:4]])
    exposed_information.extend([f"Internal IP: {item}" for item in internal_ips[:2]])
    exposed_information = _dedup(exposed_information)
    if not exposed_information:
        return []

    severity = "Medium" if writable_paths or filesystem_paths else "Low"
    confidence = 0.9 if writable_paths or len(diagnostic_values) >= 3 else 0.83

    return [
        _build_signal(
            signal_type="setup_diagnostic_disclosure",
            finding_type="HTTP_SYSTEM_INFO_EXPOSURE",
            family="HTTP_BODY_DISCLOSURE",
            subtype="setup_diagnostics",
            title="Setup Or Diagnostic Page Discloses Internal Environment Details",
            severity=severity,
            confidence=confidence,
            where="response.body",
            evidence={
                "final_url": final_url,
                "requested_url": str(request_meta.get("url") or ""),
                "response_kind": response_kind,
                "setup_diagnostic_values": diagnostic_values,
                "writable_paths": writable_paths,
                "file_paths": filesystem_paths,
                "internal_ips": internal_ips,
                "strong_version_tokens_in_body": strong_versions,
                "technology_fingerprint": technology_fingerprint,
                "direct_http_access_confirmed": False,
                "follow_up_constraints": [
                    "The scanner confirmed disclosure of an internal path or writable location, but did not confirm direct HTTP access to that filesystem location in-band."
                ],
            },
            exposed_information=exposed_information[:10],
            recommendation=[
                "Remove internal absolute paths, writable-directory status, and environment details from setup, install, status, or diagnostic pages.",
                "Treat disclosed writable paths as potentially actionable follow-up targets if additional host or application privileges are later obtained.",
                "Direct HTTP access to the disclosed filesystem path was not confirmed during this scan and should be verified separately if higher privileges become available.",
            ],
            leak_type="setup_diagnostics",
            leak_value=_first(writable_paths) or _first(filesystem_paths) or _first(diagnostic_values) or final_url,
            cwe="CWE-497",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="response_body",
            root_cause_signature=f"setupdiag:{tech}|setup:{setup_like}|writable:{bool(writable_paths)}",
            technology_fingerprint=technology_fingerprint,
        )
    ]


def build_file_path_handling_signal(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> List[Dict[str, Any]]:
    fileish_params = _dedup(feats.get("file_path_parameter_names") or [])
    status_code = _status_code(snapshot, feats)
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or request_meta.get("url") or "")
    body_text = _body_text(snapshot, feats)

    if not fileish_params:
        return []
    if _is_external_auth_transition(str(request_meta.get("url") or ""), final_url):
        return []
    if _is_auth_or_session_loss(feats):
        return []
    if looks_like_setup_or_install_page(final_url, body_text):
        return []

    file_paths = _dedup(feats.get("file_paths") or [])
    stack_traces = _dedup(feats.get("stack_traces") or [])
    db_errors = _dedup(feats.get("db_errors") or [])
    debug_hints = _dedup(feats.get("debug_hints") or [])
    error_exposure_class = feats.get("error_exposure_class")
    template_fingerprint = feats.get("error_template_fingerprint")
    default_error_hint = feats.get("default_error_hint")

    concrete = bool(file_paths or stack_traces or db_errors or (error_exposure_class in {"file_path", "stack_trace", "db_error"}))
    if not concrete:
        return []

    path_handling_combo = bool(file_paths or stack_traces or (default_error_hint and error_exposure_class in {"file_path", "stack_trace"}))
    if not path_handling_combo:
        return []

    if status_code is not None and status_code < 400 and not (file_paths or stack_traces):
        return []

    evidence_exposed: List[str] = [
        f"File/path-related parameter observed: {', '.join(fileish_params[:4])}",
        "Response indicates internal file/path handling behavior",
    ]
    if file_paths:
        evidence_exposed.extend([f"File path: {item}" for item in file_paths[:3]])
    if stack_traces:
        evidence_exposed.extend([f"Stack trace: {item}" for item in stack_traces[:2]])
    evidence_exposed = _dedup(evidence_exposed)

    return [
        _build_signal(
            signal_type="file_path_handling_anomaly",
            finding_type="FILE_PATH_HANDLING_ANOMALY",
            family="HTTP_ERROR_DISCLOSURE",
            subtype="file_path_parameter",
            title="File Or Path Parameter Handling Exposes Internal Behavior",
            severity="Medium",
            confidence=0.89 if file_paths or stack_traces else 0.84,
            where="response.body",
            evidence={
                "final_url": final_url,
                "requested_url": str(request_meta.get("url") or ""),
                "file_path_parameter_names": fileish_params,
                "file_paths": file_paths,
                "stack_traces": stack_traces,
                "db_errors": db_errors,
                "debug_hints": debug_hints,
                "default_error_hint": default_error_hint,
                "error_exposure_class": error_exposure_class,
                "technology_fingerprint": feats.get("technology_fingerprint") or [],
                "template_fingerprint": template_fingerprint,
                "status_code": status_code,
            },
            exposed_information=evidence_exposed,
            leak_type="file_path_parameter",
            leak_value=",".join(fileish_params),
            cwe=None,
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="file_path_parameter",
            root_cause_signature=f"file_path_param:{','.join(sorted(fileish_params))}",
            technology_fingerprint=feats.get("technology_fingerprint") or [],
            template_fingerprint=template_fingerprint,
            cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
            cwe_mapping_reason=(
                "OWASP category is applicable, but no precise single CWE mapping is used for this file/path handling signal."
            ),
        )
    ]


def build_disclosure_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    *,
    status_code: int | None,
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
    tech: str,
    info_skip: bool,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    out.extend(
        _build_error_disclosure_signals(
            request_meta,
            status_code,
            response_kind,
            final_url,
            snapshot,
            feats,
            technology_fingerprint,
            tech,
        )
    )
    out.extend(
        build_detector_disclosure_signals(
            request_meta=request_meta,
            snapshot=snapshot,
            feats=feats,
            info_skip=info_skip,
        )
    )
    out.extend(
        _build_static_client_bundle_disclosure_signals(
            request_meta,
            snapshot,
            feats,
            response_kind,
            final_url,
            technology_fingerprint,
            tech,
        )
    )
    if info_skip:
        return out

    out.extend(
        _build_header_disclosure_signals(
            request_meta,
            snapshot,
            feats,
            response_kind,
            final_url,
            technology_fingerprint,
            tech,
        )
    )
    out.extend(
        _build_setup_diagnostic_disclosure_signals(
            request_meta,
            snapshot,
            feats,
            response_kind,
            final_url,
            technology_fingerprint,
            tech,
        )
    )
    out.extend(
        _build_non_error_body_disclosure_signals(
            request_meta,
            snapshot,
            feats,
            response_kind,
            final_url,
            technology_fingerprint,
            tech,
        )
    )
    out.extend(build_file_path_handling_signal(request_meta, snapshot, feats))

    out.sort(key=lambda item: _severity_rank(item.get("severity") or "Info"), reverse=True)
    return out
