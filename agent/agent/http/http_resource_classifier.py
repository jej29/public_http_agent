from __future__ import annotations

import html
import re
from typing import Any, Dict, List
from urllib.parse import urlsplit

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


def _lower_text(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> str:
    return _body_text(snapshot, feats).lower()


def _is_redirect_status(status_code: int | None) -> bool:
    return status_code in {301, 302, 303, 307, 308}


def _is_auth_redirect(snapshot: Dict[str, Any]) -> bool:
    location = _redirect_location(snapshot).lower()
    return any(token in location for token in ("login", "signin", "auth"))


def _is_access_denied_status(status_code: int | None) -> bool:
    return status_code in {401, 403}


def _is_not_found_status(status_code: int | None) -> bool:
    return status_code == 404


def _is_static_response(feats: Dict[str, Any]) -> bool:
    return (feats.get("response_kind") or "") == "static_asset"


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


def _resource_probe_is_actually_error_disclosure(feats: Dict[str, Any]) -> bool:
    return bool(
        feats.get("error_exposure_class")
        or feats.get("stack_traces")
        or feats.get("file_paths")
        or feats.get("db_errors")
        or feats.get("debug_hints")
    )


def _looks_like_generic_notfound_template(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> bool:
    status_code = _status_code(snapshot, feats)
    body_l = _lower_text(snapshot, feats)
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
    if status_code == 200 and any(token in final_url for token in route_tokens):
        if hit_count >= 1 and not _resource_probe_is_actually_error_disclosure(feats):
            return True

    return False


def _is_same_error_page_for_resource_probe(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> bool:
    if not _resource_probe_is_actually_error_disclosure(feats):
        return False

    if _looks_like_generic_notfound_template(snapshot, feats):
        return True

    if _status_code(snapshot, feats) != 200:
        return False

    body_l = _lower_text(snapshot, feats)
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or "").lower()
    file_paths = [str(item).lower() for item in (feats.get("file_paths") or [])]

    if "fatal error" in body_l and "bootstrap.php" in body_l:
        return True
    if "failed opening required" in body_l:
        return True
    if any("bootstrap.php" in path for path in file_paths):
        return True
    if "/public/index.php" in body_l and any(tok in final_url for tok in (".env", "phpinfo.php", "server-status", ".git/config")):
        return True

    return False


def _resource_exposure_is_confirmable(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> bool:
    status_code = _status_code(snapshot, feats)
    response_kind = feats.get("response_kind") or "other"
    body_len = len(str(snapshot.get("body_snippet") or ""))

    if _is_redirect_status(status_code):
        return False
    if _is_access_denied_status(status_code):
        return False
    if _is_not_found_status(status_code):
        return False
    if _is_auth_redirect(snapshot):
        return False
    if _is_auth_or_session_loss(feats):
        return False
    if status_code != 200:
        return False
    if response_kind == "other" and body_len == 0:
        return False
    if _looks_like_generic_notfound_template(snapshot, feats):
        return False
    return True


def _default_resource_subtype_from_hints(hints: List[str]) -> str:
    joined = " ".join(_dedup(hints)).lower()
    if ".env" in joined or "env" in joined:
        return "env_file"
    if ".git" in joined or "git_repository" in joined:
        return "git_metadata"
    if "phpinfo" in joined:
        return "phpinfo_page"
    if "server-status" in joined:
        return "server_status"
    if "actuator" in joined:
        return "actuator_endpoint"
    if "debug" in joined:
        return "debug_endpoint"
    return "default_resource"


def _default_resource_has_concrete_marker(
    subtype: str,
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> bool:
    body = _body_text(snapshot, feats)
    body_l = body.lower()

    if _is_same_error_page_for_resource_probe(snapshot, feats):
        return False
    if _looks_like_generic_notfound_template(snapshot, feats):
        return False
    if _is_auth_or_session_loss(feats):
        return False

    if subtype == "phpinfo_page":
        indicators = feats.get("phpinfo_indicators") or []
        if len(indicators) >= 2:
            return True
        return "phpinfo()" in body_l and "php version" in body_l

    if subtype == "git_metadata":
        return any(
            marker in body_l
            for marker in (
                "[core]",
                "repositoryformatversion",
                "bare = ",
                "filemode = ",
                'remote "origin"',
            )
        )

    if subtype == "env_file":
        env_like_lines = 0
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", stripped):
                env_like_lines += 1
        return env_like_lines >= 2

    if subtype == "server_status":
        return any(
            marker in body_l
            for marker in (
                "apache server status",
                "server uptime",
                "total accesses",
                "scoreboard",
                "apache status",
            )
        )

    if subtype == "actuator_endpoint":
        markers = ('"status"', '"components"', '"_links"', "/actuator")
        return sum(1 for marker in markers if marker in body_l) >= 2

    if subtype == "debug_endpoint":
        markers = ("debug toolbar", "trace", "environment", "application config")
        return sum(1 for marker in markers if marker in body_l) >= 2

    return False


def _phpinfo_has_concrete_marker(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> bool:
    body_l = _body_text(snapshot, feats).lower()
    indicators = feats.get("phpinfo_indicators") or []

    if _is_same_error_page_for_resource_probe(snapshot, feats):
        return False
    if _looks_like_generic_notfound_template(snapshot, feats):
        return False
    if len(indicators) >= 2:
        return True

    tokens = ("phpinfo()", "php version", "loaded modules", "php variables", "server api", "<title>php")
    return sum(1 for token in tokens if token in body_l) >= 2


def _normalize_config_key_name(key: str) -> str:
    value = str(key or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value


def _classify_config_key(key: str) -> str:
    normalized = _normalize_config_key_name(key)
    if any(tok in normalized for tok in ("db_password", "database_password", "mysql_password", "password")):
        return "db_password"
    if any(tok in normalized for tok in ("db_user", "database_user", "database_username", "username", "user")):
        return "db_user"
    if any(tok in normalized for tok in ("db_host", "database_host", "database_server", "host", "server")):
        return "db_host"
    if any(tok in normalized for tok in ("db_name", "database_name", "database")):
        return "db_name"
    if "db_port" in normalized or "database_port" in normalized or normalized == "port":
        return "db_port"
    if "connection_string" in normalized or "database_url" in normalized or "database_uri" in normalized:
        return "connection_string"
    if "api_key" in normalized:
        return "api_key"
    if "access_key" in normalized or "aws_access_key" in normalized:
        return "access_key"
    if "secret" in normalized and "client_secret" not in normalized:
        return "secret"
    if "client_secret" in normalized:
        return "client_secret"
    if "token" in normalized or "auth_token" in normalized:
        return "token"
    if "private_key" in normalized:
        return "private_key"
    if "redis_password" in normalized or "redis_pass" in normalized:
        return "redis_password"
    if "redis_host" in normalized:
        return "redis_host"
    return "generic"


def _is_masked_config_value(value: str) -> bool:
    lowered = str(value or "").strip().lower()
    if not lowered:
        return False
    return lowered in {
        "******",
        "*****",
        "****",
        "***",
        "xxxxx",
        "xxxx",
        "xxx",
        "masked",
        "hidden",
        "redacted",
    }


def _clean_config_value(value: str) -> str:
    cleaned = str(value or "").strip()
    cleaned = cleaned.strip("\"'`")
    cleaned = re.sub(r"<[^>]+>", "", cleaned).strip()
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    cleaned = cleaned.rstrip(",;")
    return cleaned[:200]


def _summarize_config_extracted_values(extracted_values: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "real_values": [],
        "masked_values": [],
        "interesting_values": [],
        "classified": {},
    }
    seen_real = set()
    seen_masked = set()

    for item in extracted_values or []:
        if not isinstance(item, dict):
            continue

        raw_key = str(item.get("key") or "").strip()
        raw_value = _clean_config_value(item.get("value") or "")
        if not raw_key or not raw_value:
            continue

        key_class = _classify_config_key(raw_key)
        masked = bool(item.get("masked")) or _is_masked_config_value(raw_value)
        interesting = bool(item.get("interesting"))
        row = {
            "key": raw_key,
            "value": raw_value,
            "key_class": key_class,
            "masked": masked,
            "interesting": interesting,
        }

        summary["classified"].setdefault(key_class, [])
        if row not in summary["classified"][key_class]:
            summary["classified"][key_class].append(row)

        sig = (raw_key, raw_value)
        if masked:
            if sig not in seen_masked:
                seen_masked.add(sig)
                summary["masked_values"].append(row)
        elif sig not in seen_real:
            seen_real.add(sig)
            summary["real_values"].append(row)
            if interesting:
                summary["interesting_values"].append(row)

    return summary


def _format_config_exposed_information(
    extracted_summary: Dict[str, Any],
    markers: List[str],
) -> List[str]:
    exposed_information: List[str] = []
    classified = extracted_summary.get("classified") or {}

    def _clean_value(value: str) -> str:
        text = html.unescape(str(value or "")).replace("\ufffd", "").strip()
        return re.sub(r"\s+", " ", text)

    def _is_meaningful_value(value: str) -> bool:
        text = _clean_value(value)
        if not text:
            return False
        if text.lower() in {"array (", "array(", "{}", "[]", "null", "none"}:
            return False
        if len(text) < 4:
            return False
        if text.count("*") >= max(4, len(text) // 2):
            return False
        return True

    def _first_value(key_class: str) -> str | None:
        for row in classified.get(key_class) or []:
            value = _clean_value(row.get("value") or "")
            if not row.get("masked") and _is_meaningful_value(value):
                return value
        return None

    mapping = [
        ("db_host", "Database host: {value}"),
        ("db_name", "Database name: {value}"),
        ("db_user", "Database user: {value}"),
        ("db_password", "Database password: {value}"),
        ("db_port", "Database port: {value}"),
        ("connection_string", "Connection string: {value}"),
        ("redis_host", "Redis host: {value}"),
        ("redis_password", "Redis password: {value}"),
        ("api_key", "API key: {value}"),
        ("access_key", "Access key: {value}"),
        ("secret", "Secret: {value}"),
        ("client_secret", "Client secret: {value}"),
        ("token", "Token: {value}"),
    ]
    for key_class, template in mapping:
        value = _first_value(key_class)
        if value:
            if key_class == "token" and len(value) < 12:
                continue
            exposed_information.append(template.format(value=value))

    if _first_value("private_key"):
        exposed_information.append("Private key material exposed")

    if exposed_information:
        return _dedup(exposed_information)[:6]

    if not exposed_information:
        if "db_password" in markers or "mysql_password" in markers:
            exposed_information.append("Database password disclosed")
        if "db_user" in markers:
            exposed_information.append("Database username disclosed")
        if "db_host" in markers:
            exposed_information.append("Database host disclosed")
        if "database" in markers:
            exposed_information.append("Database name disclosed")
        if "api_key" in markers or "access_key" in markers or "aws_access_key" in markers:
            exposed_information.append("API or access key material disclosed")
        if "aws_secret" in markers or "private_key" in markers or "secret" in markers:
            exposed_information.append("Sensitive secret material disclosed")
        if "connection_string" in markers:
            exposed_information.append("Connection string disclosed")

    return _dedup(exposed_information)[:6]


def _build_directory_listing_signals(
    response_kind: str,
    final_url: str,
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    hints = feats.get("directory_listing_hints") or []
    if not hints:
        return []
    if _resource_probe_is_actually_error_disclosure(feats):
        return []
    if _looks_like_generic_notfound_template(snapshot, feats):
        return []

    route_label = str(final_url or "").strip() or "/"
    compact_hints = _dedup([str(item or "").strip() for item in hints])[:3]
    exposed_information = [f"Directory listing enabled at: {route_label}"]

    return [
        _build_signal(
            signal_type="directory_listing",
            finding_type="DIRECTORY_LISTING_ENABLED",
            family="DIRECTORY_LISTING",
            subtype="directory_listing",
            title="Directory listing appears to be enabled",
            severity="Medium",
            confidence=0.88,
            where="response.body",
            evidence={
                "response_kind": response_kind,
                "directory_listing_hints": compact_hints,
                "final_url": final_url,
                "redirect_chain": snapshot.get("redirect_chain", []),
            },
            exposed_information=exposed_information,
            leak_type="directory_listing",
            leak_value=route_label,
            cwe="CWE-548",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="directory_route",
            root_cause_signature="directory_listing_enabled",
            technology_fingerprint=technology_fingerprint,
        )
    ]


def _build_default_resource_signals(
    response_kind: str,
    final_url: str,
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    hints = _dedup(feats.get("default_file_hints") or [])
    if not hints:
        return []

    requested_url = str((snapshot.get("request") or {}).get("url") or final_url or "")
    status_code = _status_code(snapshot, feats)
    subtype = _default_resource_subtype_from_hints(hints)

    if not _resource_exposure_is_confirmable(snapshot, feats):
        return []
    if not _default_resource_has_concrete_marker(subtype, snapshot, feats):
        return []

    body_l = _body_text(snapshot, feats).lower()
    phpinfo_indicators = _dedup(feats.get("phpinfo_indicators") or [])
    config_markers = _dedup(feats.get("config_exposure_markers") or [])
    log_patterns = _dedup(feats.get("log_exposure_patterns") or [])

    url_l = final_url.lower()
    phpinfo_route_like = "phpinfo.php" in url_l or url_l.endswith("/phpinfo") or url_l.endswith("/info.php")
    if phpinfo_route_like and subtype == "phpinfo_page" and not _phpinfo_has_concrete_marker(snapshot, feats):
        return []

    title = "Default Or Sensitive Resource Exposed Directly"
    confidence = 0.84
    severity = "Medium"
    subtype_mapping = {
        "phpinfo_page": ["Exposed resource: phpinfo page"],
        "git_metadata": ["Exposed resource: .git/config", "Git repository metadata exposed"],
        "env_file": ["Exposed resource: .env file"],
        "server_status": ["Exposed resource: server-status", "Operational server status details exposed"],
        "actuator_endpoint": ["Exposed resource: actuator endpoint", "Application operational endpoint exposed"],
        "debug_endpoint": ["Exposed resource: debug endpoint", "Debug or diagnostic endpoint exposed"],
    }
    exposed_information = subtype_mapping.get(subtype, [f"Exposed resource hint: {item}" for item in hints[:4]])

    if subtype == "phpinfo_page":
        confidence = 0.95
        for item in phpinfo_indicators[:4]:
            exposed_information.append(f"phpinfo indicator: {item}")
    elif subtype == "git_metadata":
        confidence = 0.95
    elif subtype == "env_file":
        confidence = 0.94
        severity = "High" if config_markers else "Medium"
        for item in config_markers[:4]:
            exposed_information.append(f"Config marker: {item}")
    elif subtype == "server_status":
        confidence = 0.93
    elif subtype == "actuator_endpoint":
        confidence = 0.88
    elif subtype == "debug_endpoint":
        confidence = 0.86

    document_like = any(
        token in body_l
        for token in (
            "installation",
            "instructions",
            "readme",
            "license",
            "copying",
            "download",
            "docker",
            "virtualbox",
            "vmware",
            "github",
        )
    )
    if document_like and subtype not in {"git_metadata"}:
        return []

    exposed_information = _dedup(exposed_information)
    if not exposed_information:
        return []

    return [
        _build_signal(
            signal_type="default_resource",
            finding_type="DEFAULT_FILE_EXPOSED",
            family="DEFAULT_RESOURCE_EXPOSURE",
            subtype=subtype,
            title=title,
            severity=severity,
            confidence=confidence,
            where="response.body" if response_kind != "other" else "response.headers",
            evidence={
                "response_kind": response_kind,
                "default_file_hints": hints,
                "final_url": final_url,
                "requested_url": requested_url,
                "redirect_chain": snapshot.get("redirect_chain", []),
                "status_code": status_code,
                "location": _redirect_location(snapshot),
                "error_exposure_class": feats.get("error_exposure_class"),
                "stack_traces": feats.get("stack_traces") or [],
                "file_paths": feats.get("file_paths") or [],
                "db_errors": feats.get("db_errors") or [],
                "debug_hints": feats.get("debug_hints") or [],
                "phpinfo_indicators": phpinfo_indicators,
                "config_exposure_markers": config_markers,
                "log_exposure_patterns": log_patterns,
                "document_like": document_like,
            },
            exposed_information=exposed_information,
            leak_type="default_file_exposed",
            leak_value=_first(exposed_information) or _first(hints) or final_url,
            cwe="CWE-552",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="resource_path",
            root_cause_signature=f"default_resource:{subtype}|hints:{'|'.join(hints[:6])}",
            technology_fingerprint=technology_fingerprint,
        )
    ]


def _build_phpinfo_signal(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> List[Dict[str, Any]]:
    status_code = _status_code(snapshot, feats)
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or request_meta.get("url") or "")
    requested_url = str(request_meta.get("url") or "")
    body_l = _body_text(snapshot, feats).lower()

    if status_code != 200:
        return []
    if _is_auth_redirect(snapshot):
        return []
    if _is_auth_or_session_loss(feats):
        return []
    if _is_static_response(feats):
        return []
    if _looks_like_generic_notfound_template(snapshot, feats):
        return []
    if _is_external_auth_transition(requested_url, final_url):
        return []

    url_l = final_url.lower()
    route_hint = "phpinfo.php" in url_l or url_l.endswith("/phpinfo") or url_l.endswith("/info.php")
    indicators = _dedup(feats.get("phpinfo_indicators") or [])

    strong_tokens = [
        "phpinfo()",
        "php version",
        "loaded modules",
        "configuration file",
        "server api",
        "php variables",
        "apache environment",
        "php license",
        "<title>phpinfo()</title>",
        '<h1 class="p">php version',
    ]
    weak_tokens = [
        "zend engine",
        "include_path",
        "_server[",
        "_get[",
        "_post[",
        "document_root",
        "server software",
        "remote address",
        "http user agent",
    ]

    strong_hit_count = sum(1 for token in strong_tokens if token in body_l)
    weak_hit_count = sum(1 for token in weak_tokens if token in body_l)
    has_phpinfo_table_shape = "<table" in body_l and (
        "php credits" in body_l or "php core" in body_l or "apache2handler" in body_l
    )
    document_like = any(
        token in body_l
        for token in (
            "installation",
            "instructions",
            "readme",
            "license",
            "copying",
            "download",
            "docker",
            "virtualbox",
            "vmware",
            "github",
        )
    )
    if document_like and not route_hint:
        return []

    concrete_phpinfo = (
        ("<title>phpinfo()</title>" in body_l)
        or (route_hint and len(indicators) >= 2)
        or (route_hint and strong_hit_count >= 1 and weak_hit_count >= 2)
        or (route_hint and has_phpinfo_table_shape)
    )
    if not concrete_phpinfo:
        return []

    phpinfo_extracted_values = feats.get("phpinfo_extracted_values") or []
    exposed_information: List[str] = []
    for item in phpinfo_extracted_values[:10]:
        display = str(item.get("display") or "").strip()
        if display:
            exposed_information.append(display)
    for item in (feats.get("strong_version_tokens_in_body") or [])[:4]:
        token = str(item).strip()
        if not token:
            continue
        if token.lower().startswith("php/"):
            exposed_information.append(f"PHP version: {token}")
        else:
            exposed_information.append(f"Server software: {token}")
    for item in indicators[:4]:
        normalized = str(item).strip().lower()
        if normalized in {"php version", "phpinfo()"}:
            continue
        if normalized == "loaded modules":
            exposed_information.append("Loaded PHP modules listed")
        elif normalized == "server api":
            exposed_information.append("Server API listed")
        elif normalized == "php variables":
            exposed_information.append("PHP variables listed")
        elif normalized == "configuration file":
            exposed_information.append("PHP configuration file path listed")
        else:
            exposed_information.append(f"phpinfo indicator: {item}")
    if not exposed_information:
        exposed_information.append("PHP runtime and environment details exposed")
    if "php version" in body_l:
        exposed_information.append("PHP version disclosed")
    if "loaded modules" in body_l:
        exposed_information.append("Loaded PHP modules disclosed")
    if "server api" in body_l:
        exposed_information.append("PHP server API disclosed")
    if "configuration file" in body_l or "include_path" in body_l:
        exposed_information.append("PHP configuration details disclosed")
    technology_fingerprint = feats.get("technology_fingerprint") or []
    return [
        _build_signal(
            signal_type="phpinfo_exposure",
            finding_type="PHPINFO_EXPOSURE",
            family="HTTP_BODY_DISCLOSURE",
            subtype="phpinfo",
            title="phpinfo() Page Exposed",
            severity="Medium",
            confidence=0.96,
            where="response.body",
            evidence={
                "final_url": final_url,
                "requested_url": requested_url,
                "status_code": status_code,
                "phpinfo_indicators": indicators,
                "route_hint": route_hint,
                "strong_hit_count": strong_hit_count,
                "weak_hit_count": weak_hit_count,
                "has_phpinfo_table_shape": has_phpinfo_table_shape,
                "technology_fingerprint": technology_fingerprint,
                "strong_version_tokens_in_body": feats.get("strong_version_tokens_in_body") or [],
                "phpinfo_extracted_values": phpinfo_extracted_values,
            },
            exposed_information=_dedup(exposed_information)[:12],
            leak_type="phpinfo_page",
            leak_value=final_url,
            cwe="CWE-538",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="phpinfo_page",
            root_cause_signature="phpinfo_page_exposed",
            technology_fingerprint=technology_fingerprint,
        )
    ]


def _build_config_exposure_signal(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> List[Dict[str, Any]]:
    markers = _dedup(feats.get("config_exposure_markers") or [])
    extracted_values = feats.get("config_extracted_values") or []
    status_code = _status_code(snapshot, feats)
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or request_meta.get("url") or "")
    requested_url = str(request_meta.get("url") or "")
    body_text = _body_text(snapshot, feats)
    body_text_l = body_text.lower()
    path_l = final_url.lower()
    php_config_assignment_count = sum(
        1
        for token in (
            "$_dvwa['db_server']",
            "$_dvwa['db_database']",
            "$_dvwa['db_user']",
            "$_dvwa['db_password']",
            '$_dvwa["db_server"]',
            '$_dvwa["db_database"]',
            '$_dvwa["db_user"]',
            '$_dvwa["db_password"]',
        )
        if token in body_text_l
    )

    if status_code != 200:
        return []
    if _looks_like_generic_notfound_template(snapshot, feats):
        return []

    config_like_path_tokens = (
        "config",
        ".env",
        ".yml",
        ".yaml",
        ".ini",
        ".conf",
        ".cfg",
        ".properties",
        ".dist",
        "compose",
        "docker-compose",
        "appsettings",
        "settings",
        "application.yml",
        "application.yaml",
        "application.properties",
        ".npmrc",
        ".pypirc",
    )
    path_is_config_like = any(token in path_l for token in config_like_path_tokens)
    body_kind = str(feats.get("body_content_type_hint") or "")
    config_like_body_kind = body_kind in {"json", "json_like", "yaml", "yaml_like", "xml", "xml_like", "properties_like"}

    document_like = any(
        token in body_text_l
        for token in (
            "installation",
            "instructions",
            "readme",
            "license",
            "copying",
            "download",
            "docker",
            "virtualbox",
            "vmware",
            "github",
        )
    )
    if document_like and not path_is_config_like:
        return []
    if _resource_probe_is_actually_error_disclosure(feats) and not path_is_config_like:
        return []

    extracted_summary = _summarize_config_extracted_values(extracted_values)
    real_values = extracted_summary.get("real_values") or []
    masked_values = extracted_summary.get("masked_values") or []
    interesting_values = extracted_summary.get("interesting_values") or []
    real_key_classes = {str(item.get("key_class") or "generic") for item in real_values}

    strong_secret_classes = {
        "db_password",
        "connection_string",
        "api_key",
        "access_key",
        "secret",
        "client_secret",
        "private_key",
        "redis_password",
    }
    db_context_classes = {"db_host", "db_name", "db_user", "db_password", "db_port"}

    has_real_secret = bool(real_key_classes.intersection(strong_secret_classes))
    has_real_db_context = bool(real_key_classes.intersection(db_context_classes))
    distinct_db_context_count = len(real_key_classes.intersection(db_context_classes))
    token_only_values = bool(real_key_classes) and real_key_classes.issubset({"token"})
    only_generic_or_token_values = bool(real_key_classes) and not (
        real_key_classes.intersection(db_context_classes)
        or real_key_classes.intersection(strong_secret_classes)
    )
    setup_like_path = any(token in path_l for token in ("setup", "install", "installer"))
    html_db_setup_exposure = (
        distinct_db_context_count >= 3
        and (
            has_real_secret
            or "database" in markers
            or "db_user" in markers
            or "db_host" in markers
            or "db_password" in markers
            or setup_like_path
        )
    )
    masked_key_classes = {
        str(item.get("key_class") or "generic")
        for item in masked_values
        if str(item.get("key_class") or "").strip()
    }
    masked_db_context_count = len(masked_key_classes.intersection(db_context_classes))

    allow_config_exposure = (
        php_config_assignment_count >= 3
        or html_db_setup_exposure
        or (
            path_is_config_like
            and (
                distinct_db_context_count >= 3
                or masked_db_context_count >= 3
                or has_real_secret
            )
        )
        or (
            config_like_body_kind
            and (
                distinct_db_context_count >= 3
                or (has_real_secret and has_real_db_context)
                or masked_db_context_count >= 3
            )
        )
        or (
            has_real_secret
            and (
                path_is_config_like
                or config_like_body_kind
                or distinct_db_context_count >= 2
            )
        )
    )
    if only_generic_or_token_values and not path_is_config_like and php_config_assignment_count < 3:
        allow_config_exposure = False
    if token_only_values and not path_is_config_like and distinct_db_context_count == 0:
        allow_config_exposure = False
    if not allow_config_exposure:
        return []

    exposed_information = _format_config_exposed_information(extracted_summary, markers)
    if not exposed_information:
        return []
    severity = "High" if has_real_secret or len(real_values) >= 3 or html_db_setup_exposure or php_config_assignment_count >= 3 else "Medium"
    confidence = 0.94 if severity == "High" else 0.86

    representative_leak = final_url
    for item in real_values:
        value = str(item.get("value") or "")
        if value:
            representative_leak = value
            break

    return [
        _build_signal(
            signal_type="config_exposure",
            finding_type="HTTP_CONFIG_FILE_EXPOSURE",
            family="HTTP_BODY_DISCLOSURE",
            subtype="exposed_config_file",
            title="Configuration Content Exposed Over HTTP",
            severity=severity,
            confidence=confidence,
            where="response.body",
            evidence={
                "final_url": final_url,
                "requested_url": requested_url,
                "config_exposure_markers": markers,
                "config_extracted_values": extracted_values[:20],
                "config_real_values": real_values[:12],
                "config_masked_values": masked_values[:12],
                "config_interesting_values": interesting_values[:12],
                "config_key_classes": sorted(real_key_classes),
                "distinct_db_context_count": distinct_db_context_count,
                "html_db_setup_exposure": html_db_setup_exposure,
                "php_config_assignment_count": php_config_assignment_count,
                "body_content_type_hint": feats.get("body_content_type_hint"),
                "path_is_config_like": path_is_config_like,
                "config_like_body_kind": config_like_body_kind,
                "technology_fingerprint": feats.get("technology_fingerprint") or [],
            },
            exposed_information=exposed_information,
            leak_type="config_content",
            leak_value=representative_leak,
            cwe="CWE-497",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="config_file",
            root_cause_signature=f"config_exposure:{path_is_config_like}:{config_like_body_kind}",
            technology_fingerprint=feats.get("technology_fingerprint") or [],
        )
    ]


def _build_log_exposure_signal(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> List[Dict[str, Any]]:
    status_code = _status_code(snapshot, feats)
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or request_meta.get("url") or "")
    requested_url = str(request_meta.get("url") or "")
    body_text = _body_text(snapshot, feats)
    body_l = body_text.lower()
    final_path_l = (urlsplit(final_url).path or "/").lower()

    if status_code != 200:
        return []
    if _is_same_error_page_for_resource_probe(snapshot, feats):
        return []
    if _resource_probe_is_actually_error_disclosure(feats):
        return []
    if _looks_like_generic_notfound_template(snapshot, feats):
        return []
    if _is_auth_or_session_loss(feats):
        return []
    if _is_external_auth_transition(requested_url, final_url):
        return []

    low_value_path_tokens = (
        "/login",
        "/signin",
        "/logout",
        "/instructions",
        "/readme",
        "/about",
        "/help",
        "/faq",
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
    )
    if any(token in final_path_l for token in low_value_path_tokens):
        return []

    log_file_or_dir_patterns = [
        r"(?:^|/)logs?(?:/|$)",
        r"(?:^|/)(?:access|error|debug|application|server)\.log(?:$|[/?#])",
        r"(?:^|/)catalina\.out(?:$|[/?#])",
        r"(?:^|/)stdout(?:$|[/?#])",
        r"(?:^|/)stderr(?:$|[/?#])",
    ]
    path_like_log = any(re.search(pattern, final_path_l, re.I) for pattern in log_file_or_dir_patterns)

    access_log_lines = re.findall(
        r'(?im)^\s*\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^"]+\s+HTTP/[0-9.]+"\s+\d{3}\s+\d+.*$',
        body_text,
    )
    app_log_lines = re.findall(
        r"(?im)^\s*20\d{2}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?\s+(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b.*$",
        body_text,
    )
    java_log_lines = re.findall(
        r"(?im)^\s*(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+[A-Za-z0-9_.$-]{3,120}\s+-\s+.*$",
        body_text,
    )
    stacktrace_log_lines = re.findall(
        r"(?im)^\s*at\s+[a-zA-Z0-9_.$]+\([A-Za-z0-9_.-]+:\d+\)\s*$",
        body_text,
    )

    document_like = any(
        token in body_l
        for token in (
            "installation",
            "instructions",
            "readme",
            "license",
            "copying",
            "docker",
            "download",
            "virtualbox",
            "vmware",
            "github",
            "warning!",
            "damn vulnerable web application",
        )
    )

    concrete_log_lines: List[str] = []
    for lines in (access_log_lines[:3], app_log_lines[:3], java_log_lines[:3]):
        for line in lines:
            stripped = line.strip()
            if stripped and stripped not in concrete_log_lines:
                concrete_log_lines.append(stripped)

    if not concrete_log_lines:
        return []
    if document_like and not path_like_log:
        return []
    if not path_like_log and len(concrete_log_lines) < 2:
        return []

    confidence = 0.94 if (path_like_log and len(concrete_log_lines) >= 2) else 0.88
    exposed_information = concrete_log_lines[:4]

    return [
        _build_signal(
            signal_type="log_exposure",
            finding_type="LOG_VIEWER_EXPOSURE",
            family="HTTP_BODY_DISCLOSURE",
            subtype="log_content",
            title="Application Or Access Log Content Exposed Over HTTP",
            severity="Medium",
            confidence=confidence,
            where="response.body",
            evidence={
                "final_url": final_url,
                "requested_url": requested_url,
                "path_like_log": path_like_log,
                "access_log_line_count": len(access_log_lines),
                "app_log_line_count": len(app_log_lines),
                "java_log_line_count": len(java_log_lines),
                "stacktrace_line_count": len(stacktrace_log_lines),
                "concrete_log_lines": concrete_log_lines[:4],
                "technology_fingerprint": feats.get("technology_fingerprint") or [],
            },
            exposed_information=exposed_information,
            leak_type="log_content",
            leak_value=exposed_information[0],
            cwe="CWE-532",
            owasp="A09:2021 Security Logging and Monitoring Failures",
            scope_hint="route-specific",
            policy_object="log_viewer",
            root_cause_signature="log_content_exposed",
            technology_fingerprint=feats.get("technology_fingerprint") or [],
        )
    ]


def build_resource_exposure_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    *,
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
    resource_skip: bool,
) -> List[Dict[str, Any]]:
    if resource_skip:
        return []

    out: List[Dict[str, Any]] = []
    out.extend(_build_directory_listing_signals(response_kind, final_url, snapshot, feats, technology_fingerprint))
    out.extend(_build_default_resource_signals(response_kind, final_url, snapshot, feats, technology_fingerprint))
    out.extend(_build_phpinfo_signal(request_meta, snapshot, feats))
    out.extend(_build_config_exposure_signal(request_meta, snapshot, feats))
    out.extend(_build_log_exposure_signal(request_meta, snapshot, feats))
    return out
