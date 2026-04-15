from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, urlsplit

from agent.verification_policy import build_signal_metadata
from agent.common import log


def _dedup(items: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in items or []:
        s = str(x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _is_host_root_url(url: str) -> bool:
    try:
        parsed = urlparse(str(url or ""))
        path = parsed.path or "/"
        return path in {"", "/"}
    except Exception:
        return False


def _first(items: List[str]) -> str:
    vals = _dedup(items)
    return vals[0] if vals else ""


def _compact(items: List[str], limit: int = 4) -> List[str]:
    return _dedup(items)[:limit]


def _severity_rank(sev: str) -> int:
    order = {"Info": 1, "Low": 2, "Medium": 3, "High": 4}
    return order.get(str(sev or "Info"), 1)


def _status_code(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> int | None:
    return feats.get("status_code") or snapshot.get("status_code")


def _response_headers(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    return snapshot.get("headers") or {}


def _redirect_location(snapshot: Dict[str, Any]) -> str:
    headers = _response_headers(snapshot)
    for k, v in headers.items():
        if str(k).lower() == "location":
            return str(v or "")
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
    return any(x in location for x in ("login", "signin", "auth"))


def _is_access_denied_status(status_code: int | None) -> bool:
    return status_code in {401, 403}


def _is_not_found_status(status_code: int | None) -> bool:
    return status_code == 404


def _is_static_response(feats: Dict[str, Any]) -> bool:
    return (feats.get("response_kind") or "") == "static_asset"


def _request_name(request_meta: Dict[str, Any]) -> str:
    return str(request_meta.get("name") or "").lower()


def _request_family(request_meta: Dict[str, Any]) -> str:
    return str(request_meta.get("family") or "")


def _is_baseline_probe(request_meta: Dict[str, Any]) -> bool:
    name = _request_name(request_meta)
    family = _request_family(request_meta)
    return name in {"baseline_get", "baseline_head", "baseline_query_session"} or family == "baseline"


def _is_synthetic_probe(request_meta: Dict[str, Any]) -> bool:
    name = _request_name(request_meta)
    family = _request_family(request_meta)

    synthetic_prefixes = (
        "notfound_",
        "resource_",
        "dir_list_",
        "path_",
        "qs_",
        "hdr_",
        "cors_",
        "method_",
        "body_",
    )
    if name.startswith(synthetic_prefixes):
        return True

    return family in {
        "comparison",
        "default_resource",
        "directory_behavior",
        "error_path",
        "error_query",
        "header_behavior",
        "cors_behavior",
        "method_behavior",
        "body_behavior",
    }


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
    is_auth_landing = any(tok in final_url_l for tok in ("login", "signin", "adfs", "/auth", "/sso"))
    return is_cross_origin and is_auth_landing


def _is_direct_200_response(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> bool:
    status_code = _status_code(snapshot, feats)
    if status_code != 200:
        return False
    if _is_redirect_status(status_code):
        return False
    if _is_auth_redirect(snapshot):
        return False

    final_url = str(feats.get("final_url") or snapshot.get("final_url") or "").lower()
    if any(x in final_url for x in ("login", "signin", "/auth", "/sso")):
        return False
    return True


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
        "페이지를 찾을 수가 없습니다",
        "the requested url was not found",
        "requested resource",
        "this system is strictly restricted to authorized users only",
    ]
    hit_count = sum(1 for marker in generic_markers if marker in body_l)

    if hit_count >= 2:
        return True

    if (
        "<html" in body_l
        and "<title>page not found" in body_l
        and "페이지를 찾을 수가 없습니다" in body_l
    ):
        return True

    if status_code == 200 and any(tok in final_url for tok in (".env", ".git/config", "phpinfo.php", "server-status", "actuator", "debug")):
        if hit_count >= 1 and not _resource_probe_is_actually_error_disclosure(feats):
            return True

    return False


def _is_same_error_page_for_resource_probe(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> bool:
    if not _resource_probe_is_actually_error_disclosure(feats):
        return False

    if _looks_like_generic_notfound_template(snapshot, feats):
        return True

    status_code = _status_code(snapshot, feats)
    if status_code != 200:
        return False

    body_l = _lower_text(snapshot, feats)
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or "").lower()
    file_paths = [str(x).lower() for x in (feats.get("file_paths") or [])]

    if "fatal error" in body_l and "bootstrap.php" in body_l:
        return True
    if "failed opening required" in body_l:
        return True
    if any("bootstrap.php" in p for p in file_paths):
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
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", s):
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
        marker_count = 0
        for marker in ('"status"', '"components"', '"_links"', "/actuator"):
            if marker in body_l:
                marker_count += 1
        return marker_count >= 2

    if subtype == "debug_endpoint":
        marker_count = 0
        for marker in ("debug toolbar", "trace", "environment", "application config"):
            if marker in body_l:
                marker_count += 1
        return marker_count >= 2

    return False


def _phpinfo_has_concrete_marker(snapshot: Dict[str, Any], feats: Dict[str, Any]) -> bool:
    body = _body_text(snapshot, feats)
    body_l = body.lower()
    indicators = feats.get("phpinfo_indicators") or []

    if _is_same_error_page_for_resource_probe(snapshot, feats):
        return False
    if _looks_like_generic_notfound_template(snapshot, feats):
        return False

    if len(indicators) >= 2:
        return True

    marker_count = 0
    for token in (
        "phpinfo()",
        "php version",
        "loaded modules",
        "php variables",
        "server api",
        "<title>php",
    ):
        if token in body_l:
            marker_count += 1
    return marker_count >= 2

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

    if _should_skip_resource_exposure(request_meta, snapshot, feats):
        return []

    if _looks_like_generic_notfound_template(snapshot, feats):
        return []

    config_like_path_tokens = (
        "config", ".env", ".yml", ".yaml", ".ini", ".conf", ".cfg", ".properties", ".dist",
        "compose", "docker-compose", "appsettings", "settings",
        "application.yml", "application.yaml", "application.properties",
        ".npmrc", ".pypirc",
    )
    path_is_config_like = any(token in path_l for token in config_like_path_tokens)

    body_kind = str(feats.get("body_content_type_hint") or "")
    config_like_body_kind = body_kind in {
        "json", "json_like", "yaml", "yaml_like", "xml", "xml_like", "properties_like"
    }

    document_like = any(
        tok in body_text_l
        for tok in (
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
        "token",
        "client_secret",
    }
    medium_markers = {
        "db_user",
        "db_host",
        "database",
        "db_name",
        "db_port",
        "redis",
        "postgres",
        "mysql",
        "mariadb",
        "services:",
        "environment:",
        "volumes:",
        "image:",
    }

    strong_hits = [m for m in markers if m in strong_secret_markers]
    medium_hits = [m for m in markers if m in medium_markers]

    extracted_summary = _summarize_config_extracted_values(extracted_values)
    real_values = extracted_summary.get("real_values") or []
    masked_values = extracted_summary.get("masked_values") or []
    interesting_values = extracted_summary.get("interesting_values") or []

    real_key_classes = {
        str(item.get("key_class") or "generic")
        for item in real_values
    }

    has_real_secret = bool(real_key_classes.intersection({
        "db_password",
        "connection_string",
        "api_key",
        "access_key",
        "secret",
        "client_secret",
        "token",
        "private_key",
        "redis_password",
    }))
    has_real_db_context = bool(real_key_classes.intersection({
        "db_host", "db_name", "db_user", "db_password", "db_port",
    }))
    concrete_value_count = len(real_values)

    def _clean_value(v: str) -> str:
        s = str(v or "").strip()
        s = s.strip("\"'`")
        s = re.sub(r"<[^>]+>", "", s).strip()
        s = re.sub(r"\s+", " ", s).strip()
        s = s.rstrip(",;")
        return s[:200]

    def _extract_first(patterns: List[str], text: str) -> str | None:
        for pat in patterns:
            m = re.search(pat, text, re.I | re.M)
            if not m:
                continue
            val = m.group(1) if m.groups() else m.group(0)
            val = _clean_value(val)
            if val:
                return val
        return None

    def _extract_all(patterns: List[str], text: str, limit: int = 5) -> List[str]:
        out: List[str] = []
        seen = set()
        for pat in patterns:
            for m in re.finditer(pat, text, re.I | re.M):
                val = m.group(1) if m.groups() else m.group(0)
                val = _clean_value(val)
                if not val or val in seen:
                    continue
                seen.add(val)
                out.append(val)
                if len(out) >= limit:
                    return out
        return out

    db_user_patterns = [
        r"""['"]?db_user['"]?\s*[:=]\s*['"]([^'"\r\n]+)['"]""",
        r"""['"]?database[_ ]username['"]?\s*[:=]\s*<?em>?\s*([^<\r\n]+)""",
        r"""['"]?database[_ ]user['"]?\s*[:=]\s*<?em>?\s*([^<\r\n]+)""",
        r"""\$DB_USER\s*=\s*['"]([^'"\r\n]+)['"]""",
        r"""\$_DVWA\[\s*['"]db_user['"]\s*\]\s*=\s*['"]([^'"\r\n]+)['"]""",
    ]
    db_password_patterns = [
        r"""['"]?db_password['"]?\s*[:=]\s*['"]([^'"\r\n]+)['"]""",
        r"""['"]?mysql_password['"]?\s*[:=]\s*['"]([^'"\r\n]+)['"]""",
        r"""['"]?database[_ ]password['"]?\s*[:=]\s*<?em>?\s*([^<\r\n]+)""",
        r"""\$DB_PASSWORD\s*=\s*['"]([^'"\r\n]+)['"]""",
        r"""\$_DVWA\[\s*['"]db_password['"]\s*\]\s*=\s*['"]([^'"\r\n]+)['"]""",
    ]
    db_name_patterns = [
        r"""['"]?database[_ ]name['"]?\s*[:=]\s*<?em>?\s*([^<\r\n]+)""",
        r"""['"]?db_name['"]?\s*[:=]\s*['"]([^'"\r\n]+)['"]""",
        r"""\$DB_NAME\s*=\s*['"]([^'"\r\n]+)['"]""",
        r"""\$_DVWA\[\s*['"]db_database['"]\s*\]\s*=\s*['"]([^'"\r\n]+)['"]""",
        r"""\$_DVWA\[\s*['"]db_name['"]\s*\]\s*=\s*['"]([^'"\r\n]+)['"]""",
    ]
    db_host_patterns = [
        r"""['"]?db_host['"]?\s*[:=]\s*['"]([^'"\r\n]+)['"]""",
        r"""['"]?database[_ ]host(?:name)?['"]?\s*[:=]\s*<?em>?\s*([^<\r\n]+)""",
        r"""['"]?database[_ ]server(?: hostname)?['"]?\s*[:=]\s*<?em>?\s*([^<\r\n]+)""",
        r"""\$DB_SERVER\s*=\s*['"]([^'"\r\n]+)['"]""",
        r"""\$DB_HOST\s*=\s*['"]([^'"\r\n]+)['"]""",
        r"""\$_DVWA\[\s*['"]db_server['"]\s*\]\s*=\s*['"]([^'"\r\n]+)['"]""",
        r"""\$_DVWA\[\s*['"]db_host['"]\s*\]\s*=\s*['"]([^'"\r\n]+)['"]""",
    ]
    db_port_patterns = [
        r"""['"]?db_port['"]?\s*[:=]\s*['"]?([0-9]{2,6})['"]?""",
        r"""['"]?database[_ ]port['"]?\s*[:=]\s*<?em>?\s*([0-9]{2,6})""",
        r"""\$_DVWA\[\s*['"]db_port['"]\s*\]\s*=\s*['"]?([0-9]{2,6})['"]?""",
    ]
    db_engine_patterns = [
        r"""['"]?backend database['"]?\s*[:=]\s*<?em>?\s*([^<\r\n]+)""",
        r"""\b(mysql/mariadb|mysql|mariadb|postgresql|postgres|sqlite|oracle)\b""",
    ]

    fallback_db_user = _extract_first(db_user_patterns, body_text)
    fallback_db_password = _extract_first(db_password_patterns, body_text)
    fallback_db_name = _extract_first(db_name_patterns, body_text)
    fallback_db_host = _extract_first(db_host_patterns, body_text)
    fallback_db_port = _extract_first(db_port_patterns, body_text)
    fallback_db_engine_hits = _extract_all(db_engine_patterns, body_text, limit=3)

    fallback_concrete_count = sum(
        1 for x in [fallback_db_host, fallback_db_name, fallback_db_user, fallback_db_password, fallback_db_port] if x
    )

    req_family = str(request_meta.get("family") or "").strip().lower()
    req_name = str(request_meta.get("name") or "").strip().lower()
    is_param_probe = (
        req_family == "query_param"
        or "param" in req_name
        or "template" in req_name
        or "file" in req_name
        or "path" in req_name
    )

    if is_param_probe:
        if concrete_value_count == 0 and fallback_concrete_count == 0 and not path_is_config_like:
            return []

        weak_only_markers = {"mysql", "mariadb", "postgres", "redis", "database", "environment:"}
        if concrete_value_count == 0 and fallback_concrete_count == 0:
            if set(markers).issubset(weak_only_markers):
                return []

        low_value_doc_paths = ("instructions", "about", "readme", "help", "faq", "docs")
        if any(tok in path_l for tok in low_value_doc_paths):
            if not has_real_secret and not has_real_db_context and fallback_concrete_count < 2:
                return []

    allow_config_exposure = False

    if has_real_secret:
        allow_config_exposure = True
    elif has_real_db_context and concrete_value_count >= 2:
        allow_config_exposure = True
    elif fallback_concrete_count >= 2 and path_is_config_like:
        allow_config_exposure = True
    elif fallback_concrete_count >= 3:
        allow_config_exposure = True
    elif strong_hits and (path_is_config_like or config_like_body_kind):
        allow_config_exposure = True
    elif path_is_config_like:
        if len(set(medium_hits)) >= 2:
            allow_config_exposure = True
        elif config_like_body_kind and len(markers) >= 1:
            allow_config_exposure = True
        elif fallback_concrete_count >= 1:
            allow_config_exposure = True
    else:
        if config_like_body_kind and len(set(medium_hits)) >= 3:
            allow_config_exposure = True
        elif config_like_body_kind and len(markers) >= 4 and not document_like:
            allow_config_exposure = True
        elif fallback_concrete_count >= 3:
            allow_config_exposure = True

    if not allow_config_exposure:
        return []

    exposed_information = _format_config_exposed_information(extracted_summary, markers)

    if (not exposed_information) or exposed_information == ["Application configuration details disclosed"]:
        fallback_items: List[str] = []
        if fallback_db_host:
            fallback_items.append(f"Database host: {fallback_db_host}")
        if fallback_db_name:
            fallback_items.append(f"Database name: {fallback_db_name}")
        if fallback_db_user:
            fallback_items.append(f"Database user: {fallback_db_user}")
        if fallback_db_password:
            fallback_items.append(f"Database password: {fallback_db_password}")
        if fallback_db_port:
            fallback_items.append(f"Database port: {fallback_db_port}")
        for eng in fallback_db_engine_hits[:2]:
            eng_clean = _clean_value(eng)
            if eng_clean:
                fallback_items.append(f"Database engine: {eng_clean}")

        if fallback_items:
            exposed_information = _dedup(fallback_items)[:6]

    generic_only_exposure = {
        "Application configuration details disclosed",
        "Database password disclosed",
        "Database username disclosed",
        "Database user disclosed",
        "Database name disclosed",
        "Database host disclosed",
        "Database server disclosed",
        "API or access key material disclosed",
        "Sensitive secret material disclosed",
        "Connection string disclosed",
    }

    exposed_information_set = {str(x).strip() for x in exposed_information if str(x).strip()}
    has_only_generic_exposure = bool(exposed_information_set) and exposed_information_set.issubset(generic_only_exposure)

    if has_only_generic_exposure:
        if concrete_value_count == 0 and fallback_concrete_count == 0 and not has_real_secret and not has_real_db_context:
            return []

    confidence = 0.86
    severity = "Medium"

    if strong_hits:
        confidence = max(confidence, 0.90)
        severity = "High"

    if has_real_secret:
        confidence = max(confidence, 0.93)
        severity = "High"

    if concrete_value_count >= 3 or fallback_concrete_count >= 3:
        confidence = max(confidence, 0.94)
        severity = "High"

    representative_leak = ""
    if real_values:
        for item in real_values:
            kc = str(item.get("key_class") or "")
            if kc in {"db_password", "connection_string", "api_key", "access_key", "secret", "token", "private_key"}:
                representative_leak = str(item.get("value") or "")
                break
        if not representative_leak:
            representative_leak = str(real_values[0].get("value") or "")
    elif fallback_db_password:
        representative_leak = fallback_db_password
    elif fallback_db_host:
        representative_leak = fallback_db_host
    else:
        representative_leak = final_url

    return [
        _build_signal(
            signal_type="config_exposure",
            finding_type="HTTP_CONFIG_FILE_EXPOSURE",
            family="HTTP_BODY_DISCLOSURE",
            subtype="exposed_config_file",
            title="설정 파일 내용이 HTTP로 노출됨",
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
                "strong_secret_markers": strong_hits,
                "medium_markers": medium_hits,
                "body_content_type_hint": feats.get("body_content_type_hint"),
                "path_is_config_like": path_is_config_like,
                "config_like_body_kind": config_like_body_kind,
                "technology_fingerprint": feats.get("technology_fingerprint") or [],
                "body_snippet": body_text[:1000],
                "has_real_secret": has_real_secret,
                "has_real_db_context": has_real_db_context,
                "concrete_value_count": concrete_value_count,
                "fallback_db_user": fallback_db_user,
                "fallback_db_password": fallback_db_password,
                "fallback_db_name": fallback_db_name,
                "fallback_db_host": fallback_db_host,
                "fallback_db_port": fallback_db_port,
                "fallback_db_engine": fallback_db_engine_hits[:2],
                "is_param_probe": is_param_probe,
                "document_like": document_like,
            },
            exposed_information=exposed_information,
            leak_type="config_file",
            leak_value=representative_leak,
            cwe="CWE-200",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="config_file",
            root_cause_signature="config_file_exposed",
            technology_fingerprint=feats.get("technology_fingerprint") or [],
        )
    ]

def _looks_like_setup_or_install_page(final_url: str, body_text: str) -> bool:
    path_l = final_url.lower()
    body_l = body_text.lower()
    return any(x in path_l for x in ("setup.php", "/setup", "install", "installer", "init")) or any(
        x in body_l for x in ("create / reset database", "database setup", "setup check", "installation")
    )


def _is_sensitive_cookie_name(name: str) -> bool:
    n = str(name or "").strip().lower()
    if not n:
        return False

    # 명확한 세션 / 인증 / CSRF 쿠키 우선
    strong_exact = {
        "jsessionid",
        "phpsessid",
        "sessionid",
        "session_id",
        "sessid",
        "sid",
        "connect.sid",
        "_session",
        "_sessionid",
        "auth_token",
        "access_token",
        "refresh_token",
        "remember_token",
        "csrftoken",
        "csrf_token",
        "xsrf-token",
        "x-csrf-token",
        "jwt",
    }
    if n in strong_exact:
        return True

    # 이름 전체에 강한 민감 토큰이 포함된 경우만 허용
    strong_contains = (
        "jsession",
        "phpsess",
        "session",
        "sess",
        "auth",
        "token",
        "jwt",
        "csrf",
        "xsrf",
        "remember",
        "login",
        "sso",
        "oauth",
        "saml",
    )
    if any(tok in n for tok in strong_contains):
        return True

    return False

def _is_probably_non_sensitive_cookie_name(name: str) -> bool:
    n = str(name or "").strip().lower()
    if not n:
        return True

    # 일반 환경에서 흔한 비민감/보조/UX 쿠키
    exact_names = {
        "lang",
        "language",
        "locale",
        "theme",
        "timezone",
        "tz",
        "returnpath",
        "return_path",
        "redirect",
        "redirecturl",
        "redirect_url",
        "lastactivitytime",
        "last_activity_time",
        "visit",
        "visited",
        "menu",
        "menuid",
        "_menuid",
        "_menuf",
        "search",
        "search_arguments_data",
        "search_arguments_path",
    }
    if n in exact_names:
        return True

    weak_tokens = (
        "lang",
        "locale",
        "theme",
        "return",
        "redirect",
        "lastactivity",
        "menu",
        "search",
        "view",
        "tab",
        "sort",
        "filter",
        "popup",
    )
    if any(tok in n for tok in weak_tokens):
        return True

    return False





def _signal_meta_for(family: str, subtype: str) -> Dict[str, str]:
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

    if family == "HTTP_HEADER_DISCLOSURE":
        return build_signal_metadata(
            signal_strength="deterministic",
            signal_repeatability="stable",
            observation_scope="response_policy",
        )

    if family == "HTTP_HEADER_SECURITY":
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

    if family in {"HTTP_ERROR_DISCLOSURE", "HTTP_BODY_DISCLOSURE"}:
        return build_signal_metadata(
            signal_strength="strong",
            signal_repeatability="likely_stable",
            observation_scope="route_behavior",
        )

    if family in {"DIRECTORY_LISTING", "DEFAULT_RESOURCE_EXPOSURE"}:
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


def _alignment_meta_for(finding_type: str) -> Dict[str, Any]:
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

    classification_kind = "finding"
    if finding_type == "HTTPS_REDIRECT_MISSING":
        classification_kind = "supporting_signal"

    return {
        "classification_kind": classification_kind,
        "burp_zap_aligned": finding_type in burp_zap_aligned_types,
    }


def _why_and_rec(family: str) -> Dict[str, Any]:
    mapping = {
        "HTTP_HEADER_DISCLOSURE": {
            "why": "응답 헤더가 서버/프레임워크 식별 정보를 노출하면 공격자의 정찰과 익스플로잇 선택을 돕는다.",
            "rec": [
                "불필요한 Server/X-Powered-By/Via 계열 헤더를 제거하거나 축소한다.",
                "리버스 프록시, WAS, 프레임워크 레벨에서 배너 노출 정책을 정리한다.",
            ],
        },
        "HTTP_ERROR_DISCLOSURE": {
            "why": "에러 페이지가 스택트레이스, 파일경로, DB 오류 등을 노출하면 내부 구조가 드러난다.",
            "rec": [
                "운영 환경에서는 커스텀 에러 페이지를 사용하고 verbose 오류를 비활성화한다.",
                "스택트레이스, 내부 경로, 예외 상세를 외부 응답에서 제거한다.",
            ],
        },
        "HTTP_BODY_DISCLOSURE": {
            "why": "본문의 제품 버전, 프레임워크 힌트, 디버그 정보는 공격자 정찰에 유용하다.",
            "rec": [
                "응답 본문에서 제품/버전/디버그 정보를 제거한다.",
                "운영 환경에서 프레임워크 시그니처 노출을 줄인다.",
            ],
        },
        "COOKIE_SECURITY": {
            "why": "쿠키 속성이 약하면 브라우저 측 보호가 약화된다.",
            "rec": [
                "민감 쿠키에는 HttpOnly, Secure, SameSite를 적절히 설정한다.",
                "세션/인증 쿠키부터 우선 점검한다.",
            ],
        },
        "CORS_MISCONFIG": {
            "why": "과도한 CORS 허용은 공격자 Origin에서 사용자 브라우저를 통해 응답을 읽게 만들 수 있다.",
            "rec": [
                "임의 Origin 반사를 금지한다.",
                "credentials 사용 시 엄격한 allowlist를 적용한다.",
            ],
        },
        "HTTP_METHOD_SECURITY": {
            "why": "불필요하거나 위험한 HTTP 메서드는 공격면을 넓힌다.",
            "rec": [
                "필요한 메서드만 허용한다.",
                "TRACE 등 불필요한 메서드를 웹서버/프록시/앱 전 구간에서 비활성화한다.",
            ],
        },
        "TRANSPORT_SECURITY": {
            "why": "전송 보안이 약하면 다운그레이드, 도청, 혼합 접속 위험이 생긴다.",
            "rec": [
                "HTTP를 HTTPS로 일관되게 리다이렉트한다.",
                "HTTPS 응답에 HSTS를 설정한다.",
            ],
        },
        "DEFAULT_RESOURCE_EXPOSURE": {
            "why": "기본 파일, 디버그 엔드포인트, 저장소 메타데이터 노출은 민감 정보와 운영 구조를 드러낼 수 있다.",
            "rec": [
                "기본/디버그/운영 파일의 외부 노출을 제거한다.",
                "배포 산출물에 민감 파일이 포함되지 않도록 점검한다.",
            ],
        },
        "DIRECTORY_LISTING": {
            "why": "디렉터리 listing은 파일명과 구조를 노출해 추가 탐색을 쉽게 만든다.",
            "rec": [
                "디렉터리 listing을 비활성화한다.",
                "디렉터리 경로에는 generic 403/404를 반환한다.",
            ],
        },
        "HTTP_HEADER_SECURITY": {
            "why": "브라우저 보안 헤더 부재는 클릭재킹, MIME sniffing, referrer leakage 등의 노출을 키운다.",
            "rec": [
                "외부 노출 HTML 응답에 대한 표준 보안 헤더 baseline을 정의한다.",
                "앱 전반에 동일 정책을 일관되게 적용한다.",
            ],
        },
    }
    return mapping.get(
        family,
        {
            "why": "관찰된 HTTP 동작이 정보 노출 또는 보안 설정 미흡을 시사한다.",
            "rec": ["운영 환경에서 불필요한 노출을 제거한다."],
        },
    )


def _build_signal(
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
    why_rec = _why_and_rec(family)
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
        "exposed_information": _compact(exposed_information),
        "leak_type": leak_type,
        "leak_value": leak_value,
        "cwe": cwe,
        "owasp": owasp,
        "scope_hint": scope_hint,
        "policy_object": policy_object,
        "root_cause_signature": root_cause_signature,
        "technology_fingerprint": technology_fingerprint,
        "template_fingerprint": template_fingerprint,
        "why_it_matters": why_rec["why"],
        "recommendation": why_rec["rec"],
        "cwe_mapping_status": cwe_mapping_status,
        "cwe_mapping_reason": cwe_mapping_reason,
        **_signal_meta_for(family, subtype),
        **_alignment_meta_for(finding_type),
    }
    return {k: v for k, v in out.items() if v not in (None, "", [], {})}


def _build_header_disclosure_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
    tech: str,
) -> List[Dict[str, Any]]:
    if _is_static_response(feats):
        return []

    status_code = _status_code(snapshot, feats)
    header_disclosures = feats.get("header_disclosures") or []
    if not header_disclosures:
        return []

    requested_url = str(request_meta.get("url") or "")
    is_cross_origin = _requested_and_final_origin(requested_url, final_url)[0] != _requested_and_final_origin(requested_url, final_url)[1]
    is_redirect = _is_redirect_status(status_code)
    is_external_auth = _is_external_auth_transition(requested_url, final_url)

    def _is_too_generic_header_value(header: str, value: str) -> bool:
        h = str(header or "").lower().strip()
        v = str(value or "").strip().lower()

        if not v:
            return True

        generic_values = {
            "",
            "unknown",
            "server",
            "backend",
            "proxy",
            "gateway",
            "application",
            "web server",
        }
        if v in generic_values:
            return True

        if len(v) <= 2:
            return True

        if h == "via":
            if v in {"1.1", "2", "http/1.1", "proxy", "gateway"}:
                return True

        return False

    def _looks_low_value_banner(header: str, value: str, has_version: bool) -> bool:
        h = str(header or "").lower().strip()
        v = str(value or "").strip().lower()

        if has_version:
            return False

        if h == "server":
            return v in {"apache", "nginx", "iis", "envoy", "gunicorn", "uvicorn", "openresty", "jetty", "caddy"}

        if h == "x-powered-by":
            return v in {"php", "asp.net", "express", "servlet"}

        if h in {"x-aspnet-version", "x-aspnetmvc-version"}:
            return False

        if h == "via":
            return not any(tok in v for tok in ("nginx", "apache", "varnish", "squid", "cloudfront", "envoy"))

        return False

    def _header_severity_confidence(subtype: str, has_version: bool, value: str) -> tuple[str, float]:
        value_l = str(value or "").lower()

        if subtype in {"server_header", "x_powered_by", "x_aspnet_version", "x_aspnetmvc_version"}:
            if has_version:
                return "Low", 0.92
            return "Info", 0.80

        if subtype == "via_header":
            if any(tok in value_l for tok in ("nginx", "apache", "varnish", "squid", "cloudfront", "envoy")):
                return "Info", 0.74
            return "Info", 0.66

        return ("Low", 0.88) if has_version else ("Info", 0.70)

    out: List[Dict[str, Any]] = []

    for item in header_disclosures:
        header = str(item.get("header") or "").lower().strip()
        value = str(item.get("value") or "").strip()
        subtype = str(item.get("subtype") or "header_disclosure").strip()
        has_version = bool(item.get("has_version"))
        product_family = str(item.get("product_family") or tech or "unknown").strip()

        if not header or not value:
            continue
        if _is_too_generic_header_value(header, value):
            continue

        allowed_headers = {
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version",
            "via",
        }
        if header not in allowed_headers:
            continue

        if header == "via" and not (has_version or any(tok in value.lower() for tok in ("nginx", "apache", "varnish", "squid", "cloudfront", "envoy"))):
            continue

        if is_external_auth and not has_version:
            continue

        if is_redirect and _looks_low_value_banner(header, value, has_version):
            continue

        severity, confidence = _header_severity_confidence(subtype, has_version, value)

        title_map = {
            "server_header": "Server 헤더가 시스템 정보를 노출함",
            "x_powered_by": "X-Powered-By 헤더가 시스템 정보를 노출함",
            "via_header": "Via 헤더가 시스템 정보를 노출함",
            "x_aspnet_version": "X-AspNet-Version 헤더가 시스템 정보를 노출함",
            "x_aspnetmvc_version": "X-AspNetMvc-Version 헤더가 시스템 정보를 노출함",
        }

        out.append(
            _build_signal(
                signal_type="header_disclosure",
                finding_type="HTTP_SYSTEM_INFO_EXPOSURE",
                family="HTTP_HEADER_DISCLOSURE",
                subtype=subtype,
                title=title_map.get(subtype, "응답 헤더가 시스템 정보를 노출함"),
                severity=severity,
                confidence=confidence,
                where="response.headers",
                evidence={
                    "response_kind": response_kind,
                    "final_url": final_url,
                    "requested_url": requested_url,
                    "status_code": status_code,
                    "banner_headers": {header: value},
                    "header_name": header,
                    "header_value": value,
                    "header_has_version": has_version,
                    "is_redirect": is_redirect,
                    "is_auth_redirect": _is_auth_redirect(snapshot),
                    "is_cross_origin": is_cross_origin,
                    "is_external_auth_transition": is_external_auth,
                    "reasons": feats.get("reasons") or [],
                },
                exposed_information=[f"{header}: {value}"],
                leak_type="header_disclosure",
                leak_value=value,
                cwe="CWE-497",
                owasp="A05:2021 Security Misconfiguration",
                scope_hint="host-wide",
                policy_object=header,
                root_cause_signature=f"header:{header}|product:{product_family}|value:{value}",
                technology_fingerprint=technology_fingerprint,
            )
        )

    return out


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
    out: List[Dict[str, Any]] = []

    error_class = str(feats.get("error_exposure_class") or "").strip()
    if error_class not in {"db_error", "stack_trace", "file_path", "debug_error_page"}:
        return out

    if _is_static_response(feats):
        return out
    if _is_auth_redirect(snapshot):
        return out

    requested_url = str(request_meta.get("url") or "")
    if _is_external_auth_transition(requested_url, final_url):
        return out

    body_text = _body_text(snapshot, feats)
    stack_traces = _dedup(feats.get("stack_traces") or [])
    file_paths = _dedup(feats.get("file_paths") or [])
    db_errors = _dedup(feats.get("db_errors") or [])
    debug_hints = _dedup(feats.get("debug_hints") or [])
    framework_hints = _dedup(feats.get("framework_hints") or [])
    strong_versions = _dedup(feats.get("strong_version_tokens_in_body") or [])
    default_error_hint = feats.get("default_error_hint")
    error_template = feats.get("error_template_fingerprint")

    phpinfo_indicators = _dedup(feats.get("phpinfo_indicators") or [])
    config_markers = _dedup(feats.get("config_exposure_markers") or [])
    config_values = feats.get("config_extracted_values") or []
    default_file_hints = _dedup(feats.get("default_file_hints") or [])

    if status_code is None:
        return out

    strong_error_artifacts = bool(stack_traces or file_paths)
    medium_error_artifacts = bool(db_errors)
    debug_error_artifacts = bool(debug_hints or default_error_hint)

    # generic 404/placeholder는 제외
    if _looks_like_generic_notfound_template(snapshot, feats) and not strong_error_artifacts and not medium_error_artifacts:
        return out

    # setup/install 문서는 매우 보수적으로
    if _looks_like_setup_or_install_page(final_url, body_text):
        if error_class not in {"stack_trace", "file_path"}:
            return out

    # 핵심:
    # 200 본문에서 phpinfo/config/default resource가 직접 보이는 경우
    # 약한 db_error 계열로 다시 분류하지 않음
    looks_like_concrete_resource_disclosure = bool(
        default_file_hints
        or (phpinfo_indicators and status_code == 200)
        or (config_values and status_code == 200)
        or (config_markers and status_code == 200 and "config" in final_url.lower())
    )

    if error_class == "db_error":
        if not db_errors:
            return out

        # 200 + 약한 db_error 단독은 버림
        if status_code < 400 and not strong_error_artifacts and not default_error_hint:
            return out

        # concrete resource disclosure와 겹치면 error finding으로 올리지 않음
        if status_code == 200 and looks_like_concrete_resource_disclosure and not strong_error_artifacts:
            return out

    if error_class == "debug_error_page":
        concrete_debug_combo = (
            len(debug_hints) >= 2
            or (default_error_hint and (stack_traces or db_errors or file_paths))
            or (default_error_hint and len(framework_hints) >= 2)
        )
        if not concrete_debug_combo:
            return out

    if error_class == "file_path":
        if not file_paths:
            return out
        if status_code < 400 and not stack_traces and not default_error_hint:
            return out

    if error_class == "stack_trace":
        if not stack_traces:
            return out

    exposed_information: List[str] = []
    severity = "Low"
    confidence = 0.76
    subtype = error_class

    if error_class == "db_error":
        severity = "Medium"
        confidence = 0.88 if status_code >= 400 else 0.80
        exposed_information.extend([f"Database error: {x}" for x in db_errors[:4]])

    elif error_class == "stack_trace":
        severity = "Medium"
        confidence = 0.92
        exposed_information.extend([f"Stack trace: {x}" for x in stack_traces[:4]])

    elif error_class == "file_path":
        severity = "Medium"
        confidence = 0.88 if status_code >= 400 else 0.82
        exposed_information.extend([f"File path: {x}" for x in file_paths[:4]])

    elif error_class == "debug_error_page":
        severity = "Medium"
        confidence = 0.80 if default_error_hint else 0.78
        exposed_information.extend([f"Debug hint: {x}" for x in debug_hints[:4]])
        if default_error_hint:
            exposed_information.append(f"Default error template: {default_error_hint}")

    exposed_information = _dedup(exposed_information)
    if not exposed_information:
        return out

    title_map = {
        "db_error": "HTTP 에러 페이지가 DB 오류를 노출함",
        "stack_trace": "HTTP 에러 페이지가 스택트레이스를 노출함",
        "file_path": "HTTP 에러 페이지가 내부 파일 경로를 노출함",
        "debug_error_page": "디버그 에러 페이지가 노출됨",
    }

    out.append(
        _build_signal(
            signal_type="error_disclosure",
            finding_type="HTTP_ERROR_INFO_EXPOSURE",
            family="HTTP_ERROR_DISCLOSURE",
            subtype=subtype,
            title=title_map[subtype],
            severity=severity,
            confidence=confidence,
            where="response.body",
            evidence={
                "response_kind": response_kind,
                "final_url": final_url,
                "requested_url": requested_url,
                "redirect_chain": snapshot.get("redirect_chain", []),
                "default_error_hint": default_error_hint,
                "version_tokens_in_body": feats.get("version_tokens_in_body") or [],
                "strong_version_tokens_in_body": strong_versions,
                "stack_traces": stack_traces,
                "file_paths": file_paths,
                "db_errors": db_errors,
                "debug_hints": debug_hints,
                "framework_hints": framework_hints,
                "phpinfo_indicators": phpinfo_indicators,
                "config_exposure_markers": config_markers,
                "config_extracted_values": config_values[:10],
                "default_file_hints": default_file_hints,
                "reasons": feats.get("reasons") or [],
                "status_code": status_code,
                "is_cross_origin": _requested_and_final_origin(requested_url, final_url)[0] != _requested_and_final_origin(requested_url, final_url)[1],
            },
            exposed_information=exposed_information,
            leak_type="error_info",
            leak_value=_first(exposed_information) or f"HTTP {status_code} error disclosure",
            cwe="CWE-209",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="error_template",
            root_cause_signature=f"error:{subtype}|template:{error_template or default_error_hint or 'generic'}|tech:{tech}",
            technology_fingerprint=technology_fingerprint,
            template_fingerprint=error_template,
        )
    )

    return out


def _build_non_error_body_disclosure_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
    tech: str,
) -> List[Dict[str, Any]]:
    status_code = _status_code(snapshot, feats)
    if status_code is None or status_code >= 400:
        return []

    requested_url = str(request_meta.get("url") or "")
    body_text = _body_text(snapshot, feats)
    body_l = body_text.lower()

    if _should_skip_info_disclosure(request_meta, snapshot, feats):
        return []

    strong_versions = _dedup(feats.get("strong_version_tokens_in_body") or [])
    generic_versions = _dedup(feats.get("version_tokens_in_body") or [])
    internal_ips = _dedup(feats.get("internal_ips") or [])
    framework_hints = _dedup(feats.get("framework_hints") or [])
    debug_hints = _dedup(feats.get("debug_hints") or [])
    fingerprint_tech = _dedup(feats.get("fingerprint_tech") or [])
    fingerprint_clues = _dedup(feats.get("fingerprint_clues") or [])
    stack_traces = _dedup(feats.get("stack_traces") or [])
    db_errors = _dedup(feats.get("db_errors") or [])
    file_paths = _dedup(feats.get("file_paths") or [])

    # ------------------------------------------------------------------
    # strong noise filtering
    # ------------------------------------------------------------------
    document_like = any(
        tok in body_l
        for tok in (
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
            "damn vulnerable web application",
            "owasp juice shop",
        )
    )

    spa_shell_markers = [
        "<!doctype html",
        "<html",
        "<head",
        "<body",
        "<app-root",
        "<base href=",
        "<meta name=\"viewport\"",
        "<script",
        "<title>",
    ]
    spa_shell_hit_count = sum(1 for marker in spa_shell_markers if marker in body_l)
    looks_like_spa_shell = spa_shell_hit_count >= 5

    if document_like or looks_like_spa_shell:
        return []

    # ------------------------------------------------------------------
    # extract concrete body markers
    # ------------------------------------------------------------------
    body_marker_hits: List[str] = []
    body_marker_patterns = [
        ("generator_meta", r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']'),
        ("powered_by_text", r"(powered by [a-z0-9 ._\-+/]{3,120})"),
        ("server_banner_text", r"(apache tomcat/[0-9][a-z0-9._\-]*)"),
        ("server_banner_text", r"(jboss eap ?[0-9][a-z0-9._\-]*)"),
        ("server_banner_text", r"(wildfly/[0-9][a-z0-9._\-]*)"),
        ("server_banner_text", r"(undertow/[0-9][a-z0-9._\-]*)"),
        ("server_banner_text", r"(weblogic(?: server)?[ /][0-9][a-z0-9._\-]*)"),
        ("server_banner_text", r"(websphere(?: application server)?[ /][0-9][a-z0-9._\-]*)"),
        ("framework_banner_text", r"(spring boot[ /][0-9][a-z0-9._\-]*)"),
        ("framework_banner_text", r"(django[ /][0-9][a-z0-9._\-]*)"),
        ("framework_banner_text", r"(flask[ /][0-9][a-z0-9._\-]*)"),
        ("framework_banner_text", r"(laravel[ /][0-9][a-z0-9._\-]*)"),
        ("framework_banner_text", r"(asp\.net(?: core)?[ /][0-9][a-z0-9._\-]*)"),
        ("framework_banner_text", r"(struts[ /][0-9][a-z0-9._\-]*)"),
        ("framework_banner_text", r"(drupal[ /][0-9][a-z0-9._\-]*)"),
        ("framework_banner_text", r"(wordpress[ /][0-9][a-z0-9._\-]*)"),
        ("comment_banner", r"<!--\s*(generated by [^>]{3,160})\s*-->"),
        ("comment_banner", r"<!--\s*(powered by [^>]{3,160})\s*-->"),
    ]

    noise_tokens = (
        "react app",
        "vue app",
        "angular app",
        "javascript required",
        "single page application",
        "webpack",
        "vite",
        "next.js app",
        "nuxt",
    )

    for marker_type, pattern in body_marker_patterns:
        try:
            for m in re.finditer(pattern, body_l, re.I):
                val = str(m.group(1) if m.groups() else m.group(0)).strip()
                if not val:
                    continue
                if any(tok in val for tok in noise_tokens):
                    continue
                hit = f"{marker_type}: {val}"
                if hit not in body_marker_hits:
                    body_marker_hits.append(hit)
                if len(body_marker_hits) >= 6:
                    break
        except Exception:
            pass
        if len(body_marker_hits) >= 6:
            break

    # ------------------------------------------------------------------
    # stricter signal gating
    # ------------------------------------------------------------------
    strong_debug_context = bool(stack_traces or db_errors or file_paths or debug_hints)

    # loopback-only / weak internal IPs are not enough
    internal_ips = [ip for ip in internal_ips if not str(ip).startswith("127.")]
    if internal_ips and not strong_debug_context:
        internal_ips = []

    strong_body_marker_disclosure = any(
        tok in hit
        for hit in body_marker_hits
        for tok in (
            "apache tomcat/",
            "jboss eap ",
            "wildfly/",
            "undertow/",
            "weblogic",
            "websphere",
            "spring boot",
            "django ",
            "flask ",
            "laravel ",
            "asp.net",
            "struts",
            "drupal",
            "wordpress",
        )
    )

    has_version_disclosure = bool(strong_versions)
    has_internal_context_disclosure = bool(internal_ips and strong_debug_context)
    has_body_marker_disclosure = bool(body_marker_hits)

    # framework/debug hint만으로는 약함
    combined_framework_debug = len(framework_hints) + len(debug_hints)
    has_multi_hint_disclosure = bool(
        combined_framework_debug >= 2
        and (generic_versions or has_body_marker_disclosure)
    )

    # 최종 gate
    if not (
        has_version_disclosure
        or has_internal_context_disclosure
        or strong_body_marker_disclosure
        or has_multi_hint_disclosure
    ):
        return []

    exposed_information: List[str] = []
    decision_reasons: List[str] = []

    if has_version_disclosure:
        for x in strong_versions[:4]:
            exposed_information.append(f"Version token: {x}")
        decision_reasons.append("strong_version_tokens_in_body")

    if has_internal_context_disclosure:
        for x in internal_ips[:2]:
            exposed_information.append(f"Internal IP: {x}")
        for x in framework_hints[:2]:
            exposed_information.append(f"Framework hint: {x}")
        for x in debug_hints[:2]:
            exposed_information.append(f"Debug hint: {x}")
        decision_reasons.append("internal_context_disclosure")

    if has_body_marker_disclosure:
        exposed_information.extend(body_marker_hits[:4])
        decision_reasons.append("body_marker_disclosure")

    if has_multi_hint_disclosure and not has_internal_context_disclosure and not has_version_disclosure:
        for x in framework_hints[:3]:
            exposed_information.append(f"Framework hint: {x}")
        for x in debug_hints[:2]:
            exposed_information.append(f"Debug hint: {x}")
        for x in generic_versions[:2]:
            exposed_information.append(f"Version hint: {x}")
        decision_reasons.append("multi_hint_disclosure")

    exposed_information = _dedup(exposed_information)
    if not exposed_information:
        return []

    subtype = "body_info_marker"
    severity = "Info"
    confidence = 0.72

    if has_version_disclosure:
        subtype = "product_version_in_body"
        severity = "Low"
        confidence = max(confidence, 0.86)

    if has_internal_context_disclosure:
        subtype = "internal_ip_in_body"
        severity = "Low"
        confidence = max(confidence, 0.88)

    if strong_body_marker_disclosure and not has_version_disclosure and not has_internal_context_disclosure:
        subtype = "server_framework_banner_in_body"
        severity = "Low"
        confidence = max(confidence, 0.83)

    if has_multi_hint_disclosure and subtype == "body_info_marker":
        subtype = "framework_hint_in_body"
        severity = "Info"
        confidence = max(confidence, 0.78)

    return [
        _build_signal(
            signal_type="body_disclosure",
            finding_type="HTTP_SYSTEM_INFO_EXPOSURE",
            family="HTTP_BODY_DISCLOSURE",
            subtype=subtype,
            title="HTTP 응답 본문이 시스템 정보를 노출함",
            severity=severity,
            confidence=confidence,
            where="response.body",
            evidence={
                "response_kind": response_kind,
                "final_url": final_url,
                "requested_url": requested_url,
                "redirect_chain": snapshot.get("redirect_chain", []),
                "version_tokens_in_body": generic_versions,
                "strong_version_tokens_in_body": strong_versions,
                "internal_ips": internal_ips,
                "framework_hints": framework_hints,
                "debug_hints": debug_hints,
                "stack_traces": stack_traces,
                "db_errors": db_errors,
                "file_paths": file_paths,
                "fingerprint_tech": fingerprint_tech,
                "fingerprint_clues": fingerprint_clues,
                "body_info_markers": body_marker_hits,
                "decision_reasons": decision_reasons,
                "is_cross_origin": _requested_and_final_origin(requested_url, final_url)[0] != _requested_and_final_origin(requested_url, final_url)[1],
                "reasons": feats.get("reasons") or [],
                "status_code": status_code,
                "document_like": document_like,
                "looks_like_spa_shell": looks_like_spa_shell,
            },
            exposed_information=exposed_information,
            leak_type="system_info",
            leak_value=_first(exposed_information),
            cwe="CWE-497",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="response_body",
            root_cause_signature=f"body:{subtype}|tech:{tech}|kind:{response_kind}",
            technology_fingerprint=technology_fingerprint,
        )
    ]

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

    return [
        _build_signal(
            signal_type="directory_listing",
            finding_type="DIRECTORY_LISTING_ENABLED",
            family="DIRECTORY_LISTING",
            subtype="directory_listing",
            title="Directory listing 이 활성화된 것으로 보임",
            severity="Medium",
            confidence=0.88,
            where="response.body",
            evidence={
                "response_kind": response_kind,
                "directory_listing_hints": hints,
                "final_url": final_url,
                "redirect_chain": snapshot.get("redirect_chain", []),
            },
            exposed_information=[f"Directory listing detected: {x}" for x in hints],
            leak_type="directory_listing",
            leak_value=_first(hints),
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

    if _should_skip_resource_exposure(
        {"url": requested_url},
        snapshot,
        feats,
    ):
        return []

    if not _resource_exposure_is_confirmable(snapshot, feats):
        return []

    if not _default_resource_has_concrete_marker(subtype, snapshot, feats):
        return []

    body_text = _body_text(snapshot, feats)
    body_l = body_text.lower()
    url_l = final_url.lower()

    phpinfo_indicators = _dedup(feats.get("phpinfo_indicators") or [])
    config_markers = _dedup(feats.get("config_exposure_markers") or [])
    log_patterns = _dedup(feats.get("log_exposure_patterns") or [])

    # phpinfo route인데 concrete phpinfo marker가 부족하면 default_resource로도 올리지 않음
    phpinfo_route_like = (
        "phpinfo.php" in url_l
        or url_l.endswith("/phpinfo")
        or url_l.endswith("/info.php")
    )
    if phpinfo_route_like and subtype == "phpinfo_page":
        if not _phpinfo_has_concrete_marker(snapshot, feats):
            return []

    title = "기본 또는 민감 리소스가 직접 노출됨"
    confidence = 0.84
    severity = "Medium"
    exposed_information: List[str] = []

    if subtype == "phpinfo_page":
        confidence = 0.95
        severity = "Medium"
        exposed_information = ["Exposed resource: phpinfo page"]
        for item in phpinfo_indicators[:4]:
            exposed_information.append(f"phpinfo indicator: {item}")

    elif subtype == "git_metadata":
        confidence = 0.95
        severity = "Medium"
        exposed_information = [
            "Exposed resource: .git/config",
            "Git repository metadata exposed",
        ]

    elif subtype == "env_file":
        confidence = 0.94
        severity = "High" if config_markers else "Medium"
        exposed_information = ["Exposed resource: .env file"]
        for marker in config_markers[:4]:
            exposed_information.append(f"Config marker: {marker}")

    elif subtype == "server_status":
        confidence = 0.93
        severity = "Medium"
        exposed_information = [
            "Exposed resource: server-status",
            "Operational server status details exposed",
        ]

    elif subtype == "actuator_endpoint":
        confidence = 0.88
        severity = "Medium"
        exposed_information = [
            "Exposed resource: actuator endpoint",
            "Application operational endpoint exposed",
        ]

    elif subtype == "debug_endpoint":
        confidence = 0.86
        severity = "Medium"
        exposed_information = [
            "Exposed resource: debug endpoint",
            "Debug or diagnostic endpoint exposed",
        ]

    else:
        exposed_information = [f"Exposed resource hint: {x}" for x in hints[:4]]

    document_like = any(
        tok in body_l
        for tok in (
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
    body = _body_text(snapshot, feats)
    body_l = body.lower()

    if status_code != 200:
        return []
    if _is_auth_redirect(snapshot):
        return []
    if _is_static_response(feats):
        return []
    if _looks_like_generic_notfound_template(snapshot, feats):
        return []
    if _is_external_auth_transition(requested_url, final_url):
        return []

    # phpinfo direct route hint
    url_l = final_url.lower()
    route_hint = (
        "phpinfo.php" in url_l
        or url_l.endswith("/phpinfo")
        or url_l.endswith("/info.php")
    )

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
        "<h1 class=\"p\">php version",
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

    strong_hit_count = sum(1 for tok in strong_tokens if tok in body_l)
    weak_hit_count = sum(1 for tok in weak_tokens if tok in body_l)

    has_phpinfo_table_shape = (
        "<table" in body_l
        and ("php credits" in body_l or "php core" in body_l or "apache2handler" in body_l)
    )

    concrete_phpinfo = (
        len(indicators) >= 2
        or strong_hit_count >= 2
        or (route_hint and strong_hit_count >= 1 and weak_hit_count >= 2)
        or (route_hint and has_phpinfo_table_shape)
    )

    if not concrete_phpinfo:
        return []

    exposed_information: List[str] = [
        "PHP runtime and environment details exposed",
    ]

    for item in indicators[:4]:
        exposed_information.append(f"phpinfo indicator: {item}")

    if "php version" in body_l:
        exposed_information.append("PHP version disclosed")
    if "loaded modules" in body_l:
        exposed_information.append("Loaded PHP modules disclosed")
    if "server api" in body_l:
        exposed_information.append("PHP server API disclosed")
    if "configuration file" in body_l or "include_path" in body_l:
        exposed_information.append("PHP configuration details disclosed")

    exposed_information = _dedup(exposed_information)[:6]

    technology_fingerprint = feats.get("technology_fingerprint") or []

    return [
        _build_signal(
            signal_type="phpinfo_exposure",
            finding_type="PHPINFO_EXPOSURE",
            family="HTTP_BODY_DISCLOSURE",
            subtype="phpinfo",
            title="phpinfo() 페이지가 노출됨",
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
            },
            exposed_information=exposed_information,
            leak_type="phpinfo_page",
            leak_value=final_url,
            cwe="CWE-200",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="phpinfo_page",
            root_cause_signature="phpinfo_page_exposed",
            technology_fingerprint=technology_fingerprint,
        )
    ]


def _normalize_config_key_name(key: str) -> str:
    s = str(key or "").strip().lower()
    s = re.sub(r"[^a-z0-9]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def _classify_config_key(key: str) -> str:
    k = _normalize_config_key_name(key)

    if any(tok in k for tok in ("db_password", "database_password", "mysql_password", "password")):
        return "db_password"
    if any(tok in k for tok in ("db_user", "database_user", "database_username", "username", "user")):
        return "db_user"
    if any(tok in k for tok in ("db_host", "database_host", "database_server", "host", "server")):
        return "db_host"
    if any(tok in k for tok in ("db_name", "database_name", "database")):
        return "db_name"
    if "db_port" in k or "database_port" in k or k == "port":
        return "db_port"
    if "connection_string" in k or "database_url" in k or "database_uri" in k:
        return "connection_string"
    if "api_key" in k:
        return "api_key"
    if "access_key" in k or "aws_access_key" in k:
        return "access_key"
    if "secret" in k and "client_secret" not in k:
        return "secret"
    if "client_secret" in k:
        return "client_secret"
    if "token" in k or "auth_token" in k:
        return "token"
    if "private_key" in k:
        return "private_key"
    if "redis_password" in k or "redis_pass" in k:
        return "redis_password"
    if "redis_host" in k:
        return "redis_host"
    return "generic"


def _is_masked_config_value(value: str) -> bool:
    s = str(value or "").strip().lower()
    if not s:
        return False
    return s in {
        "******", "*****", "****", "***",
        "xxxxx", "xxxx", "xxx",
        "masked", "hidden", "redacted",
    }


def _clean_config_value(value: str) -> str:
    s = str(value or "").strip()
    s = s.strip("\"'`")
    s = re.sub(r"<[^>]+>", "", s).strip()
    s = re.sub(r"\s+", " ", s).strip()
    s = s.rstrip(",;")
    return s[:200]


def _summarize_config_extracted_values(
    extracted_values: List[Dict[str, Any]],
) -> Dict[str, Any]:
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

        if masked:
            sig = (raw_key, raw_value)
            if sig not in seen_masked:
                seen_masked.add(sig)
                summary["masked_values"].append(row)
        else:
            sig = (raw_key, raw_value)
            if sig not in seen_real:
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

    def _first_value(key_class: str) -> str | None:
        rows = classified.get(key_class) or []
        for row in rows:
            if not row.get("masked") and row.get("value"):
                return str(row["value"])
        return None

    db_host = _first_value("db_host")
    db_name = _first_value("db_name")
    db_user = _first_value("db_user")
    db_password = _first_value("db_password")
    db_port = _first_value("db_port")
    conn = _first_value("connection_string")
    api_key = _first_value("api_key")
    access_key = _first_value("access_key")
    secret = _first_value("secret")
    client_secret = _first_value("client_secret")
    token = _first_value("token")
    private_key = _first_value("private_key")
    redis_host = _first_value("redis_host")
    redis_password = _first_value("redis_password")

    if db_host:
        exposed_information.append(f"Database host: {db_host}")
    if db_name:
        exposed_information.append(f"Database name: {db_name}")
    if db_user:
        exposed_information.append(f"Database user: {db_user}")
    if db_password:
        exposed_information.append(f"Database password: {db_password}")
    if db_port:
        exposed_information.append(f"Database port: {db_port}")
    if conn:
        exposed_information.append(f"Connection string: {conn}")
    if redis_host:
        exposed_information.append(f"Redis host: {redis_host}")
    if redis_password:
        exposed_information.append(f"Redis password: {redis_password}")
    if api_key:
        exposed_information.append(f"API key: {api_key}")
    if access_key:
        exposed_information.append(f"Access key: {access_key}")
    if secret:
        exposed_information.append(f"Secret: {secret}")
    if client_secret:
        exposed_information.append(f"Client secret: {client_secret}")
    if token:
        exposed_information.append(f"Token: {token}")
    if private_key:
        exposed_information.append("Private key material exposed")

    if exposed_information:
        return _dedup(exposed_information)[:6]

    masked_rows = extracted_summary.get("masked_values") or []
    if masked_rows:
        masked_key_classes = sorted({
            str(item.get("key_class") or "generic")
            for item in masked_rows
        })
        for kc in masked_key_classes[:4]:
            exposed_information.append(f"Masked configuration value present: {kc}")

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

    if not exposed_information:
        exposed_information.append("Application configuration details disclosed")

    return _dedup(exposed_information)[:6]



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
    if _is_external_auth_transition(requested_url, final_url):
        return []

    # login / instructions / css / image / readme 류는 원칙적으로 로그 판단 금지
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
    if any(tok in final_path_l for tok in low_value_path_tokens):
        return []

    # 진짜 로그 경로만 인정
    log_file_or_dir_patterns = [
        r"(?:^|/)logs?(?:/|$)",
        r"(?:^|/)(?:access|error|debug|application|server)\.log(?:$|[/?#])",
        r"(?:^|/)catalina\.out(?:$|[/?#])",
        r"(?:^|/)stdout(?:$|[/?#])",
        r"(?:^|/)stderr(?:$|[/?#])",
    ]
    path_like_log = any(re.search(pat, final_path_l, re.I) for pat in log_file_or_dir_patterns)

    # 실제 로그 라인 샘플 추출
    access_log_lines = re.findall(
        r'(?im)^\s*\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^"]+\s+HTTP/[0-9.]+"\s+\d{3}\s+\d+.*$',
        body_text,
    )

    app_log_lines = re.findall(
        r'(?im)^\s*20\d{2}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,6})?\s+(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b.*$',
        body_text,
    )

    java_log_lines = re.findall(
        r'(?im)^\s*(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\s+[A-Za-z0-9_.$-]{3,120}\s+-\s+.*$',
        body_text,
    )

    stacktrace_log_lines = re.findall(
        r'(?im)^\s*at\s+[a-zA-Z0-9_.$]+\([A-Za-z0-9_.-]+:\d+\)\s*$',
        body_text,
    )

    # 문서/README/설치가이드류 차단
    document_like = any(
        tok in body_l
        for tok in (
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

    # 실제 로그 샘플 수
    concrete_log_lines: List[str] = []
    for line in access_log_lines[:3]:
        s = line.strip()
        if s:
            concrete_log_lines.append(s)
    for line in app_log_lines[:3]:
        s = line.strip()
        if s and s not in concrete_log_lines:
            concrete_log_lines.append(s)
    for line in java_log_lines[:3]:
        s = line.strip()
        if s and s not in concrete_log_lines:
            concrete_log_lines.append(s)

    # stack trace만 있다고 로그 노출로 보지 않음
    if not concrete_log_lines:
        return []

    # 문서류는 더 강하게 차단
    if document_like and not path_like_log:
        return []

    # 로그 경로도 아니고 로그 샘플도 2줄 미만이면 버림
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
            title="애플리케이션 또는 접근 로그 내용이 HTTP로 노출됨",
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


def _build_file_path_handling_signal(
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
    if _looks_like_setup_or_install_page(final_url, body_text):
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

    if status_code is not None and status_code < 400:
        if not (file_paths or stack_traces):
            return []

    evidence_exposed: List[str] = [
        f"File/path-related parameter observed: {', '.join(fileish_params[:4])}",
        "Response indicates internal file/path handling behavior",
    ]
    if file_paths:
        evidence_exposed.extend([f"File path: {x}" for x in file_paths[:3]])
    if stack_traces:
        evidence_exposed.extend([f"Stack trace: {x}" for x in stack_traces[:2]])

    evidence_exposed = _dedup(evidence_exposed)

    return [
        _build_signal(
            signal_type="file_path_handling_anomaly",
            finding_type="FILE_PATH_HANDLING_ANOMALY",
            family="HTTP_ERROR_DISCLOSURE",
            subtype="file_path_parameter",
            title="파일/경로 파라미터 처리에서 내부 동작이 노출됨",
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
            cwe="CWE-200",
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="route-specific",
            policy_object="file_path_parameter",
            root_cause_signature=f"file_path_param:{','.join(sorted(fileish_params))}",
            technology_fingerprint=feats.get("technology_fingerprint") or [],
            template_fingerprint=template_fingerprint,
        )
    ]


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
        _build_signal(
            signal_type="cors_policy",
            finding_type="CORS_MISCONFIG",
            family="CORS_MISCONFIG",
            subtype=subtype,
            title="과도한 CORS 정책이 관찰됨",
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
            exposed_information=[
                f"Access-Control-Allow-Origin: {acao}",
                f"Access-Control-Allow-Credentials: {acac_raw}",
            ],
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
    status_code = _status_code(snapshot, feats)

    if req_method not in {"GET", "HEAD"}:
        return []
    if status_code is None or status_code >= 400:
        return []
    if _is_static_response(feats):
        return []
    if req_family in {"cors_behavior", "method_behavior", "body_behavior"}:
        return []

    requested_url = str(request_meta.get("url") or "")
    if _is_external_auth_transition(requested_url, final_url):
        return []

    is_redirect = _is_redirect_status(status_code)
    is_auth_redirect = _is_auth_redirect(snapshot)
    is_baseline = _is_baseline_probe(request_meta)

    if is_auth_redirect and not is_baseline:
        return []

    out: List[Dict[str, Any]] = []

    common_evidence = {
        "response_kind": response_kind,
        "final_url": final_url,
        "requested_url": requested_url,
        "status_code": status_code,
        "is_redirect": is_redirect,
        "is_auth_redirect": is_auth_redirect,
        "is_cross_origin": _requested_and_final_origin(requested_url, final_url)[0] != _requested_and_final_origin(requested_url, final_url)[1],
        "location": _redirect_location(snapshot),
        "present": feats.get("security_headers_present") or [],
        "missing": feats.get("security_headers_missing") or [],
    }

    if not feats.get("clickjacking_protection_present"):
        out.append(
            _build_signal(
                signal_type="missing_header",
                finding_type="CLICKJACKING",
                family="HTTP_HEADER_SECURITY",
                subtype="clickjacking_protection_missing",
                title="Clickjacking 보호 헤더가 없음",
                severity="Low",
                confidence=0.86,
                where="response.headers",
                evidence={
                    **common_evidence,
                    "x_frame_options_present": feats.get("x_frame_options_present"),
                    "csp_frame_ancestors_present": feats.get("csp_frame_ancestors_present"),
                },
                exposed_information=[
                    "Missing X-Frame-Options header",
                    "Missing CSP frame-ancestors directive",
                ],
                leak_type="missing_clickjacking_protection",
                leak_value="x-frame-options/frame-ancestors missing",
                cwe="CWE-1021",
                owasp="A05:2021 Security Misconfiguration",
                scope_hint="host-wide",
                policy_object="clickjacking_protection",
                root_cause_signature="missing_header:clickjacking_protection",
                technology_fingerprint=technology_fingerprint,
            )
        )

    if not feats.get("csp_present"):
        out.append(
            _build_signal(
                signal_type="missing_header",
                finding_type="CSP_MISSING",
                family="HTTP_HEADER_SECURITY",
                subtype="csp_missing",
                title="Content-Security-Policy 헤더가 없음",
                severity="Low",
                confidence=0.82,
                where="response.headers",
                evidence=common_evidence,
                exposed_information=["Missing Content-Security-Policy header"],
                leak_type="missing_csp",
                leak_value="content-security-policy",
                cwe=None,
                owasp="A05:2021 Security Misconfiguration",
                scope_hint="host-wide",
                policy_object="content-security-policy",
                root_cause_signature="missing_header:content-security-policy",
                technology_fingerprint=technology_fingerprint,
                cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
                cwe_mapping_reason="OWASP category is applicable, but no precise single CWE mapping is used for this finding.",
            )
        )

    if not feats.get("x_content_type_options_present"):
        out.append(
            _build_signal(
                signal_type="missing_header",
                finding_type="CONTENT_TYPE_SNIFFING",
                family="HTTP_HEADER_SECURITY",
                subtype="content_type_sniffing",
                title="X-Content-Type-Options 헤더가 없음",
                severity="Low",
                confidence=0.88,
                where="response.headers",
                evidence=common_evidence,
                exposed_information=["Missing X-Content-Type-Options: nosniff"],
                leak_type="missing_x_content_type_options",
                leak_value="x-content-type-options",
                cwe=None,
                owasp="A05:2021 Security Misconfiguration",
                scope_hint="host-wide",
                policy_object="x-content-type-options",
                root_cause_signature="missing_header:x-content-type-options",
                technology_fingerprint=technology_fingerprint,
                cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
                cwe_mapping_reason="OWASP category is applicable, but no precise single CWE mapping is used for this finding.",
            )
        )

    if not feats.get("referrer_policy_present"):
        out.append(
            _build_signal(
                signal_type="missing_header",
                finding_type="REFERRER_POLICY_MISSING",
                family="HTTP_HEADER_SECURITY",
                subtype="referrer_policy_missing",
                title="Referrer-Policy 헤더가 없음",
                severity="Info",
                confidence=0.80,
                where="response.headers",
                evidence=common_evidence,
                exposed_information=["Missing Referrer-Policy header"],
                leak_type="missing_referrer_policy",
                leak_value="referrer-policy",
                cwe=None,
                owasp="A05:2021 Security Misconfiguration",
                scope_hint="host-wide",
                policy_object="referrer-policy",
                root_cause_signature="missing_header:referrer-policy",
                technology_fingerprint=technology_fingerprint,
                cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
                cwe_mapping_reason="OWASP category is applicable, but no precise single CWE mapping is used for this finding.",
            )
        )

    if not feats.get("permissions_policy_present"):
        out.append(
            _build_signal(
                signal_type="missing_header",
                finding_type="PERMISSIONS_POLICY_MISSING",
                family="HTTP_HEADER_SECURITY",
                subtype="permissions_policy_missing",
                title="Permissions-Policy 헤더가 없음",
                severity="Info",
                confidence=0.78,
                where="response.headers",
                evidence=common_evidence,
                exposed_information=["Missing Permissions-Policy header"],
                leak_type="missing_permissions_policy",
                leak_value="permissions-policy",
                cwe=None,
                owasp="A05:2021 Security Misconfiguration",
                scope_hint="host-wide",
                policy_object="permissions-policy",
                root_cause_signature="missing_header:permissions-policy",
                technology_fingerprint=technology_fingerprint,
                cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
                cwe_mapping_reason="OWASP category is applicable, but no precise single CWE mapping is used for this finding.",
            )
        )

    return out

def _build_cookie_signals(
    request_meta: Dict[str, Any],
    response_kind: str,
    final_url: str,
    feats: Dict[str, Any],
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    if _is_static_response(feats):
        return out

    status_code = feats.get("status_code")
    if status_code is None or status_code >= 400:
        return out

    requested_url = str(request_meta.get("url") or "")
    if _is_external_auth_transition(requested_url, final_url):
        return out

    req_family = str(request_meta.get("family") or "")
    req_name = str(request_meta.get("name") or "").lower()
    is_https_response = str(final_url or "").lower().startswith("https://")

    final_url_l = str(final_url or "").lower()
    auth_context = (
        req_family == "authentication"
        or "login" in final_url_l
        or "signin" in final_url_l
        or req_name.startswith("auth_")
    )

    request_sensitive_cookie_names = {
        str(x).strip().lower()
        for x in (feats.get("request_sensitive_cookie_names") or [])
        if str(x).strip()
    }
    request_sensitive_cookie_names_missing_in_response = {
        str(x).strip().lower()
        for x in (feats.get("request_sensitive_cookie_names_missing_in_response") or [])
        if str(x).strip()
    }

    cookie_objects = list(feats.get("cookie_objects") or [])
    response_cookie_names = {
        str(c.get("name") or "").strip().lower()
        for c in cookie_objects
        if str(c.get("name") or "").strip()
    }

    seen_cookie_issue_keys: Set[tuple[str, str]] = set()

    for cookie in cookie_objects:
        name = str(cookie.get("name") or "").strip()
        raw = str(cookie.get("raw") or "").strip()
        if not name:
            continue

        name_l = name.lower()

        sensitive_cookie = bool(cookie.get("sensitive"))
        request_present = bool(cookie.get("request_present"))
        request_sensitive_candidate = bool(cookie.get("request_sensitive_candidate"))
        prefix = str(cookie.get("prefix") or "")
        persistent = bool(cookie.get("persistent"))
        samesite_present = bool(cookie.get("samesite"))
        secure_present = bool(cookie.get("secure"))
        httponly_present = bool(cookie.get("httponly"))

        # response에 실제 Set-Cookie 된 쿠키 중에서만 판단
        # request에만 있었던 쿠키는 이 함수에서 취약점으로 올리지 않음
        target_cookie = (
            sensitive_cookie
            or request_sensitive_candidate
            or name_l in request_sensitive_cookie_names
            or prefix in {"__Host-", "__Secure-"}
        )
        if not target_cookie:
            continue

        common_evidence = {
            "response_kind": response_kind,
            "cookie": raw,
            "cookie_name": name,
            "cookie_prefix": prefix,
            "cookie_sensitive": sensitive_cookie,
            "cookie_persistent": persistent,
            "auth_context": auth_context,
            "request_present": request_present,
            "request_sensitive_candidate": request_sensitive_candidate,
            "request_sensitive_cookie_names": sorted(request_sensitive_cookie_names),
            "request_sensitive_cookie_names_missing_in_response": sorted(request_sensitive_cookie_names_missing_in_response),
            "response_cookie_names": sorted(response_cookie_names),
            "sensitive_reason": cookie.get("sensitive_reason") or [],
            "is_https_response": is_https_response,
            "final_url": final_url,
            "requested_url": requested_url,
        }

        if not httponly_present:
            dedup_key = (name.lower(), "httponly_missing")
            if dedup_key not in seen_cookie_issue_keys:
                seen_cookie_issue_keys.add(dedup_key)
                out.append(
                    _build_signal(
                        signal_type="missing_cookie_attr",
                        finding_type="COOKIE_HTTPONLY_MISSING",
                        family="COOKIE_SECURITY",
                        subtype="httponly_missing",
                        title=f"Cookie '{name}' 에 HttpOnly 속성이 없음",
                        severity="Low",
                        confidence=0.92 if (sensitive_cookie or request_sensitive_candidate) else 0.84,
                        where="response.headers",
                        evidence=common_evidence,
                        exposed_information=[f"Cookie '{name}' missing HttpOnly"],
                        leak_type="cookie_missing_httponly",
                        leak_value=raw,
                        cwe="CWE-1004",
                        owasp="A05:2021 Security Misconfiguration",
                        scope_hint="cookie-specific",
                        policy_object=name,
                        root_cause_signature=f"cookie:{name}|httponly_missing",
                        technology_fingerprint=technology_fingerprint,
                    )
                )

        if not secure_present:
            dedup_key = (name.lower(), "secure_missing")
            if dedup_key not in seen_cookie_issue_keys:
                seen_cookie_issue_keys.add(dedup_key)
                out.append(
                    _build_signal(
                        signal_type="missing_cookie_attr",
                        finding_type="COOKIE_SECURE_MISSING",
                        family="COOKIE_SECURITY",
                        subtype="secure_missing",
                        title=f"Cookie '{name}' 에 Secure 속성이 없음",
                        severity="Low" if is_https_response else "Info",
                        confidence=0.94 if (is_https_response and (sensitive_cookie or request_sensitive_candidate or prefix in {"__Host-", "__Secure-"})) else 0.82,
                        where="response.headers",
                        evidence=common_evidence,
                        exposed_information=[f"Cookie '{name}' missing Secure"],
                        leak_type="cookie_missing_secure",
                        leak_value=raw,
                        cwe="CWE-614",
                        owasp="A05:2021 Security Misconfiguration",
                        scope_hint="cookie-specific",
                        policy_object=name,
                        root_cause_signature=f"cookie:{name}|secure_missing",
                        technology_fingerprint=technology_fingerprint,
                    )
                )

        if not samesite_present:
            dedup_key = (name.lower(), "samesite_missing")
            if dedup_key not in seen_cookie_issue_keys:
                seen_cookie_issue_keys.add(dedup_key)
                out.append(
                    _build_signal(
                        signal_type="missing_cookie_attr",
                        finding_type="COOKIE_SAMESITE_MISSING",
                        family="COOKIE_SECURITY",
                        subtype="samesite_missing",
                        title=f"Cookie '{name}' 에 SameSite 속성이 없음",
                        severity="Info",
                        confidence=0.86 if (sensitive_cookie or request_sensitive_candidate) else 0.80,
                        where="response.headers",
                        evidence=common_evidence,
                        exposed_information=[f"Cookie '{name}' missing SameSite"],
                        leak_type="cookie_missing_samesite",
                        leak_value=raw,
                        cwe="CWE-1275",
                        owasp="A05:2021 Security Misconfiguration",
                        scope_hint="cookie-specific",
                        policy_object=name,
                        root_cause_signature=f"cookie:{name}|samesite_missing",
                        technology_fingerprint=technology_fingerprint,
                        cwe_mapping_status="DIRECT",
                        cwe_mapping_reason="Sensitive or authentication-related cookie missing SameSite attribute.",
                    )
                )

    return out


def _build_method_signals(
    request_meta: Dict[str, Any],
    response_kind: str,
    final_url: str,
    feats: Dict[str, Any],
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    requested_url = str(request_meta.get("url") or "")
    if _is_external_auth_transition(requested_url, final_url):
        return out

    req_method = str(request_meta.get("method") or "").upper().strip()

    status_code_raw = feats.get("status_code")
    try:
        status_code = int(status_code_raw) if status_code_raw is not None else None
    except (TypeError, ValueError):
        status_code = None

    allowed_methods = [
        str(m).upper().strip()
        for m in _dedup(feats.get("allowed_methods") or [])
        if str(m).strip()
    ]

    seeded_risky = {
        str(m).upper().strip()
        for m in _dedup(feats.get("risky_methods_enabled") or [])
        if str(m).strip()
    }
    seeded_risky.discard("TRACE")

    risky_probe_methods = {"PUT", "DELETE", "PATCH", "PROPFIND", "SEARCH"}
    aggregate_risky_methods: Set[str] = set(seeded_risky)
    method_capability_signals = list(feats.get("method_capability_signals") or [])

    if feats.get("trace_reflected"):
        out.append(
            _build_signal(
                signal_type="trace_reflection",
                finding_type="TRACE_ENABLED",
                family="HTTP_METHOD_SECURITY",
                subtype="trace_reflection",
                title="TRACE 메서드가 활성화되어 요청 내용을 반사함",
                severity="Medium",
                confidence=0.90,
                where="response.body",
                evidence={
                    "response_kind": response_kind,
                    "final_url": final_url,
                    "requested_url": requested_url,
                    "status_code": status_code,
                },
                exposed_information=["TRACE reflected request content"],
                leak_type="trace_enabled",
                leak_value="reflected",
                cwe=None,
                owasp="A05:2021 Security Misconfiguration",
                scope_hint="host-wide",
                policy_object="TRACE",
                root_cause_signature="method:TRACE|reflection:true",
                technology_fingerprint=technology_fingerprint,
                cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
                cwe_mapping_reason="OWASP category is applicable, but no precise single CWE mapping is used.",
            )
        )

    if req_method == "OPTIONS":
        for m in allowed_methods:
            if m in risky_probe_methods or m == "TRACE":
                aggregate_risky_methods.add(m)

    observed_probe_outcome = None

    if req_method in risky_probe_methods:
        if status_code not in {405, 501, None}:
            if status_code in {200, 201, 202, 204, 207}:
                aggregate_risky_methods.add(req_method)
                observed_probe_outcome = "success_like"
                method_capability_signals.append(f"{req_method} returned {status_code}, treated as handled")
            elif status_code in {401, 403}:
                aggregate_risky_methods.add(req_method)
                observed_probe_outcome = "blocked_after_routing"
                method_capability_signals.append(f"{req_method} returned {status_code}, treated as routed/handled but access-controlled")
            elif status_code in {301, 302, 307, 308}:
                aggregate_risky_methods.add(req_method)
                observed_probe_outcome = "redirected"
                method_capability_signals.append(f"{req_method} returned redirect ({status_code}), treated as weak handling evidence")
            else:
                observed_probe_outcome = f"other:{status_code}"

    risky_methods_sorted = sorted(aggregate_risky_methods)
    if not risky_methods_sorted:
        return out

    severity = "Medium" if any(m in {"PUT", "DELETE", "TRACE"} for m in risky_methods_sorted) else "Low"

    confidence = 0.80
    if observed_probe_outcome == "success_like":
        confidence = 0.90
    elif observed_probe_outcome == "blocked_after_routing":
        confidence = 0.86
    elif observed_probe_outcome == "redirected":
        confidence = 0.72
    elif req_method == "OPTIONS" and risky_methods_sorted:
        confidence = 0.82

    out.append(
        _build_signal(
            signal_type="risky_methods",
            finding_type="RISKY_HTTP_METHODS_ENABLED",
            family="HTTP_METHOD_SECURITY",
            subtype="risky_methods_enabled",
            title="위험 가능성이 있는 HTTP 메서드가 허용되거나 처리됨",
            severity=severity,
            confidence=confidence,
            where="response.headers",
            evidence={
                "response_kind": response_kind,
                "allowed_methods": allowed_methods,
                "risky_methods_enabled": risky_methods_sorted,
                "observed_probe_method": req_method if req_method in risky_probe_methods else None,
                "observed_probe_outcome": observed_probe_outcome,
                "status_code": status_code,
                "final_url": final_url,
                "requested_url": requested_url,
                "method_capability_signals": _dedup(method_capability_signals),
            },
            exposed_information=[f"Allowed or handled risky method: {m}" for m in risky_methods_sorted],
            leak_type="http_methods",
            leak_value=",".join(risky_methods_sorted),
            cwe=None,
            owasp="A05:2021 Security Misconfiguration",
            scope_hint="host-wide",
            policy_object="Allow",
            root_cause_signature=f"methods:{','.join(risky_methods_sorted)}",
            technology_fingerprint=technology_fingerprint,
            cwe_mapping_status="OWASP_ONLY_NO_CWE_MAPPING",
            cwe_mapping_reason="OWASP category is applicable, but no precise single CWE mapping is used.",
        )
    )

    return out


def _build_transport_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    if not _is_baseline_probe(request_meta):
        return []

    requested_url = str(request_meta.get("url") or "")
    requested_origin, final_origin = _requested_and_final_origin(requested_url, final_url)

    is_cross_origin = requested_origin != final_origin
    final_url_l = str(final_url or "").lower()

    if is_cross_origin:
        return []
    if any(tok in final_url_l for tok in ("login", "signin", "adfs", "/auth", "/sso")):
        return []

    out: List[Dict[str, Any]] = []

    if feats.get("https_redirect_missing"):
        out.append(
            _build_signal(
                signal_type="transport_posture",
                finding_type="HTTPS_REDIRECT_MISSING",
                family="TRANSPORT_SECURITY",
                subtype="https_redirect_missing",
                title="HTTP 엔드포인트가 HTTPS 강제를 하지 않음",
                severity="Info",
                confidence=0.78,
                where="response.headers",
                evidence={
                    "response_kind": response_kind,
                    "final_url": final_url,
                    "requested_url": requested_url,
                    "is_cross_origin": is_cross_origin,
                },
                exposed_information=[
                    f"HTTP endpoint accessible: {requested_url or final_url}",
                    f"Final URL remained HTTP: {final_url}" if str(final_url).startswith("http://") else "",
                ],
                leak_type="https_redirect_missing",
                leak_value=requested_url or final_url,
                cwe="CWE-319",
                owasp="A05:2021 Security Misconfiguration",
                scope_hint="host-wide",
                policy_object="https_redirect",
                root_cause_signature="transport:https_redirect_missing",
                technology_fingerprint=technology_fingerprint,
            )
        )

    if feats.get("hsts_missing"):
        out.append(
            _build_signal(
                signal_type="transport_posture",
                finding_type="HSTS_MISSING",
                family="TRANSPORT_SECURITY",
                subtype="hsts_missing",
                title="HTTPS 응답에 HSTS 헤더가 없음",
                severity="Low",
                confidence=0.76,
                where="response.headers",
                evidence={
                    "response_kind": response_kind,
                    "present": feats.get("security_headers_present") or [],
                    "missing": ["strict-transport-security"],
                    "final_url": final_url,
                    "requested_url": requested_url,
                    "is_cross_origin": is_cross_origin,
                },
                exposed_information=["Missing Strict-Transport-Security header"],
                leak_type="hsts_missing",
                leak_value="strict-transport-security",
                cwe="CWE-319",
                owasp="A05:2021 Security Misconfiguration",
                scope_hint="host-wide",
                policy_object="strict-transport-security",
                root_cause_signature="transport:hsts_missing",
                technology_fingerprint=technology_fingerprint,
            )
        )

    return out

def collect_http_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> List[Dict[str, Any]]:
    status_code = feats.get("status_code")
    response_kind = feats.get("response_kind") or "other"
    final_url = snapshot.get("final_url") or request_meta.get("url") or ""

    technology_fingerprint = _dedup(feats.get("technology_fingerprint") or [])
    tech = _first(technology_fingerprint) or "unknown"

    out: List[Dict[str, Any]] = []

    # always-on policy / posture findings
    out.extend(_build_cors_signals(response_kind, final_url, feats, technology_fingerprint))
    out.extend(_build_header_policy_signals(
        request_meta, snapshot, feats, response_kind, final_url, technology_fingerprint
    ))
    out.extend(_build_cookie_signals(
        request_meta, response_kind, final_url, feats, technology_fingerprint
    ))
    out.extend(_build_method_signals(
        request_meta, response_kind, final_url, feats, technology_fingerprint
    ))
    out.extend(_build_transport_signals(
        request_meta, snapshot, feats, response_kind, final_url, technology_fingerprint
    ))

    # error disclosure는 공통 skip보다 우선
    out.extend(_build_error_disclosure_signals(
        request_meta, status_code, response_kind, final_url, snapshot, feats, technology_fingerprint, tech
    ))

    info_skip = _should_skip_info_disclosure(request_meta, snapshot, feats)
    resource_skip = _should_skip_resource_exposure(request_meta, snapshot, feats)

    if not info_skip:
        out.extend(_build_header_disclosure_signals(
            request_meta, snapshot, feats, response_kind, final_url, technology_fingerprint, tech
        ))
        out.extend(_build_non_error_body_disclosure_signals(
            request_meta, snapshot, feats, response_kind, final_url, technology_fingerprint, tech
        ))
        out.extend(_build_file_path_handling_signal(request_meta, snapshot, feats))

    if not resource_skip:
        out.extend(_build_directory_listing_signals(
            response_kind, final_url, snapshot, feats, technology_fingerprint
        ))
        out.extend(_build_default_resource_signals(
            response_kind, final_url, snapshot, feats, technology_fingerprint
        ))
        out.extend(_build_phpinfo_signal(request_meta, snapshot, feats))
        out.extend(_build_config_exposure_signal(request_meta, snapshot, feats))
        out.extend(_build_log_exposure_signal(request_meta, snapshot, feats))

    deduped: List[Dict[str, Any]] = []
    seen = set()
    for item in out:
        marker = (
            str(item.get("finding_type") or ""),
            str(item.get("subtype") or ""),
            str(item.get("policy_object") or ""),
            str(item.get("root_cause_signature") or ""),
            str((item.get("evidence") or {}).get("final_url") or ""),
        )
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(item)

    final_signals: List[Dict[str, Any]] = []
    final_url_to_types: Dict[str, Set[str]] = {}

    for item in deduped:
        item_final_url = str((item.get("evidence") or {}).get("final_url") or "")
        final_url_to_types.setdefault(item_final_url, set()).add(str(item.get("finding_type") or ""))

    for item in deduped:
        finding_type = str(item.get("finding_type") or "")
        family = str(item.get("family") or "")
        subtype = str(item.get("subtype") or "")
        item_final_url = str((item.get("evidence") or {}).get("final_url") or "")
        same_url_types = final_url_to_types.get(item_final_url, set())

        if finding_type == "HTTP_SYSTEM_INFO_EXPOSURE":
            if "PHPINFO_EXPOSURE" in same_url_types:
                continue
            if "HTTP_CONFIG_FILE_EXPOSURE" in same_url_types:
                continue
            if "LOG_VIEWER_EXPOSURE" in same_url_types:
                continue
            if "DEFAULT_FILE_EXPOSED" in same_url_types and family == "HTTP_BODY_DISCLOSURE":
                continue
            if "HTTP_ERROR_INFO_EXPOSURE" in same_url_types and subtype in {
                "body_info_marker",
                "framework_hint_in_body",
            }:
                continue

        if finding_type == "LOG_VIEWER_EXPOSURE":
            if any(t in same_url_types for t in {
                "PHPINFO_EXPOSURE",
                "HTTP_CONFIG_FILE_EXPOSURE",
                "HTTP_ERROR_INFO_EXPOSURE",
            }):
                continue

        if finding_type == "DEFAULT_FILE_EXPOSED":
            if "PHPINFO_EXPOSURE" in same_url_types and subtype == "phpinfo_page":
                continue

        final_signals.append(item)

    final_signals.sort(
        key=lambda x: (
            _severity_rank(x.get("severity", "Info")) * -1,
            x.get("finding_type") or "",
            x.get("title") or "",
        )
    )

    log(
        "SCAN",
        "[classifier] "
        f"method={request_meta.get('method')} "
        f"name={request_meta.get('name')} "
        f"family={request_meta.get('family')} "
        f"status={status_code} "
        f"kind={response_kind} "
        f"url={final_url} "
        f"header_disclosures={len(feats.get('header_disclosures') or [])} "
        f"missing_headers={len(feats.get('security_headers_missing') or [])} "
        f"risky_methods={len(feats.get('risky_methods_enabled') or [])} "
        f"cookies={len(feats.get('cookie_objects') or [])} "
        f"error_class={feats.get('error_exposure_class') or ''} "
        f"default_hints={len(feats.get('default_file_hints') or [])} "
        f"info_skip={info_skip} "
        f"resource_skip={resource_skip} "
        f"signals_before={len(out)} "
        f"signals_deduped={len(deduped)} "
        f"signals_final={len(final_signals)} "
        f"types={[x.get('finding_type') for x in final_signals]}"
    )
    return final_signals


def _should_skip_info_disclosure(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> bool:
    requested_url = str(request_meta.get("url") or "")
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or requested_url or "")

    # static asset은 계속 제외
    if _is_static_response(feats):
        return True

    # 외부 auth transition은 제외
    if _is_external_auth_transition(requested_url, final_url):
        return True

    # 여기부터는 "강한 에러/노출 신호가 있으면 skip 금지"
    has_strong_error_like_signal = bool(
        feats.get("error_exposure_class")
        or (feats.get("stack_traces") or [])
        or (feats.get("file_paths") or [])
        or (feats.get("db_errors") or [])
        or (feats.get("debug_hints") or [])
    )

    if has_strong_error_like_signal:
        return False

    # 약한 auth redirect / generic notfound만 있을 때만 skip
    if _is_auth_redirect(snapshot):
        return True

    if _looks_like_generic_notfound_template(snapshot, feats):
        return True

    return False

def _should_skip_resource_exposure(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> bool:
    requested_url = str(request_meta.get("url") or "")
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or requested_url or "")
    body_text = _body_text(snapshot, feats)
    status_code = _status_code(snapshot, feats)

    if _should_skip_info_disclosure(request_meta, snapshot, feats):
        return True

    if _is_same_error_page_for_resource_probe(snapshot, feats):
        return True

    if _resource_probe_is_actually_error_disclosure(feats):
        return True

    if _looks_like_setup_or_install_page(final_url, body_text):
        return True

    if status_code != 200:
        return True

    return False


validation_policy.py
from __future__ import annotations

from typing import Any, Dict

from agent.evidence_policy import (
    has_strong_config_evidence,
    has_strong_log_evidence,
    has_strong_phpinfo_evidence,
    is_direct_200_observation,
    is_low_value_disclosure,
)
from agent.finding_types import AMBIGUOUS_TYPES, CONCRETE_EXPOSURE_TYPES, DETERMINISTIC_TYPES


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


def _is_concrete_error_disclosure(candidate: Dict[str, Any]) -> bool:
    evidence = _evidence(candidate)
    status_code = candidate.get("status_code") or evidence.get("status_code")

    stack_traces = evidence.get("stack_traces") or []
    file_paths = evidence.get("file_paths") or []
    db_errors = evidence.get("db_errors") or []
    debug_hints = evidence.get("debug_hints") or []
    default_error_hint = evidence.get("default_error_hint")

    if db_errors:
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

    # HTML shell / weak document-like 페이지는 concrete system info로 보지 않음
    if response_kind == "static_asset":
        return False

    # strong version token은 concrete
    if strong_versions:
        return True

    # internal IP는 debug/error context가 같이 있을 때만 concrete
    if internal_ips and (framework_hints or debug_hints or stack_traces or db_errors or file_paths):
        return True

    # 강한 제품/프레임워크 배너 마커
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

    # classifier가 이미 다중 힌트로 올린 경우만 제한적으로 인정
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
    db_errors = evidence.get("db_errors") or []
    phpinfo_indicators = evidence.get("phpinfo_indicators") or []

    # 진짜 stack/file path 노출이면 error finding 유지 가능
    if stack_traces:
        return False
    if file_paths and _has_local_file_path(candidate):
        return False

    # phpinfo 경로에서 db_error만 약하게 걸린 경우는 오탐 처리
    if subtype == "db_error" and (db_errors or phpinfo_indicators):
        return True

    # phpinfo 힌트가 있는데 concrete error artifact가 없으면 오탐
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
        # phpinfo route에서 잘못 붙은 error disclosure 선제 차단
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