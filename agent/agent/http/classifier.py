from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, urlsplit

from agent.http.http_disclosure_classifier import (
    build_disclosure_signals as _build_disclosure_signal_bundle,
    looks_like_setup_or_install_page,
    should_skip_info_disclosure,
)
from agent.http.http_policy_classifier import build_policy_signals as _build_policy_signal_bundle
from agent.http.http_resource_classifier import build_resource_exposure_signals as _build_resource_exposure_signal_bundle
from agent.http.http_signal_postprocessing import finalize_http_signals
from agent.core.common import log


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
        "page could not be found",
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
        and "page could not be found" in body_l
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


def _has_strong_config_payload(feats: Dict[str, Any], snapshot: Dict[str, Any]) -> bool:
    extracted_values = feats.get("config_extracted_values") or []
    real_values = [
        item
        for item in extracted_values
        if isinstance(item, dict) and not bool(item.get("masked"))
    ]
    if len(real_values) >= 3:
        return True

    key_classes = set()
    for item in extracted_values:
        if not isinstance(item, dict):
            continue
        key = str(item.get("key") or "").strip().lower()
        if not key:
            continue
        if "password" in key:
            key_classes.add("db_password")
        if key in {"db_server", "database_server", "db_host", "database_host", "host"}:
            key_classes.add("db_host")
        if key in {"db_database", "database", "db_name", "database_name", "dbname"}:
            key_classes.add("db_name")
        if key in {"db_user", "database_user", "database_username", "username", "user"}:
            key_classes.add("db_user")
        if "secret" in key or "token" in key or "api_key" in key or "access_key" in key:
            key_classes.add("secret")

    if len(key_classes.intersection({"db_host", "db_name", "db_user", "db_password"})) >= 3:
        return True
    if "secret" in key_classes or "db_password" in key_classes:
        return True

    body_l = _body_text(snapshot, feats).lower()
    php_config_tokens = (
        "$_dvwa['db_server']",
        "$_dvwa['db_database']",
        "$_dvwa['db_user']",
        "$_dvwa['db_password']",
        "db_server",
        "db_database",
        "db_user",
        "db_password",
    )
    return sum(1 for token in php_config_tokens if token in body_l) >= 3


def _build_policy_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    *,
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
) -> List[Dict[str, Any]]:
    return _build_policy_signal_bundle(
        request_meta,
        snapshot,
        feats,
        response_kind=response_kind,
        final_url=final_url,
        technology_fingerprint=technology_fingerprint,
    )


def _build_disclosure_signals(
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
    return _build_disclosure_signal_bundle(
        request_meta,
        snapshot,
        feats,
        status_code=status_code,
        response_kind=response_kind,
        final_url=final_url,
        technology_fingerprint=technology_fingerprint,
        tech=tech,
        info_skip=info_skip,
    )


def _build_resource_exposure_signals(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
    *,
    response_kind: str,
    final_url: str,
    technology_fingerprint: List[str],
    resource_skip: bool,
) -> List[Dict[str, Any]]:
    return _build_resource_exposure_signal_bundle(
        request_meta,
        snapshot,
        feats,
        response_kind=response_kind,
        final_url=final_url,
        technology_fingerprint=technology_fingerprint,
        resource_skip=resource_skip,
    )

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

    info_skip = should_skip_info_disclosure(request_meta, snapshot, feats)
    resource_skip = _should_skip_resource_exposure(request_meta, snapshot, feats)
    out: List[Dict[str, Any]] = []
    out.extend(_build_policy_signals(
        request_meta,
        snapshot,
        feats,
        response_kind=response_kind,
        final_url=final_url,
        technology_fingerprint=technology_fingerprint,
    ))
    out.extend(_build_disclosure_signals(
        request_meta,
        snapshot,
        feats,
        status_code=status_code,
        response_kind=response_kind,
        final_url=final_url,
        technology_fingerprint=technology_fingerprint,
        tech=tech,
        info_skip=info_skip,
    ))
    out.extend(_build_resource_exposure_signals(
        request_meta,
        snapshot,
        feats,
        response_kind=response_kind,
        final_url=final_url,
        technology_fingerprint=technology_fingerprint,
        resource_skip=resource_skip,
    ))

    final_signals = finalize_http_signals(out, severity_rank_fn=_severity_rank)
    deduped = final_signals

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


def _should_skip_resource_exposure(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> bool:
    requested_url = str(request_meta.get("url") or "")
    final_url = str(feats.get("final_url") or snapshot.get("final_url") or requested_url or "")
    body_text = _body_text(snapshot, feats)
    status_code = _status_code(snapshot, feats)

    if status_code == 200 and _has_strong_config_payload(feats, snapshot):
        return False

    if should_skip_info_disclosure(request_meta, snapshot, feats):
        return True

    if _is_same_error_page_for_resource_probe(snapshot, feats):
        return True

    if _resource_probe_is_actually_error_disclosure(feats):
        return True

    if looks_like_setup_or_install_page(final_url, body_text):
        return True

    if status_code != 200:
        return True

    return False
