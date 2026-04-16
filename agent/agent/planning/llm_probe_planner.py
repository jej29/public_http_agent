from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlsplit

from agent.llm_client import plan_additional_probes
from agent.planning.probes import RequestSpec


MAX_PLANNER_ENDPOINTS = 30
MAX_PLANNER_FINDINGS = 30
MAX_PLANNER_RAW_INDEX = 180
MAX_RETURNED_LLM_PROBES = 24


def _safe_str(value: Any, limit: int = 240) -> str:
    if value is None:
        return ""
    s = str(value)
    return s[:limit] if len(s) > limit else s


def _compact_endpoint(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return {
            "url": _safe_str(item.get("url"), 320),
            "kind": _safe_str(item.get("kind"), 50),
            "score": item.get("score", 0),
            "states": item.get("states") or [],
            "field_names": (item.get("field_names") or [])[:10],
            "query_param_names": (item.get("query_param_names") or [])[:10],
        }
    return {
        "url": _safe_str(item, 320),
        "kind": "page",
        "score": 0,
        "states": [],
        "field_names": [],
        "query_param_names": [],
    }

def _compact_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    evidence = f.get("evidence") or {}
    return {
        "type": _safe_str(f.get("type"), 80),
        "title": _safe_str(f.get("title"), 160),
        "severity": _safe_str(f.get("severity"), 20),
        "family": _safe_str(f.get("family"), 80),
        "subtype": _safe_str(f.get("subtype"), 80),
        "scope_hint": _safe_str(f.get("scope_hint"), 50),
        "policy_object": _safe_str(f.get("policy_object"), 80),
        "normalized_url": _safe_str(f.get("normalized_url"), 320),
        "cwe": _safe_str(f.get("cwe") or f.get("cwe_mapping_status"), 80),
        "verification": f.get("verification") or {},
        "error_exposure_class": _safe_str(evidence.get("error_exposure_class"), 80),
        "default_file_hints": (evidence.get("default_file_hints") or [])[:6],
        "query_param_names": (evidence.get("query_param_names") or [])[:8],
        "file_path_parameter_names": (evidence.get("file_path_parameter_names") or [])[:8],
        "technology_fingerprint": (evidence.get("technology_fingerprint") or f.get("technology_fingerprint") or [])[:8],
        "body_content_type_hint": _safe_str(evidence.get("body_content_type_hint"), 40),
        "config_exposure_markers": (evidence.get("config_exposure_markers") or [])[:8],
        "config_key_classes": (evidence.get("config_key_classes") or [])[:8],
        "debug_hints": (evidence.get("debug_hints") or [])[:6],
        "framework_hints": (evidence.get("framework_hints") or [])[:6],
        "allowed_methods": (evidence.get("allowed_methods") or [])[:10],
        "risky_methods_enabled": (evidence.get("risky_methods_enabled") or [])[:10],
        "exposed_information": (f.get("exposed_information") or [])[:6],
    }

def _finding_urls(f: Dict[str, Any]) -> List[str]:
    urls: List[str] = []

    for key in ("normalized_url",):
        v = str(f.get(key) or "").strip()
        if v:
            urls.append(v)

    ev = f.get("evidence") or {}
    for key in ("final_url", "requested_url"):
        v = str(ev.get(key) or "").strip()
        if v:
            urls.append(v)

    out: List[str] = []
    seen = set()
    for u in urls:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _path_only(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except Exception:
        return "/"


def _build_endpoint_context_map(
    *,
    endpoint_compact: List[Dict[str, Any]],
    confirmed_compact: List[Dict[str, Any]],
    informational_compact: List[Dict[str, Any]],
    raw_compact: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    finding_items = list(confirmed_compact) + list(informational_compact)

    path_to_finding_types: Dict[str, Set[str]] = {}
    path_to_markers: Dict[str, Set[str]] = {}
    path_to_key_classes: Dict[str, Set[str]] = {}
    path_to_probe_families: Dict[str, Set[str]] = {}
    path_to_status_codes: Dict[str, Set[int]] = {}
    path_to_req_names: Dict[str, Set[str]] = {}

    for f in finding_items:
        f_urls = _finding_urls(f)
        for u in f_urls:
            p = _path_only(u)
            path_to_finding_types.setdefault(p, set()).add(str(f.get("type") or ""))
            for m in f.get("config_exposure_markers") or []:
                path_to_markers.setdefault(p, set()).add(str(m))
            for kc in f.get("config_key_classes") or []:
                path_to_key_classes.setdefault(p, set()).add(str(kc))

    for r in raw_compact:
        p = _path_only(str(r.get("final_url") or r.get("url") or ""))
        fam = str(r.get("family") or "").strip()
        req_name = str(r.get("request_name") or "").strip()
        sc = r.get("status_code")

        if fam:
            path_to_probe_families.setdefault(p, set()).add(fam)
        if req_name:
            path_to_req_names.setdefault(p, set()).add(req_name)
        if isinstance(sc, int):
            path_to_status_codes.setdefault(p, set()).add(sc)

    out: Dict[str, Dict[str, Any]] = {}
    for ep in endpoint_compact:
        url = str(ep.get("url") or "")
        p = _path_only(url)
        out[url] = {
            "related_finding_types": sorted(path_to_finding_types.get(p, set()))[:8],
            "related_config_markers": sorted(path_to_markers.get(p, set()))[:8],
            "related_config_key_classes": sorted(path_to_key_classes.get(p, set()))[:8],
            "observed_probe_families": sorted(path_to_probe_families.get(p, set()))[:8],
            "observed_request_names": sorted(path_to_req_names.get(p, set()))[:8],
            "observed_status_codes": sorted(path_to_status_codes.get(p, set()))[:8],
        }
    return out


def _recent_suspicious_paths(raw_compact: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()

    for item in reversed(raw_compact):
        url = str(item.get("final_url") or item.get("url") or "").strip()
        if not url or url in seen:
            continue

        tags = item.get("suspicion_tags") or []
        if not tags:
            continue

        seen.add(url)
        out.append(
            {
                "url": url,
                "method": item.get("method"),
                "family": item.get("family"),
                "status_code": item.get("status_code"),
                "suspicion_tags": tags[:6],
            }
        )
        if len(out) >= 20:
            break

    return out

def _compact_raw_item(item: Dict[str, Any]) -> Dict[str, Any]:
    body_text = _safe_str(item.get("body_text"), 600)

    suspicion_tags: List[str] = []
    url_l = str(item.get("url") or "").lower()
    req_name_l = str(item.get("request_name") or "").lower()
    family_l = str(item.get("family") or "").lower()
    body_l = body_text.lower()

    if any(tok in url_l for tok in ("config", ".env", ".git", "debug", "phpinfo", "server-status", "actuator", "backup", "log")):
        suspicion_tags.append("suspicious_path")
    if any(tok in req_name_l for tok in ("debug", "path", "qs_", "hdr_", "resource_", "dir_list_", "cors_", "method_")):
        suspicion_tags.append("synthetic_probe")
    if any(tok in family_l for tok in ("error", "default_resource", "query_param", "header_behavior", "method_behavior", "cors_behavior")):
        suspicion_tags.append("interesting_probe_family")
    if any(tok in body_l for tok in ("phpinfo()", "db_password", "database", "stack trace", "traceback", "warning", "fatal error")):
        suspicion_tags.append("interesting_response_content")

    return {
        "request_name": _safe_str(item.get("request_name"), 100),
        "method": _safe_str(item.get("method"), 20),
        "url": _safe_str(item.get("url"), 320),
        "final_url": _safe_str(item.get("final_url"), 320),
        "status_code": item.get("status_code"),
        "ok": item.get("ok"),
        "family": _safe_str(item.get("family"), 60),
        "auth_state": _safe_str(item.get("auth_state"), 30),
        "scope_key": _safe_str(item.get("scope_key"), 160),
        "content_type": _safe_str(item.get("content_type"), 80),
        "body_len": item.get("body_len"),
        "body_preview": body_text,
        "suspicion_tags": suspicion_tags[:6],
    }


def _probe_key(method: str, url: str) -> str:
    return f"{method.upper()} {url.strip()}"


def _endpoint_path(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except Exception:
        return "/"


def _high_value_endpoint(ep: Dict[str, Any]) -> bool:
    url = str(ep.get("url") or "").lower()
    qp = {str(x).lower() for x in (ep.get("query_param_names") or [])}
    kind = str(ep.get("kind") or "").lower()
    score = int(ep.get("score", 0) or 0)
    states = {str(x).lower() for x in (ep.get("states") or [])}
    endpoint_signals = ep.get("endpoint_signals") or {}

    if any(tok in url for tok in (
        "api", "config", "phpinfo", "log", "debug", "admin", ".env", ".git", "server-status",
        "actuator", "backup", "upload", "download", "setup", "security", "instructions",
    )):
        return True

    if {"file", "path", "page", "doc", "document", "include", "template", "folder", "redirect", "next", "url"}.intersection(qp):
        return True

    if endpoint_signals.get("related_finding_types"):
        return True

    if endpoint_signals.get("observed_probe_families"):
        interesting = {
            "error_path", "error_query", "default_resource", "directory_behavior",
            "query_param", "method_behavior", "cors_behavior", "header_behavior",
        }
        if interesting.intersection(set(endpoint_signals.get("observed_probe_families") or [])):
            return True

    if "authenticated" in states and "anonymous" not in states:
        return True

    if kind == "form":
        return True

    return score >= 50


def build_observation_summary(
    *,
    target: str,
    raw_index: List[Dict[str, Any]],
    findings_confirmed: List[Dict[str, Any]],
    findings_informational: List[Dict[str, Any]],
    discovered_endpoints: List[Any] | None = None,
) -> Dict[str, Any]:
    confirmed_compact = [_compact_finding(x) for x in findings_confirmed[:MAX_PLANNER_FINDINGS]]
    informational_compact = [_compact_finding(x) for x in findings_informational[:MAX_PLANNER_FINDINGS]]
    endpoint_compact = [_compact_endpoint(x) for x in (discovered_endpoints or [])[:MAX_PLANNER_ENDPOINTS]]
    raw_compact = [_compact_raw_item(x) for x in raw_index[-MAX_PLANNER_RAW_INDEX:]]

    endpoint_context_map = _build_endpoint_context_map(
        endpoint_compact=endpoint_compact,
        confirmed_compact=confirmed_compact,
        informational_compact=informational_compact,
        raw_compact=raw_compact,
    )

    enriched_endpoint_compact: List[Dict[str, Any]] = []
    for ep in endpoint_compact:
        enriched = dict(ep)
        enriched["endpoint_signals"] = endpoint_context_map.get(str(ep.get("url") or ""), {})
        enriched_endpoint_compact.append(enriched)

    confirmed_types = sorted({x.get("type") for x in confirmed_compact if x.get("type")})
    informational_types = sorted({x.get("type") for x in informational_compact if x.get("type")})

    attempted_probe_keys = []
    seen_attempted: Set[str] = set()
    for r in raw_index:
        key = _probe_key(str(r.get("method") or "GET"), str(r.get("url") or ""))
        if key and key not in seen_attempted:
            seen_attempted.add(key)
            attempted_probe_keys.append(key)

    endpoint_urls = [x["url"] for x in enriched_endpoint_compact if x.get("url")]
    high_value_endpoints = [x for x in enriched_endpoint_compact if _high_value_endpoint(x)]

    by_path_status: Dict[str, List[int]] = {}
    for r in raw_index[-MAX_PLANNER_RAW_INDEX:]:
        url = str(r.get("final_url") or r.get("url") or "")
        sc = r.get("status_code")
        path = _endpoint_path(url)
        by_path_status.setdefault(path, [])
        if isinstance(sc, int):
            by_path_status[path].append(sc)

    path_status_summary = {
        k: sorted(set(v))[:8]
        for k, v in list(by_path_status.items())[:50]
    }

    recent_suspicious = _recent_suspicious_paths(raw_compact)

    return {
        "target": target,
        "planner_goal": (
            "Propose only NOVEL, high-value, safe HTTP probes that are not redundant with already attempted probes. "
            "Prefer adaptive probes for dynamic endpoints, config/debug/default-resource discovery, "
            "parameter-aware mutations, and follow-up probes for suspicious responses."
        ),
        "stats": {
            "request_count": len(raw_index),
            "confirmed_count": len(findings_confirmed),
            "informational_count": len(findings_informational),
            "discovered_endpoint_count": len(discovered_endpoints or []),
        },
        "confirmed_types": confirmed_types,
        "informational_types": informational_types,
        "confirmed_findings_sample": confirmed_compact,
        "informational_findings_sample": informational_compact,
        "discovered_endpoints_sample": enriched_endpoint_compact,
        "high_value_endpoints_sample": high_value_endpoints[:16],
        "recent_suspicious_paths": recent_suspicious,
        "discovered_endpoint_urls": endpoint_urls,
        "recent_requests_sample": raw_compact,
        "attempted_probe_keys": attempted_probe_keys[-140:],
        "path_status_summary": path_status_summary,
        "instructions": {
            "avoid_repeating_attempted_probe_keys": True,
            "prefer_discovered_dynamic_routes": True,
            "prefer_query_param_specific_probes": True,
            "prefer_followup_on_suspicious_paths": True,
            "prefer_config_debug_default_resource_hunting": True,
            "avoid_root_baseline_duplication": True,
            "avoid_only_head_options_trace_on_root": True,
            "max_new_probes": MAX_RETURNED_LLM_PROBES,
        },
    }

def _normalize_probe_item(target: str, item: Dict[str, Any]) -> RequestSpec:
    path_or_url = str(item.get("path_or_url") or "/").strip()

    target_parts = urlsplit(target)
    target_origin = f"{target_parts.scheme}://{target_parts.netloc}"
    target_path = target_parts.path or "/"
    target_path = "/" + target_path.lstrip("/")
    target_path = target_path.rstrip("/") or "/"

    if path_or_url.startswith(("http://", "https://")):
        url = path_or_url.strip()
    else:
        raw = path_or_url.strip()

        if not raw:
            raw = "/"

        # query-only / fragment-only 입력도 보정
        if raw.startswith("?") or raw.startswith("#"):
            base_path = "" if target_path == "/" else target_path
            url = f"{target_origin}{base_path}{raw}"
        else:
            raw_path = "/" + raw.lstrip("/")

            # LLM이 이미 /common/... 같이 app path를 포함해서 반환한 경우
            # target path를 다시 붙이지 않음
            if target_path != "/" and (raw_path == target_path or raw_path.startswith(target_path + "/")):
                url = f"{target_origin}{raw_path}"
            else:
                base_path = "" if target_path == "/" else target_path
                url = f"{target_origin}{base_path}{raw_path}"

    body = item.get("body")
    return RequestSpec(
        name=str(item.get("name") or "llm_probe"),
        method=str(item.get("method") or "GET").upper(),
        url=url,
        headers=item.get("headers") or {},
        body=(body.encode("utf-8") if isinstance(body, str) else body),
        origin=item.get("origin"),
        probe=item.get("probe"),
        trace_marker=item.get("trace_marker"),
        source="llm",
        family=str(item.get("family") or "llm_adaptive"),
        mutation_class="llm_adaptive",
        surface_hint="unknown",
        expected_signal=None,
        comparison_group="llm_adaptive",
    )

def _is_novel_probe(spec: RequestSpec, attempted_keys: Set[str]) -> bool:
    key = _probe_key(spec.method, spec.url)
    if key in attempted_keys:
        return False

    url_l = spec.url.lower()
    name_l = (spec.name or "").lower()

    if url_l.rstrip("/") in {"http://dvwa", "http://dvwa/"}:
        if spec.method in {"HEAD", "OPTIONS", "TRACE"}:
            return False
        if name_l.startswith(("baseline_", "cors_", "method_")):
            return False

    return True


def generate_llm_probes(target: str, observation_summary: Dict[str, Any]) -> List[RequestSpec]:
    probe_dicts = plan_additional_probes(target, observation_summary)

    attempted_keys = {
        str(x).strip()
        for x in (observation_summary.get("attempted_probe_keys") or [])
        if str(x).strip()
    }

    specs: List[RequestSpec] = []
    seen: Set[Tuple[str, str]] = set()

    for item in probe_dicts:
        if not isinstance(item, dict):
            continue

        spec = _normalize_probe_item(target, item)
        dedup_key = (spec.method.upper(), spec.url)

        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        if not _is_novel_probe(spec, attempted_keys):
            continue

        specs.append(spec)
        if len(specs) >= MAX_RETURNED_LLM_PROBES:
            break

    return specs
