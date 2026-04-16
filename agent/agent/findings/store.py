from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from agent.core.common import prune_empty
from agent.findings.identity import finding_group, stable_finding_filename
from agent.core.serializer import serialize_compact_finding, serialize_debug_finding
from agent.core.scope import canonical_finding_url, normalize_url_for_dedup


def compact_trigger(trigger: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(trigger, dict):
        return {}
    compact = {
        "name": trigger.get("name"),
        "method": trigger.get("method"),
        "url": trigger.get("url"),
    }
    return {k: v for k, v in compact.items() if v not in (None, "", [], {})}


def _dedup_str_list(items: List[Any], limit: int | None = None) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items or []:
        s = str(item or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
        if limit is not None and len(out) >= limit:
            break
    return out


def _severity_rank(sev: str) -> int:
    return {"Info": 1, "Low": 2, "Medium": 3, "High": 4}.get(str(sev or "Info"), 1)


def _verdict_rank(verdict: str) -> int:
    return {"FALSE_POSITIVE": 1, "INFORMATIONAL": 2, "INCONCLUSIVE": 2, "CONFIRMED": 3}.get(str(verdict or ""), 0)


def _split_product_version(token: str) -> tuple[str, str | None]:
    s = str(token or "").strip().lower()
    if not s:
        return "", None
    if "/" in s:
        name, ver = s.split("/", 1)
        name = name.strip()
        ver = ver.strip()
        if name:
            return name, ver or None
    return s, None


def _normalize_technology_fingerprint(items: List[Any]) -> List[str]:
    ordered = _dedup_str_list(items)
    if not ordered:
        return []

    versioned_by_name: Dict[str, str] = {}
    for tok in ordered:
        name, ver = _split_product_version(tok)
        if name and ver and name not in versioned_by_name:
            versioned_by_name[name] = tok

    out: List[str] = []
    seen = set()
    for tok in ordered:
        name, ver = _split_product_version(tok)
        if not name:
            continue

        if ver:
            if tok not in seen:
                out.append(tok)
                seen.add(tok)
            continue

        if name in versioned_by_name:
            continue

        if tok not in seen:
            out.append(tok)
            seen.add(tok)

    return out[:10]


def _classification_rank(finding: Dict[str, Any]) -> tuple[int, int, int, int]:
    candidate_type = str(finding.get("type") or "")
    cwe = str(finding.get("cwe") or "")
    mapping_status = str(finding.get("cwe_mapping_status") or "")
    confidence = float(finding.get("confidence") or 0.0)

    type_priority = {
        "HTTP_CONFIG_FILE_EXPOSURE": 110,
        "PHPINFO_EXPOSURE": 105,
        "LOG_VIEWER_EXPOSURE": 100,
        "FILE_PATH_HANDLING_ANOMALY": 98,
        "HTTP_ERROR_INFO_EXPOSURE": 95,
        "DIRECTORY_LISTING_ENABLED": 80,
        "DEFAULT_FILE_EXPOSED": 70,
        "HTTP_SYSTEM_INFO_EXPOSURE": 60,
        "HTTP_PUT_UPLOAD_CAPABILITY": 58,
        "HTTP_DELETE_CAPABILITY": 57,
        "CORS_MISCONFIG": 55,
        "TRACE_ENABLED": 50,
        "RISKY_HTTP_METHODS_ENABLED": 45,
        "HSTS_MISSING": 40,
        "CLICKJACKING": 35,
        "CSP_MISSING": 34,
        "CONTENT_TYPE_SNIFFING": 33,
        "REFERRER_POLICY_MISSING": 32,
        "PERMISSIONS_POLICY_MISSING": 31,
        "COOKIE_HTTPONLY_MISSING": 30,
        "COOKIE_SECURE_MISSING": 25,
        "COOKIE_SAMESITE_MISSING": 20,
        "HTTPS_REDIRECT_MISSING": 10,
    }

    return (
        type_priority.get(candidate_type, 0),
        1 if cwe else 0,
        1 if not mapping_status else 0,
        int(confidence * 100),
    )


def _preferred_finding(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    return new if _classification_rank(new) > _classification_rank(existing) else existing


def ensure_output_dirs(run_dir: Path) -> None:
    (run_dir / "findings").mkdir(parents=True, exist_ok=True)
    (run_dir / "debug").mkdir(parents=True, exist_ok=True)
    (run_dir / "raw").mkdir(parents=True, exist_ok=True)


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(prune_empty(data), indent=2, ensure_ascii=False), encoding="utf-8")


def save_raw_capture(raw_dir: Path, seq: int, spec: Any, snapshot: Dict[str, Any]) -> Path:
    filename = f"{seq:04d}_{spec.name}.json"
    path = raw_dir / filename

    actual_request = snapshot.get("actual_request") or {}

    request_block = {
        "name": spec.name,
        "method": actual_request.get("method") or spec.method,
        "url": actual_request.get("url") or spec.url,
        "headers": actual_request.get("headers") or spec.headers,
        "body": actual_request.get("body"),
        "origin": getattr(spec, "origin", None),
        "probe": getattr(spec, "probe", None),
        "trace_marker": getattr(spec, "trace_marker", None),
        "source": getattr(spec, "source", None),
        "family": getattr(spec, "family", None),
        "mutation_class": getattr(spec, "mutation_class", None),
        "target_param": getattr(spec, "target_param", None),
        "target_header": getattr(spec, "target_header", None),
        "surface_hint": getattr(spec, "surface_hint", None),
        "expected_signal": getattr(spec, "expected_signal", None),
        "comparison_group": getattr(spec, "comparison_group", None),
    }

    if request_block["body"] is None and spec.body:
        request_block["body"] = spec.body.decode("utf-8", errors="replace")

    data = {
        "request": request_block,
        "response": snapshot,
    }
    save_json(path, data)
    return path

def seed_bucket_candidate(cand: Dict[str, Any]) -> Dict[str, Any]:
    cand = dict(cand)

    evidence = cand.get("evidence") or {}
    final_url = (
        evidence.get("final_url")
        or evidence.get("anon_final_url")
        or evidence.get("auth_final_url")
        or evidence.get("resource_url")
    )

    cand["normalized_url"] = normalize_url_for_dedup(canonical_finding_url(cand))
    cand["technology_fingerprint"] = _normalize_technology_fingerprint(cand.get("technology_fingerprint") or [])

    first_event = prune_empty(
        {
            "trigger": compact_trigger(cand.get("trigger") or {}),
            "final_url": final_url,
            "raw_ref": cand.get("raw_ref"),
            "finding_ref": cand.get("finding_ref"),
            "status_code": (
                cand.get("status_code")
                or evidence.get("status_code")
                or evidence.get("anon_status_code")
                or evidence.get("auth_status_code")
            ),
        }
    )

    cand["events"] = [first_event] if first_event else []
    cand["trigger_count"] = len(cand["events"])
    cand["triggers"] = [ev.get("trigger") for ev in cand["events"] if ev.get("trigger")]
    cand["final_urls"] = [final_url] if final_url else []
    cand["raw_refs"] = [cand["raw_ref"]] if cand.get("raw_ref") else []
    return cand



def _merge_unique_list(target: Dict[str, Any], field: str, new_vals: Any) -> None:
    if not new_vals:
        return

    target.setdefault(field, [])
    if not isinstance(target[field], list):
        target[field] = []

    incoming = new_vals if isinstance(new_vals, list) else [new_vals]
    for item in incoming:
        if item not in target[field]:
            target[field].append(item)

    if field in {
        "technology_fingerprint",
        "exposed_information",
        "severity_reason",
        "missing_security_controls",
        "notes",
    }:
        target[field] = _dedup_str_list(target[field])


def _same_route_or_final_url(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    a_norm = normalize_url_for_dedup(str(a.get("normalized_url") or canonical_finding_url(a) or ""))
    b_norm = normalize_url_for_dedup(str(b.get("normalized_url") or canonical_finding_url(b) or ""))
    if a_norm and b_norm and a_norm == b_norm:
        return True

    a_final = normalize_url_for_dedup(str((a.get("evidence") or {}).get("final_url") or ""))
    b_final = normalize_url_for_dedup(str((b.get("evidence") or {}).get("final_url") or ""))
    return bool(a_final and b_final and a_final == b_final)


def _default_subtype(finding: Dict[str, Any]) -> str:
    return str(finding.get("subtype") or "")


def _has_real_exposure_evidence(finding: Dict[str, Any]) -> bool:
    evidence = finding.get("evidence") or {}
    return bool(
        evidence.get("phpinfo_indicators")
        or evidence.get("config_exposure_markers")
        or evidence.get("log_exposure_patterns")
        or evidence.get("stack_traces")
        or evidence.get("db_errors")
        or evidence.get("file_paths")
    )


def _dominates(stronger: Dict[str, Any], weaker: Dict[str, Any]) -> bool:
    stronger_type = str(stronger.get("type") or "")
    weaker_type = str(weaker.get("type") or "")
    weaker_subtype = _default_subtype(weaker)

    if not _same_route_or_final_url(stronger, weaker):
        return False

    if stronger_type == "PHPINFO_EXPOSURE" and weaker_type == "DEFAULT_FILE_EXPOSED":
        return weaker_subtype == "phpinfo_page"

    if stronger_type == "HTTP_CONFIG_FILE_EXPOSURE" and weaker_type == "DEFAULT_FILE_EXPOSED":
        return weaker_subtype in {"env_file", "git_metadata", "default_resource", "debug_endpoint", "actuator_endpoint"}

    if stronger_type == "LOG_VIEWER_EXPOSURE" and weaker_type == "DEFAULT_FILE_EXPOSED":
        return weaker_subtype in {"debug_endpoint", "default_resource"}

    if stronger_type in {"PHPINFO_EXPOSURE", "HTTP_CONFIG_FILE_EXPOSURE", "LOG_VIEWER_EXPOSURE"} and weaker_type == "HTTP_SYSTEM_INFO_EXPOSURE":
        return True

    if stronger_type == "HTTP_ERROR_INFO_EXPOSURE" and weaker_type == "DEFAULT_FILE_EXPOSED":
        return True

    if stronger_type == "HTTP_ERROR_INFO_EXPOSURE" and weaker_type == "FILE_PATH_HANDLING_ANOMALY":
        return True

    if stronger_type == "HTTP_CONFIG_FILE_EXPOSURE" and weaker_type == "FILE_PATH_HANDLING_ANOMALY":
        return True

    if stronger_type == "FILE_PATH_HANDLING_ANOMALY" and weaker_type == "DEFAULT_FILE_EXPOSED":
        return weaker_subtype == "default_resource"

    if stronger_type == "HTTP_ERROR_INFO_EXPOSURE" and weaker_type == "HTTP_SYSTEM_INFO_EXPOSURE":
        return _has_real_exposure_evidence(stronger)

    return False


def dedupe_and_reduce_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not findings:
        return findings

    kept: List[Dict[str, Any]] = []
    for cand in sorted(findings, key=_classification_rank, reverse=True):
        if any(_dominates(existing, cand) for existing in kept):
            continue
        kept.append(cand)
    return kept

def merge_finding(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    existing = dict(existing)
    if "events" not in existing:
        existing = seed_bucket_candidate(existing)

    max_events = 5
    existing.setdefault("events", [])

    new_evidence = new.get("evidence") or {}
    new_event = prune_empty(
        {
            "trigger": compact_trigger(new.get("trigger") or {}),
            "final_url": (
                new_evidence.get("final_url")
                or new_evidence.get("anon_final_url")
                or new_evidence.get("auth_final_url")
                or new_evidence.get("resource_url")
            ),
            "raw_ref": new.get("raw_ref"),
            "finding_ref": new.get("finding_ref"),
            "status_code": (
                new.get("status_code")
                or new_evidence.get("status_code")
                or new_evidence.get("anon_status_code")
                or new_evidence.get("auth_status_code")
            ),
        }
    )

    if new_event and new_event not in existing["events"] and len(existing["events"]) < max_events:
        existing["events"].append(new_event)

    if _severity_rank(str(new.get("severity") or "Info")) > _severity_rank(str(existing.get("severity") or "Info")):
        existing["severity"] = new.get("severity")

    existing["confidence"] = max(float(existing.get("confidence") or 0), float(new.get("confidence") or 0))

    existing_ver = existing.setdefault("verification", {})
    new_ver = new.get("verification") or {}
    if _verdict_rank(str(new_ver.get("verdict") or "")) >= _verdict_rank(str(existing_ver.get("verdict") or "")):
        existing["verification"] = new_ver

    for field in ("exposed_information", "missing_security_controls", "severity_reason", "technology_fingerprint"):
        _merge_unique_list(existing, field, new.get(field) or [])

    existing["technology_fingerprint"] = _normalize_technology_fingerprint(existing.get("technology_fingerprint") or [])
    existing["exposed_information"] = _dedup_str_list(existing.get("exposed_information") or [])[:8]
    existing["severity_reason"] = _dedup_str_list(existing.get("severity_reason") or [])[:6]

    existing_evidence = existing.setdefault("evidence", {})

    list_fields = [
        "strong_version_tokens_in_body",
        "version_tokens_in_body",
        "all_version_tokens",
        "header_version_tokens",
        "stack_traces",
        "file_paths",
        "db_errors",
        "internal_ips",
        "debug_hints",
        "framework_hints",
        "default_file_hints",
        "directory_listing_hints",
        "risky_methods_enabled",
        "allowed_methods",
        "missing",
        "present",
        "phpinfo_indicators",
        "config_exposure_markers",
        "log_exposure_patterns",
        "query_param_names",
        "file_path_parameter_names",
        "redirect_parameter_names",
        "resource_hits",
        "marker_hits",
        "indicator_hits",
        "method_capability_signals",
        "notes",
        "auth_json_indicators",
        "anon_json_indicators",
        "decision_reasons",
    ]

    for field in list_fields:
        _merge_unique_list(existing_evidence, field, new_evidence.get(field) or [])

    for field in list_fields:
        if isinstance(existing_evidence.get(field), list):
            existing_evidence[field] = _dedup_str_list(existing_evidence[field])

    if new_evidence.get("banner_headers"):
        existing_evidence.setdefault("banner_headers", {})
        if isinstance(existing_evidence["banner_headers"], dict):
            for k, v in (new_evidence.get("banner_headers") or {}).items():
                if k not in existing_evidence["banner_headers"]:
                    existing_evidence["banner_headers"][k] = v

    scalar_evidence_fields = (
        "default_error_hint",
        "acao",
        "acac",
        "acam",
        "acah",
        "vary",
        "body_content_type_hint",
        "content_type",
        "location",
        "cookie_name",
        "final_url",
        "response_kind",
        "error_exposure_class",
        "status_code",
        "candidate_url",
        "allow_header",
        "dav_header",
        "put_status",
        "get_status",
        "delete_status",
        "verify_delete_status",
        "marker",
        "uploaded_bytes",
        "retrieved_marker_present",
        "delete_verified_absent",
        # protected resource exposure
        "target",
        "resource_url",
        "resource_kind",
        "source",
        "seen_in_anonymous_crawl",
        "auth_status_code",
        "auth_final_url",
        "auth_content_type",
        "auth_is_json_like",
        "auth_body_len",
        "anon_status_code",
        "anon_final_url",
        "anon_content_type",
        "anon_is_json_like",
        "anon_body_len",
        "anon_body_snippet",
    )

    for field in scalar_evidence_fields:
        if new_evidence.get(field) not in (None, "", [], {}):
            existing_evidence[field] = new_evidence.get(field)

    preferred = _preferred_finding(existing, new)
    for scalar_field in (
        "title",
        "type",
        "cwe",
        "cwe_mapping_status",
        "cwe_mapping_reason",
        "owasp",
        "family",
        "subtype",
        "surface",
        "scope_hint",
        "policy_object",
        "root_cause_signature",
        "template_fingerprint",
        "classification_kind",
        "burp_zap_aligned",
        "signal_strength",
        "signal_repeatability",
        "observation_scope",
        "verification_strategy",
        "why_it_matters",
        "llm_severity",
        "final_severity",
        "severity_validation_reason",
        "reproduction_attempts",
        "where",
        "status_code",
        "normalized_url",
    ):
        preferred_value = preferred.get(scalar_field)
        if preferred_value not in (None, "", [], {}):
            existing[scalar_field] = preferred_value

    if new.get("recommendation"):
        existing.setdefault("recommendation", [])
        for item in new.get("recommendation") or []:
            if item not in existing["recommendation"]:
                existing["recommendation"].append(item)

    if new.get("llm_judgement"):
        existing["llm_judgement"] = new.get("llm_judgement")

    if new.get("exposed_information_raw"):
        existing["exposed_information_raw"] = _dedup_str_list(
            (existing.get("exposed_information_raw") or []) + (new.get("exposed_information_raw") or [])
        )[:8]

    if new.get("normalized_exposed_information"):
        existing["normalized_exposed_information"] = _dedup_str_list(
            (existing.get("normalized_exposed_information") or []) + (new.get("normalized_exposed_information") or [])
        )[:8]

    if new.get("llm_evidence_review"):
        existing["llm_evidence_review"] = new.get("llm_evidence_review")

    existing["normalized_url"] = normalize_url_for_dedup(canonical_finding_url(existing))
    existing["trigger_count"] = len(existing.get("events", []))
    existing["triggers"] = [ev.get("trigger") for ev in existing.get("events", []) if ev.get("trigger")][:max_events]

    existing["final_urls"] = []
    for ev in existing.get("events", []):
        final_url = ev.get("final_url")
        if final_url and final_url not in existing["final_urls"]:
            existing["final_urls"].append(final_url)
    existing["final_urls"] = existing["final_urls"][:max_events]

    existing["raw_refs"] = []
    for ev in existing.get("events", []):
        raw_ref = ev.get("raw_ref")
        if raw_ref and raw_ref not in existing["raw_refs"]:
            existing["raw_refs"].append(raw_ref)
    existing["raw_refs"] = existing["raw_refs"][:max_events]

    return prune_empty(existing)

def store_candidate_in_bucket(bucket_map: Dict[str, Dict[str, Any]], finding_key: str, cand: Dict[str, Any]) -> Dict[str, Any]:
    if finding_key in bucket_map:
        bucket_map[finding_key] = merge_finding(bucket_map[finding_key], cand)
    else:
        bucket_map[finding_key] = seed_bucket_candidate(cand)
    return bucket_map[finding_key]

def save_or_update_merged_finding(run_dir: Path, verdict_dirname: str, finding: Dict[str, Any]) -> str:
    import re

    group = finding_group(finding)
    compact_dir = run_dir / "findings" / verdict_dirname / group
    debug_dir = run_dir / "debug" / verdict_dirname / group
    compact_dir.mkdir(parents=True, exist_ok=True)
    debug_dir.mkdir(parents=True, exist_ok=True)

    def _slug(value: Any) -> str:
        s = str(value or "").strip().lower()
        s = re.sub(r"[^\w]+", "_", s)
        s = re.sub(r"_+", "_", s).strip("_")
        return s

    base_filename = stable_finding_filename(finding)
    stem = Path(base_filename).stem
    suffix = Path(base_filename).suffix or ".json"

    subtype = _slug(finding.get("subtype"))
    policy_object = _slug(finding.get("policy_object"))

    # 파일 저장 충돌 방지:
    # 같은 type/cwe/url 이어도 subtype/policy_object가 다르면 별도 파일로 분리
    extra_parts = [x for x in [subtype, policy_object] if x]
    if extra_parts:
        stem = f"{stem}__{'__'.join(extra_parts)}"

    filename = f"{stem}{suffix}"
    compact_path = compact_dir / filename
    debug_path = debug_dir / filename.replace(".json", ".debug.json")

    compact_data = prune_empty(serialize_compact_finding(finding))
    debug_data = prune_empty(serialize_debug_finding(finding))

    compact_path.write_text(json.dumps(compact_data, ensure_ascii=False, indent=2), encoding="utf-8")
    debug_path.write_text(json.dumps(debug_data, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(compact_path)


def persist_finding_map(run_dir: Path, verdict_dirname: str, finding_map: Dict[str, Dict[str, Any]], log_fn) -> List[Dict[str, Any]]:
    persisted: List[Dict[str, Any]] = []
    log_fn("SAVE", f"{verdict_dirname}: {len(finding_map)} finding(s)")

    reduced = dedupe_and_reduce_findings(list(finding_map.values()))
    for finding in reduced:
        if "events" not in finding:
            finding = seed_bucket_candidate(finding)
        finding["finding_ref"] = save_or_update_merged_finding(run_dir, verdict_dirname, finding)
        persisted.append(finding)

    return persisted 
