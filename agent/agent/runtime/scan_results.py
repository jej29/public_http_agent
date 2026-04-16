from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit


def _candidate_signal_key(signal: Dict[str, Any]) -> str:
    evidence = signal.get("evidence") or {}
    final_url = str(evidence.get("final_url") or "")
    subtype = str(signal.get("subtype") or "")
    finding_type = str(signal.get("finding_type") or "")
    policy_object = str(signal.get("policy_object") or "")

    try:
        parsed = urlsplit(final_url)
        host_scope = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}/" if parsed.scheme and parsed.netloc else final_url
        route_scope = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or '/'}" if parsed.scheme and parsed.netloc else final_url
    except Exception:
        host_scope = final_url
        route_scope = final_url

    if subtype in {
        "detector_version_disclosure",
        "detector_framework_hint",
        "detector_internal_structure",
        "banner_header",
    }:
        scope = host_scope
    else:
        scope = route_scope

    return "||".join([finding_type, subtype, policy_object, scope])


def _reduce_candidate_signals(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    reduced: Dict[str, Dict[str, Any]] = {}
    for signal in signals or []:
        key = _candidate_signal_key(signal)
        existing = reduced.get(key)
        if existing is None:
            signal = dict(signal)
            signal["observation_count"] = 1
            reduced[key] = signal
            continue

        existing["observation_count"] = int(existing.get("observation_count") or 1) + 1
        existing_conf = float(existing.get("confidence") or 0.0)
        signal_conf = float(signal.get("confidence") or 0.0)
        if signal_conf > existing_conf:
            merged_count = existing["observation_count"]
            signal = dict(signal)
            signal["observation_count"] = merged_count
            reduced[key] = signal
    return list(reduced.values())


def store_verified_findings(
    *,
    findings: List[Dict[str, Any]],
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    stable_key_fn,
    store_with_verdict_precedence_fn,
) -> None:
    for finding in findings:
        key = stable_key_fn(finding)
        verdict = (finding.get("verification") or {}).get("verdict")
        store_with_verdict_precedence_fn(
            key=key,
            cand=finding,
            verdict=verdict,
            confirmed_map=confirmed_map,
            informational_map=informational_map,
            false_positive_map=false_positive_map,
        )


def finalize_and_write_results(
    *,
    results: Dict[str, Any],
    coverage: Dict[str, Dict[str, Any]],
    run_dir: Path,
    out_path: Path,
    raw_index: List[Dict[str, Any]],
    request_failures: List[Dict[str, Any]],
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
    discovered_endpoints: List[Dict[str, Any]],
    original_discovered_count: int,
    max_endpoints: int,
    consolidate_generic_vs_concrete_fn,
    drop_shadowed_false_positives_fn,
    reconcile_bucket_precedence_fn,
    persist_finding_map_fn,
    add_confirmed_counts_to_coverage_fn,
    finalize_coverage_assessment_fn,
    compute_summary_fn,
    now_utc_iso_fn,
    endpoint_url_fn,
    endpoint_kind_fn,
    log_fn,
    save_json_fn,
    generate_reports_fn,
) -> Dict[str, Any]:
    candidate_signals: List[Dict[str, Any]] = []

    def _split_supporting_signals(bucket_map: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        filtered: Dict[str, Dict[str, Any]] = {}
        for key, finding in bucket_map.items():
            if str(finding.get("classification_kind") or "") == "supporting_signal":
                candidate_signals.append(finding)
                continue
            filtered[key] = finding
        return filtered

    confirmed_map = _split_supporting_signals(confirmed_map)
    informational_map = _split_supporting_signals(informational_map)
    false_positive_map = _split_supporting_signals(false_positive_map)
    candidate_signals = _reduce_candidate_signals(candidate_signals)

    confirmed_map, informational_map = consolidate_generic_vs_concrete_fn(
        confirmed_map,
        informational_map,
    )
    false_positive_map = drop_shadowed_false_positives_fn(
        false_positive_map,
        list(confirmed_map.values()) + list(informational_map.values()),
    )

    confirmed_map, informational_map, false_positive_map = reconcile_bucket_precedence_fn(
        confirmed_map,
        informational_map,
        false_positive_map,
    )

    confirmed_list = persist_finding_map_fn(run_dir, "confirmed", confirmed_map, log_fn)
    informational_list = persist_finding_map_fn(run_dir, "informational", informational_map, log_fn)
    false_positive_list = persist_finding_map_fn(run_dir, "false_positive", false_positive_map, log_fn)

    results["findings_confirmed"] = confirmed_list
    results["findings_informational"] = informational_list
    results["findings_false_positive"] = false_positive_list
    results["candidate_signals"] = candidate_signals
    results["request_failures"] = request_failures

    add_confirmed_counts_to_coverage_fn(results, coverage)
    results["coverage"] = finalize_coverage_assessment_fn(coverage)

    results["metadata"]["finished_at"] = now_utc_iso_fn()
    results["metadata"]["request_count"] = len(raw_index)
    results["metadata"]["discovered_endpoint_count_before_pruning"] = original_discovered_count
    results["metadata"]["discovered_endpoint_count"] = len(discovered_endpoints)
    results["metadata"]["max_endpoints"] = max_endpoints
    results["metadata"]["discovered_endpoints_sample"] = [
        {
            "url": endpoint_url_fn(endpoint),
            "kind": endpoint_kind_fn(endpoint),
            "states": endpoint.get("states", []) if isinstance(endpoint, dict) else [],
            "score": endpoint.get("score", 0) if isinstance(endpoint, dict) else 0,
            "field_names": endpoint.get("field_names", []) if isinstance(endpoint, dict) else [],
        }
        for endpoint in discovered_endpoints[:20]
    ]

    results["summary"] = compute_summary_fn(results)
    results["raw_index"] = raw_index

    summary = results["summary"]
    log_fn("SUMMARY", f"Requests sent: {results['metadata']['request_count']}")
    log_fn("SUMMARY", f"Confirmed findings: {summary['confirmed_count']}")
    log_fn("SUMMARY", f"Informational findings: {summary['informational_count']}")
    log_fn("SUMMARY", f"False positives: {summary['false_positive_count']}")
    log_fn("SUMMARY", f"Candidate signals: {len(candidate_signals)}")

    save_json_fn(out_path, results)
    candidate_signal_path = run_dir / "debug" / "candidate_signals.json"
    candidate_signal_path.parent.mkdir(parents=True, exist_ok=True)
    candidate_signal_path.write_text(
        json.dumps(candidate_signals, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    generate_reports_fn(run_dir, results)
    return results
