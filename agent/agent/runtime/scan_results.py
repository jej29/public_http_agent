from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List


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

    save_json_fn(out_path, results)
    generate_reports_fn(run_dir, results)
    return results
