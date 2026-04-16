from __future__ import annotations

from typing import Any, Dict, List

from agent.findings.types import (
    INFORMATION_DISCLOSURE_TYPES,
    OWASP_ONLY_NO_CWE_MAPPING,
    SECURITY_MISCONFIGURATION_TYPES,
)


def finding_group(finding: Dict[str, Any]) -> str:
    finding_type = str(finding.get("type") or "")

    if finding_type in INFORMATION_DISCLOSURE_TYPES:
        return "information_disclosure"

    if finding_type in SECURITY_MISCONFIGURATION_TYPES:
        return "security_misconfiguration"

    return "other"


def _increment_coverage_counter(
    *,
    coverage: Dict[str, Dict[str, Any]],
    cwe: Any,
    finding_type: str,
    field: str,
) -> None:
    if cwe == "CWE-209" or finding_type == "HTTP_ERROR_INFO_EXPOSURE":
        coverage["cwe_209"][field] += 1
    elif cwe == "CWE-497" or finding_type == "HTTP_SYSTEM_INFO_EXPOSURE":
        coverage["cwe_497"][field] += 1
    elif cwe == "CWE-548" or finding_type == "DIRECTORY_LISTING_ENABLED":
        coverage["cwe_548"][field] += 1
    elif cwe == "CWE-552" or finding_type == "DEFAULT_FILE_EXPOSED":
        coverage["cwe_552"][field] += 1
    elif cwe == "CWE-942" or finding_type == "CORS_MISCONFIG":
        coverage["cwe_942"][field] += 1
    elif cwe == "CWE-1004" or finding_type == "COOKIE_HTTPONLY_MISSING":
        coverage["cwe_1004"][field] += 1
    elif cwe == "CWE-614" or finding_type == "COOKIE_SECURE_MISSING":
        coverage["cwe_614"][field] += 1
    elif cwe == "CWE-319" or finding_type in {"HTTPS_REDIRECT_MISSING", "HSTS_MISSING"}:
        coverage["cwe_319"][field] += 1


def add_confirmed_counts_to_coverage(results: Dict[str, Any], coverage: Dict[str, Dict[str, Any]]) -> None:
    for finding in results.get("findings_confirmed", []):
        _increment_coverage_counter(
            coverage=coverage,
            cwe=finding.get("cwe"),
            finding_type=str(finding.get("type") or ""),
            field="confirmed_count",
        )


def finalize_coverage_assessment(coverage: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    for key, item in coverage.items():
        attempted = item.get("attempted", False)
        candidate_count = item.get("candidate_count", 0)
        confirmed_count = item.get("confirmed_count", 0)

        if not attempted:
            item["assessment"] = "not_attempted"
            continue

        if key in {"cwe_1004", "cwe_614"} and item.get("set_cookie_observed") is False:
            item["assessment"] = "not_yet_sufficiently_validated"
            continue

        if confirmed_count > 0:
            item["assessment"] = "confirmed"
        elif candidate_count > 0:
            item["assessment"] = "observed_but_not_confirmed"
        else:
            item["assessment"] = "not_observed_in_current_scope"

    return coverage


def compute_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    confirmed = results.get("findings_confirmed", [])
    informational = results.get("findings_informational", [])
    false_positive = results.get("findings_false_positive", [])

    def by_cwe(items: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in items:
            key = finding.get("cwe") or finding.get("cwe_mapping_status") or "UNMAPPED"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def by_group(items: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for finding in items:
            group = finding_group(finding)
            counts[group] = counts.get(group, 0) + 1
        return counts

    summary = {
        "confirmed_count": len(confirmed),
        "informational_count": len(informational),
        "false_positive_count": len(false_positive),
        "total_findings": len(confirmed) + len(informational) + len(false_positive),
        "confirmed_by_cwe": by_cwe(confirmed),
        "informational_by_cwe": by_cwe(informational),
        "false_positive_by_cwe": by_cwe(false_positive),
        "confirmed_by_group": by_group(confirmed),
        "informational_by_group": by_group(informational),
        "false_positive_by_group": by_group(false_positive),
    }

    if any(
        (finding.get("cwe_mapping_status") == OWASP_ONLY_NO_CWE_MAPPING)
        for finding in confirmed + informational + false_positive
    ):
        summary["cwe_mapping_note"] = {
            OWASP_ONLY_NO_CWE_MAPPING: "OWASP category is assigned, but no precise single CWE mapping is used for this finding."
        }

    return summary
