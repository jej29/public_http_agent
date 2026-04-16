from __future__ import annotations

from typing import Any, Dict, List, Set


def _severity_rank(severity: str) -> int:
    ranking = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
    return ranking.get(str(severity or "Info"), 1)


def _evidence_size(item: Dict[str, Any]) -> int:
    evidence = item.get("evidence") or {}
    score = 0
    for value in evidence.values():
        if isinstance(value, list):
            score += len(value)
        elif isinstance(value, dict):
            score += len(value)
        elif value not in (None, "", False):
            score += 1
    score += len(item.get("exposed_information") or [])
    return score


def dedupe_signals(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    kept_by_marker: Dict[tuple[str, str, str, str, str], Dict[str, Any]] = {}
    for item in signals or []:
        finding_type = str(item.get("finding_type") or "")
        subtype = str(item.get("subtype") or "")
        root_cause_signature = str(item.get("root_cause_signature") or "")
        if finding_type in {"HTTP_ERROR_INFO_EXPOSURE", "HTTP_CONFIG_FILE_EXPOSURE", "FILE_PATH_HANDLING_ANOMALY"}:
            subtype = ""
            root_cause_signature = ""
        marker = (
            finding_type,
            subtype,
            str(item.get("policy_object") or ""),
            root_cause_signature,
            str((item.get("evidence") or {}).get("final_url") or ""),
        )
        existing = kept_by_marker.get(marker)
        if existing is None:
            kept_by_marker[marker] = item
            continue
        current_rank = (
            _severity_rank(item.get("severity", "Info")),
            float(item.get("confidence") or 0),
            _evidence_size(item),
        )
        existing_rank = (
            _severity_rank(existing.get("severity", "Info")),
            float(existing.get("confidence") or 0),
            _evidence_size(existing),
        )
        if current_rank > existing_rank:
            kept_by_marker[marker] = item
    return list(kept_by_marker.values())


def finalize_http_signals(
    signals: List[Dict[str, Any]],
    *,
    severity_rank_fn,
) -> List[Dict[str, Any]]:
    deduped = dedupe_signals(signals)
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
        evidence = item.get("evidence") or {}

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
                "detector_framework_hint",
            }:
                continue

        if finding_type == "LOG_VIEWER_EXPOSURE":
            if any(found in same_url_types for found in {
                "PHPINFO_EXPOSURE",
                "HTTP_CONFIG_FILE_EXPOSURE",
                "HTTP_ERROR_INFO_EXPOSURE",
            }):
                continue

        if finding_type == "FILE_PATH_HANDLING_ANOMALY":
            if "HTTP_ERROR_INFO_EXPOSURE" in same_url_types:
                continue
            if "HTTP_CONFIG_FILE_EXPOSURE" in same_url_types:
                continue

        if finding_type == "HTTP_ERROR_INFO_EXPOSURE":
            only_file_paths = bool(evidence.get("file_paths")) and not bool(evidence.get("stack_traces") or evidence.get("db_errors"))
            if "PHPINFO_EXPOSURE" in same_url_types and only_file_paths:
                continue

        if finding_type == "DEFAULT_FILE_EXPOSED":
            if "PHPINFO_EXPOSURE" in same_url_types and subtype == "phpinfo_page":
                continue

        final_signals.append(item)

    final_signals.sort(
        key=lambda item: (
            severity_rank_fn(item.get("severity", "Info")) * -1,
            item.get("finding_type") or "",
            item.get("title") or "",
        )
    )
    return final_signals
