from __future__ import annotations

from typing import Any, Dict, List, Set


def dedupe_signals(signals: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for item in signals or []:
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
    return deduped


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
