from __future__ import annotations

from typing import Any, Dict, List


def _dedup(items: List[Any]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items or []:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _compact_trigger(trigger: Dict[str, Any]) -> str:
    if not isinstance(trigger, dict):
        return ""

    method = str(trigger.get("method") or "").strip()
    url = str(trigger.get("url") or "").strip()
    name = str(trigger.get("name") or "").strip()

    parts = [part for part in [method, url, f"({name})" if name else ""] if part]
    return " ".join(parts).strip()


def _trigger_lines(finding: Dict[str, Any]) -> List[str]:
    triggers = finding.get("triggers") or []
    if isinstance(triggers, list) and triggers:
        lines = [_compact_trigger(item) for item in triggers if _compact_trigger(item)]
        return _dedup(lines)

    trigger = finding.get("trigger") or {}
    one = _compact_trigger(trigger)
    return [one] if one else []


def _raw_refs(finding: Dict[str, Any]) -> List[str]:
    return _dedup(finding.get("raw_refs") or [])


def _final_urls(finding: Dict[str, Any]) -> List[str]:
    final_urls = _dedup(finding.get("final_urls") or [])
    if final_urls:
        return final_urls

    evidence = finding.get("evidence") or {}
    final_url = str(evidence.get("final_url") or "").strip()
    return [final_url] if final_url else []


def _evidence_markers(finding: Dict[str, Any]) -> List[str]:
    evidence = finding.get("evidence") or {}
    markers: List[str] = []

    for field in (
        "stack_traces",
        "file_paths",
        "db_errors",
        "framework_hints",
        "internal_ips",
        "phpinfo_indicators",
        "config_exposure_markers",
        "config_extracted_values",
        "log_exposure_patterns",
        "header_version_tokens",
        "strong_version_tokens_in_body",
        "detector_evidence",
        "source_code_markers",
    ):
        values = evidence.get(field) or []
        if isinstance(values, list):
            markers.extend(str(value) for value in values[:5])

    markers.extend(str(value) for value in (finding.get("exposed_information") or [])[:5])
    return _dedup(markers)


def build_reproduction_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    evidence = finding.get("evidence") or {}
    return {
        "trigger_requests": _trigger_lines(finding),
        "final_urls": _final_urls(finding),
        "status_code": finding.get("status_code") or evidence.get("status_code"),
        "raw_refs": _raw_refs(finding),
        "finding_ref": finding.get("finding_ref"),
        "evidence_markers": _evidence_markers(finding),
    }


def build_reproduction_section_markdown(finding: Dict[str, Any]) -> str:
    summary = build_reproduction_summary(finding)

    lines = ["## Reproduction Evidence", ""]

    trigger_requests = summary["trigger_requests"] or []
    lines.append("Trigger Requests:")
    if trigger_requests:
        lines.extend(f"- {item}" for item in trigger_requests)
    else:
        lines.append("- None")

    lines.append("")
    lines.append("Observed Final URLs:")
    final_urls = summary["final_urls"] or []
    if final_urls:
        lines.extend(f"- {item}" for item in final_urls)
    else:
        lines.append("- None")

    lines.append("")
    lines.append("Observed Status Code:")
    lines.append(f"- {summary['status_code']}" if summary["status_code"] is not None else "- None")

    lines.append("")
    lines.append("Raw Capture References:")
    raw_refs = summary["raw_refs"] or []
    if raw_refs:
        lines.extend(f"- `{item}`" for item in raw_refs)
    else:
        lines.append("- None")

    if summary["finding_ref"]:
        lines.append(f"- Finding JSON: `{summary['finding_ref']}`")

    lines.append("")
    lines.append("Evidence Markers:")
    evidence_markers = summary["evidence_markers"] or []
    if evidence_markers:
        lines.extend(f"- {item}" for item in evidence_markers)
    else:
        lines.append("- None")

    lines.append("")
    return "\n".join(lines)
