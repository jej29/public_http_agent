from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

from agent.findings.types import (
    INFORMATION_DISCLOSURE_TYPES,
    SECURITY_MISCONFIGURATION_TYPES,
)
from agent.llm_client import generate_llm_report_summary
from agent.reporting.report_evidence import (
    build_reproduction_section_markdown,
    build_reproduction_summary,
)


def _slugify(text: str) -> str:
    value = (text or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    return value or "finding"


def _md_escape(text: Any) -> str:
    if text is None:
        return ""
    return str(text).replace("\n", " ").strip()


def _dedup(items: List[Any]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items or []:
        value = _md_escape(item)
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _split_product_version(token: str) -> tuple[str, str | None]:
    value = _md_escape(token).lower()
    if not value:
        return "", None
    if "/" in value:
        name, version = value.split("/", 1)
        name = name.strip()
        version = version.strip()
        if name:
            return name, version or None
    return value, None


def _normalize_technology_fingerprint(items: List[Any]) -> List[str]:
    ordered = _dedup(items)
    if not ordered:
        return []

    versioned_by_name: Dict[str, str] = {}
    for token in ordered:
        name, version = _split_product_version(token)
        if name and version and name not in versioned_by_name:
            versioned_by_name[name] = token

    out: List[str] = []
    seen = set()

    for token in ordered:
        name, version = _split_product_version(token)
        if not name:
            continue
        if version:
            if token not in seen:
                out.append(token)
                seen.add(token)
            continue
        if name in versioned_by_name:
            continue
        if token not in seen:
            out.append(token)
            seen.add(token)

    return out[:10]


def _severity_rank(severity: str) -> int:
    order = {"Info": 1, "Low": 2, "Medium": 3, "High": 4}
    return order.get(str(severity or "Info"), 1)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, content: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(content, ensure_ascii=False, indent=2), encoding="utf-8")


def _group_of(finding: Dict[str, Any]) -> str:
    family = str(finding.get("family") or "").lower()
    if family in {"http_error_disclosure", "http_body_disclosure", "directory_listing", "default_resource_exposure"}:
        return "information_disclosure"
    if family in {
        "http_header_disclosure",
        "cors_misconfig",
        "cookie_security",
        "http_method_security",
        "transport_security",
        "http_header_security",
    }:
        return "security_misconfiguration"

    finding_type = str(finding.get("type") or "")
    if finding_type in INFORMATION_DISCLOSURE_TYPES:
        return "information_disclosure"
    if finding_type in SECURITY_MISCONFIGURATION_TYPES:
        return "security_misconfiguration"
    return "other"


def _list_to_md(items: List[str]) -> str:
    values = _dedup(items)
    if not values:
        return "- None"
    return "\n".join(f"- {_md_escape(item)}" for item in values)


def _final_urls_md(finding: Dict[str, Any]) -> str:
    summary = build_reproduction_summary(finding)
    return _list_to_md(summary["final_urls"])


def _details_title(finding: Dict[str, Any]) -> str:
    family = str(finding.get("family") or "").upper()
    if family == "COOKIE_SECURITY":
        return "Missing Cookie Controls"
    if family in {"TRANSPORT_SECURITY", "HTTP_METHOD_SECURITY", "CORS_MISCONFIG", "HTTP_HEADER_SECURITY"}:
        return "Observed Security Posture"
    return "Observed Exposure"


def _details_section(finding: Dict[str, Any]) -> str:
    items = _dedup(finding.get("exposed_information") or finding.get("missing_security_controls") or [])
    return f"## {_details_title(finding)}\n\n{_list_to_md(items)}\n"


def _severity_reason_section(finding: Dict[str, Any]) -> str:
    reasons = _dedup(finding.get("severity_reason") or [])
    return f"## Severity Rationale\n\n{_list_to_md(reasons)}\n"


def _recommendation_section(finding: Dict[str, Any]) -> str:
    recommendations = _dedup(finding.get("recommendation") or [])
    return f"## Recommendation\n\n{_list_to_md(recommendations)}\n"


def _llm_reason_section(finding: Dict[str, Any]) -> str:
    llm = finding.get("llm_judgement") or {}
    reason = llm.get("reason") or (finding.get("verification") or {}).get("reason") or ""
    if not reason:
        reason = "None"
    return f"## Verification Notes\n\n{_md_escape(reason)}\n"


def _description_text(finding: Dict[str, Any]) -> str:
    llm = finding.get("llm_judgement") or {}
    llm_reason = _md_escape(llm.get("reason"))
    rule_reason = _md_escape(finding.get("why_it_matters"))

    if llm_reason:
        if rule_reason and rule_reason.lower() != llm_reason.lower():
            return f"{llm_reason}\n\nRule-based context: {rule_reason}"
        return llm_reason

    return rule_reason or "None"


def _finding_instance_count(finding: Dict[str, Any]) -> int:
    trigger_count = finding.get("trigger_count")
    if isinstance(trigger_count, int):
        return trigger_count
    triggers = finding.get("triggers") or []
    return len(triggers) if isinstance(triggers, list) else 0


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        findings or [],
        key=lambda finding: (
            -_severity_rank(str(finding.get("severity") or "Info")),
            _group_of(finding),
            str(finding.get("title") or finding.get("type") or ""),
            str(finding.get("normalized_url") or ""),
        ),
    )


def _overview_table_row(finding: Dict[str, Any]) -> str:
    family = finding.get("family") or _group_of(finding)
    subtype = finding.get("subtype") or "-"
    severity = finding.get("severity") or ""
    cwe = finding.get("cwe") or finding.get("cwe_mapping_status") or ""
    scope = finding.get("scope_hint") or "-"
    url = finding.get("normalized_url") or ""
    title = finding.get("title") or finding.get("type") or "Finding"
    instances = _finding_instance_count(finding)
    return (
        f"| {_md_escape(family)} | {_md_escape(subtype)} | {_md_escape(severity)} | "
        f"{_md_escape(cwe)} | {_md_escape(scope)} | {_md_escape(title)} | "
        f"`{_md_escape(url)}` | `{instances}` |"
    )


def _compact_finding_json(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": finding.get("title"),
        "type": finding.get("type"),
        "family": finding.get("family"),
        "subtype": finding.get("subtype"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "cwe": finding.get("cwe") or finding.get("cwe_mapping_status"),
        "owasp": finding.get("owasp"),
        "scope_hint": finding.get("scope_hint"),
        "surface": finding.get("surface") or finding.get("where"),
        "policy_object": finding.get("policy_object"),
        "root_cause_signature": finding.get("root_cause_signature"),
        "technology_fingerprint": _normalize_technology_fingerprint(
            finding.get("technology_fingerprint") or []
        ),
        "template_fingerprint": finding.get("template_fingerprint"),
        "normalized_url": finding.get("normalized_url"),
        "trigger_count": _finding_instance_count(finding),
        "final_urls": _dedup(finding.get("final_urls") or []),
        "triggers": build_reproduction_summary(finding)["trigger_requests"],
        "exposed_information": _dedup(finding.get("exposed_information") or []),
        "missing_security_controls": _dedup(finding.get("missing_security_controls") or []),
        "severity_reason": _dedup(finding.get("severity_reason") or []),
        "recommendation": _dedup(finding.get("recommendation") or []),
        "verification": finding.get("verification") or {},
        "raw_refs": _dedup(finding.get("raw_refs") or []),
        "finding_ref": finding.get("finding_ref"),
        "reproduction_evidence": build_reproduction_summary(finding),
    }


def _finding_markdown(finding: Dict[str, Any]) -> str:
    title = finding.get("title") or finding.get("type") or "Finding"
    severity = finding.get("severity") or ""
    cwe = finding.get("cwe") or finding.get("cwe_mapping_status") or "N/A"
    owasp = finding.get("owasp") or "N/A"
    where = finding.get("where") or finding.get("surface") or ""
    status_code = finding.get("status_code")
    normalized_url = finding.get("normalized_url") or ""
    description = _description_text(finding)
    family = finding.get("family") or _group_of(finding)
    subtype = finding.get("subtype") or "-"
    scope_hint = finding.get("scope_hint") or "-"
    policy_object = finding.get("policy_object") or "-"
    trigger_count = _finding_instance_count(finding)
    root_cause_signature = finding.get("root_cause_signature") or ""
    technology = ", ".join(_normalize_technology_fingerprint(finding.get("technology_fingerprint") or [])) or "-"
    template = finding.get("template_fingerprint") or "-"
    confidence = finding.get("confidence")

    lines = [
        f"# {title}",
        "",
        f"- Family: `{family}`",
        f"- Subtype: `{subtype}`",
        f"- Severity: `{severity}`",
        f"- Confidence: `{confidence}`" if confidence is not None else "- Confidence: `N/A`",
        f"- CWE: `{cwe}`",
        f"- OWASP: `{owasp}`",
        f"- Scope: `{scope_hint}`",
        f"- Policy Object: `{policy_object}`",
        f"- Location: `{where}`" if where else "- Location: `N/A`",
        f"- HTTP Status Code: `{status_code}`" if status_code is not None else "- HTTP Status Code: `N/A`",
        f"- URL: `{normalized_url}`" if normalized_url else "- URL: `N/A`",
        f"- Trigger Count: `{trigger_count}`",
        f"- Technology Fingerprint: `{technology}`",
        f"- Template Fingerprint: `{template}`",
    ]

    if root_cause_signature:
        lines.append(f"- Root Cause Signature: `{root_cause_signature}`")

    lines.extend(
        [
            "",
            "## Description",
            "",
            _md_escape(description) or "None",
            "",
            "## Trigger Requests",
            "",
            _list_to_md(build_reproduction_summary(finding)["trigger_requests"]),
            "",
            "## Final URLs",
            "",
            _final_urls_md(finding),
            "",
            _details_section(finding).rstrip(),
            "",
            _severity_reason_section(finding).rstrip(),
            "",
            _llm_reason_section(finding).rstrip(),
            "",
            _recommendation_section(finding).rstrip(),
            "",
            build_reproduction_section_markdown(finding).rstrip(),
            "",
        ]
    )

    return "\n".join(lines).strip() + "\n"


def _summary_markdown(results: Dict[str, Any]) -> str:
    metadata = results.get("metadata") or {}
    summary = results.get("summary") or {}
    confirmed = _sort_findings(results.get("findings_confirmed") or [])

    lines = [
        "# Scan Summary",
        "",
        f"- Target: `{_md_escape(metadata.get('target'))}`",
        f"- Run ID: `{_md_escape(metadata.get('run_id'))}`",
        f"- Started At: `{_md_escape(metadata.get('started_at'))}`",
        f"- Finished At: `{_md_escape(metadata.get('finished_at'))}`",
        f"- Request Count: `{_md_escape(metadata.get('request_count'))}`",
        "",
        "## Counts",
        "",
        f"- Confirmed: `{summary.get('confirmed_count', 0)}`",
        f"- Informational: `{summary.get('informational_count', 0)}`",
        f"- False Positive: `{summary.get('false_positive_count', 0)}`",
        "",
        "## Confirmed By Group",
        "",
    ]

    confirmed_by_group = summary.get("confirmed_by_group") or {}
    if confirmed_by_group:
        for key, value in confirmed_by_group.items():
            lines.append(f"- `{_md_escape(key)}`: `{_md_escape(value)}`")
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Confirmed Findings Overview",
            "",
            "| Family | Subtype | Severity | CWE | Scope | Title | URL | Instances |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )

    if confirmed:
        for finding in confirmed:
            lines.append(_overview_table_row(finding))
    else:
        lines.append("| None |  |  |  |  |  |  |  |")

    lines.append("")
    return "\n".join(lines)


def generate_reports(run_dir: Path, results: Dict[str, Any]) -> None:
    report_dir = run_dir / "report"
    findings_dir = report_dir / "findings"

    confirmed = _sort_findings(results.get("findings_confirmed") or [])
    informational = _sort_findings(results.get("findings_informational") or [])
    false_positive = _sort_findings(results.get("findings_false_positive") or [])

    _write_text(report_dir / "summary.md", _summary_markdown(results))

    for index, finding in enumerate(confirmed, start=1):
        base = finding.get("title") or finding.get("type") or f"finding_{index}"
        filename = f"{index:03d}_{_slugify(base)}.md"
        _write_text(findings_dir / filename, _finding_markdown(finding))

    _write_json(
        report_dir / "compact.json",
        {
            "metadata": results.get("metadata") or {},
            "summary": results.get("summary") or {},
            "confirmed": [_compact_finding_json(finding) for finding in confirmed],
            "informational": [_compact_finding_json(finding) for finding in informational],
            "false_positive": [_compact_finding_json(finding) for finding in false_positive],
        },
    )

    _write_json(
        report_dir / "summary_compact.json",
        {
            "metadata": results.get("metadata") or {},
            "summary": results.get("summary") or {},
            "confirmed_families": sorted({_group_of(finding) for finding in confirmed}),
            "confirmed_count": len(confirmed),
            "informational_count": len(informational),
            "false_positive_count": len(false_positive),
        },
    )

    if os.getenv("LLM_REPORT_MODE", "off").lower() != "on":
        return

    try:
        llm_summary = generate_llm_report_summary(results)
        _write_json(report_dir / "llm_summary.json", llm_summary)

        lines = [
            "# LLM Executive Summary",
            "",
            llm_summary.get("executive_summary") or "No summary generated.",
            "",
            "## Top Risks",
            "",
        ]

        top_risks = llm_summary.get("top_risks") or []
        if top_risks:
            lines.extend(f"- {_md_escape(item)}" for item in top_risks)
        else:
            lines.append("- None")

        lines.extend(["", "## Priority Actions", ""])
        priority_actions = llm_summary.get("priority_actions") or []
        if priority_actions:
            lines.extend(f"- {_md_escape(item)}" for item in priority_actions)
        else:
            lines.append("- None")

        lines.append("")
        _write_text(report_dir / "llm_summary.md", "\n".join(lines))
    except Exception as exc:
        _write_json(
            report_dir / "llm_summary.error.json",
            {"error": f"{type(exc).__name__}: {exc}"},
        )
