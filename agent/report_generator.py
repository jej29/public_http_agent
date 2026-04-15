
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List

from agent.llm_client import generate_llm_report_summary


INFORMATION_DISCLOSURE_TYPES = {
    "HTTP_ERROR_INFO_EXPOSURE",
    "HTTP_SYSTEM_INFO_EXPOSURE",
    "DIRECTORY_LISTING_ENABLED",
    "DEFAULT_FILE_EXPOSED",
    "PHPINFO_EXPOSURE",
    "HTTP_CONFIG_FILE_EXPOSURE",
    "LOG_VIEWER_EXPOSURE",
    "FILE_PATH_HANDLING_ANOMALY",
}

SECURITY_MISCONFIGURATION_TYPES = {
    "SECURITY_HEADERS_MISSING",
    "CORS_MISCONFIG",
    "COOKIE_HTTPONLY_MISSING",
    "COOKIE_SECURE_MISSING",
    "COOKIE_SAMESITE_MISSING",
    "TRACE_ENABLED",
    "RISKY_HTTP_METHODS_ENABLED",
    "HTTPS_REDIRECT_MISSING",
    "HSTS_MISSING",
    "CLICKJACKING",
    "CSP_MISSING",
    "CONTENT_TYPE_SNIFFING",
    "REFERRER_POLICY_MISSING",
    "PERMISSIONS_POLICY_MISSING",
}


def _slugify(text: str) -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text or "finding"


def _md_escape(text: Any) -> str:
    if text is None:
        return ""
    return str(text).replace("\n", " ").strip()


def _dedup(items: List[Any]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in items or []:
        s = _md_escape(x)
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _split_product_version(token: str) -> tuple[str, str | None]:
    s = _md_escape(token).lower()
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
    ordered = _dedup(items)
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


def _severity_rank(sev: str) -> int:
    order = {"Info": 1, "Low": 2, "Medium": 3, "High": 4}
    return order.get(str(sev or "Info"), 1)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, content: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(content, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _group_of(f: Dict[str, Any]) -> str:
    family = f.get("family")
    if family:
        fam = str(family).lower()
        if fam in {"http_error_disclosure", "http_body_disclosure", "directory_listing", "default_resource_exposure"}:
            return "information_disclosure"
        if fam in {
            "http_header_disclosure",
            "cors_misconfig",
            "cookie_security",
            "http_method_security",
            "transport_security",
            "http_header_security",
        }:
            return "security_misconfiguration"

    ftype = str(f.get("type") or "")

    if ftype in INFORMATION_DISCLOSURE_TYPES:
        return "information_disclosure"

    if ftype in SECURITY_MISCONFIGURATION_TYPES:
        return "security_misconfiguration"

    return "other"


def _compact_trigger(trigger: Dict[str, Any]) -> str:
    if not isinstance(trigger, dict):
        return ""

    method = trigger.get("method") or ""
    url = trigger.get("url") or ""
    name = trigger.get("name") or ""

    parts = [x for x in [method, url, f"({name})" if name else ""] if x]
    return " ".join(parts).strip()


def _list_to_md(items: List[str]) -> str:
    items = _dedup(items)
    if not items:
        return "- 없음"
    return "\n".join(f"- {_md_escape(x)}" for x in items)


def _trigger_lines(f: Dict[str, Any]) -> str:
    triggers = f.get("triggers") or []
    if not isinstance(triggers, list) or not triggers:
        trigger = f.get("trigger") or {}
        one = _compact_trigger(trigger)
        return f"- {one}" if one else "- 없음"

    out = []
    seen = set()
    for t in triggers:
        line = _compact_trigger(t)
        if line and line not in seen:
            seen.add(line)
            out.append(f"- {line}")
    return "\n".join(out) if out else "- 없음"


def _final_urls_md(f: Dict[str, Any]) -> str:
    final_urls = _dedup(f.get("final_urls") or [])
    if not final_urls:
        evidence = f.get("evidence") or {}
        final_url = evidence.get("final_url")
        if final_url:
            final_urls = [final_url]
    return _list_to_md(final_urls)


def _evidence_refs_md(f: Dict[str, Any]) -> str:
    raw_refs = _dedup(f.get("raw_refs") or [])
    finding_ref = f.get("finding_ref")

    lines = []
    if raw_refs:
        lines.append("원본 캡처:")
        for r in raw_refs:
            lines.append(f"- `{_md_escape(r)}`")

    if finding_ref:
        lines.append("Finding 파일:")
        lines.append(f"- `{_md_escape(finding_ref)}`")

    return "\n".join(lines) if lines else "- 없음"


def _details_title(f: Dict[str, Any]) -> str:
    family = (f.get("family") or "").upper()
    if family == "COOKIE_SECURITY":
        return "설정 미흡"
    if family in {"TRANSPORT_SECURITY", "HTTP_METHOD_SECURITY", "CORS_MISCONFIG", "HTTP_HEADER_SECURITY"}:
        return "관측 내용"
    return "노출/관측 정보"


def _details_section(f: Dict[str, Any]) -> str:
    items = _dedup(
        f.get("exposed_information")
        or f.get("missing_security_controls")
        or []
    )
    return f"## {_details_title(f)}\n\n{_list_to_md(items)}\n"


def _severity_reason_section(f: Dict[str, Any]) -> str:
    reasons = _dedup(f.get("severity_reason") or [])
    return f"## Severity 판단 근거\n\n{_list_to_md(reasons)}\n"


def _recommendation_section(f: Dict[str, Any]) -> str:
    rec = _dedup(f.get("recommendation") or [])
    return f"## 권고사항\n\n{_list_to_md(rec)}\n"


def _llm_reason_section(f: Dict[str, Any]) -> str:
    llm = f.get("llm_judgement") or {}
    reason = llm.get("reason") or (f.get("verification") or {}).get("reason") or ""
    if not reason:
        reason = "없음"
    return f"## 판단 근거\n\n{_md_escape(reason)}\n"


def _finding_instance_count(f: Dict[str, Any]) -> int:
    trigger_count = f.get("trigger_count")
    if isinstance(trigger_count, int):
        return trigger_count
    triggers = f.get("triggers") or []
    return len(triggers) if isinstance(triggers, list) else 0


def _sort_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(
        findings or [],
        key=lambda f: (
            -_severity_rank(str(f.get("severity") or "Info")),
            _group_of(f),
            str(f.get("title") or f.get("type") or ""),
            str(f.get("normalized_url") or ""),
        ),
    )


def _overview_table_row(f: Dict[str, Any]) -> str:
    family = f.get("family") or _group_of(f)
    subtype = f.get("subtype") or "-"
    severity = f.get("severity") or ""
    cwe = f.get("cwe") or f.get("cwe_mapping_status") or ""
    scope = f.get("scope_hint") or "-"
    url = f.get("normalized_url") or ""
    title = f.get("title") or f.get("type") or "Finding"
    instances = _finding_instance_count(f)

    return (
        f"| {_md_escape(family)} | {_md_escape(subtype)} | {_md_escape(severity)} | "
        f"{_md_escape(cwe)} | {_md_escape(scope)} | {_md_escape(title)} | "
        f"`{_md_escape(url)}` | `{instances}` |"
    )


def _compact_finding_json(f: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "title": f.get("title"),
        "type": f.get("type"),
        "family": f.get("family"),
        "subtype": f.get("subtype"),
        "severity": f.get("severity"),
        "confidence": f.get("confidence"),
        "cwe": f.get("cwe") or f.get("cwe_mapping_status"),
        "owasp": f.get("owasp"),
        "scope_hint": f.get("scope_hint"),
        "surface": f.get("surface") or f.get("where"),
        "policy_object": f.get("policy_object"),
        "root_cause_signature": f.get("root_cause_signature"),
        "technology_fingerprint": _normalize_technology_fingerprint(
            f.get("technology_fingerprint") or []
        ),
        "template_fingerprint": f.get("template_fingerprint"),
        "normalized_url": f.get("normalized_url"),
        "trigger_count": _finding_instance_count(f),
        "final_urls": _dedup(f.get("final_urls") or []),
        "triggers": [
            _compact_trigger(t) for t in (f.get("triggers") or []) if _compact_trigger(t)
        ],
        "exposed_information": _dedup(f.get("exposed_information") or []),
        "missing_security_controls": _dedup(f.get("missing_security_controls") or []),
        "severity_reason": _dedup(f.get("severity_reason") or []),
        "recommendation": _dedup(f.get("recommendation") or []),
        "verification": f.get("verification") or {},
        "raw_refs": _dedup(f.get("raw_refs") or []),
        "finding_ref": f.get("finding_ref"),
    }


def _finding_markdown(f: Dict[str, Any]) -> str:
    title = f.get("title") or f.get("type") or "Finding"
    severity = f.get("severity") or ""
    cwe = f.get("cwe") or f.get("cwe_mapping_status") or "N/A"
    owasp = f.get("owasp") or "N/A"
    where = f.get("where") or f.get("surface") or ""
    status_code = f.get("status_code")
    normalized_url = f.get("normalized_url") or ""
    description = f.get("why_it_matters") or ""
    family = f.get("family") or _group_of(f)
    subtype = f.get("subtype") or "-"
    scope_hint = f.get("scope_hint") or "-"
    policy_object = f.get("policy_object") or "-"
    trigger_count = _finding_instance_count(f)
    root_cause_signature = f.get("root_cause_signature") or ""
    tech = ", ".join(_normalize_technology_fingerprint(f.get("technology_fingerprint") or [])) or "-"
    template = f.get("template_fingerprint") or "-"
    confidence = f.get("confidence")

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
        f"- 위치: `{where}`" if where else "- 위치: `N/A`",
        f"- HTTP 상태코드: `{status_code}`" if status_code is not None else "- HTTP 상태코드: `N/A`",
        f"- 대표 URL: `{normalized_url}`" if normalized_url else "- 대표 URL: `N/A`",
        f"- Trigger 수: `{trigger_count}`",
        f"- Technology Fingerprint: `{tech}`",
        f"- Template Fingerprint: `{template}`",
    ]

    if root_cause_signature:
        lines.append(f"- Root Cause Signature: `{root_cause_signature}`")

    lines.extend(
        [
            "",
            "## 설명",
            "",
            _md_escape(description) or "설명 없음",
            "",
            "## 관측된 요청(Triggers)",
            "",
            _trigger_lines(f),
            "",
            "## 최종 응답 URL(Final URLs)",
            "",
            _final_urls_md(f),
            "",
            _details_section(f).rstrip(),
            "",
            _severity_reason_section(f).rstrip(),
            "",
            _llm_reason_section(f).rstrip(),
            "",
            _recommendation_section(f).rstrip(),
            "",
            "## Evidence References",
            "",
            _evidence_refs_md(f),
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
        "## Confirmed by Group",
        "",
    ]

    confirmed_by_group = summary.get("confirmed_by_group") or {}
    if confirmed_by_group:
        for k, v in confirmed_by_group.items():
            lines.append(f"- `{_md_escape(k)}`: `{_md_escape(v)}`")
    else:
        lines.append("- 없음")

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
        for f in confirmed:
            lines.append(_overview_table_row(f))
    else:
        lines.append("| 없음 |  |  |  |  |  |  |  |")

    lines.append("")
    return "\n".join(lines)


def generate_reports(run_dir: Path, results: Dict[str, Any]) -> None:
    """
    출력 구조:
      report/
        summary.md
        findings/
          001_xxx.md
          ...
        compact.json
        summary_compact.json
        llm_summary.{json,md} (옵션)
    """
    report_dir = run_dir / "report"
    findings_dir = report_dir / "findings"

    confirmed = _sort_findings(results.get("findings_confirmed") or [])
    informational = _sort_findings(results.get("findings_informational") or [])
    false_positive = _sort_findings(results.get("findings_false_positive") or [])

    _write_text(report_dir / "summary.md", _summary_markdown(results))

    for idx, f in enumerate(confirmed, start=1):
        base = f.get("title") or f.get("type") or f"finding_{idx}"
        slug = _slugify(base)
        filename = f"{idx:03d}_{slug}.md"
        _write_text(findings_dir / filename, _finding_markdown(f))

    _write_json(
        report_dir / "compact.json",
        {
            "metadata": results.get("metadata") or {},
            "summary": results.get("summary") or {},
            "confirmed": [_compact_finding_json(f) for f in confirmed],
            "informational": [_compact_finding_json(f) for f in informational],
            "false_positive": [_compact_finding_json(f) for f in false_positive],
        },
    )

    _write_json(
        report_dir / "summary_compact.json",
        {
            "metadata": results.get("metadata") or {},
            "summary": results.get("summary") or {},
            "confirmed_families": sorted({_group_of(f) for f in confirmed}),
            "confirmed_count": len(confirmed),
            "informational_count": len(informational),
            "false_positive_count": len(false_positive),
        },
    )

    if os.getenv("LLM_REPORT_MODE", "off").lower() == "on":
        try:
            llm_summary = generate_llm_report_summary(results)

            _write_json(report_dir / "llm_summary.json", llm_summary)

            md_lines = [
                "# LLM Executive Summary",
                "",
                llm_summary.get("executive_summary") or "No summary generated.",
                "",
                "## Top Risks",
                "",
            ]

            top_risks = llm_summary.get("top_risks") or []
            if top_risks:
                for item in top_risks:
                    md_lines.append(f"- {_md_escape(item)}")
            else:
                md_lines.append("- None")

            md_lines.extend(["", "## Priority Actions", ""])

            priority_actions = llm_summary.get("priority_actions") or []
            if priority_actions:
                for item in priority_actions:
                    md_lines.append(f"- {_md_escape(item)}")
            else:
                md_lines.append("- None")

            md_lines.append("")
            _write_text(report_dir / "llm_summary.md", "\n".join(md_lines))

        except Exception as e:
            _write_json(
                report_dir / "llm_summary.error.json",
                {
                    "error": f"{type(e).__name__}: {e}",
                },
            )
