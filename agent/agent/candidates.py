
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from agent.http.classifier import collect_http_signals
from agent.findings.types import ensure_type_cwe_consistency

OWASP_ONLY_NO_CWE_MAPPING = "OWASP_ONLY_NO_CWE_MAPPING"
OWASP_ONLY_NO_CWE_REASON = (
    "OWASP category is applicable, but no precise single CWE mapping is used for this finding."
)

def _merge_candidate_lists(primary: List[Dict[str, Any]], extra: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []
    seen = set()

    for cand in (primary or []) + (extra or []):
        marker = (
            str(cand.get("type") or ""),
            str(cand.get("subtype") or ""),
            str(cand.get("policy_object") or ""),
            str(cand.get("root_cause_signature") or ""),
            str(((cand.get("evidence") or {}).get("final_url")) or ""),
        )
        if marker in seen:
            continue
        seen.add(marker)
        merged.append(cand)

    return merged

def _truncate_text(value: Any, max_len: int = 200) -> str:
    s = str(value or "")
    return s[:max_len]


def _signal_group_key(sig: Dict[str, Any]) -> Tuple[Any, ...]:
    evidence = sig.get("evidence") or {}
    final_url = str(
        evidence.get("final_url")
        or evidence.get("requested_url")
        or ""
    ).strip()

    return (
        sig.get("finding_type"),
        sig.get("policy_object"),
        sig.get("subtype"),
        sig.get("scope_hint"),
        sig.get("root_cause_signature"),
        sig.get("template_fingerprint"),
        final_url,
    )


def _group_signals(signals: List[Dict[str, Any]]) -> Dict[Tuple[Any, ...], List[Dict[str, Any]]]:
    grouped: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}

    for sig in signals:
        key = _signal_group_key(sig)
        grouped.setdefault(key, []).append(sig)

    return grouped


def _merge_unique_list(items: List[Any]) -> List[Any]:
    out: List[Any] = []
    seen = set()

    for item in items or []:
        marker = repr(item)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)

    return out


def _merge_signal_evidence(group: List[Dict[str, Any]]) -> Dict[str, Any]:
    merged_evidence: Dict[str, Any] = {}

    list_fields = set()
    scalar_fields = set()

    for sig in group:
        ev = sig.get("evidence") or {}
        for k, v in ev.items():
            if isinstance(v, list):
                list_fields.add(k)
            else:
                scalar_fields.add(k)

    for field in sorted(list_fields):
        values: List[Any] = []
        for sig in group:
            values.extend((sig.get("evidence") or {}).get(field) or [])
        if values:
            merged_evidence[field] = _merge_unique_list(values)

    for field in sorted(scalar_fields):
        for sig in group:
            val = (sig.get("evidence") or {}).get(field)
            if val not in (None, "", [], {}):
                merged_evidence[field] = val
                break

    return merged_evidence


def _signal_strength_rank(value: str) -> int:
    order = {
        "weak": 1,
        "low": 1,
        "strong": 2,
        "likely_stable": 2,
        "deterministic": 3,
        "stable": 3,
    }
    return order.get(str(value or "").lower(), 0)


def _strongest_signal_value(group: List[Dict[str, Any]], field: str, default: str = "") -> str:
    best = default
    best_rank = -1

    for sig in group:
        value = str(sig.get(field) or "")
        rank = _signal_strength_rank(value)
        if rank > best_rank:
            best = value
            best_rank = rank

    return best


def _merge_signal_group(group: List[Dict[str, Any]]) -> Dict[str, Any]:
    base = dict(group[0])

    base["evidence"] = _merge_signal_evidence(group)
    base["confidence"] = max(float(s.get("confidence") or 0.0) for s in group)

    signal_strength = _strongest_signal_value(group, "signal_strength", "low")
    if signal_strength:
        base["signal_strength"] = signal_strength

    signal_repeatability = _strongest_signal_value(group, "signal_repeatability", "unknown")
    if signal_repeatability:
        base["signal_repeatability"] = signal_repeatability

    tech_items: List[Any] = []
    exposed_items: List[Any] = []

    for sig in group:
        tech_items.extend(sig.get("technology_fingerprint") or [])
        exposed_items.extend(sig.get("exposed_information") or [])

    if tech_items:
        base["technology_fingerprint"] = _merge_unique_list(tech_items)

    if exposed_items:
        base["exposed_information"] = _merge_unique_list(exposed_items)

    return base


def _build_candidate(
    signal: Dict[str, Any],
    request_meta: Dict[str, Any],
    status_code: int | None,
) -> Dict[str, Any]:
    evidence = dict(signal.get("evidence") or {})
    if not evidence.get("final_url"):
        evidence["final_url"] = request_meta.get("url")

    candidate = {
        "type": signal["finding_type"],
        "cwe": signal.get("cwe"),
        "owasp": signal.get("owasp") or "A05:2021 Security Misconfiguration",
        "title": signal.get("title") or signal["finding_type"],
        "severity": signal.get("severity") or "Info",
        "confidence": float(signal.get("confidence") or 0.5),
        "where": signal.get("where") or "response.body",
        "status_code": status_code,
        "trigger": request_meta,
        "match": signal.get("signal_type") or "http_signal",
        "leak_type": signal.get("leak_type") or "http_signal",
        "leak_value": _truncate_text(signal.get("leak_value")),
        "evidence": evidence,
        "why_it_matters": signal.get("why_it_matters") or "",
        "recommendation": signal.get("recommendation") or [],
        "exposed_information": signal.get("exposed_information") or [],
    }

    passthrough = [
        "family",
        "subtype",
        "scope_hint",
        "policy_object",
        "root_cause_signature",
        "technology_fingerprint",
        "template_fingerprint",
        "classification_kind",
        "burp_zap_aligned",
        "signal_strength",
        "signal_repeatability",
        "observation_scope",
        "verification_strategy",
        "signal_type",
        "classification_source",
        "cwe_source",
        "severity_source",
        "exposure_context",
        "cwe_mapping_status",
        "cwe_mapping_reason",
    ]

    for field in passthrough:
        if signal.get(field) is not None:
            candidate[field] = signal[field]

    if candidate.get("cwe") is None and not candidate.get("cwe_mapping_status"):
        candidate["cwe_mapping_status"] = OWASP_ONLY_NO_CWE_MAPPING
        candidate["cwe_mapping_reason"] = OWASP_ONLY_NO_CWE_REASON

    return ensure_type_cwe_consistency(candidate)

def generate_candidates(
    request_meta: Dict[str, Any],
    snapshot: Dict[str, Any],
    feats: Dict[str, Any],
) -> List[Dict[str, Any]]:
    signals = collect_http_signals(
        request_meta=request_meta,
        snapshot=snapshot,
        feats=feats,
    )

    status_code = feats.get("status_code") or snapshot.get("status_code")
    if not signals:
        return []

    grouped = _group_signals(signals)

    candidates: List[Dict[str, Any]] = []
    for group in grouped.values():
        merged_signal = _merge_signal_group(group)
        candidate = _build_candidate(merged_signal, request_meta, status_code)
        candidates.append(candidate)

    return candidates
