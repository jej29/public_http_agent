from __future__ import annotations

import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional

try:
    from openai import OpenAI
except Exception:  # pragma: no cover
    OpenAI = None  # type: ignore


OWASP_ONLY_NO_CWE_MAPPING = "OWASP_ONLY_NO_CWE_MAPPING"

ALLOWED_PRIMARY_CWES = {
    "CWE-209",
    "CWE-497",
    "CWE-548",
    "CWE-552",
    "CWE-942",
    "CWE-1004",
    "CWE-614",
    "CWE-319",
    "CWE-200",
    "CWE-532",
    "CWE-601",
    None,
}

_DEFAULT_CONTEXT_WINDOW = int(os.getenv("OPENAI_CONTEXT_WINDOW", "32768"))
_DEFAULT_MIN_COMPLETION = int(os.getenv("OPENAI_MIN_COMPLETION_TOKENS", "256"))

_DEFAULT_JUDGE_COMPLETION_CAP = int(os.getenv("OPENAI_JUDGE_MAX_TOKENS", "1536"))
_DEFAULT_NORMALIZE_COMPLETION_CAP = int(os.getenv("OPENAI_NORMALIZE_MAX_TOKENS", "768"))
_DEFAULT_PLANNER_COMPLETION_CAP = int(os.getenv("OPENAI_PLANNER_MAX_TOKENS", "2048"))
_DEFAULT_REPORT_COMPLETION_CAP = int(os.getenv("OPENAI_REPORT_MAX_TOKENS", "1200"))
_DEFAULT_RETRY_COMPLETION_CAP = int(os.getenv("OPENAI_RETRY_MAX_TOKENS", "3072"))


# ---------------------------------------------------------------------
# generic helpers
# ---------------------------------------------------------------------
def _estimate_text_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, len(text) // 4)


def _estimate_messages_tokens(messages: List[Dict[str, Any]]) -> int:
    total = 0
    for msg in messages:
        total += 12
        total += _estimate_text_tokens(str(msg.get("content") or ""))
    return total


def _message_content_to_text(content: Any) -> str:
    if content is None:
        return ""

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts: List[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
                continue

            if isinstance(item, dict):
                if item.get("type") in {"output_text", "text"} and item.get("text"):
                    parts.append(str(item["text"]))
                    continue

                text_val = item.get("text")
                if isinstance(text_val, str):
                    parts.append(text_val)
                    continue
            else:
                parts.append(str(item))

        return "\n".join(x for x in parts if x).strip()

    return str(content).strip()


def _extract_response_text(resp: Any) -> str:
    try:
        choice0 = resp.choices[0]
    except Exception:
        return ""

    message = getattr(choice0, "message", None)
    if message is None:
        return ""

    return _message_content_to_text(getattr(message, "content", None)).strip()


def _safe_model_dump(resp: Any) -> str:
    try:
        if hasattr(resp, "model_dump_json"):
            return resp.model_dump_json(indent=2)[:4000]
        if hasattr(resp, "model_dump"):
            return json.dumps(resp.model_dump(), ensure_ascii=False, indent=2)[:4000]
        return str(resp)[:4000]
    except Exception as e:
        return f"<failed to dump response: {type(e).__name__}: {e}>"


def _debug_response_meta(resp: Any) -> str:
    try:
        choice0 = resp.choices[0]
    except Exception:
        return "no choices[0]"

    finish_reason = getattr(choice0, "finish_reason", None)
    message = getattr(choice0, "message", None)

    if message is None:
        return f"finish_reason={finish_reason}, message=None"

    content = getattr(message, "content", None)
    refusal = getattr(message, "refusal", None)
    reasoning_content = getattr(message, "reasoning_content", None)

    return (
        f"finish_reason={finish_reason}, "
        f"content_type={type(content).__name__}, "
        f"content_preview={repr(content)[:500]}, "
        f"reasoning_preview={repr(reasoning_content)[:500]}, "
        f"refusal={repr(refusal)[:200]}"
    )


def _should_retry_for_empty_final(resp: Any) -> bool:
    try:
        choice0 = resp.choices[0]
    except Exception:
        return False

    finish_reason = getattr(choice0, "finish_reason", None)
    message = getattr(choice0, "message", None)
    content = getattr(message, "content", None) if message is not None else None
    return finish_reason == "length" and not _message_content_to_text(content)


def _safe_completion_tokens(
    messages: List[Dict[str, Any]],
    *,
    context_window: int = _DEFAULT_CONTEXT_WINDOW,
    reserve_tokens: int = 1024,
    min_completion_tokens: int = _DEFAULT_MIN_COMPLETION,
    max_completion_tokens: int = _DEFAULT_JUDGE_COMPLETION_CAP,
) -> int:
    prompt_tokens = _estimate_messages_tokens(messages)
    remaining = context_window - prompt_tokens - reserve_tokens

    if remaining <= 0:
        return min_completion_tokens
    if remaining < min_completion_tokens:
        return min_completion_tokens
    return min(remaining, max_completion_tokens)


def _truncate_text(text: str, max_chars: int) -> str:
    if not text:
        return ""
    return text[:max_chars] if len(text) > max_chars else text


def _dedup_str_list(items: List[Any], limit: Optional[int] = None) -> List[str]:
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


# ---------------------------------------------------------------------
# OpenAI client / completion
# ---------------------------------------------------------------------
def build_client() -> OpenAI:
    if OpenAI is None:
        raise RuntimeError("openai package is not available")

    os.environ["OPENAI_API_KEY"] = "dummy"

    base_url = (os.getenv("OPENAI_BASE_URL") or "").strip()
    credential_key = (os.getenv("OPENAI_CREDENTIAL_KEY") or "").strip().strip('"').strip("'")
    system_name = (os.getenv("OPENAI_SYSTEM_NAME") or "playground").strip()
    user_id = (os.getenv("OPENAI_USER_ID") or "").strip()
    user_type = (os.getenv("OPENAI_USER_TYPE") or "").strip()

    if not base_url:
        raise RuntimeError("OPENAI_BASE_URL is not set.")
    if not credential_key:
        raise RuntimeError("OPENAI_CREDENTIAL_KEY is not set.")

    default_headers = {
        "x-dep-ticket": credential_key,
        "Send-System-Name": system_name,
        "User-Id": user_id,
        "User-Type": user_type,
        "Prompt-Msg-Id": str(uuid.uuid4()),
        "Completion-Msg-Id": str(uuid.uuid4()),
    }

    return OpenAI(
        base_url=base_url,
        default_headers=default_headers,
    )


def _create_chat_completion(
    *,
    client: OpenAI,
    model: str,
    messages: List[Dict[str, Any]],
    temperature: float,
    max_completion_tokens: Optional[int] = None,
    reasoning_effort: str = "medium",
) -> Any:
    safe_messages: List[Dict[str, Any]] = []
    for msg in messages:
        safe_messages.append(
            {
                "role": msg["role"],
                "content": _truncate_text(str(msg.get("content") or ""), 24000),
            }
        )

    max_tokens = _safe_completion_tokens(
        safe_messages,
        max_completion_tokens=max_completion_tokens or _DEFAULT_JUDGE_COMPLETION_CAP,
    )

    return client.chat.completions.create(
        model=model,
        messages=safe_messages,
        temperature=temperature,
        max_tokens=max_tokens,
        extra_body={"reasoning_effort": reasoning_effort},
    )


# ---------------------------------------------------------------------
# JSON parsing helpers
# ---------------------------------------------------------------------
def _extract_string_field(text: str, field_name: str) -> Optional[str]:
    m = re.search(
        rf'"{re.escape(field_name)}"\s*:\s*"((?:[^"\\]|\\.)*)"',
        text,
        re.DOTALL,
    )
    if not m:
        return None
    try:
        return json.loads(f'"{m.group(1)}"')
    except Exception:
        return m.group(1)


def _extract_nullable_string_field(text: str, field_name: str) -> Optional[str]:
    if re.search(rf'"{re.escape(field_name)}"\s*:\s*null', text):
        return None
    return _extract_string_field(text, field_name)


def _extract_string_list_field(text: str, field_name: str) -> Optional[List[str]]:
    m = re.search(
        rf'"{re.escape(field_name)}"\s*:\s*\[(.*?)\]',
        text,
        re.DOTALL,
    )
    if not m:
        return None

    inner = m.group(1)
    values = re.findall(r'"((?:[^"\\]|\\.)*)"', inner, re.DOTALL)

    out: List[str] = []
    for v in values:
        try:
            out.append(json.loads(f'"{v}"'))
        except Exception:
            out.append(v)
    return out


def _coerce_partial_judgement_json(text: str) -> Optional[Dict[str, Any]]:
    verdict = _extract_string_field(text, "verdict")
    cwe = _extract_nullable_string_field(text, "cwe")
    title = _extract_string_field(text, "title")
    severity = _extract_string_field(text, "severity")
    reason = _extract_string_field(text, "reason")
    exposed_information = _extract_string_list_field(text, "exposed_information") or []

    if not any([verdict, title, severity, cwe is not None, exposed_information]):
        return None

    return {
        "verdict": verdict or "INCONCLUSIVE",
        "cwe": cwe,
        "additional_cwe_candidate": _extract_nullable_string_field(text, "additional_cwe_candidate"),
        "additional_cwe_reason": _extract_nullable_string_field(text, "additional_cwe_reason"),
        "cwe_mapping_status": _extract_nullable_string_field(text, "cwe_mapping_status"),
        "cwe_mapping_reason": _extract_nullable_string_field(text, "cwe_mapping_reason"),
        "title": title or "Finding",
        "severity": severity or "Low",
        "exposed_information": exposed_information,
        "reason": reason or "LLM response was truncated before full JSON completed.",
        "safe_verification_requests": [],
    }


def _extract_json(text: str) -> Dict[str, Any]:
    if not text:
        raise ValueError("Empty LLM response")

    text = text.strip()

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if m:
        payload = m.group(1).strip()
        try:
            data = json.loads(payload)
            if isinstance(data, dict):
                return data
        except Exception:
            pass

    start = text.find("{")
    if start == -1:
        raise ValueError(f"Could not extract JSON from LLM response: {text[:400]}")

    depth = 0
    in_string = False
    escape = False

    for i in range(start, len(text)):
        ch = text[i]

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                payload = text[start:i + 1]
                try:
                    data = json.loads(payload)
                    if isinstance(data, dict):
                        return data
                except Exception:
                    break

    partial = _coerce_partial_judgement_json(text)
    if partial is not None:
        return partial

    raise ValueError(f"Could not extract JSON from LLM response: {text[:400]}")


def _extract_json_array(text: str) -> List[Dict[str, Any]]:
    if not text:
        raise ValueError("Empty LLM response")

    text = text.strip()

    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
    except Exception:
        pass

    fenced_matches = re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", text, flags=re.IGNORECASE)
    for block in fenced_matches:
        try:
            data = json.loads(block)
            if isinstance(data, list):
                return data
        except Exception:
            continue

    candidates = re.findall(r"\[[\s\S]*\]", text)
    for candidate in candidates:
        try:
            data = json.loads(candidate)
            if isinstance(data, list):
                return data
        except Exception:
            continue

    start = text.find("[")
    end = text.rfind("]")
    if start != -1 and end != -1 and end > start:
        snippet = text[start:end + 1]
        try:
            data = json.loads(snippet)
            if isinstance(data, list):
                return data
        except Exception:
            pass

    raise ValueError(f"Could not extract JSON array from LLM response: {text[:300]}")


# ---------------------------------------------------------------------
# candidate / snapshot compaction
# ---------------------------------------------------------------------
def _compact_headers_for_llm(headers: Dict[str, Any], allowlist: Optional[set[str]] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    allow = {x.lower() for x in (allowlist or set())}

    for k, v in (headers or {}).items():
        key = str(k).lower().strip()
        if allow and key not in allow:
            continue

        if isinstance(v, list):
            vals = _dedup_str_list(v, limit=3)
            if vals:
                out[key] = vals
        else:
            sval = str(v or "").strip()
            if sval:
                out[key] = sval[:300]

    return out


def _compact_candidate_for_llm(candidate: Dict[str, Any]) -> Dict[str, Any]:
    evidence = candidate.get("evidence") or {}

    compact_evidence = {
        "final_url": evidence.get("final_url"),
        "status_code": candidate.get("status_code") or evidence.get("status_code"),
        "response_kind": evidence.get("response_kind"),
        "default_error_hint": evidence.get("default_error_hint"),
        "error_exposure_class": evidence.get("error_exposure_class"),
        "body_content_type_hint": evidence.get("body_content_type_hint"),
        "location": evidence.get("location"),
        "acao": evidence.get("acao"),
        "acac": evidence.get("acac"),
        "banner_headers": _compact_headers_for_llm(
            evidence.get("banner_headers") or {},
            allowlist={"server", "x-powered-by", "via", "x-aspnet-version", "x-aspnetmvc-version"},
        ),
        "strong_version_tokens_in_body": _dedup_str_list(evidence.get("strong_version_tokens_in_body") or [], limit=6),
        "header_version_tokens": _dedup_str_list(evidence.get("header_version_tokens") or [], limit=6),
        "stack_traces": _dedup_str_list(evidence.get("stack_traces") or [], limit=3),
        "file_paths": _dedup_str_list(evidence.get("file_paths") or [], limit=4),
        "db_errors": _dedup_str_list(evidence.get("db_errors") or [], limit=3),
        "internal_ips": _dedup_str_list(evidence.get("internal_ips") or [], limit=4),
        "debug_hints": _dedup_str_list(evidence.get("debug_hints") or [], limit=4),
        "framework_hints": _dedup_str_list(evidence.get("framework_hints") or [], limit=4),
        "default_file_hints": _dedup_str_list(evidence.get("default_file_hints") or [], limit=4),
        "directory_listing_hints": _dedup_str_list(evidence.get("directory_listing_hints") or [], limit=4),
        "phpinfo_indicators": _dedup_str_list(evidence.get("phpinfo_indicators") or [], limit=4),
        "config_exposure_markers": _dedup_str_list(evidence.get("config_exposure_markers") or [], limit=6),
        "log_exposure_patterns": _dedup_str_list(evidence.get("log_exposure_patterns") or [], limit=4),
        "query_param_names": _dedup_str_list(evidence.get("query_param_names") or [], limit=8),
        "file_path_parameter_names": _dedup_str_list(evidence.get("file_path_parameter_names") or [], limit=8),
        "redirect_parameter_names": _dedup_str_list(evidence.get("redirect_parameter_names") or [], limit=8),
        "allowed_methods": _dedup_str_list(evidence.get("allowed_methods") or [], limit=10),
        "risky_methods_enabled": _dedup_str_list(evidence.get("risky_methods_enabled") or [], limit=10),
        "reasons": _dedup_str_list(evidence.get("reasons") or [], limit=10),
    }

    compact = {
        "type": candidate.get("type"),
        "title": candidate.get("title"),
        "severity": candidate.get("severity"),
        "confidence": candidate.get("confidence"),
        "cwe": candidate.get("cwe"),
        "cwe_mapping_status": candidate.get("cwe_mapping_status"),
        "family": candidate.get("family"),
        "subtype": candidate.get("subtype"),
        "scope_hint": candidate.get("scope_hint"),
        "policy_object": candidate.get("policy_object"),
        "root_cause_signature": candidate.get("root_cause_signature"),
        "template_fingerprint": candidate.get("template_fingerprint"),
        "where": candidate.get("where"),
        "signal_strength": candidate.get("signal_strength"),
        "signal_repeatability": candidate.get("signal_repeatability"),
        "observation_scope": candidate.get("observation_scope"),
        "verification_strategy": candidate.get("verification_strategy"),
        "technology_fingerprint": _dedup_str_list(candidate.get("technology_fingerprint") or [], limit=8),
        "exposed_information": _dedup_str_list(candidate.get("exposed_information") or [], limit=6),
        "evidence": {k: v for k, v in compact_evidence.items() if v not in (None, "", [], {})},
    }
    return {k: v for k, v in compact.items() if v not in (None, "", [], {})}


def _compact_snapshot_for_llm(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    headers = snapshot.get("headers") or {}
    redirect_chain = snapshot.get("redirect_chain") or []

    compact_redirect_chain = []
    for item in redirect_chain[:5]:
        compact_redirect_chain.append(
            {
                "url": str(item.get("url") or "")[:300],
                "status_code": item.get("status_code"),
                "headers": _compact_headers_for_llm(
                    item.get("headers") or {},
                    allowlist={"location", "server", "x-powered-by", "content-type"},
                ),
            }
        )

    body_snippet = str(snapshot.get("body_snippet") or "")[:2500]

    return {
        "status_code": snapshot.get("status_code"),
        "final_url": snapshot.get("final_url"),
        "headers": _compact_headers_for_llm(
            headers,
            allowlist={
                "content-type",
                "location",
                "server",
                "x-powered-by",
                "via",
                "x-aspnet-version",
                "x-aspnetmvc-version",
                "access-control-allow-origin",
                "access-control-allow-credentials",
                "access-control-allow-methods",
                "access-control-allow-headers",
                "vary",
                "allow",
                "set-cookie",
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
            },
        ),
        "body_snippet": body_snippet,
        "redirect_chain": compact_redirect_chain,
    }


# ---------------------------------------------------------------------
# post-process
# ---------------------------------------------------------------------
def _normalize_primary_cwe(candidate_type: str, cwe: Any, candidate: Dict[str, Any]) -> Any:
    if cwe in ALLOWED_PRIMARY_CWES:
        return cwe

    if candidate_type in {
        "CLICKJACKING",
        "CSP_MISSING",
        "CONTENT_TYPE_SNIFFING",
        "REFERRER_POLICY_MISSING",
        "PERMISSIONS_POLICY_MISSING",
        "COOKIE_SAMESITE_MISSING",
        "TRACE_ENABLED",
        "RISKY_HTTP_METHODS_ENABLED",
    }:
        return None

    fallback = candidate.get("cwe")
    if fallback in ALLOWED_PRIMARY_CWES:
        return fallback

    return None


def _postprocess_judgement(candidate: Dict[str, Any], judged: Dict[str, Any]) -> Dict[str, Any]:
    candidate_type = candidate.get("type")

    verdict = judged.get("verdict")
    if verdict not in {"CONFIRMED", "INCONCLUSIVE", "FALSE_POSITIVE"}:
        judged["verdict"] = "INCONCLUSIVE"

    severity = judged.get("severity")
    if severity not in {"Info", "Low", "Medium", "High"}:
        judged["severity"] = candidate.get("severity") or "Low"

    judged["cwe"] = _normalize_primary_cwe(candidate_type, judged.get("cwe"), candidate)

    if judged.get("cwe") is None and candidate_type in {
        "CLICKJACKING",
        "CSP_MISSING",
        "CONTENT_TYPE_SNIFFING",
        "REFERRER_POLICY_MISSING",
        "PERMISSIONS_POLICY_MISSING",
        "COOKIE_SAMESITE_MISSING",
        "TRACE_ENABLED",
        "RISKY_HTTP_METHODS_ENABLED",
    }:
        judged["cwe_mapping_status"] = OWASP_ONLY_NO_CWE_MAPPING
        judged["cwe_mapping_reason"] = (
            "OWASP category is applicable, but no precise single CWE mapping is used for this finding."
        )

    if not isinstance(judged.get("exposed_information"), list):
        judged["exposed_information"] = candidate.get("exposed_information") or []

    if not isinstance(judged.get("safe_verification_requests"), list):
        judged["safe_verification_requests"] = []

    if not judged.get("title"):
        judged["title"] = candidate.get("title") or candidate_type or "Finding"

    if not judged.get("reason"):
        judged["reason"] = "The evidence was reviewed, but the explanation was missing."

    return judged


# ---------------------------------------------------------------------
# fallback semantic judge
# ---------------------------------------------------------------------
def _fallback_judge_candidate(candidate: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
    ctype = str(candidate.get("type") or "")
    evidence = candidate.get("evidence") or {}
    body = str(snapshot.get("body_snippet") or "").lower()

    if ctype == "HTTP_ERROR_INFO_EXPOSURE":
        if evidence.get("stack_traces") or evidence.get("db_errors") or evidence.get("file_paths"):
            return {
                "verdict": "CONFIRMED",
                "severity": "Medium",
                "title": candidate.get("title"),
                "cwe": "CWE-209",
                "exposed_information": candidate.get("exposed_information") or [],
                "reason": "Concrete error disclosure evidence was observed.",
                "safe_verification_requests": [],
            }

    if ctype == "HTTP_SYSTEM_INFO_EXPOSURE":
        if evidence.get("banner_headers") or evidence.get("strong_version_tokens_in_body"):
            return {
                "verdict": "CONFIRMED",
                "severity": candidate.get("severity") or "Low",
                "title": candidate.get("title"),
                "cwe": "CWE-497",
                "exposed_information": candidate.get("exposed_information") or [],
                "reason": "Concrete server/product identification signal was observed.",
                "safe_verification_requests": [],
            }
        return {
            "verdict": "INCONCLUSIVE",
            "severity": "Info",
            "title": candidate.get("title"),
            "cwe": "CWE-497",
            "exposed_information": candidate.get("exposed_information") or [],
            "reason": "Weak system information signal only.",
            "safe_verification_requests": [],
        }

    if ctype == "PHPINFO_EXPOSURE":
        if len(evidence.get("phpinfo_indicators") or []) >= 2 or ("phpinfo()" in body and "php version" in body):
            return {
                "verdict": "CONFIRMED",
                "severity": "Medium",
                "title": candidate.get("title"),
                "cwe": "CWE-200",
                "exposed_information": candidate.get("exposed_information") or [],
                "reason": "phpinfo-like diagnostic page was directly observed.",
                "safe_verification_requests": [],
            }

    if ctype == "HTTP_CONFIG_FILE_EXPOSURE":
        markers = evidence.get("config_exposure_markers") or []
        if markers:
            return {
                "verdict": "CONFIRMED",
                "severity": candidate.get("severity") or "Medium",
                "title": candidate.get("title"),
                "cwe": "CWE-200",
                "exposed_information": candidate.get("exposed_information") or [],
                "reason": "Configuration disclosure markers were directly observed.",
                "safe_verification_requests": [],
            }

    if ctype == "LOG_VIEWER_EXPOSURE":
        if len(evidence.get("log_exposure_patterns") or []) >= 2:
            return {
                "verdict": "CONFIRMED",
                "severity": "Medium",
                "title": candidate.get("title"),
                "cwe": "CWE-532",
                "exposed_information": candidate.get("exposed_information") or [],
                "reason": "Log-like content was directly observed.",
                "safe_verification_requests": [],
            }

    return {
        "verdict": "INCONCLUSIVE",
        "severity": candidate.get("severity") or "Low",
        "title": candidate.get("title"),
        "cwe": candidate.get("cwe"),
        "exposed_information": candidate.get("exposed_information") or [],
        "reason": "Fallback judge could not strengthen or reject the signal confidently.",
        "safe_verification_requests": [],
    }


# ---------------------------------------------------------------------
# public functions
# ---------------------------------------------------------------------
def judge_candidate(candidate: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """
    중요:
    - finding type / subtype / root_cause_signature는 caller가 lock한다.
    - 여기서는 semantic 판별만 수행한다.
    - LLM 실패 시 fallback heuristic으로 내려간다.
    """
    if os.getenv("LLM_MODE", "off").lower() != "on":
        return _fallback_judge_candidate(candidate, snapshot)

    client = build_client()
    model = os.getenv("OPENAI_MODEL", "gpt-oss-120b")

    system = """
You are a senior web application security analyst reviewing HTTP DAST findings.

Your job:
1) Decide whether the candidate is CONFIRMED, INCONCLUSIVE, or FALSE_POSITIVE.
2) Refine title/severity/CWE/exposed_information conservatively.
3) Preserve the original semantic category. Do NOT invent a new finding type.
4) Prefer concrete evidence over generic wording.
5) Use FALSE_POSITIVE only when the observed signal clearly does not support the claimed finding.

Return ONLY JSON:
{
  "verdict": "CONFIRMED|INCONCLUSIVE|FALSE_POSITIVE",
  "cwe": "CWE-xxx or null",
  "additional_cwe_candidate": "optional or null",
  "additional_cwe_reason": "optional or null",
  "cwe_mapping_status": "optional or null",
  "cwe_mapping_reason": "optional or null",
  "title": "refined title",
  "severity": "Info|Low|Medium|High",
  "exposed_information": ["concise concrete items"],
  "reason": "brief explanation",
  "safe_verification_requests": []
}
""".strip()

    user_payload = {
        "candidate": _compact_candidate_for_llm(candidate),
        "evidence": _compact_snapshot_for_llm(snapshot),
    }

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, indent=2)},
    ]

    try:
        resp = _create_chat_completion(
            client=client,
            model=model,
            messages=messages,
            temperature=0.1,
            max_completion_tokens=int(os.getenv("OPENAI_JUDGE_MAX_COMPLETION_TOKENS", "3072")),
            reasoning_effort=os.getenv("OPENAI_JUDGE_REASONING_EFFORT", "medium"),
        )

        if _should_retry_for_empty_final(resp):
            resp = _create_chat_completion(
                client=client,
                model=model,
                messages=messages,
                temperature=0.1,
                max_completion_tokens=_DEFAULT_RETRY_COMPLETION_CAP,
                reasoning_effort="low",
            )

        resp_text = _extract_response_text(resp)
        if not resp_text:
            raise ValueError(
                "Empty LLM response. " + _debug_response_meta(resp) + " | raw=" + _safe_model_dump(resp)
            )

        judged = _extract_json(resp_text)
        return _postprocess_judgement(candidate, judged)
    except Exception:
        return _fallback_judge_candidate(candidate, snapshot)


def normalize_exposure_with_llm(
    raw_exposed_information: List[str],
    severity: Optional[str],
    title: Optional[str],
) -> Dict[str, Any]:
    if os.getenv("LLM_MODE", "off").lower() != "on":
        return {
            "exposed_information_normalized": _dedup_str_list(raw_exposed_information, limit=5),
            "severity_reason": [],
        }

    client = build_client()
    model = os.getenv("OPENAI_MODEL", "gpt-oss-120b")

    system = """
You normalize raw finding details into concise, deduplicated reporting phrases.

Rules:
- Keep only concrete and user-meaningful items.
- Remove duplicates and weak near-duplicates.
- Prefer short reporting phrases.

Return ONLY JSON:
{
  "exposed_information_normalized": ["..."],
  "severity_reason": ["..."]
}
""".strip()

    user_payload = {
        "raw_exposed_information": raw_exposed_information,
        "severity": severity,
        "title": title,
    }

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, indent=2)},
    ]

    try:
        resp = _create_chat_completion(
            client=client,
            model=model,
            messages=messages,
            temperature=0.0,
            max_completion_tokens=_DEFAULT_NORMALIZE_COMPLETION_CAP,
            reasoning_effort="low",
        )

        if _should_retry_for_empty_final(resp):
            resp = _create_chat_completion(
                client=client,
                model=model,
                messages=messages,
                temperature=0.0,
                max_completion_tokens=_DEFAULT_RETRY_COMPLETION_CAP,
                reasoning_effort="low",
            )

        resp_text = _extract_response_text(resp)
        if not resp_text:
            raise ValueError(
                "Empty LLM response. " + _debug_response_meta(resp) + " | raw=" + _safe_model_dump(resp)
            )

        data = _extract_json(resp_text)

        normalized = data.get("exposed_information_normalized")
        if not isinstance(normalized, list):
            normalized = raw_exposed_information or []

        severity_reason = data.get("severity_reason")
        if not isinstance(severity_reason, list):
            severity_reason = []

        return {
            "exposed_information_normalized": [str(x).strip() for x in normalized if str(x).strip()][:5],
            "severity_reason": [str(x).strip() for x in severity_reason if str(x).strip()][:5],
        }
    except Exception:
        return {
            "exposed_information_normalized": _dedup_str_list(raw_exposed_information, limit=5),
            "severity_reason": [],
        }

def _fallback_additional_probes(target: str, observation_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    target = (target or "").rstrip("/")
    endpoints = observation_summary.get("high_value_endpoints_sample") or observation_summary.get("discovered_endpoints_sample") or []
    attempted = {
        str(x).strip()
        for x in (observation_summary.get("attempted_probe_keys") or [])
        if str(x).strip()
    }

    probes: List[Dict[str, Any]] = []

    def already(method: str, path_or_url: str) -> bool:
        if str(path_or_url).startswith(("http://", "https://")):
            key = f"{method.upper()} {path_or_url.strip()}"
        else:
            key = f"{method.upper()} {target}{path_or_url if str(path_or_url).startswith('/') else '/' + str(path_or_url)}"
        return key in attempted

    def add_probe(
        name: str,
        method: str,
        path_or_url: str,
        family: str,
        reason: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        if already(method, path_or_url):
            return
        probes.append(
            {
                "name": name,
                "method": method,
                "path_or_url": path_or_url,
                "headers": headers or {},
                "body": None,
                "origin": None,
                "probe": None,
                "trace_marker": None,
                "family": family,
                "reason": reason,
            }
        )

    common_sensitive_paths = [
        "/.env",
        "/.env.local",
        "/.git/HEAD",
        "/.git/config",
        "/backup.zip",
        "/config.php.bak",
        "/config.bak",
        "/config.old",
        "/config.dist",
        "/application.yml",
        "/application.yaml",
        "/application.properties",
        "/appsettings.json",
        "/server-status",
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/debug",
        "/debug/default/view",
        "/phpinfo.php",
    ]

    for path in common_sensitive_paths:
        add_probe(
            name=f"llm_fallback_resource_{path.strip('/').replace('/', '_').replace('.', '_') or 'root'}",
            method="GET",
            path_or_url=path,
            family="default_resource",
            reason="Fallback planner: check common sensitive/config/debug/default resource.",
        )

    for ep in endpoints[:8]:
        url = str(ep.get("url") or "").strip()
        if not url:
            continue

        qps = [str(x).strip() for x in (ep.get("query_param_names") or []) if str(x).strip()]
        endpoint_signals = ep.get("endpoint_signals") or {}
        related_keys = {str(x).strip().lower() for x in (endpoint_signals.get("related_config_key_classes") or [])}

        if qps:
            for qp in qps[:4]:
                qp_l = qp.lower()
                if qp_l in {"file", "path", "page", "template", "include", "doc", "document", "folder"}:
                    add_probe(
                        name=f"llm_fallback_param_{qp_l}_config",
                        method="GET",
                        path_or_url=f"{url}?{qp}=config.php",
                        family="query_param",
                        reason="Fallback planner: file/path style parameter may disclose config/debug content.",
                    )
                    add_probe(
                        name=f"llm_fallback_param_{qp_l}_env",
                        method="GET",
                        path_or_url=f"{url}?{qp}=.env",
                        family="query_param",
                        reason="Fallback planner: file/path style parameter may disclose environment file content.",
                    )
                elif qp_l in {"debug", "test", "verbose", "env", "mode"}:
                    add_probe(
                        name=f"llm_fallback_param_{qp_l}_1",
                        method="GET",
                        path_or_url=f"{url}?{qp}=1",
                        family="query_param",
                        reason="Fallback planner: debug-like parameter may trigger verbose behavior.",
                    )
                    add_probe(
                        name=f"llm_fallback_param_{qp_l}_true",
                        method="GET",
                        path_or_url=f"{url}?{qp}=true",
                        family="query_param",
                        reason="Fallback planner: debug-like parameter may trigger verbose behavior.",
                    )

        if related_keys.intersection({"db_password", "connection_string", "api_key", "secret", "token"}):
            add_probe(
                name="llm_fallback_head_followup",
                method="HEAD",
                path_or_url=url,
                family="header_behavior",
                reason="Fallback planner: follow-up HEAD probe on endpoint with sensitive config-like context.",
            )

        add_probe(
            name="llm_fallback_options_followup",
            method="OPTIONS",
            path_or_url=url,
            family="method_behavior",
            reason="Fallback planner: observe allowed methods on high-value endpoint.",
        )

        add_probe(
            name="llm_fallback_cors_followup",
            method="GET",
            path_or_url=url,
            family="cors_behavior",
            reason="Fallback planner: observe ACAO reflection on high-value endpoint.",
            headers={"Origin": "https://planner-fallback.attacker.test"},
        )

    return probes[:16]


def plan_additional_probes(target: str, observation_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    if os.getenv("LLM_MODE", "off").lower() != "on":
        return _fallback_additional_probes(target, observation_summary)

    client = build_client()
    model = os.getenv("OPENAI_MODEL", "gpt-oss-120b")

    system = """
You are helping an HTTP DAST scanner generate additional SAFE, NON-DESTRUCTIVE HTTP probes.

Your job is NOT to declare vulnerabilities.
Your job is to propose NOVEL follow-up probes that increase coverage and help reveal existing issues.

Critical goals:
1. Propose only probes that were NOT already attempted.
2. Prefer high-value adaptive probes for:
   - config / environment / backup / debug / default resource discovery
   - parameter-aware mutations on discovered dynamic routes
   - file/path/template/include style parameter testing
   - benign debug / verbose / env / mode toggles
   - CORS checks on dynamic routes
   - method observation on high-value routes
3. Prefer discovered routes over root-only guesses.
4. Use the provided findings, suspicious paths, endpoint signals, and recent request patterns.
5. Keep probes safe and read-only.
6. Prefer a diverse set of probe families rather than near-duplicates.

Important planning guidance:
- If endpoint signals or findings suggest config exposure, generate more config-like resource checks.
- If query parameters look like file/path/page/include/template/document, generate benign file/path-style mutations.
- If an endpoint or finding suggests debug/framework/error behavior, generate debug-oriented benign mutations.
- If a route is authenticated-only or high-value, OPTIONS/CORS/HEAD follow-ups may be useful.
- When config/debug/default-resource signals exist, propose follow-up probes around the same route and sibling paths.
- Prefer specific, realistic checks such as:
  /.env
  /.git/config
  /config.php.bak
  /application.yml
  /actuator/env
  ?file=.env
  ?path=config.php
  ?template=config.php
  ?debug=1
  ?verbose=true

Allowed probe families:
- default_resource
- query_param
- path_mutation
- cors_behavior
- method_behavior
- header_behavior
- directory_behavior

Allowed methods:
- GET
- HEAD
- OPTIONS
- TRACE

Do NOT propose:
- brute force
- state-changing or destructive payloads
- exploit payloads
- login attempts
- repeated baseline probes
- obvious duplicates

Return ONLY a JSON array.

Each item must follow this schema:
{
  "name": "short_probe_name",
  "method": "GET|HEAD|OPTIONS|TRACE",
  "path_or_url": "/relative/path/or/full/url",
  "headers": {"optional":"headers"},
  "body": null,
  "origin": null,
  "probe": null,
  "trace_marker": null,
  "family": "short_family_name",
  "reason": "why this probe adds NEW coverage"
}
""".strip()

    compact_observation_summary = {
        "target": observation_summary.get("target"),
        "planner_goal": observation_summary.get("planner_goal"),
        "stats": observation_summary.get("stats") or {},
        "confirmed_types": _dedup_str_list(observation_summary.get("confirmed_types") or [], limit=14),
        "informational_types": _dedup_str_list(observation_summary.get("informational_types") or [], limit=14),
        "confirmed_findings_sample": (observation_summary.get("confirmed_findings_sample") or [])[:16],
        "informational_findings_sample": (observation_summary.get("informational_findings_sample") or [])[:16],
        "high_value_endpoints_sample": (observation_summary.get("high_value_endpoints_sample") or [])[:14],
        "discovered_endpoints_sample": (observation_summary.get("discovered_endpoints_sample") or [])[:14],
        "recent_suspicious_paths": (observation_summary.get("recent_suspicious_paths") or [])[:16],
        "recent_requests_sample": (observation_summary.get("recent_requests_sample") or [])[-60:],
        "attempted_probe_keys": _dedup_str_list(observation_summary.get("attempted_probe_keys") or [], limit=120),
        "path_status_summary": observation_summary.get("path_status_summary") or {},
        "instructions": observation_summary.get("instructions") or {},
    }

    user_payload = {
        "target": target,
        "observation_summary": compact_observation_summary,
    }

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, indent=2)},
    ]

    try:
        resp = _create_chat_completion(
            client=client,
            model=model,
            messages=messages,
            temperature=0.2,
            max_completion_tokens=_DEFAULT_PLANNER_COMPLETION_CAP,
            reasoning_effort="low",
        )

        if _should_retry_for_empty_final(resp):
            resp = _create_chat_completion(
                client=client,
                model=model,
                messages=messages,
                temperature=0.1,
                max_completion_tokens=_DEFAULT_RETRY_COMPLETION_CAP,
                reasoning_effort="low",
            )

        resp_text = _extract_response_text(resp)
        if not resp_text:
            return _fallback_additional_probes(target, observation_summary)

        probes = _extract_json_array(resp_text)

        normalized: List[Dict[str, Any]] = []
        for item in probes:
            if not isinstance(item, dict):
                continue

            method = str(item.get("method") or "GET").upper()
            if method not in {"GET", "HEAD", "OPTIONS", "TRACE", "PUT", "DELETE", "PATCH", "PROPFIND", "SEARCH", "BREW", "FOO"}:
                method = "GET"

            normalized.append(
                {
                    "name": item.get("name") or "llm_probe",
                    "method": method,
                    "path_or_url": item.get("path_or_url") or "/",
                    "headers": item.get("headers") or {},
                    "body": item.get("body"),
                    "origin": item.get("origin"),
                    "probe": item.get("probe"),
                    "trace_marker": item.get("trace_marker"),
                    "family": item.get("family") or "llm_adaptive",
                    "reason": item.get("reason") or "",
                }
            )

        return normalized or _fallback_additional_probes(target, observation_summary)
    except Exception:
        return _fallback_additional_probes(target, observation_summary)


def generate_llm_report_summary(results: Dict[str, Any]) -> Dict[str, Any]:
    if os.getenv("LLM_MODE", "off").lower() != "on":
        summary = results.get("summary") or {}
        return {
            "executive_summary": (
                f"Confirmed {summary.get('confirmed_count', 0)} findings, "
                f"informational {summary.get('informational_count', 0)}, "
                f"false positive {summary.get('false_positive_count', 0)}."
            ),
            "top_risks": [],
            "priority_actions": [],
        }

    client = build_client()
    model = os.getenv("OPENAI_MODEL", "gpt-oss-120b")

    system = """
You are a senior application security consultant.

Write a concise executive summary from provided DAST scan results.

Return ONLY JSON:
{
  "executive_summary": "short paragraph",
  "top_risks": ["..."],
  "priority_actions": ["..."]
}
""".strip()

    confirmed = results.get("findings_confirmed") or []
    informational = results.get("findings_informational") or []
    summary = results.get("summary") or {}
    metadata = results.get("metadata") or {}

    compact_payload = {
        "metadata": {
            "target": metadata.get("target"),
            "run_id": metadata.get("run_id"),
            "request_count": metadata.get("request_count"),
        },
        "summary": summary,
        "confirmed_findings": [
            {
                "type": f.get("type"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "cwe": f.get("cwe") or f.get("cwe_mapping_status"),
                "family": f.get("family"),
                "subtype": f.get("subtype"),
                "normalized_url": f.get("normalized_url"),
                "scope_hint": f.get("scope_hint"),
            }
            for f in confirmed[:15]
        ],
        "informational_findings": [
            {
                "type": f.get("type"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "family": f.get("family"),
                "subtype": f.get("subtype"),
            }
            for f in informational[:15]
        ],
    }

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(compact_payload, ensure_ascii=False, indent=2)},
    ]

    try:
        resp = _create_chat_completion(
            client=client,
            model=model,
            messages=messages,
            temperature=0.1,
            max_completion_tokens=_DEFAULT_REPORT_COMPLETION_CAP,
            reasoning_effort="low",
        )

        if _should_retry_for_empty_final(resp):
            resp = _create_chat_completion(
                client=client,
                model=model,
                messages=messages,
                temperature=0.1,
                max_completion_tokens=_DEFAULT_RETRY_COMPLETION_CAP,
                reasoning_effort="low",
            )

        resp_text = _extract_response_text(resp)
        if not resp_text:
            raise ValueError(
                "Empty LLM report response. " + _debug_response_meta(resp) + " | raw=" + _safe_model_dump(resp)
            )

        data = _extract_json(resp_text)
        executive_summary = str(data.get("executive_summary") or "").strip()
        top_risks = data.get("top_risks") or []
        priority_actions = data.get("priority_actions") or []

        if not isinstance(top_risks, list):
            top_risks = []
        if not isinstance(priority_actions, list):
            priority_actions = []

        return {
            "executive_summary": executive_summary,
            "top_risks": [str(x).strip() for x in top_risks if str(x).strip()][:5],
            "priority_actions": [str(x).strip() for x in priority_actions if str(x).strip()][:5],
        }
    except Exception:
        return {
            "executive_summary": (
                f"Confirmed {summary.get('confirmed_count', 0)} findings, "
                f"informational {summary.get('informational_count', 0)}, "
                f"false positive {summary.get('false_positive_count', 0)}."
            ),
            "top_risks": [],
            "priority_actions": [],
        }
