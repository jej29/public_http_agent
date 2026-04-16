from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List

import httpx
from agent.runtime.candidate_finalizer import (
    _has_concrete_body_exposure,
    _has_concrete_default_resource_exposure,
    _is_concrete_exposure_type,
    _is_direct_200_exposure,
    _should_downgrade_weak_resource_signal,
)
from agent.candidates import generate_candidates
from agent.analysis.features import extract_features
from agent.method_capability import verify_risky_http_methods_capability
from agent.analysis.verification_policy import should_mark_manual_review, should_skip_reproduce


async def _verify_cors_misconfig_active(
    *,
    client: httpx.AsyncClient,
    candidate: Dict[str, Any],
    timeout_s: float,
) -> Dict[str, Any]:
    candidate = dict(candidate)
    candidate.setdefault("verification", {})
    evidence = dict(candidate.get("evidence") or {})
    final_url = str(
        evidence.get("final_url")
        or (candidate.get("trigger") or {}).get("url")
        or candidate.get("where")
        or ""
    ).strip()

    if not final_url.startswith(("http://", "https://")):
        if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE"}:
            candidate["verification"]["verdict"] = "INFORMATIONAL"
            candidate["verification"]["reason"] = "CORS validation skipped because no concrete URL was available."
        candidate["reproduction_attempts"] = 1
        return candidate

    probe_origin = "https://evil.example"
    attempts = []

    async def _send(kind: str, headers: Dict[str, str]) -> Dict[str, Any]:
        try:
            response = await client.get(
                final_url,
                headers=headers,
                follow_redirects=False,
                timeout=timeout_s,
            )
            return {
                "kind": kind,
                "status_code": response.status_code,
                "acao": response.headers.get("Access-Control-Allow-Origin"),
                "acac": response.headers.get("Access-Control-Allow-Credentials"),
                "vary": response.headers.get("Vary"),
            }
        except Exception as exc:
            return {
                "kind": kind,
                "error": f"{type(exc).__name__}: {exc}",
            }

    attempts.append(await _send("evil_origin", {"Origin": probe_origin}))
    attempts.append(await _send("evil_origin_with_cookie", {"Origin": probe_origin, "Cookie": "oai_test=1"}))

    confirmed = False
    high_risk = False

    for attempt in attempts:
        acao = str(attempt.get("acao") or "").strip()
        acac = str(attempt.get("acac") or "").strip().lower()

        reflected = acao == probe_origin
        wildcard = acao == "*"
        creds_true = acac == "true"

        if (reflected and creds_true) or (wildcard and creds_true):
            confirmed = True
            high_risk = True
            break

        if reflected:
            confirmed = True

    evidence["active_cors_validation"] = attempts
    evidence["active_probe_origin"] = probe_origin
    candidate["evidence"] = evidence

    if confirmed:
        candidate["verification"]["verdict"] = "CONFIRMED"
        if high_risk:
            candidate["verification"]["reason"] = (
                "CORS policy was actively confirmed with attacker-controlled Origin and credentialed cross-origin access characteristics."
            )
            candidate["severity"] = "High"
            candidate["final_severity"] = "High"
        else:
            candidate["verification"]["reason"] = (
                "CORS policy was actively confirmed with attacker-controlled Origin reflection."
            )
            if str(candidate.get("severity") or "") not in {"High"}:
                candidate["severity"] = "Medium"
                candidate["final_severity"] = "Medium"
    else:
        if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE"}:
            candidate["verification"]["verdict"] = "FALSE_POSITIVE"
            candidate["verification"]["reason"] = (
                "Initial CORS signal was not reproduced during active validation with attacker-controlled Origin."
            )

    candidate["reproduction_attempts"] = len(attempts)
    return candidate


async def reproduce_verify(
    *,
    client: httpx.AsyncClient,
    spec: Any,
    timeout_s: float,
    retries: int,
    candidate: Dict[str, Any],
    first_snapshot: Dict[str, Any],
    stable_key_fn,
    scan_profile_fn,
    send_once_fn,
    build_request_meta_fn,
) -> Dict[str, Any] | List[Dict[str, Any]]:
    candidate.setdefault("verification", {})

    profile = scan_profile_fn()
    fast_repro_mode = profile == "fast"
    candidate_type = str(candidate.get("type") or "")

    if candidate_type == "RISKY_HTTP_METHODS_ENABLED":
        verified = await verify_risky_http_methods_capability(
            client=client,
            candidate=candidate,
            timeout_s=timeout_s,
        )
        if isinstance(verified, dict):
            verified["reproduction_attempts"] = max(1, int(verified.get("reproduction_attempts") or 0))
        elif isinstance(verified, list):
            for item in verified:
                if isinstance(item, dict):
                    item["reproduction_attempts"] = max(1, int(item.get("reproduction_attempts") or 0))
        return verified

    if candidate_type == "CORS_MISCONFIG":
        return await _verify_cors_misconfig_active(
            client=client,
            candidate=candidate,
            timeout_s=timeout_s,
        )

    if _is_concrete_exposure_type(candidate_type):
        if _is_direct_200_exposure(first_snapshot) and _has_concrete_body_exposure(candidate):
            candidate["verification"]["verdict"] = "CONFIRMED"
            candidate["verification"]["reason"] = (
                "Concrete diagnostic, configuration, or log exposure was directly observed in a 200 response."
            )
            candidate["reproduction_attempts"] = 1
            return candidate

    if candidate_type == "DEFAULT_FILE_EXPOSED":
        if _is_direct_200_exposure(first_snapshot) and _has_concrete_default_resource_exposure(candidate, first_snapshot):
            candidate["verification"]["verdict"] = "CONFIRMED"
            candidate["verification"]["reason"] = (
                "Direct default or sensitive resource exposure was observed with concrete content markers."
            )
            candidate["reproduction_attempts"] = 1
            return candidate

    if _should_downgrade_weak_resource_signal(candidate, first_snapshot):
        if candidate["verification"].get("verdict") != "FALSE_POSITIVE":
            candidate["verification"]["verdict"] = "INFORMATIONAL"
            candidate["verification"]["reason"] = (
                "Observed path signal was retained as informational, but it did not prove concrete exposure."
            )
        candidate["reproduction_attempts"] = 1
        return candidate

    if should_mark_manual_review(candidate):
        if candidate["verification"].get("verdict") != "FALSE_POSITIVE":
            candidate["verification"]["verdict"] = "INFORMATIONAL"
            candidate["verification"]["reason"] = (
                "Weak or ambiguous signal was retained as informational without reproduce escalation."
            )
        candidate["reproduction_attempts"] = 1
        return candidate

    deterministic_header_types = {
        "CLICKJACKING",
        "HSTS_MISSING",
        "CSP_MISSING",
        "CONTENT_TYPE_SNIFFING",
        "REFERRER_POLICY_MISSING",
        "PERMISSIONS_POLICY_MISSING",
        "COOKIE_HTTPONLY_MISSING",
        "COOKIE_SECURE_MISSING",
        "COOKIE_SAMESITE_MISSING",
    }

    if candidate_type in deterministic_header_types:
        if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE", "INFORMATIONAL"}:
            candidate["verification"]["verdict"] = "CONFIRMED"
            candidate["verification"]["reason"] = (
                "Confirmed from response headers in a deterministic single-response check."
            )
        candidate["reproduction_attempts"] = 1
        return candidate

    if should_skip_reproduce(candidate):
        if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE", "INFORMATIONAL"}:
            candidate["verification"]["verdict"] = "CONFIRMED"
            candidate["verification"]["reason"] = (
                "Confirmed from a deterministic single-response signal; reproduce step skipped."
            )
        candidate["reproduction_attempts"] = 1
        return candidate

    if fast_repro_mode:
        effective_retries = 1
        sleep_s = 0.0
    else:
        effective_retries = max(1, retries)
        sleep_s = float(os.getenv("REPRODUCE_RETRY_SLEEP_SECONDS", "0.2"))

    attempts = [first_snapshot]

    for attempt_index in range(effective_retries):
        if sleep_s > 0:
            await asyncio.sleep(sleep_s * (attempt_index + 1))
        attempts.append(await send_once_fn(client, spec, timeout_s))

    target_key = stable_key_fn(candidate)
    reproduced = False

    for snapshot in attempts[1:]:
        if not snapshot.get("ok"):
            continue

        request_meta = build_request_meta_fn(spec)
        features = extract_features(request_meta, snapshot)
        reproduced_candidates = generate_candidates(request_meta, snapshot, features)

        if any(stable_key_fn(item) == target_key for item in reproduced_candidates):
            reproduced = True
            break

    if candidate["verification"].get("verdict") == "FALSE_POSITIVE":
        return candidate

    if reproduced:
        if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE"}:
            candidate["verification"]["verdict"] = "CONFIRMED"
            candidate["verification"]["reason"] = "Reproduced across repeated requests with stable evidence."
    else:
        if _is_concrete_exposure_type(candidate_type):
            if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE"}:
                candidate["verification"]["verdict"] = "INFORMATIONAL"
                candidate["verification"]["reason"] = (
                    "Concrete exposure markers were observed once, but repeat reproduction was not stable."
                )
        elif fast_repro_mode:
            if candidate["verification"].get("verdict") not in {"CONFIRMED", "FALSE_POSITIVE"}:
                candidate["verification"]["verdict"] = "INFORMATIONAL"
                candidate["verification"]["reason"] = "Not reproduced in fast verification mode."
        else:
            if candidate["verification"].get("verdict") not in {"INFORMATIONAL", "FALSE_POSITIVE", "CONFIRMED"}:
                candidate["verification"]["verdict"] = "FALSE_POSITIVE"
                candidate["verification"]["reason"] = "Not consistently reproduced."

    candidate["reproduction_attempts"] = len(attempts)
    return candidate
