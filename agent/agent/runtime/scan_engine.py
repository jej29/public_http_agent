from __future__ import annotations

import os
import re
import asyncio
import time
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlsplit, urlunsplit, urlencode

import httpx
from agent.candidates import generate_candidates
from agent.analysis.features import extract_features
from agent.runtime.candidate_finalizer import (
    _normalize_method_capability_candidates,
    finalize_without_reproduce,
    try_direct_finalize_candidate,
)
from agent.runtime.candidate_verifier import reproduce_verify
from agent.core.common import log
from agent.findings.store import merge_finding, save_raw_capture, seed_bucket_candidate
from agent.runtime.cookie_diagnostics import raw_index_cookie_observation_fields
from agent.http.http_session import (
    clear_cookie_name_from_client,
    cookie_jar_delta,
    parse_manual_auth_cookie_pairs,
    preferred_cookie_path_for_url,
    sanitize_request_headers_and_cookie_jar,
    snapshot_cookie_jar,
)
from agent.method_capability import verify_risky_http_methods_capability
from agent.core.severity import apply_base_severity_to_candidates, apply_combination_severity
from agent.analysis.validation_policy import validate_candidate_after_llm
from agent.analysis.verification_policy import (
    build_auth_payload_from_form,
    looks_like_login_page,
    parse_login_forms,
    select_login_form,
    should_run_llm_judge,
    should_run_reproduce,
    verify_auth_bypass,
    verify_session_controls,
    verify_session_fixation,
    _authenticated_markers,
)

STATIC_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz",
    ".mp4", ".mp3", ".avi", ".mov",
)

HIGH_VALUE_HTTP_HINTS = (
    "phpinfo",
    "config",
    "compose",
    "log",
    "backup",
    ".env",
    ".git",
    "debug",
    "actuator",
    "admin",
)

FILEISH_PARAM_NAMES = {
    "file", "path", "page", "template", "include", "inc", "doc", "document", "folder"
}

def scan_profile() -> str:
    return (os.getenv("SCAN_PROFILE") or "balanced").strip().lower()


def looks_like_static_asset_url(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(STATIC_EXTS)


def is_baseline_probe(spec: Any) -> bool:
    name = str(getattr(spec, "name", "") or "").lower()
    return name in {"baseline_get", "baseline_head", "baseline_query_session"}


def normalize_planner_inputs(items: List[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in items or []:
        if isinstance(item, dict):
            if item.get("url"):
                out.append(item)
        elif isinstance(item, str):
            out.append({"url": item, "kind": "page"})
    return out

def mask_headers(h: Dict[str, str]) -> Dict[str, str]:
    try:
        return dict(h or {})
    except Exception:
        out: Dict[str, str] = {}
        try:
            for k, v in (h or {}).items():
                out[str(k)] = "" if v is None else str(v)
        except Exception:
            return {}
        return out


def _redact_set_cookie_header(raw_cookie: str) -> str:
    return str(raw_cookie or "")


def _safe_set_cookie_headers_from_headers(headers: httpx.Headers) -> List[str]:
    try:
        raw_items = [x for x in headers.get_list("set-cookie") if x]
    except Exception:
        raw = headers.get("set-cookie")
        raw_items = [raw] if raw else []

    return [str(x) for x in raw_items if x]

def _safe_set_cookie_objects_from_headers(headers: httpx.Headers) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    try:
        raw_items = [x for x in headers.get_list("set-cookie") if x]
    except Exception:
        raw = headers.get("set-cookie")
        raw_items = [raw] if raw else []

    def _cookie_name_sensitive(name: str) -> bool:
        n = str(name or "").strip().lower()
        if not n:
            return False

        explicit_non_sensitive = {
            "language",
            "lang",
            "lastactivitytime",
            "search_arguments_data",
            "search_arguments_path",
            "theme",
            "locale",
            "tz",
            "timezone",
            "returnpath",
        }
        if n in explicit_non_sensitive:
            return False

        explicit_sensitive = {
            "jsessionid",
            "phpsessid",
            "session",
            "sessionid",
            "sid",
            "connect.sid",
        }
        if n in explicit_sensitive:
            return True

        if n.startswith("__host-") or n.startswith("__secure-"):
            return True

        keywords = (
            "sess",
            "session",
            "sid",
            "phpsessid",
            "jsessionid",
            "csrf",
            "csrftoken",
            "xsrf",
            "auth",
            "token",
            "jwt",
            "remember",
            "login",
        )
        return any(k in n for k in keywords)

    def _cookie_prefix(name: str) -> str:
        if name.startswith("__Host-"):
            return "__Host-"
        if name.startswith("__Secure-"):
            return "__Secure-"
        return ""

    def _has_persistence(raw_cookie: str) -> bool:
        raw_l = str(raw_cookie or "").lower()
        return "expires=" in raw_l or "max-age=" in raw_l

    for raw in raw_items:
        raw = str(raw or "").strip()
        if not raw:
            continue

        first = raw.split(";", 1)[0].strip()
        cookie_name = first.split("=", 1)[0].strip() if "=" in first else first.strip()
        raw_l = raw.lower()

        if not cookie_name:
            continue

        out.append(
            {
                "name": cookie_name,
                "raw": raw,  # Preserve the original raw Set-Cookie header value.
                "value": first.split("=", 1)[1] if "=" in first else "",
                "httponly": "httponly" in raw_l,
                "secure": "secure" in raw_l,
                "samesite": "samesite" in raw_l,
                "persistent": _has_persistence(raw),
                "sensitive": _cookie_name_sensitive(cookie_name),
                "prefix": _cookie_prefix(cookie_name),
            }
        )

    return out

def _attach_analysis_metadata(resp: httpx.Response, snap: Dict[str, Any]) -> Dict[str, Any]:
    snap = dict(snap)
    snap["set_cookie_objects"] = _safe_set_cookie_objects_from_headers(resp.headers)
    snap["set_cookie_headers"] = _safe_set_cookie_headers_from_headers(resp.headers)
    snap["set_cookie_present"] = bool(snap["set_cookie_objects"])
    return snap

def should_skip_probe_for_static(spec: Any) -> bool:
    url = str(getattr(spec, "url", "") or "")
    if not looks_like_static_asset_url(url):
        return False

    if is_baseline_probe(spec):
        return False

    method = str(getattr(spec, "method", "") or "").upper()
    if method not in {"GET", "HEAD"}:
        return True

    name = str(getattr(spec, "name", "") or "").lower()
    if name not in {"baseline_get", "baseline_head"}:
        return True

    return False

def _cookie_name_set_from_any(value: Any) -> set[str]:
    if value is None:
        return set()

    if isinstance(value, set):
        return {str(x).lower() for x in value if str(x).strip()}

    if isinstance(value, dict):
        return {str(k).lower() for k in value.keys() if str(k).strip()}

    if isinstance(value, list):
        out = set()
        for item in value:
            if isinstance(item, dict):
                name = str(item.get("name") or item.get("cookie_name") or "").strip()
                if name:
                    out.add(name.lower())
            else:
                s = str(item).strip()
                if s:
                    out.add(s.lower())
        return out

    return set()

def evaluate_auth_success(
    *,
    login_url: str,
    response: httpx.Response,
    cookies_before: Any,
    cookies_after: Any,
) -> bool:
    before_names = _cookie_name_set_from_any(cookies_before)
    after_names = _cookie_name_set_from_any(cookies_after)

    final_url = str(response.url or "")
    final_url_l = final_url.lower()
    login_url_l = (login_url or "").lower()

    body = response.text or ""
    body_l = body.lower()

    score = 0

    # ------------------------------------------------------------
    # positive signals
    # ------------------------------------------------------------
    if len(response.history) > 0:
        score += 2

    if final_url_l != login_url_l:
        score += 2

    if not looks_like_login_page(final_url, body):
        score += 3

    authenticated_markers = _authenticated_markers(body, final_url)
    if authenticated_markers:
        score += 4

    if any(x in body_l for x in (
        "logout",
        "log out",
        "sign out",
        "dashboard",
        "welcome",
        "account",
        "profile",
        "portal",
        "home",
        "choose your bug",
        "my account",
    )):
        score += 2

    new_cookie_names = after_names - before_names
    if new_cookie_names:
        score += 2

    if any(x in after_names for x in (
        "phpsessid",
        "jsessionid",
        "session",
        "sessionid",
        "auth",
        "token",
        "remember",
        "security_level",
    )):
        score += 1

    if response.status_code in {200, 201, 202, 204, 301, 302, 303, 307, 308}:
        score += 1

    # ------------------------------------------------------------
    # negative signals
    # ------------------------------------------------------------
    if looks_like_login_page(final_url, body):
        score -= 4

    if any(x in body_l for x in (
        "invalid",
        "incorrect",
        "failed",
        "try again",
        "wrong password",
        "authentication failed",
        "login failed",
        "bad credentials",
        "access denied",
        "unauthorized",
        "forbidden",
    )):
        score -= 4

    if response.status_code in {401, 403}:
        score -= 5
    elif response.status_code >= 400:
        score -= 2

    # Staying on the login URL and still looking like a login page is a strong failure signal.
    if final_url_l == login_url_l and looks_like_login_page(final_url, body):
        score -= 3

    return score >= 4

async def send_once(client: httpx.AsyncClient, spec: Any, timeout_s: float) -> Dict[str, Any]:
    start = time.time()

    def _safe_body_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _safe_headers_dict(value: Any) -> Dict[str, str]:
        if not value:
            return {}
        try:
            return mask_headers(dict(value))
        except Exception:
            out: Dict[str, str] = {}
            try:
                for k, v in value.items():
                    out[str(k)] = str(v)
            except Exception:
                return {}
            return mask_headers(out)

    def _preferred_cookie_path(url: str) -> str:
        return preferred_cookie_path_for_url(url)

    def _parse_manual_auth_cookie_pairs() -> Dict[str, str]:
        return parse_manual_auth_cookie_pairs()

    def _clear_cookie_name_from_client(cookie_name: str) -> None:
        clear_cookie_name_from_client(client, cookie_name)

    def _sanitize_headers_and_reseed_session(url: str, headers: Dict[str, Any]) -> Dict[str, str]:
        safe_headers: Dict[str, str] = {}
        for k, v in (headers or {}).items():
            ks = str(k or "").strip()
            if not ks:
                continue
            # Never pass Cookie as a raw header here; use only the cookie jar.
            if ks.lower() == "cookie":
                continue
            safe_headers[ks] = "" if v is None else str(v)

        manual_pairs = _parse_manual_auth_cookie_pairs()
        preferred_path = _preferred_cookie_path(url)
        host = (urlsplit(url).hostname or "").strip() or None

        # Keep only one JSESSIONID value active at a time.
        manual_jsessionid = None
        for name, value in manual_pairs.items():
            if name.lower() == "jsessionid":
                manual_jsessionid = value
                break

        if manual_jsessionid is not None:
            _clear_cookie_name_from_client("JSESSIONID")
            try:
                if host:
                    client.cookies.set(
                        "JSESSIONID",
                        manual_jsessionid,
                        domain=host,
                        path=preferred_path,
                    )
                else:
                    client.cookies.set(
                        "JSESSIONID",
                        manual_jsessionid,
                        path=preferred_path,
                    )
            except Exception:
                pass

        return safe_headers

    request_body_text = _safe_body_text(getattr(spec, "body", None))
    request_headers = _safe_headers_dict(getattr(spec, "headers", {}) or {})
    request_url = str(getattr(spec, "url", "") or "")

    request_headers = _sanitize_headers_and_reseed_session(
        request_url,
        request_headers,
    )

    cookies_before = snapshot_cookie_jar(client)

    request_meta = {
        "method": str(getattr(spec, "method", "") or "").upper(),
        "url": request_url,
        "headers": request_headers,
        "body_text": request_body_text,
        "body_len": len(request_body_text),
        "has_body": bool(request_body_text),
    }

    per_request_follow_redirects = getattr(spec, "follow_redirects", None)
    if per_request_follow_redirects is None:
        effective_follow_redirects = False
    else:
        effective_follow_redirects = bool(per_request_follow_redirects)

    error_phase = None
    response = None

    try:
        error_phase = "request"
        response = await client.request(
            method=request_meta["method"],
            url=request_meta["url"],
            headers=request_headers,
            content=getattr(spec, "body", None),
            follow_redirects=effective_follow_redirects,
            timeout=httpx.Timeout(timeout_s, connect=min(3.0, timeout_s)),
        )

        error_phase = "read_body"
        body_text = response.text or ""
        body_snippet = body_text[:8000]
        cookies_after = snapshot_cookie_jar(client)

        redirect_chain = []
        for hist in response.history:
            redirect_chain.append(
                {
                    "url": str(hist.url),
                    "status_code": hist.status_code,
                    "headers": _safe_headers_dict(hist.headers),
                }
            )

        actual_request = {
            "method": str(getattr(response.request, "method", request_meta["method"]) or request_meta["method"]).upper(),
            "url": str(getattr(response.request, "url", request_meta["url"]) or request_meta["url"]),
            "headers": _safe_headers_dict(getattr(response.request, "headers", {}) or {}),
            "body_text": request_body_text,
            "body_len": len(request_body_text),
            "has_body": bool(request_body_text),
        }

        snap = {
            "ok": True,
            "error": None,
            "error_phase": None,
            "error_class": None,
            "status_code": response.status_code,
            "reason_phrase": getattr(response, "reason_phrase", None),
            "final_url": str(response.url),
            "headers": _safe_headers_dict(response.headers),
            "headers_received": True,
            "content_type": str(response.headers.get("content-type") or ""),
            "body_text": body_text,
            "body_snippet": body_snippet,
            "body_len": len(body_text),
            "body_read_ok": True,
            "redirect_chain": redirect_chain,
            "follow_redirects": effective_follow_redirects,
            "elapsed_ms": int((time.time() - start) * 1000),
            "request": request_meta,
            "actual_request": actual_request,
        }

        snap = _attach_analysis_metadata(response, snap)
        snap.update(cookie_jar_delta(cookies_before, cookies_after))
        return snap

    except Exception as e:
        cookies_after = snapshot_cookie_jar(client)

        headers_received = False
        if response is not None:
            try:
                headers_received = bool(response.headers)
            except Exception:
                headers_received = False

        return {
            "ok": False,
            "error": f"{type(e).__name__}: {e}",
            "error_phase": error_phase or "request",
            "error_class": type(e).__name__,
            "status_code": None,
            "reason_phrase": None,
            "final_url": request_meta["url"],
            "headers": {},
            "headers_received": headers_received,
            "content_type": "",
            "body_text": "",
            "body_snippet": "",
            "body_len": 0,
            "body_read_ok": False,
            "redirect_chain": [],
            "follow_redirects": effective_follow_redirects,
            "elapsed_ms": int((time.time() - start) * 1000),
            "set_cookie_objects": [],
            "set_cookie_headers": [],
            "set_cookie_present": False,
            "request": request_meta,
            "actual_request": request_meta,
            **cookie_jar_delta(cookies_before, cookies_after),
        }

def _response_to_snapshot(resp: httpx.Response, elapsed_ms: int) -> Dict[str, Any]:
    def _safe_body_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _safe_headers_dict(value: Any) -> Dict[str, str]:
        if not value:
            return {}
        try:
            return mask_headers(dict(value))
        except Exception:
            out: Dict[str, str] = {}
            try:
                for k, v in value.items():
                    out[str(k)] = str(v)
            except Exception:
                return {}
            return mask_headers(out)

    body_text = resp.text or ""
    body_snippet = body_text[:8000]

    request_obj = getattr(resp, "request", None)
    request_headers = _safe_headers_dict(getattr(request_obj, "headers", {}) or {})
    request_method = str(getattr(request_obj, "method", "") or "").upper()
    request_url = str(getattr(request_obj, "url", "") or "")

    snap = {
        "ok": True,
        "error": None,
        "status_code": resp.status_code,
        "reason_phrase": getattr(resp, "reason_phrase", None),
        "final_url": str(resp.url),
        "headers": _safe_headers_dict(resp.headers),
        "content_type": str(resp.headers.get("content-type") or ""),
        "body_text": body_text,
        "body_snippet": body_snippet,
        "body_len": len(body_text),
        "redirect_chain": [
            {
                "url": str(h.url),
                "status_code": h.status_code,
                "headers": _safe_headers_dict(h.headers),
            }
            for h in resp.history
        ],
        "elapsed_ms": elapsed_ms,
        "request": {
            "method": request_method,
            "url": request_url,
            "headers": request_headers,
            "body_text": "",
            "body_len": 0,
            "has_body": False,
        },
        "actual_request": {
            "method": request_method,
            "url": request_url,
            "headers": request_headers,
            "body_text": "",
            "body_len": 0,
            "has_body": False,
        },
    }

    return _attach_analysis_metadata(resp, snap)

def extract_hidden_inputs(body_text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for m in re.finditer(
        r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
        body_text or "",
        flags=re.IGNORECASE,
    ):
        out[m.group(1)] = m.group(2)
    return out


def guess_login_field_names(body_text: str) -> Dict[str, str]:
    text = (body_text or "").lower()

    user_name = "username"
    pass_name = "password"

    if 'name="username"' in text:
        user_name = "username"
    elif 'name="user"' in text:
        user_name = "user"
    elif 'name="email"' in text:
        user_name = "email"
    elif 'name="userid"' in text:
        user_name = "userid"

    if 'name="password"' in text:
        pass_name = "password"
    elif 'name="pass"' in text:
        pass_name = "pass"
    elif 'name="passwd"' in text:
        pass_name = "passwd"

    return {"username": user_name, "password": pass_name}


def _set_cookie_headers_from_response(resp: httpx.Response) -> List[str]:
    try:
        return [x for x in resp.headers.get_list("set-cookie") if x]
    except Exception:
        raw = resp.headers.get("set-cookie")
        return [raw] if raw else []


def _cookie_observations_from_response(resp: httpx.Response, phase: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for raw in _set_cookie_headers_from_response(resp):
        first = raw.split(";", 1)[0].strip()
        cookie_name = first.split("=", 1)[0].strip() if "=" in first else first.strip()
        raw_l = raw.lower()

        if not cookie_name:
            continue

        out.append(
            {
                "phase": phase,
                "url": str(resp.url),
                "status_code": resp.status_code,
                "cookie_name": cookie_name,
                "httponly": "httponly" in raw_l,
                "secure": "secure" in raw_l,
                "samesite": "samesite" in raw_l,
                "raw_set_cookie": _redact_set_cookie_header(raw),
            }
        )

    return out

def _auth_spec(
    *,
    name: str,
    method: str,
    url: str,
    headers: Dict[str, str] | None = None,
    body: bytes | None = None,
) -> Any:
    safe_headers: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        ks = str(k).strip()
        if not ks:
            continue
        safe_headers[ks] = "" if v is None else str(v)

    return type(
        "AuthSpec",
        (),
        {
            "name": str(name or "").strip(),
            "method": str(method or "GET").upper().strip(),
            "url": str(url or "").strip(),
            "headers": safe_headers,
            "body": body,

            # generic request metadata
            "origin": None,
            "probe": None,
            "trace_marker": None,
            "source": "auth",
            "family": "authentication",
            "mutation_class": str(name or "").strip() or "auth_flow",
            "target_param": None,
            "target_header": None,
            "surface_hint": "response.headers",
            "expected_signal": "auth_flow",
            "comparison_group": "auth",

            # replay / auth lineage metadata
            "auth_state": "authenticated",
            "replay_key": None,
            "replay_source_url": str(url or "").strip(),
            "replay_source_state": "authenticated",
            "replay_priority": 0,
        },
    )()


async def maybe_authenticate(
    client: httpx.AsyncClient,
    target: str,
    timeout_s: float,
    username: str | None,
    password: str | None,
) -> Dict[str, Any]:
    import json
    import time
    from urllib.parse import urljoin, urlsplit

    def _empty_result() -> Dict[str, Any]:
        return {
            "ok": False,
            "landing_url": None,
            "login_url": None,
            "final_login_url": None,
            "auth_mode": None,
            "bearer_token": None,
            "auth_headers": {},
            "auth_events": [],
            "cookie_observations": [],
            "auth_snapshots": [],
            "auth_header_names": [],
        }

    if not username or not password:
        return _empty_result()

    def _dedupe(items: List[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for x in items:
            s = str(x or "").strip()
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    def _base_root(url: str) -> str:
        p = urlsplit(url)
        return f"{p.scheme}://{p.netloc}"

    def _candidate_form_login_urls(base_target: str) -> List[str]:
        base = base_target.rstrip("/")
        root = _base_root(base_target)

        candidates = [
            f"{base}/login",
            f"{base}/login.php",
            f"{base}/signin",
            f"{base}/sign-in",
            f"{base}/auth/login",
            f"{base}/users/sign_in",
            f"{base}/session/login",
            f"{root}/login",
            f"{root}/login.php",
            f"{root}/signin",
            f"{root}/auth/login",
        ]
        return _dedupe(candidates)

    def _candidate_json_login_urls(base_target: str) -> List[str]:
        base = base_target.rstrip("/")
        root = _base_root(base_target)
        candidates = [
            f"{base}/rest/user/login",
            f"{base}/rest/login",
            f"{base}/api/login",
            f"{base}/api/auth/login",
            f"{base}/auth/login",
            f"{base}/session/login",
            f"{base}/login",
            f"{base}/signin",
            f"{root}/rest/user/login",
            f"{root}/api/login",
            f"{root}/auth/login",
            f"{root}/login",
        ]
        return _dedupe(candidates)

    def _candidate_verify_urls(base_target: str) -> List[str]:
        root = _base_root(base_target)
        base = base_target.rstrip("/")
        candidates = [
            f"{root}/rest/user/whoami",
            f"{root}/api/Users",
            f"{root}/rest/user/change-password",
            f"{root}/api/BasketItems",
            f"{root}/profile",
            f"{root}/wallet",
            base,
            root,
        ]
        return _dedupe(candidates)

    def _json_payload_variants(user_value: str, pass_value: str) -> List[Dict[str, Any]]:
        variants: List[Dict[str, Any]] = [
            {"username": user_value, "password": pass_value},
            {"login": user_value, "password": pass_value},
            {"user": user_value, "password": pass_value},
        ]
        if "@" in user_value:
            variants.insert(0, {"email": user_value, "password": pass_value})
            variants.append({"email": user_value, "passwd": pass_value})
        else:
            variants.append({"email": user_value, "password": pass_value})
        return variants

    def _extract_token_from_obj(obj: Any) -> str | None:
        if isinstance(obj, dict):
            for key in ("token", "access_token", "accessToken", "jwt", "id_token", "idToken"):
                value = obj.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

            for key in ("authentication", "data", "result", "response", "auth"):
                nested = obj.get(key)
                token = _extract_token_from_obj(nested)
                if token:
                    return token

            for value in obj.values():
                token = _extract_token_from_obj(value)
                if token:
                    return token

        elif isinstance(obj, list):
            for item in obj:
                token = _extract_token_from_obj(item)
                if token:
                    return token

        return None

    def _extract_token_from_response(resp: httpx.Response) -> str | None:
        authz = str(resp.headers.get("Authorization") or "").strip()
        if authz.lower().startswith("bearer "):
            token = authz[7:].strip()
            if token:
                return token

        try:
            parsed = resp.json()
        except Exception:
            parsed = None

        token = _extract_token_from_obj(parsed)
        if token:
            return token

        body = resp.text or ""
        for pattern in [
            r'"token"\s*:\s*"([^"]+)"',
            r'"access_token"\s*:\s*"([^"]+)"',
            r'"accessToken"\s*:\s*"([^"]+)"',
        ]:
            m = re.search(pattern, body, flags=re.I)
            if m:
                return m.group(1).strip()

        return None

    def _looks_json_response(resp: httpx.Response) -> bool:
        ct = str(resp.headers.get("content-type") or "").lower()
        body_l = (resp.text or "").lstrip().lower()
        return ("application/json" in ct) or body_l.startswith("{") or body_l.startswith("[")

    def _extract_json_indicators(text: str) -> List[str]:
        body_l = (text or "").lower()
        indicators: List[str] = []
        for tok in (
            '"user"', '"users"', '"email"', '"username"', '"role"',
            '"authentication"', '"token"', '"basket"', '"address"',
            '"card"', '"wallet"', '"order"', '"orders"',
        ):
            if tok in body_l:
                indicators.append(tok)
        return sorted(set(indicators))

    def _looks_bearer_auth_success(resp: httpx.Response) -> bool:
        if resp.status_code in {401, 403}:
            return False

        body = resp.text or ""
        body_l = body.lower()
        indicators = _extract_json_indicators(body)

        if _looks_json_response(resp) and indicators:
            return True

        if any(tok in body_l for tok in ("email", "username", "basket", "wallet", "order", "logout", "profile")):
            return True

        return False

    def _auth_spec(
        *,
        name: str,
        method: str,
        url: str,
        headers: Dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> Any:
        return type(
            "AuthSpec",
            (),
            {
                "name": name,
                "method": method,
                "url": url,
                "headers": headers or {},
                "body": body,
                "origin": None,
                "probe": None,
                "trace_marker": None,
                "source": "auth",
                "family": "authentication",
                "mutation_class": name,
                "target_param": None,
                "target_header": None,
                "surface_hint": "response.headers",
                "expected_signal": "auth_flow",
                "comparison_group": "auth",
                "auth_state": "authenticated",
                "replay_key": None,
                "replay_source_url": None,
                "replay_source_state": "authenticated",
                "replay_priority": 0,
            },
        )()

    async def _capture_get_snapshot(
        *,
        name: str,
        url: str,
        headers: Dict[str, str] | None,
        auth_events: List[Dict[str, Any]],
        auth_snapshots: List[Dict[str, Any]],
    ) -> httpx.Response | None:
        spec = _auth_spec(
            name=name,
            method="GET",
            url=url,
            headers=headers or {},
            body=None,
        )

        start = time.time()
        try:
            resp = await client.get(
                url,
                headers=headers,
                follow_redirects=True,
                timeout=timeout_s,
            )
        except Exception:
            return None

        snap = _response_to_snapshot(resp, int((time.time() - start) * 1000))
        auth_snapshots.append({"spec": spec, "snapshot": snap})
        auth_events.append(
            {
                "stage": name,
                "request_name": name,
                "method": "GET",
                "url": url,
                "final_url": str(resp.url),
                "status_code": resp.status_code,
            }
        )
        return resp

    async def _verify_bearer_auth(
        *,
        auth_headers: Dict[str, str],
        auth_events: List[Dict[str, Any]],
        auth_snapshots: List[Dict[str, Any]],
    ) -> tuple[bool, str | None]:
        for verify_url in _candidate_verify_urls(target):
            verify_resp = await _capture_get_snapshot(
                name="auth_api_verify",
                url=verify_url,
                headers=auth_headers,
                auth_events=auth_events,
                auth_snapshots=auth_snapshots,
            )
            if verify_resp is None:
                continue
            if _looks_bearer_auth_success(verify_resp):
                return True, str(verify_resp.url)
        return False, None

    best_result: Dict[str, Any] | None = None
    best_score = -9999

    # ------------------------------------------------------------------
    # 1) HTML form / session-cookie login
    # ------------------------------------------------------------------
    for login_url in _candidate_form_login_urls(target):
        auth_events: List[Dict[str, Any]] = []
        cookie_observations: List[Dict[str, Any]] = []
        auth_snapshots: List[Dict[str, Any]] = []

        login_get_resp = await _capture_get_snapshot(
            name="auth_probe",
            url=login_url,
            headers={},
            auth_events=auth_events,
            auth_snapshots=auth_snapshots,
        )
        if login_get_resp is None:
            continue

        final_url = str(login_get_resp.url)
        body = login_get_resp.text or ""

        if not looks_like_login_page(final_url, body):
            continue

        forms = parse_login_forms(final_url, body)
        form = select_login_form(forms, final_url, body)
        if form is None:
            continue

        payload = build_auth_payload_from_form(form, username, password)
        if not payload:
            continue

        form_action = str(form.get("action") or "").strip()
        post_url = urljoin(final_url, form_action) if form_action else final_url
        post_headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": final_url,
        }

        post_spec = _auth_spec(
            name="auth_submit",
            method="POST",
            url=post_url,
            headers=post_headers,
            body=None,
        )

        cookies_before = snapshot_cookie_jar(client)
        start = time.time()
        try:
            resp = await client.post(
                post_url,
                data=payload,
                headers=post_headers,
                follow_redirects=True,
                timeout=timeout_s,
            )
        except Exception:
            continue

        post_snap = _response_to_snapshot(resp, int((time.time() - start) * 1000))
        cookies_after = snapshot_cookie_jar(client)
        post_snap.update(cookie_jar_delta(cookies_before, cookies_after))
        auth_snapshots.append({"spec": post_spec, "snapshot": post_snap})

        auth_events.append(
            {
                "stage": "login_post",
                "request_name": "auth_submit",
                "method": "POST",
                "url": post_url,
                "final_url": str(resp.url),
                "status_code": resp.status_code,
            }
        )

        cookie_observations.extend(_cookie_observations_from_response(resp, "login_post_final"))

        for idx, hist in enumerate(resp.history, start=1):
            hist_snap = _response_to_snapshot(hist, int((time.time() - start) * 1000))
            hist_spec = _auth_spec(
                name=f"auth_redirect_{idx}",
                method=str(hist.request.method).upper(),
                url=str(hist.request.url),
                headers=mask_headers(dict(hist.request.headers)),
                body=None,
            )
            auth_snapshots.append({"spec": hist_spec, "snapshot": hist_snap})
            auth_events.append(
                {
                    "stage": f"login_redirect_{idx}",
                    "request_name": f"auth_redirect_{idx}",
                    "method": str(hist.request.method).upper(),
                    "url": str(hist.request.url),
                    "final_url": str(hist.url),
                    "status_code": hist.status_code,
                }
            )
            cookie_observations.extend(_cookie_observations_from_response(hist, f"login_redirect_{idx}"))

        ok = evaluate_auth_success(
            login_url=post_url,
            response=resp,
            cookies_before=_cookie_name_set_from_any(cookies_before),
            cookies_after=_cookie_name_set_from_any(cookies_after),
        )

        score = 0
        if ok:
            score += 5
        if len(resp.history) > 0:
            score += 1
        if str(resp.url).lower() != post_url.lower():
            score += 1
        if set(_cookie_name_set_from_any(cookies_after)) - set(_cookie_name_set_from_any(cookies_before)):
            score += 1

        candidate_result = {
            "ok": ok,
            "landing_url": str(resp.url),
            "login_url": login_url,
            "final_login_url": final_url,
            "auth_mode": "cookie_form",
            "bearer_token": None,
            "auth_headers": {},
            "auth_events": auth_events,
            "cookie_observations": cookie_observations,
            "auth_snapshots": auth_snapshots,
            "auth_header_names": [],
        }

        if score > best_score:
            best_score = score
            best_result = candidate_result

        if ok:
            return candidate_result

    # ------------------------------------------------------------------
    # 2) JSON / bearer-token login
    # ------------------------------------------------------------------
    for login_url in _candidate_json_login_urls(target):
        for payload in _json_payload_variants(username, password):
            auth_events: List[Dict[str, Any]] = []
            cookie_observations: List[Dict[str, Any]] = []
            auth_snapshots: List[Dict[str, Any]] = []

            post_headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
            }

            post_spec = _auth_spec(
                name="auth_api_submit",
                method="POST",
                url=login_url,
                headers=post_headers,
                body=None,
            )

            cookies_before = snapshot_cookie_jar(client)
            start = time.time()
            try:
                resp = await client.post(
                    login_url,
                    content=json.dumps(payload),
                    headers=post_headers,
                    follow_redirects=True,
                    timeout=timeout_s,
                )
            except Exception:
                continue

            post_snap = _response_to_snapshot(resp, int((time.time() - start) * 1000))
            cookies_after = snapshot_cookie_jar(client)
            post_snap.update(cookie_jar_delta(cookies_before, cookies_after))
            auth_snapshots.append({"spec": post_spec, "snapshot": post_snap})

            auth_events.append(
                {
                    "stage": "login_api_post",
                    "request_name": "auth_api_submit",
                    "method": "POST",
                    "url": login_url,
                    "final_url": str(resp.url),
                    "status_code": resp.status_code,
                    "payload_keys": sorted(payload.keys()),
                }
            )

            cookie_observations.extend(_cookie_observations_from_response(resp, "login_api_post_final"))

            token = _extract_token_from_response(resp)
            auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

            score = 0
            if resp.status_code in {200, 201, 202, 204}:
                score += 1
            if "json" in str(resp.headers.get("content-type") or "").lower():
                score += 1
            if token:
                score += 6

            candidate_result = {
                "ok": False,
                "landing_url": target,
                "login_url": login_url,
                "final_login_url": str(resp.url),
                "auth_mode": "bearer_token",
                "bearer_token": token,
                "auth_headers": auth_headers,
                "auth_events": auth_events,
                "cookie_observations": cookie_observations,
                "auth_snapshots": auth_snapshots,
                "auth_header_names": ["authorization"] if token else [],
            }

            if token:
                client.headers["Authorization"] = f"Bearer {token}"
                verified_ok, verified_url = await _verify_bearer_auth(
                    auth_headers=auth_headers,
                    auth_events=auth_events,
                    auth_snapshots=auth_snapshots,
                )
                candidate_result["ok"] = verified_ok
                if verified_url:
                    candidate_result["landing_url"] = verified_url
                if verified_ok:
                    score += 4
                else:
                    client.headers.pop("Authorization", None)

            if score > best_score:
                best_score = score
                best_result = candidate_result

            if candidate_result["ok"]:
                return candidate_result

            client.headers.pop("Authorization", None)

    if best_result is not None:
        return best_result

    return _empty_result()

def _strip_noise_suffix_from_url(url: str) -> str:
    if not url:
        return ""

    p = urlsplit(url)
    path = p.path or "/"
    segments = [s for s in path.split("/") if s]

    while segments:
        last = segments[-1].strip()
        if (
            last in {".", "..", "%", "%ZZ", "|", "<", ">", "%00"}
            or "%" in last
            or last in {'"', "'"}
        ):
            segments = segments[:-1]
            continue
        break

    collapsed_path = "/" + "/".join(segments) if segments else "/"
    return urlunsplit((p.scheme, p.netloc, collapsed_path, "", ""))


def _query_param_names(url: str) -> List[str]:
    try:
        return [k.lower() for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except Exception:
        return []


def _is_high_value_http_surface(url: str) -> bool:
    u = (url or "").lower()
    path = urlsplit(u).path.lower()
    qp = set(_query_param_names(u))

    if any(h in u for h in HIGH_VALUE_HTTP_HINTS):
        return True
    if FILEISH_PARAM_NAMES.intersection(qp):
        return True
    if path.endswith((".php", ".jsp", ".do", ".action", ".aspx")):
        return True
    return False


def probe_scope_key(spec: Any) -> str:
    url = str(getattr(spec, "url", "") or "")
    base_path = _strip_noise_suffix_from_url(url)
    qp = sorted(_query_param_names(url))

    important_qp = sorted(set(qp).intersection(FILEISH_PARAM_NAMES))
    if important_qp:
        return f"{base_path}?{'&'.join(important_qp)}"

    return base_path


def probe_category(spec: Any) -> str:
    fam = str(getattr(spec, "family", "") or "")
    if fam in {"error_path", "error_query"}:
        return "error_mutation"
    if fam in {"header_behavior"}:
        return "header_mutation"
    if fam in {"method_behavior", "trace_behavior"}:
        return "method_behavior"
    if fam in {"cors_behavior"}:
        return "cors_behavior"
    if fam in {"default_resource"}:
        return "default_resource"
    if fam in {"directory_behavior"}:
        return "directory_behavior"
    if fam in {"body_behavior"}:
        return "body_behavior"
    if fam in {"baseline", "comparison"}:
        return "baseline"
    return fam or "other"

def should_skip_probe_for_scope(scope_state: Dict[str, Any], spec: Any) -> bool:
    if is_baseline_probe(spec):
        return False

    url = str(getattr(spec, "url", "") or "")
    cat = probe_category(spec)

    # Keep probing high-value HTTP surfaces.
    # A single header finding should not block body, resource, or error probing.
    if _is_high_value_http_surface(url):
        if cat in {
            "cors_behavior",
            "method_behavior",
            "default_resource",
            "directory_behavior",
            "error_mutation",
            "header_mutation",
            "body_behavior",
        }:
            pass
        else:
            return False

    # ---------------------------------------------------------
    # Reduce duplicate probes once a category has already been observed well enough.
    # ---------------------------------------------------------
    if scope_state.get("error_disclosure_found") and cat == "error_mutation":
        return True

    if scope_state.get("cors_found") and cat == "cors_behavior":
        return True

    if scope_state.get("default_resource_found") and cat == "default_resource":
        return True

    if scope_state.get("directory_listing_found") and cat == "directory_behavior":
        return True

    # ---------------------------------------------------------
    # System information probing policy
    #
    # 1) If only header disclosure has been observed:
    #    - reduce some header mutations
    #    - but keep body, resource, and error probing active
    #
    # 2) If body disclosure or concrete exposure has been observed:
    #    - reduce duplicate header_mutation, body_behavior, and some error_mutation probes
    # ---------------------------------------------------------
    if scope_state.get("system_info_header_found") and cat == "header_mutation":
        return True

    if scope_state.get("system_info_body_found") and cat in {"header_mutation", "body_behavior"}:
        return True

    return False


def update_scope_state_from_candidate(scope_state: Dict[str, Any], cand: Dict[str, Any]) -> None:
    ctype = str(cand.get("type") or "")
    verdict = ((cand.get("verification") or {}).get("verdict") or "").upper()
    where = str(cand.get("where") or "").lower()
    subtype = str(cand.get("subtype") or "").lower()

    if verdict not in {"CONFIRMED", "INFORMATIONAL"}:
        return

    if ctype in {"HTTP_ERROR_INFO_EXPOSURE", "FILE_PATH_HANDLING_ANOMALY"}:
        scope_state["error_disclosure_found"] = True

    if ctype == "HTTP_SYSTEM_INFO_EXPOSURE":
        scope_state["system_info_found"] = True

        if where == "response.headers" or subtype in {
            "server_header",
            "x_powered_by",
            "via_header",
            "x_aspnet_version",
            "x_aspnetmvc_version",
        }:
            scope_state["system_info_header_found"] = True
        else:
            scope_state["system_info_body_found"] = True

    if ctype in {
        "HTTP_CONFIG_FILE_EXPOSURE",
        "PHPINFO_EXPOSURE",
        "LOG_VIEWER_EXPOSURE",
    }:
        scope_state["system_info_found"] = True
        scope_state["system_info_body_found"] = True

    if ctype == "CORS_MISCONFIG":
        scope_state["cors_found"] = True

    if ctype == "HTTP_CONFIG_FILE_EXPOSURE":
        scope_state["default_resource_found"] = True

    if ctype == "DEFAULT_FILE_EXPOSED" and verdict == "CONFIRMED":
        scope_state["default_resource_found"] = True

    if ctype == "DIRECTORY_LISTING_ENABLED":
        scope_state["directory_listing_found"] = True

def _build_request_meta(spec: Any) -> Dict[str, Any]:
    def _safe_str(value: Any) -> str | None:
        if value is None:
            return None
        s = str(value).strip()
        return s if s else None

    def _safe_headers(value: Any) -> Dict[str, str]:
        if not isinstance(value, dict):
            return {}
        out: Dict[str, str] = {}
        for k, v in value.items():
            ks = str(k).strip()
            if not ks:
                continue
            out[ks] = "" if v is None else str(v)
        return out

    def _body_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    body_text = _body_text(getattr(spec, "body", None))
    headers = _safe_headers(getattr(spec, "headers", {}) or {})

    auth_state = _safe_str(getattr(spec, "auth_state", None)) or "inherit"

    return {
        "name": _safe_str(getattr(spec, "name", None)),
        "method": (_safe_str(getattr(spec, "method", None)) or "GET").upper(),
        "url": _safe_str(getattr(spec, "url", None)) or "",
        "headers": headers,
        "header_names": sorted(h.lower() for h in headers.keys()),
        "body_text": body_text,
        "body_len": len(body_text),
        "has_body": bool(body_text),

        "origin": _safe_str(getattr(spec, "origin", None)),
        "probe": _safe_str(getattr(spec, "probe", None)),
        "trace_marker": _safe_str(getattr(spec, "trace_marker", None)),
        "source": _safe_str(getattr(spec, "source", None)),
        "family": _safe_str(getattr(spec, "family", None)),
        "mutation_class": _safe_str(getattr(spec, "mutation_class", None)),
        "target_param": _safe_str(getattr(spec, "target_param", None)),
        "target_header": _safe_str(getattr(spec, "target_header", None)),
        "surface_hint": _safe_str(getattr(spec, "surface_hint", None)),
        "expected_signal": _safe_str(getattr(spec, "expected_signal", None)),
        "comparison_group": _safe_str(getattr(spec, "comparison_group", None)),

        # replay / auth lineage
        "auth_state": auth_state,
        "replay_key": _safe_str(getattr(spec, "replay_key", None)),
        "replay_source_url": _safe_str(getattr(spec, "replay_source_url", None)),
        "replay_source_state": _safe_str(getattr(spec, "replay_source_state", None)),
        "replay_priority": getattr(spec, "replay_priority", None),
    }


def _merge_into_bucket(
    bucket_map: Dict[str, Dict[str, Any]],
    key: str,
    cand: Dict[str, Any],
) -> None:
    if key in bucket_map:
        bucket_map[key] = merge_finding(bucket_map[key], cand)
    else:
        bucket_map[key] = seed_bucket_candidate(cand)


def _store_with_verdict_precedence(
    *,
    key: str,
    cand: Dict[str, Any],
    verdict: str,
    confirmed_map: Dict[str, Dict[str, Any]],
    informational_map: Dict[str, Dict[str, Any]],
    false_positive_map: Dict[str, Dict[str, Any]],
) -> None:
    verdict_norm = str(verdict or "").strip().upper()

    if verdict_norm == "CONFIRMED":
        false_positive_map.pop(key, None)
        informational_map.pop(key, None)
        _merge_into_bucket(confirmed_map, key, cand)
        return

    # INFORMATIONAL / INCONCLUSIVE findings should stay in the informational bucket, not false_positive.
    if verdict_norm in {"INFORMATIONAL", "INCONCLUSIVE"}:
        if key in confirmed_map:
            return
        false_positive_map.pop(key, None)
        _merge_into_bucket(informational_map, key, cand)
        return

    if verdict_norm == "FALSE_POSITIVE":
        if key in confirmed_map or key in informational_map:
            return
        _merge_into_bucket(false_positive_map, key, cand)
        return

    # If the verdict is empty or unknown, keep it informational instead of marking it false positive.
    if key in confirmed_map:
        return

    false_positive_map.pop(key, None)
    _merge_into_bucket(informational_map, key, cand)

async def _finalize_candidate(
    *,
    client: httpx.AsyncClient,
    spec: Any,
    snap: Dict[str, Any],
    cand: Dict[str, Any],
    timeout_s: float,
    retries: int,
    llm_judge_if_enabled_fn,
    stable_key_fn,
) -> List[Dict[str, Any]]:
    cand = dict(cand)

    if should_run_llm_judge(cand):
        cand = await llm_judge_if_enabled_fn(cand, snap)

    candidate_type = str(cand.get("type") or "")

    # --------------------------------------------------
    # capability findings branch
    # --------------------------------------------------
    if candidate_type == "RISKY_HTTP_METHODS_ENABLED":
        finalized = await reproduce_verify(
            client=client,
            spec=spec,
            timeout_s=timeout_s,
            retries=retries,
            candidate=cand,
            first_snapshot=snap,
            stable_key_fn=stable_key_fn,
            scan_profile_fn=scan_profile,
            send_once_fn=send_once,
            build_request_meta_fn=_build_request_meta,
        )

        out: List[Dict[str, Any]] = []
        normalized = _normalize_method_capability_candidates(finalized)
        for item in normalized:
            item = validate_candidate_after_llm(item)
            out.append(item)
        return out

    cand = validate_candidate_after_llm(cand)

    direct_finalized = try_direct_finalize_candidate(cand, snap)
    if direct_finalized is not None:
        return [validate_candidate_after_llm(direct_finalized)]

    # --------------------------------------------------
    # reproduce path
    # --------------------------------------------------
    if should_run_reproduce(cand):
        finalized = await reproduce_verify(
            client=client,
            spec=spec,
            timeout_s=timeout_s,
            retries=retries,
            candidate=cand,
            first_snapshot=snap,
            stable_key_fn=stable_key_fn,
            scan_profile_fn=scan_profile,
            send_once_fn=send_once,
            build_request_meta_fn=_build_request_meta,
        )

        if isinstance(finalized, list):
            out: List[Dict[str, Any]] = []
            for item in finalized:
                if not isinstance(item, dict):
                    continue
                item = validate_candidate_after_llm(item)
                out.extend(_normalize_method_capability_candidates(item))
            return out

        finalized = validate_candidate_after_llm(finalized)
        return [finalized]

    # --------------------------------------------------
    # no reproduce path
    # --------------------------------------------------
    return [validate_candidate_after_llm(finalize_without_reproduce(cand))]


async def process_plan(
    *,
    client: httpx.AsyncClient,
    plan: List[Any],
    timeout_s: float,
    retries: int,
    run_dir,
    raw_index: List[Dict[str, Any]],
    coverage: Dict[str, Dict[str, Any]],
    seq_start: int,
    log_fn,
    llm_judge_if_enabled_fn,
    stable_key_fn,
    update_coverage_from_candidate_fn,
    mark_attempted_for_spec_fn,
    update_cookie_observation_fn,
    request_auth_state: str = "inherit",
    shared_unhealthy_scopes: set[str] | None = None,
    auth_deadline_monotonic: float | None = None,
) -> Dict[str, Any]:
    confirmed_map: Dict[str, Dict[str, Any]] = {}
    informational_map: Dict[str, Dict[str, Any]] = {}
    false_positive_map: Dict[str, Dict[str, Any]] = {}
    request_failures: List[Dict[str, Any]] = []

    scope_states: Dict[str, Dict[str, Any]] = {}
    seq = seq_start
    raw_dir = run_dir / "raw"
    batch_size = int(os.getenv("SCAN_BATCH_SIZE", os.getenv("CONCURRENCY", "6")))
    if str(request_auth_state or "").strip().lower() == "authenticated":
        auth_batch_override = os.getenv("AUTH_PROBE_BATCH_SIZE", "").strip()
        if auth_batch_override:
            try:
                batch_size = max(1, int(auth_batch_override))
            except ValueError:
                pass
    try:
        auth_session_budget_seconds = float(os.getenv("AUTH_SESSION_BUDGET_SECONDS", "0") or "0")
    except ValueError:
        auth_session_budget_seconds = 0.0
    auth_started_at = time.monotonic()
    auth_budget_exhausted = False
    try:
        shape_sensitive_error_threshold = int(os.getenv("SHAPE_SENSITIVE_GET_ERROR_THRESHOLD", "3"))
    except ValueError:
        shape_sensitive_error_threshold = 3
    unhealthy_scopes = shared_unhealthy_scopes if shared_unhealthy_scopes is not None else set()

    log_fn("SCAN", f"[process_plan-config] batch_size={batch_size} timeout_s={timeout_s} retries={retries}")

    def _new_scope_state() -> Dict[str, Any]:
        return {
            "error_disclosure_found": False,
            "system_info_found": False,
            "system_info_header_found": False,
            "system_info_body_found": False,
            "cors_found": False,
            "default_resource_found": False,
            "directory_listing_found": False,
            "baseline_attempts": 0,
            "baseline_failures": 0,
            "baseline_successes": 0,
            "baseline_unhealthy": False,
            "baseline_failure_examples": [],
            "auth_failure_count": 0,
            "auth_unhealthy": False,
            "auth_failure_examples": [],
            "shape_sensitive_get_errors": 0,
            "shape_sensitive_examples": [],
            "shape_sensitive_unhealthy": False,
        }

    def _effective_auth_state(spec: Any) -> str:
        spec_state = str(getattr(spec, "auth_state", "") or "").strip().lower()
        req_state = str(request_auth_state or "").strip().lower()

        if spec_state in {"authenticated", "anonymous"}:
            return spec_state
        if req_state in {"authenticated", "anonymous"}:
            return req_state
        return "inherit"

    def _origin_tuple(url: str) -> tuple[str, str]:
        try:
            p = urlsplit(str(url or ""))
            return (p.scheme.lower(), p.netloc.lower())
        except Exception:
            return ("", "")

    def _first_non_empty_url(*values: Any) -> str:
        for v in values:
            s = str(v or "").strip()
            if s:
                return s
        return ""

    def _should_skip_external_final_response(spec: Any, snap: Dict[str, Any]) -> tuple[bool, Dict[str, Any]]:
        spec_url = str(getattr(spec, "url", "") or "")
        snap_request_url = str(((snap.get("request") or {}).get("url")) or "")
        actual_request_url = str(((snap.get("actual_request") or {}).get("url")) or "")
        final_url = str(snap.get("final_url") or "")

        requested_url = _first_non_empty_url(spec_url, snap_request_url, actual_request_url)
        if not requested_url or not final_url:
            return False, {
                "requested_url": requested_url,
                "final_url": final_url,
                "requested_origin": ("", ""),
                "final_origin": ("", ""),
                "reason": "missing_url",
            }

        requested_origin = _origin_tuple(requested_url)
        final_origin = _origin_tuple(final_url)

        if not requested_origin[1] or not final_origin[1]:
            return False, {
                "requested_url": requested_url,
                "final_url": final_url,
                "requested_origin": requested_origin,
                "final_origin": final_origin,
                "reason": "missing_origin",
            }

        skip = requested_origin != final_origin
        return skip, {
            "requested_url": requested_url,
            "final_url": final_url,
            "requested_origin": requested_origin,
            "final_origin": final_origin,
            "reason": "cross_origin_final_response" if skip else "same_origin",
        }

    def _request_body_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _request_shape(spec: Any) -> Dict[str, Any]:
        body_text = _request_body_text(getattr(spec, "body", None))
        headers = getattr(spec, "headers", {}) or {}
        if not isinstance(headers, dict):
            headers = {}

        return {
            "method": str(getattr(spec, "method", "") or "").upper(),
            "url": str(getattr(spec, "url", "") or ""),
            "headers": dict(headers),
            "body_text": body_text,
            "body_len": len(body_text),
            "has_body": bool(body_text),
        }

    def _append_raw_index(
        *,
        seq_no: int,
        spec: Any,
        snap: Dict[str, Any],
        raw_path: str,
        scope_key: str,
    ) -> None:
        snap_headers = snap.get("headers") or {}
        if not isinstance(snap_headers, dict):
            snap_headers = {}

        body_text = str(snap.get("body_snippet") or snap.get("body_text") or "")
        req_shape = _request_shape(spec)

        raw_index.append(
            {
                "seq": seq_no,
                "request_name": str(getattr(spec, "name", "") or ""),
                "method": req_shape["method"],
                "url": req_shape["url"],
                "raw_ref": str(raw_path),
                "status_code": snap.get("status_code"),
                "ok": bool(snap.get("ok")),
                "source": getattr(spec, "source", None),
                "family": getattr(spec, "family", None),
                "scope_key": scope_key,
                "auth_state": _effective_auth_state(spec),
                "content_type": str(snap_headers.get("content-type") or ""),
                "body_len": len(body_text),
                "body_text": body_text,
                "final_url": str(snap.get("final_url") or ""),
                "comparison_group": getattr(spec, "comparison_group", None),
                "replay_key": getattr(spec, "replay_key", None),
                "replay_source_url": getattr(spec, "replay_source_url", None),
                "replay_source_state": getattr(spec, "replay_source_state", None),
                "replay_priority": getattr(spec, "replay_priority", None),
                "expected_signal": getattr(spec, "expected_signal", None),
                "mutation_class": getattr(spec, "mutation_class", None),
                "request_headers": req_shape["headers"],
                "request_body_len": req_shape["body_len"],
                "request_body_present": req_shape["has_body"],
                "request_body_text": req_shape["body_text"],   # Added for replay diagnostics.
                **raw_index_cookie_observation_fields(snap),
            }
        )

    def _append_request_failure(
        *,
        spec: Any,
        snap: Dict[str, Any] | None,
        raw_path: str | None,
    ) -> None:
        snap = snap or {}
        snap_headers = snap.get("headers") or {}
        if not isinstance(snap_headers, dict):
            snap_headers = {}

        request_failures.append(
            {
                "trigger": str(getattr(spec, "name", "") or ""),
                "method": str(getattr(spec, "method", "") or "").upper(),
                "url": str(getattr(spec, "url", "") or ""),
                "error": snap.get("error"),
                "error_class": snap.get("error_class"),
                "error_phase": snap.get("error_phase"),
                "status_code": snap.get("status_code"),
                "final_url": snap.get("final_url"),
                "elapsed_ms": snap.get("elapsed_ms"),
                "headers_received": bool(snap.get("headers_received")) or bool(snap_headers),
                "body_read_ok": snap.get("body_read_ok"),
                "content_type": snap.get("content_type"),
                "raw_ref": str(raw_path) if raw_path else None,
                "source": getattr(spec, "source", None),
                "family": getattr(spec, "family", None),
                "auth_state": _effective_auth_state(spec),
            }
        )

    def _is_baseline_family(spec: Any) -> bool:
        return str(getattr(spec, "family", "") or "").strip().lower() == "baseline"

    def _has_usable_response(snap: Dict[str, Any]) -> bool:
        snap_headers = snap.get("headers") or {}
        if not isinstance(snap_headers, dict):
            snap_headers = {}
        return bool(snap.get("status_code") is not None or snap_headers)

    def _is_pre_header_transport_failure(snap: Dict[str, Any]) -> bool:
        return (
            not bool(snap.get("ok"))
            and not _has_usable_response(snap)
            and str(snap.get("error_phase") or "") == "request"
            and not bool(snap.get("headers_received"))
        )

    def _response_indicates_auth_loss(
        *,
        feats: Dict[str, Any],
        auth_state: str,
    ) -> bool:
        if str(auth_state or "").strip().lower() != "authenticated":
            return False
        if feats.get("session_expired_like") or feats.get("external_auth_redirect_like"):
            return True

        if not feats.get("auth_required_like"):
            return False

        status_code = feats.get("status_code")
        noise_flags = feats.get("response_noise_flags") or {}
        is_login_like = bool(noise_flags.get("is_login_like"))
        final_url_l = str(feats.get("final_url") or "").lower()
        final_url_auth_like = any(tok in final_url_l for tok in ("login", "signin", "/auth", "/sso"))
        explicit_auth_markers = bool(feats.get("auth_required_like")) and not is_login_like

        return bool(
            (is_login_like and (final_url_auth_like or status_code in {401, 403, 407}))
            or (final_url_auth_like and explicit_auth_markers)
            or status_code in {401, 407}
            or (status_code in {301, 302, 303, 307, 308} and final_url_auth_like)
        )

    def _update_scope_auth_health(
        *,
        scope_state: Dict[str, Any],
        scope_key: str,
        spec: Any,
        feats: Dict[str, Any],
        auth_state: str,
        raw_path: str,
    ) -> None:
        if not _response_indicates_auth_loss(feats=feats, auth_state=auth_state):
            return

        scope_state["auth_failure_count"] = int(scope_state.get("auth_failure_count", 0)) + 1
        examples = scope_state.setdefault("auth_failure_examples", [])
        if len(examples) < 5:
            examples.append(
                {
                    "name": str(getattr(spec, "name", "") or ""),
                    "method": str(getattr(spec, "method", "") or "").upper(),
                    "url": str(getattr(spec, "url", "") or ""),
                    "final_url": str(feats.get("final_url") or ""),
                    "status_code": feats.get("status_code"),
                    "auth_required_like": bool(feats.get("auth_required_like")),
                    "session_expired_like": bool(feats.get("session_expired_like")),
                    "external_auth_redirect_like": bool(feats.get("external_auth_redirect_like")),
                    "raw_ref": raw_path,
                }
            )

        if not scope_state.get("auth_unhealthy") and int(scope_state.get("auth_failure_count", 0)) >= 1:
            scope_state["auth_unhealthy"] = True
            unhealthy_scopes.add(scope_key)
            log_fn(
                "AUTH",
                "[scope-auth-unhealthy] "
                f"scope_key={scope_key} "
                f"name={getattr(spec, 'name', '')} "
                f"url={getattr(spec, 'url', '')} "
                f"status={feats.get('status_code')} "
                f"final_url={feats.get('final_url')} "
                f"auth_required_like={bool(feats.get('auth_required_like'))} "
                f"session_expired_like={bool(feats.get('session_expired_like'))} "
                f"external_auth_redirect_like={bool(feats.get('external_auth_redirect_like'))}"
            )
            request_failures.append(
                {
                    "trigger": str(getattr(spec, "name", "") or ""),
                    "method": str(getattr(spec, "method", "") or "").upper(),
                    "url": str(getattr(spec, "url", "") or ""),
                    "error": "Authenticated request appears to have lost session or been redirected to authentication.",
                    "error_class": "AuthStateLoss",
                    "error_phase": "response",
                    "status_code": feats.get("status_code"),
                    "final_url": feats.get("final_url"),
                    "raw_ref": raw_path,
                    "auth_state": auth_state,
                    "auth_required_like": bool(feats.get("auth_required_like")),
                    "session_expired_like": bool(feats.get("session_expired_like")),
                    "external_auth_redirect_like": bool(feats.get("external_auth_redirect_like")),
                }
            )

    def _update_scope_baseline_health(
        *,
        scope_state: Dict[str, Any],
        scope_key: str,
        spec: Any,
        snap: Dict[str, Any],
    ) -> None:
        if not _is_baseline_family(spec):
            return

        scope_state["baseline_attempts"] = int(scope_state.get("baseline_attempts", 0)) + 1

        if _is_pre_header_transport_failure(snap):
            scope_state["baseline_failures"] = int(scope_state.get("baseline_failures", 0)) + 1

            examples = scope_state.setdefault("baseline_failure_examples", [])
            if len(examples) < 5:
                examples.append(
                    {
                        "name": str(getattr(spec, "name", "") or ""),
                        "method": str(getattr(spec, "method", "") or "").upper(),
                        "url": str(getattr(spec, "url", "") or ""),
                        "error_class": str(snap.get("error_class") or ""),
                        "error_phase": str(snap.get("error_phase") or ""),
                    }
                )

            if not scope_state.get("baseline_unhealthy") and int(scope_state.get("baseline_failures", 0)) >= 2:
                scope_state["baseline_unhealthy"] = True
                unhealthy_scopes.add(scope_key)
                log_fn(
                    "SCAN",
                    "[scope-baseline-unhealthy] "
                    f"scope_key={scope_key} "
                    f"baseline_attempts={scope_state.get('baseline_attempts')} "
                    f"baseline_failures={scope_state.get('baseline_failures')} "
                    f"examples={scope_state.get('baseline_failure_examples')}"
                )
            return

        scope_state["baseline_successes"] = int(scope_state.get("baseline_successes", 0)) + 1

    def _should_skip_due_to_unhealthy_scope(
        *,
        scope_key: str,
        scope_state: Dict[str, Any],
        spec: Any,
    ) -> tuple[bool, str]:
        if scope_key in unhealthy_scopes:
            scope_state["baseline_unhealthy"] = True
            if int(scope_state.get("auth_failure_count", 0)) > 0:
                scope_state["auth_unhealthy"] = True

        if (
            not scope_state.get("baseline_unhealthy")
            and not scope_state.get("auth_unhealthy")
            and not scope_state.get("shape_sensitive_unhealthy")
        ):
            return False, ""

        family = str(getattr(spec, "family", "") or "").strip().lower()
        method = str(getattr(spec, "method", "") or "").strip().upper()

        skip_families = {
            "baseline",
            "comparison",
            "cors_behavior",
            "header_behavior",
            "query_param",
        }

        if family in skip_families:
            return True, "auth_unhealthy_scope" if scope_state.get("auth_unhealthy") else "baseline_unhealthy_scope"

        if scope_state.get("shape_sensitive_unhealthy") and family in {"error_path", "error_query", "header_behavior"}:
            return True, "shape_sensitive_get_unhealthy_scope"
        if scope_state.get("shape_sensitive_unhealthy") and family == "authenticated_business_probe" and method == "GET":
            return True, "shape_sensitive_get_unhealthy_scope"

        return False, ""

    def _shape_sensitive_action_score(url: str) -> int:
        path_l = (urlsplit(str(url or "")).path or "").lower()
        score = 0
        for token in (
            "upload", "download", "excel", "export", "import", "update",
            "delete", "create", "insert", "submit", "save", "approval",
        ):
            if token in path_l:
                score += 1
        return score

    def _update_shape_sensitive_health(
        *,
        scope_state: Dict[str, Any],
        scope_key: str,
        spec: Any,
        snap: Dict[str, Any],
        raw_path: str,
    ) -> None:
        if shape_sensitive_error_threshold <= 0:
            return
        method = str(getattr(spec, "method", "") or "").strip().upper()
        if method != "GET":
            return
        status_code = snap.get("status_code")
        if status_code not in {400, 405, 415, 422, 500}:
            return
        if _shape_sensitive_action_score(str(getattr(spec, "url", "") or "")) <= 0:
            return

        scope_state["shape_sensitive_get_errors"] = int(scope_state.get("shape_sensitive_get_errors", 0)) + 1
        examples = scope_state.setdefault("shape_sensitive_examples", [])
        if len(examples) < 5:
            examples.append(
                {
                    "name": str(getattr(spec, "name", "") or ""),
                    "method": method,
                    "url": str(getattr(spec, "url", "") or ""),
                    "status_code": status_code,
                    "raw_ref": raw_path,
                }
            )

        if not scope_state.get("shape_sensitive_unhealthy") and int(scope_state.get("shape_sensitive_get_errors", 0)) >= shape_sensitive_error_threshold:
            scope_state["shape_sensitive_unhealthy"] = True
            log_fn(
                "SCAN",
                "[scope-shape-sensitive-get-unhealthy] "
                f"scope_key={scope_key} "
                f"errors={scope_state.get('shape_sensitive_get_errors')} "
                f"threshold={shape_sensitive_error_threshold} "
                f"examples={scope_state.get('shape_sensitive_examples')}"
            )

    async def run_one(idx: int, spec: Any) -> Dict[str, Any]:
        scope_key = probe_scope_key(spec)
        scope_state = scope_states.setdefault(scope_key, _new_scope_state())

        if scope_key in unhealthy_scopes:
            scope_state["baseline_unhealthy"] = True

        log_fn(
            "SCAN",
            "[run_one] "
            f"name={getattr(spec, 'name', '')} "
            f"method={getattr(spec, 'method', '')} "
            f"url={getattr(spec, 'url', '')} "
            f"scope_key={scope_key}"
        )

        skip_scope, skip_reason = _should_skip_due_to_unhealthy_scope(
            scope_key=scope_key,
            scope_state=scope_state,
            spec=spec,
        )
        if skip_scope:
            log_fn(
                "SCAN",
                "[scope-skip] "
                f"name={getattr(spec, 'name', '')} "
                f"method={getattr(spec, 'method', '')} "
                f"url={getattr(spec, 'url', '')} "
                f"scope_key={scope_key} "
                f"reason={skip_reason} "
                f"baseline_failures={scope_state.get('baseline_failures')} "
                f"baseline_attempts={scope_state.get('baseline_attempts')}"
            )
            return {
                "skipped": True,
                "skip_reason": skip_reason,
                "spec": spec,
                "scope_key": scope_key,
            }

        if should_skip_probe_for_static(spec):
            log_fn("SCAN", f"Skipping low-value static probe: {spec.method} {spec.url}")
            return {
                "skipped": True,
                "skip_reason": "static",
                "spec": spec,
                "scope_key": scope_key,
            }

        log_fn(
            "SCAN",
            f"({idx}/{len(plan)}) {spec.method} {spec.url} "
            f"name={getattr(spec, 'name', '')} "
            f"family={getattr(spec, 'family', '')} "
            f"mutation={getattr(spec, 'mutation_class', '')}"
        )

        try:
            mark_attempted_for_spec_fn(spec, coverage)
        except Exception:
            pass

        try:
            snap = await send_once(client, spec, timeout_s)
            log_fn(
                "SCAN",
                "[run_one-result] "
                f"name={getattr(spec, 'name', '')} "
                f"method={getattr(spec, 'method', '')} "
                f"url={getattr(spec, 'url', '')} "
                f"ok={snap.get('ok')} "
                f"status={snap.get('status_code')} "
                f"final_url={snap.get('final_url')} "
                f"headers_received={snap.get('headers_received')} "
                f"body_read_ok={snap.get('body_read_ok')} "
                f"error_phase={snap.get('error_phase')} "
                f"error_class={snap.get('error_class')}"
            )

        except Exception as e:
            snap = {
                "ok": False,
                "error": f"{type(e).__name__}: {e}",
                "error_phase": "request",
                "error_class": type(e).__name__,
                "status_code": None,
                "final_url": str(getattr(spec, "url", "") or ""),
                "headers": {},
                "body_snippet": "",
                "redirect_chain": [],
                "elapsed_ms": 0,
                "set_cookie_objects": [],
                "set_cookie_headers": [],
                "set_cookie_present": False,
                "cookie_jar_before_names": [],
                "cookie_jar_after_names": [],
                "cookie_jar_added_names": [],
                "cookie_jar_removed_names": [],
                "cookie_jar_changed": False,
                "cookie_jar_observed": False,
                "headers_received": False,
                "body_read_ok": False,
            }

        try:
            update_cookie_observation_fn(snap, coverage)
        except Exception:
            pass

        return {
            "skipped": False,
            "spec": spec,
            "snap": snap,
            "scope_key": scope_key,
        }

    for batch_start in range(0, len(plan), batch_size):
        if str(request_auth_state or "").strip().lower() == "authenticated":
            now = time.monotonic()
            deadline_exceeded = bool(auth_deadline_monotonic is not None and now >= auth_deadline_monotonic)
            elapsed = now - auth_started_at
            local_budget_exceeded = bool(auth_session_budget_seconds > 0 and elapsed >= auth_session_budget_seconds)
            if deadline_exceeded or local_budget_exceeded:
                auth_budget_exhausted = True
                log_fn(
                    "AUTH",
                    "[auth-session-budget-exhausted] "
                    f"elapsed_s={elapsed:.1f} "
                    f"budget_s={auth_session_budget_seconds:.1f} "
                    f"deadline_exceeded={deadline_exceeded} "
                    f"remaining_specs={max(0, len(plan) - batch_start)}"
                )
                break

        batch_specs = plan[batch_start: batch_start + batch_size]
        tasks = [
            run_one(batch_start + offset + 1, spec)
            for offset, spec in enumerate(batch_specs)
        ]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        for batch_offset, result in enumerate(batch_results):
            spec = batch_specs[batch_offset]

            if isinstance(result, Exception):
                log_fn(
                    "SCAN",
                    "[batch-result-exception] "
                    f"name={getattr(spec, 'name', '')} "
                    f"method={getattr(spec, 'method', '')} "
                    f"url={getattr(spec, 'url', '')} "
                    f"error={type(result).__name__}: {result}"
                )
                _append_request_failure(
                    spec=spec,
                    snap={"error": f"{type(result).__name__}: {result}"},
                    raw_path=None,
                )
                continue

            if result.get("skipped"):
                log_fn(
                    "SCAN",
                    "[batch-result-skipped] "
                    f"name={getattr(spec, 'name', '')} "
                    f"method={getattr(spec, 'method', '')} "
                    f"url={getattr(spec, 'url', '')} "
                    f"reason={result.get('skip_reason')}"
                )
                continue

            spec = result["spec"]
            snap = result["snap"]
            scope_key = result["scope_key"]
            scope_state = scope_states.setdefault(scope_key, _new_scope_state())

            raw_path = save_raw_capture(raw_dir, seq, spec, snap)
            _append_raw_index(
                seq_no=seq,
                spec=spec,
                snap=snap,
                raw_path=str(raw_path),
                scope_key=scope_key,
            )
            seq += 1

            _update_scope_baseline_health(
                scope_state=scope_state,
                scope_key=scope_key,
                spec=spec,
                snap=snap,
            )
            _update_shape_sensitive_health(
                scope_state=scope_state,
                scope_key=scope_key,
                spec=spec,
                snap=snap,
                raw_path=str(raw_path),
            )

            snap_headers = snap.get("headers") or {}
            if not isinstance(snap_headers, dict):
                snap_headers = {}

            has_usable_response = bool(
                snap.get("status_code") is not None or snap_headers
            )

            if not snap.get("ok") and not has_usable_response:
                log_fn(
                    "SCAN",
                    "[pre-candidate-drop] "
                    f"name={getattr(spec, 'name', '')} "
                    f"method={getattr(spec, 'method', '')} "
                    f"url={getattr(spec, 'url', '')} "
                    f"ok={snap.get('ok')} "
                    f"status={snap.get('status_code')} "
                    f"error={snap.get('error')} "
                    f"error_phase={snap.get('error_phase')}"
                )
                _append_request_failure(
                    spec=spec,
                    snap=snap,
                    raw_path=str(raw_path),
                )
                continue

            if not snap.get("ok") and has_usable_response:
                log_fn(
                    "SCAN",
                    "[pre-candidate-partial] "
                    f"name={getattr(spec, 'name', '')} "
                    f"method={getattr(spec, 'method', '')} "
                    f"url={getattr(spec, 'url', '')} "
                    f"ok={snap.get('ok')} "
                    f"status={snap.get('status_code')} "
                    f"error={snap.get('error')} "
                    f"error_phase={snap.get('error_phase')} "
                    f"headers_received={snap.get('headers_received')} "
                    f"body_read_ok={snap.get('body_read_ok')}"
                )

            log_fn(
                "SCAN",
                "[pre-candidate] "
                f"name={getattr(spec, 'name', '')} "
                f"method={getattr(spec, 'method', '')} "
                f"url={getattr(spec, 'url', '')} "
                f"status={snap.get('status_code')} "
                f"final_url={snap.get('final_url')} "
                f"headers_received={snap.get('headers_received')} "
                f"body_read_ok={snap.get('body_read_ok')} "
                f"error_phase={snap.get('error_phase')}"
            )

            skip_external, skip_debug = _should_skip_external_final_response(spec, snap)
            log_fn(
                "SCAN",
                "[pre-candidate-debug] "
                f"name={getattr(spec, 'name', '')} "
                f"method={getattr(spec, 'method', '')} "
                f"url={getattr(spec, 'url', '')} "
                f"requested_url={skip_debug.get('requested_url')} "
                f"final_url={skip_debug.get('final_url')} "
                f"requested_origin={skip_debug.get('requested_origin')} "
                f"final_origin={skip_debug.get('final_origin')} "
                f"skip_external={skip_external} "
                f"reason={skip_debug.get('reason')}"
            )
            if skip_external:
                log_fn(
                    "SCAN",
                    "[pre-candidate-skip-external-final] "
                    f"name={getattr(spec, 'name', '')} "
                    f"method={getattr(spec, 'method', '')} "
                    f"url={getattr(spec, 'url', '')} "
                    f"status={snap.get('status_code')} "
                    f"final_url={snap.get('final_url')} "
                    f"reason={skip_debug.get('reason')}"
                )
                continue

            req_meta = _build_request_meta(spec)
            feats = extract_features(req_meta, snap)
            auth_state = _effective_auth_state(spec)
            _update_scope_auth_health(
                scope_state=scope_state,
                scope_key=scope_key,
                spec=spec,
                feats=feats,
                auth_state=auth_state,
                raw_path=str(raw_path),
            )
            candidates = apply_base_severity_to_candidates(
                generate_candidates(req_meta, snap, feats)
            )
            log_fn(
                "SCAN",
                "[post-candidate] "
                f"name={req_meta.get('name')} "
                f"method={req_meta.get('method')} "
                f"url={req_meta.get('url')} "
                f"count={len(candidates)} "
                f"types={[c.get('type') for c in candidates]}"
            )

            for cand in candidates:
                update_coverage_from_candidate_fn(cand, coverage)

            for cand in candidates:
                cand["raw_ref"] = str(raw_path)

                finalized_items = await _finalize_candidate(
                    client=client,
                    spec=spec,
                    snap=snap,
                    cand=cand,
                    timeout_s=timeout_s,
                    retries=retries,
                    llm_judge_if_enabled_fn=llm_judge_if_enabled_fn,
                    stable_key_fn=stable_key_fn,
                )

                if not isinstance(finalized_items, list):
                    finalized_items = [finalized_items]

                for finalized in finalized_items:
                    if not isinstance(finalized, dict):
                        continue

                    finalized["raw_ref"] = str(raw_path)
                    update_scope_state_from_candidate(scope_state, finalized)

                    key = stable_key_fn(finalized)
                    verdict = (finalized.get("verification") or {}).get("verdict")

                    _store_with_verdict_precedence(
                        key=key,
                        cand=finalized,
                        verdict=verdict,
                        confirmed_map=confirmed_map,
                        informational_map=informational_map,
                        false_positive_map=false_positive_map,
                    )

    confirmed_items = apply_combination_severity(list(confirmed_map.values()))
    informational_items = apply_combination_severity(list(informational_map.values()))
    false_positive_items = apply_combination_severity(list(false_positive_map.values()))

    confirmed_map = {stable_key_fn(x): x for x in confirmed_items}
    informational_map = {stable_key_fn(x): x for x in informational_items}
    false_positive_map = {stable_key_fn(x): x for x in false_positive_items}

    return {
        "confirmed_map": confirmed_map,
        "informational_map": informational_map,
        "false_positive_map": false_positive_map,
        "request_failures": request_failures,
        "next_seq": seq,
        "auth_session_budget_exhausted": auth_budget_exhausted,
    }
