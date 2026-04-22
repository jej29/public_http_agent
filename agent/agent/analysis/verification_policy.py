from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, List, Optional

import hashlib
import difflib
import json
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit

import httpx

from pathlib import Path
from agent.core.common import log
from agent.core.evidence_policy import (
    has_strong_config_evidence,
    has_strong_error_disclosure,
    has_strong_file_path_evidence,
    has_strong_log_evidence,
    has_strong_phpinfo_evidence,
    has_strong_system_info,
    is_https_cookie_secure_case,
)
from agent.findings.types import AMBIGUOUS_TYPES, DETERMINISTIC_TYPES
from agent.core.scope import normalize_url_for_dedup

def build_signal_metadata(
    *,
    signal_strength: str = "weak",
    signal_repeatability: str = "unknown",
    observation_scope: str = "request_specific",
    verification_strategy: str | None = None,
) -> Dict[str, str]:
    return {
        "signal_strength": signal_strength,
        "signal_repeatability": signal_repeatability,
        "observation_scope": observation_scope,
        "verification_strategy": verification_strategy or derive_verification_strategy(
            signal_strength=signal_strength,
            signal_repeatability=signal_repeatability,
            observation_scope=observation_scope,
        ),
    }


def derive_verification_strategy(
    *,
    signal_strength: str,
    signal_repeatability: str,
    observation_scope: str,
) -> str:
    strength = str(signal_strength or "weak").strip().lower()
    repeatability = str(signal_repeatability or "unknown").strip().lower()
    scope = str(observation_scope or "request_specific").strip().lower()

    if strength == "deterministic" and repeatability == "stable":
        if scope in {"host_policy", "response_policy", "cookie_policy", "transport_policy"}:
            return "single_observation"

    if strength in {"deterministic", "strong"} and repeatability in {"stable", "likely_stable"}:
        if scope in {"route_behavior", "app_behavior", "request_specific"}:
            return "reproduce_required"

    if strength == "weak":
        return "manual_review"

    return "reproduce_required"


def is_deterministic_finding(candidate: Dict[str, Any]) -> bool:
    return str(candidate.get("type") or "") in DETERMINISTIC_TYPES


def is_ambiguous_finding(candidate: Dict[str, Any]) -> bool:
    return str(candidate.get("type") or "") in AMBIGUOUS_TYPES


def should_skip_reproduce(candidate: Dict[str, Any]) -> bool:
    candidate_type = str(candidate.get("type") or "")

    if candidate_type == "RISKY_HTTP_METHODS_ENABLED":
        return False

    if candidate_type in {"HTTP_PUT_UPLOAD_CAPABILITY", "HTTP_DELETE_CAPABILITY"}:
        return True

    strategy = str(candidate.get("verification_strategy") or "").strip().lower()
    if strategy == "single_observation":
        return True

    if candidate_type in {
        "COOKIE_HTTPONLY_MISSING",
        "COOKIE_SAMESITE_MISSING",
        "CLICKJACKING",
        "CSP_MISSING",
        "CONTENT_TYPE_SNIFFING",
        "REFERRER_POLICY_MISSING",
        "PERMISSIONS_POLICY_MISSING",
        "HSTS_MISSING",
        "HTTPS_REDIRECT_MISSING",
    }:
        return True

    if candidate_type == "COOKIE_SECURE_MISSING" and is_https_cookie_secure_case(candidate):
        return True

    return False


def should_mark_manual_review(candidate: Dict[str, Any]) -> bool:
    return str(candidate.get("verification_strategy") or "").strip().lower() == "manual_review"

def should_run_llm_judge(candidate: Dict[str, Any]) -> bool:
    candidate_type = str(candidate.get("type") or "")
    family = str(candidate.get("family") or "")
    evidence = candidate.get("evidence") or {}

    if candidate_type == "HTTP_ERROR_INFO_EXPOSURE":
        return has_strong_error_disclosure(candidate)

    if candidate_type == "HTTP_SYSTEM_INFO_EXPOSURE":
        # header/banner-only는 LLM까지 태우지 않음
        if family == "HTTP_HEADER_DISCLOSURE":
            return False
        if str(candidate.get("subtype") or "") == "client_bundle_source_map_or_config":
            return False

        strong_versions = evidence.get("strong_version_tokens_in_body") or []
        internal_ips = evidence.get("internal_ips") or []
        framework_hints = evidence.get("framework_hints") or []
        debug_hints = evidence.get("debug_hints") or []
        body_markers = evidence.get("body_info_markers") or []

        strong_marker_present = any(
            tok in str(x).lower()
            for x in body_markers
            for tok in (
                "apache tomcat/",
                "jboss eap",
                "wildfly/",
                "undertow/",
                "weblogic",
                "websphere",
                "spring boot",
                "django ",
                "flask ",
                "laravel ",
                "asp.net",
                "wordpress",
                "drupal",
                "struts",
            )
        )

        return bool(
            strong_versions
            or strong_marker_present
            or (internal_ips and (framework_hints or debug_hints))
        )

    if candidate_type == "PHPINFO_EXPOSURE":
        return has_strong_phpinfo_evidence(candidate)

    if candidate_type == "HTTP_CONFIG_FILE_EXPOSURE":
        return has_strong_config_evidence(candidate)

    if candidate_type == "LOG_VIEWER_EXPOSURE":
        return has_strong_log_evidence(candidate)

    if candidate_type == "FILE_PATH_HANDLING_ANOMALY":
        return has_strong_file_path_evidence(candidate)

    return False

def verification_mode(candidate: Dict[str, Any]) -> str:
    candidate_type = str(candidate.get("type") or "")
    family = str(candidate.get("family") or "")

    if candidate_type in {
        "RISKY_HTTP_METHODS_ENABLED",
        "HTTP_PUT_UPLOAD_CAPABILITY",
        "HTTP_DELETE_CAPABILITY",
    }:
        return "method_capability"

    if candidate_type == "CORS_MISCONFIG":
        return "cors_policy"

    if candidate_type == "DIRECTORY_LISTING_ENABLED":
        return "content_reproduce"

    if candidate_type == "DEFAULT_FILE_EXPOSED":
        return "resource_content"

    if candidate_type == "TRACE_ENABLED":
        return "trace_echo"

    if candidate_type == "HTTP_SYSTEM_INFO_EXPOSURE" and family == "HTTP_HEADER_DISCLOSURE":
        return "single_observation"

    if is_ambiguous_finding(candidate):
        return "content_reproduce"

    return "generic_reproduce"

def should_run_reproduce(candidate: Dict[str, Any]) -> bool:
    if should_skip_reproduce(candidate):
        return False

    candidate_type = str(candidate.get("type") or "")
    family = str(candidate.get("family") or "")
    evidence = candidate.get("evidence") or {}

    if candidate_type in {
        "TRACE_ENABLED",
        "RISKY_HTTP_METHODS_ENABLED",
        "CORS_MISCONFIG",
        "DIRECTORY_LISTING_ENABLED",
        "DEFAULT_FILE_EXPOSED",
    }:
        return True

    if candidate_type == "COOKIE_SECURE_MISSING" and not is_https_cookie_secure_case(candidate):
        return False

    if candidate_type == "HTTP_ERROR_INFO_EXPOSURE":
        return has_strong_error_disclosure(candidate)

    if candidate_type == "HTTP_SYSTEM_INFO_EXPOSURE":
        # header disclosure는 single observation 성격
        if family == "HTTP_HEADER_DISCLOSURE":
            return False

        strong_versions = evidence.get("strong_version_tokens_in_body") or []
        internal_ips = evidence.get("internal_ips") or []
        framework_hints = evidence.get("framework_hints") or []
        debug_hints = evidence.get("debug_hints") or []
        body_markers = evidence.get("body_info_markers") or []

        strong_marker_present = any(
            tok in str(x).lower()
            for x in body_markers
            for tok in (
                "apache tomcat/",
                "jboss eap",
                "wildfly/",
                "undertow/",
                "weblogic",
                "websphere",
                "spring boot",
                "django ",
                "flask ",
                "laravel ",
                "asp.net",
                "wordpress",
                "drupal",
                "struts",
            )
        )

        return bool(
            strong_versions
            or strong_marker_present
            or (internal_ips and (framework_hints or debug_hints))
        )

    if candidate_type == "PHPINFO_EXPOSURE":
        return has_strong_phpinfo_evidence(candidate)

    if candidate_type == "HTTP_CONFIG_FILE_EXPOSURE":
        return has_strong_config_evidence(candidate)

    if candidate_type == "LOG_VIEWER_EXPOSURE":
        return has_strong_log_evidence(candidate)

    if candidate_type == "FILE_PATH_HANDLING_ANOMALY":
        return has_strong_file_path_evidence(candidate)

    return is_ambiguous_finding(candidate)

# --------------------------------------------------------------------
# Auth / Session verification helpers
# --------------------------------------------------------------------

def _auth_required_like_response(resp: httpx.Response) -> bool:
    body = (resp.text or "").lower()
    final_url = str(resp.url or "").lower()

    try:
        status_code = int(resp.status_code)
    except Exception:
        status_code = None

    if status_code in {401, 403}:
        return True

    if any(x in final_url for x in ("/login", "/signin", "/sign-in", "login.php", "/auth")):
        return True

    if looks_like_login_page(str(resp.url or ""), resp.text or ""):
        return True

    auth_required_markers = (
        "login",
        "sign in",
        "please log in",
        "authentication required",
        "authorization required",
        "enter your credentials",
        "access denied",
        "unauthorized",
        "forbidden",
        "session expired",
        "your session has expired",
    )
    if any(marker in body for marker in auth_required_markers):
        return True

    form_like = "<form" in body and (
        "password" in body
        or "username" in body
        or "userid" in body
        or "email" in body
    )
    if form_like:
        return True

    redirect_like_markers = (
        "window.location",
        "location.href",
        "document.location",
    )
    if any(marker in body for marker in redirect_like_markers) and any(
        tok in body for tok in ("login", "signin", "auth")
    ):
        return True

    return False

def _protected_logout_url(landing_url: str) -> str:
    lower = landing_url.lower()
    if "/portal.php" in lower:
        return landing_url.replace("/portal.php", "/logout.php")
    if "/index.php" in lower:
        return landing_url.replace("/index.php", "/logout.php")

    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(landing_url)
    return urlunsplit((parts.scheme, parts.netloc, "/logout.php", "", ""))


def _extract_cookie_jar_map(client: httpx.AsyncClient) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for c in client.cookies.jar:
            name = str(getattr(c, "name", "") or "").strip()
            value = str(getattr(c, "value", "") or "")
            if name:
                out[name] = value
    except Exception:
        try:
            for name in client.cookies.keys():
                out[str(name)] = ""
        except Exception:
            pass
    return out


def _is_sessionish_cookie_name(name: str) -> bool:
    nl = str(name or "").strip().lower()
    if not nl:
        return False
    return any(
        tok in nl
        for tok in (
            "sess",
            "session",
            "sid",
            "phpsessid",
            "jsessionid",
            "auth",
            "token",
        )
    )


def _extract_session_cookie_names_from_auth_result(auth_result: Dict[str, Any]) -> List[str]:
    names: List[str] = []

    for obs in auth_result.get("cookie_observations") or []:
        if not isinstance(obs, dict):
            continue
        n = str(obs.get("cookie_name") or "").strip()
        if n and _is_sessionish_cookie_name(n):
            names.append(n)

    for item in auth_result.get("auth_snapshots") or []:
        if not isinstance(item, dict):
            continue
        snap = item.get("snapshot") or {}
        if not isinstance(snap, dict):
            continue
        for c in snap.get("set_cookie_objects") or []:
            if not isinstance(c, dict):
                continue
            n = str(c.get("name") or "").strip()
            if n and _is_sessionish_cookie_name(n):
                names.append(n)

    out: List[str] = []
    seen = set()
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _authenticated_markers(text: str, final_url: str) -> List[str]:
    body = (text or "").lower()
    url = (final_url or "").lower()
    markers: List[str] = []

    if any(x in url for x in ("/portal", "/dashboard", "/account", "/home", "/profile")):
        markers.append("protected_final_url")
    if "logout" in body or "log out" in body or "sign out" in body:
        markers.append("logout_link_present")
    if "choose your bug" in body:
        markers.append("bwapp_portal_marker")
    if "welcome" in body:
        markers.append("welcome_marker")

    return markers


def looks_like_login_page(final_url: str, body_text: str) -> bool:
    url_l = (final_url or "").lower()
    text = body_text or ""
    body_l = text.lower()

    if not body_l.strip():
        return False

    error_markers = (
        "404 not found",
        "405 method not allowed",
        "<title>404",
        "<title>405",
        "<h1>not found</h1>",
        "<h1>method not allowed</h1>",
        "the requested url was not found",
    )
    if any(x in body_l for x in error_markers):
        return False

    url_hint = any(x in url_l for x in (
        "login", "signin", "sign-in", "auth", "session"
    ))

    has_password_field = any(
        x in body_l for x in (
            'type="password"',
            "type='password'",
            'name="password"',
            "name='password'",
            'name="pass"',
            "name='pass'",
            'name="passwd"',
            "name='passwd'",
        )
    )

    has_user_field = any(
        x in body_l for x in (
            'name="login"',
            "name='login'",
            'name="username"',
            "name='username'",
            'name="user"',
            "name='user'",
            'name="email"',
            "name='email'",
            'name="userid"',
            "name='userid'",
        )
    )

    has_submit_like = any(
        x in body_l for x in (
            ">login<",
            'value="login"',
            "value='login'",
            ">sign in<",
            'value="sign in"',
            "value='sign in'",
            'type="submit"',
            "type='submit'",
            ">log in<",
            ">signin<",
        )
    )

    has_form_tag = "<form" in body_l
    has_auth_words = any(
        x in body_l for x in (
            "login",
            "log in",
            "sign in",
            "signin",
            "username",
            "password",
            "remember me",
            "forgot password",
            "authentication required",
        )
    )

    # 1) 가장 강한 시그널: 비밀번호 필드 + (유저 필드 or submit)
    if has_password_field and (has_user_field or has_submit_like):
        return True

    # 2) form + password + 인증 단어
    if has_form_tag and has_password_field and has_auth_words:
        return True

    # 3) URL 힌트 + password 필드
    if url_hint and has_password_field:
        return True

    # 4) URL 힌트 + form + user field
    if url_hint and has_form_tag and has_user_field:
        return True

    return False

def parse_login_forms(base_url: str, body_text: str) -> List[Dict[str, Any]]:
    from html import unescape

    text = body_text or ""
    forms: List[Dict[str, Any]] = []

    form_pattern = re.compile(
        r"<form\b(?P<attrs>[^>]*)>(?P<body>.*?)</form>",
        re.I | re.S,
    )
    attr_pattern = re.compile(
        r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(".*?"|\'.*?\'|[^\s>]+)',
        re.I | re.S,
    )

    def parse_attrs(raw_attrs: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, v in attr_pattern.findall(raw_attrs or ""):
            vv = v.strip().strip('"').strip("'")
            out[k.lower()] = unescape(vv)
        return out

    input_pattern = re.compile(r"<input\b(?P<attrs>[^>]*)>", re.I | re.S)
    select_pattern = re.compile(r"<select\b(?P<attrs>[^>]*)>(?P<body>.*?)</select>", re.I | re.S)
    option_pattern = re.compile(r"<option\b(?P<attrs>[^>]*)>(?P<body>.*?)</option>", re.I | re.S)
    textarea_pattern = re.compile(r"<textarea\b(?P<attrs>[^>]*)>(?P<body>.*?)</textarea>", re.I | re.S)
    button_pattern = re.compile(r"<button\b(?P<attrs>[^>]*)>(?P<body>.*?)</button>", re.I | re.S)

    for m in form_pattern.finditer(text):
        form_attrs = parse_attrs(m.group("attrs"))
        form_body = m.group("body") or ""

        action = form_attrs.get("action", "").strip()
        method = form_attrs.get("method", "get").strip().lower() or "get"

        inputs: List[Dict[str, Any]] = []
        selects: List[Dict[str, Any]] = []
        textareas: List[Dict[str, Any]] = []

        for im in input_pattern.finditer(form_body):
            attrs = parse_attrs(im.group("attrs"))
            inputs.append(
                {
                    "name": attrs.get("name", ""),
                    "type": attrs.get("type", "text").lower(),
                    "value": attrs.get("value", ""),
                    "checked": "checked" in (im.group("attrs") or "").lower(),
                }
            )

        for bm in button_pattern.finditer(form_body):
            attrs = parse_attrs(bm.group("attrs"))
            inputs.append(
                {
                    "name": attrs.get("name", ""),
                    "type": attrs.get("type", "submit").lower(),
                    "value": attrs.get("value", (bm.group("body") or "").strip()),
                    "checked": False,
                }
            )

        for sm in select_pattern.finditer(form_body):
            sattrs = parse_attrs(sm.group("attrs"))
            sbody = sm.group("body") or ""
            options: List[Dict[str, Any]] = []

            for om in option_pattern.finditer(sbody):
                oattrs = parse_attrs(om.group("attrs"))
                raw_attrs = (om.group("attrs") or "").lower()
                options.append(
                    {
                        "value": oattrs.get("value", (om.group("body") or "").strip()),
                        "selected": "selected" in raw_attrs,
                    }
                )

            selects.append(
                {
                    "name": sattrs.get("name", ""),
                    "options": options,
                }
            )

        for tm in textarea_pattern.finditer(form_body):
            tattrs = parse_attrs(tm.group("attrs"))
            textareas.append(
                {
                    "name": tattrs.get("name", ""),
                    "value": unescape((tm.group("body") or "").strip()),
                }
            )

        forms.append(
            {
                "action": urljoin(base_url, action) if action else base_url,
                "method": method,
                "inputs": inputs,
                "selects": selects,
                "textareas": textareas,
            }
        )

    return forms


def select_login_form(forms: List[Dict[str, Any]], final_url: str, body_text: str) -> Dict[str, Any] | None:
    if not forms:
        return None

    best_form: Dict[str, Any] | None = None
    best_score = -9999

    for form in forms:
        inputs = form.get("inputs") or []
        action = str(form.get("action") or "").lower()

        names = {str(i.get("name") or "").lower() for i in inputs if i.get("name")}
        types = {str(i.get("type") or "text").lower() for i in inputs}

        score = 0

        has_password = "password" in types or any(n in names for n in {"password", "pass", "passwd"})
        if has_password:
            score += 5
        else:
            score -= 5

        if names.intersection({"login", "username", "user", "email", "userid"}):
            score += 4

        if "email" in types or "text" in types:
            score += 1

        if "submit" in types:
            score += 1

        if any(x in action for x in ("login", "signin", "sign-in", "auth", "session")):
            score += 2

        if len(inputs) <= 12:
            score += 1

        if score > best_score:
            best_score = score
            best_form = form

    return best_form


def build_auth_payload_from_form(form: Dict[str, Any], username: str, password: str) -> Dict[str, str]:
    payload: Dict[str, str] = {}

    inputs = form.get("inputs") or []
    selects = form.get("selects") or []
    textareas = form.get("textareas") or []

    username_candidates: List[tuple[int, str]] = []
    password_candidates: List[tuple[int, str]] = []

    for item in inputs:
        name = str(item.get("name") or "").strip()
        if not name:
            continue

        itype = str(item.get("type") or "text").lower()
        value = str(item.get("value") or "")
        lname = name.lower()

        if itype == "hidden":
            payload[name] = value
            continue

        if itype in {"submit", "button"}:
            if value:
                payload[name] = value
            continue

        if itype in {"checkbox", "radio"}:
            if bool(item.get("checked")):
                payload[name] = value or "on"
            continue

        if itype == "password":
            score = 10
            if lname == "password":
                score += 3
            if lname in {"pass", "passwd"}:
                score += 2
            password_candidates.append((score, name))
            continue

        if lname in {"password", "pass", "passwd"}:
            password_candidates.append((8, name))
            continue

        if lname == "login":
            username_candidates.append((10, name))
            continue
        if lname == "username":
            username_candidates.append((9, name))
            continue
        if lname == "user":
            username_candidates.append((8, name))
            continue
        if lname == "email":
            username_candidates.append((7, name))
            continue
        if lname == "userid":
            username_candidates.append((6, name))
            continue

        if itype == "email":
            username_candidates.append((7, name))
            continue
        if itype in {"text", "search"}:
            username_candidates.append((3, name))
            continue

    for sel in selects:
        name = str(sel.get("name") or "").strip()
        if not name:
            continue

        options = sel.get("options") or []
        chosen = None

        for opt in options:
            if opt.get("selected"):
                chosen = str(opt.get("value") or "")
                break

        if chosen is None and options:
            chosen = str(options[0].get("value") or "")

        if chosen is not None:
            payload[name] = chosen

    for ta in textareas:
        name = str(ta.get("name") or "").strip()
        if not name:
            continue
        payload[name] = str(ta.get("value") or "")

    if username_candidates:
        username_candidates.sort(key=lambda x: -x[0])
        payload[username_candidates[0][1]] = username
    else:
        payload["username"] = username

    if password_candidates:
        password_candidates.sort(key=lambda x: -x[0])
        payload[password_candidates[0][1]] = password
    else:
        payload["password"] = password

    return payload


# --------------------------------------------------------------------
# Public auth/session verifiers
# --------------------------------------------------------------------

async def verify_auth_bypass(
    *,
    client: httpx.AsyncClient,
    login_url: str,
    username_field: str,
    password_field: str,
    valid_username: str,
    valid_password: str | None,
    timeout_s: float,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    if not valid_username:
        return findings

    def _norm_text(s: str) -> str:
        s = (s or "").lower()
        s = re.sub(r"\s+", " ", s)
        s = re.sub(r"[0-9a-f]{16,}", " ", s)
        return s.strip()

    def _body_fp(body: str) -> str:
        norm = _norm_text(body)
        return hashlib.sha256(norm[:12000].encode("utf-8", errors="ignore")).hexdigest()

    def _similarity(a: str, b: str) -> float:
        if not a and not b:
            return 1.0
        return difflib.SequenceMatcher(None, _norm_text(a), _norm_text(b)).ratio()

    def _extract_visible_signals(resp: httpx.Response) -> Dict[str, Any]:
        final_url = str(resp.url)
        body = resp.text or ""
        body_l = body.lower()

        login_form_like = bool(re.search(r"<form[^>]+", body_l)) and any(
            x in body_l for x in ["password", "login", "username", "user"]
        )

        auth_fail_words = [
            "invalid password",
            "wrong password",
            "invalid credentials",
            "login failed",
            "authentication failed",
            "access denied",
            "incorrect",
            "try again",
        ]
        auth_success_words = [
            "logout",
            "log out",
            "welcome",
            "my account",
            "profile",
            "portal",
            "choose your bug",
        ]

        return {
            "final_url": final_url,
            "final_path": urlparse(final_url).path or "",
            "body_fp": _body_fp(body),
            "body_len": len(body),
            "markers": _authenticated_markers(body, final_url),
            "looks_login_page": looks_like_login_page(final_url, body),
            "has_login_form": login_form_like,
            "has_auth_fail_words": any(w in body_l for w in auth_fail_words),
            "has_auth_success_words": any(w in body_l for w in auth_success_words),
            "auth_required_like": _auth_required_like_response(resp),
        }

    def _cookie_jar_snapshot(c: httpx.AsyncClient) -> List[tuple[str, str, str]]:
        out = []
        for cookie in c.cookies.jar:
            out.append((cookie.domain or "", cookie.path or "", cookie.name))
        return sorted(set(out))

    def _new_cookie_names(before: List[tuple[str, str, str]], after: List[tuple[str, str, str]]) -> List[str]:
        before_set = set(before)
        return [name for (_, _, name) in after if (_, _, name) not in before_set]

    def _remove_submit_like_fields(payload: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(payload)
        for k in list(out.keys()):
            lk = str(k).lower()
            if lk in {"submit", "form", "login", "signin", "sign_in", "submitlogin"}:
                if k not in {username_field, password_field}:
                    out.pop(k, None)
        return out

    def _score_against_baselines(
        *,
        resp: httpx.Response,
        success_sig: Dict[str, Any],
        failure_sigs: List[Dict[str, Any]],
        new_cookie_names: List[str],
    ) -> Dict[str, Any]:
        body = resp.text or ""
        curr = _extract_visible_signals(resp)

        success_sim = _similarity(body, success_sig.get("body", ""))
        failure_sims = [_similarity(body, f.get("body", "")) for f in failure_sigs]
        best_failure_sim = max(failure_sims) if failure_sims else 0.0

        score = 0
        reasons: List[str] = []

        if success_sim >= 0.92:
            score += 5
            reasons.append(f"high_success_similarity:{success_sim:.3f}")
        elif success_sim >= 0.85:
            score += 3
            reasons.append(f"medium_success_similarity:{success_sim:.3f}")
        elif success_sim >= 0.75:
            score += 1
            reasons.append(f"weak_success_similarity:{success_sim:.3f}")

        if success_sim - best_failure_sim >= 0.18:
            score += 4
            reasons.append(f"success_far_from_failure:+{success_sim - best_failure_sim:.3f}")
        elif success_sim - best_failure_sim >= 0.10:
            score += 2
            reasons.append(f"success_above_failure:+{success_sim - best_failure_sim:.3f}")

        if curr["final_path"] and curr["final_path"] == success_sig.get("final_path"):
            score += 2
            reasons.append("final_path_matches_success")

        if curr["markers"]:
            score += 4
            reasons.append(f"authenticated_markers:{curr['markers']}")
        if curr["has_auth_success_words"]:
            score += 1
            reasons.append("success_words_present")

        if curr["looks_login_page"]:
            score -= 2
            reasons.append("looks_like_login_page")
        if curr["has_login_form"]:
            score -= 2
            reasons.append("login_form_present")
        if curr["has_auth_fail_words"]:
            score -= 3
            reasons.append("auth_fail_words_present")
        if curr["auth_required_like"]:
            score -= 2
            reasons.append("auth_required_like_response")

        if new_cookie_names:
            score += 2
            reasons.append(f"new_cookies:{new_cookie_names}")

        verdict = "NEGATIVE"
        if score >= 6 and success_sim >= 0.80 and success_sim > best_failure_sim:
            verdict = "CONFIRMED"
        elif score >= 3 and success_sim >= 0.70 and success_sim > best_failure_sim:
            verdict = "SUSPECTED"

        return {
            "verdict": verdict,
            "score": score,
            "reasons": reasons,
            "success_similarity": round(success_sim, 4),
            "best_failure_similarity": round(best_failure_sim, 4),
            "signals": curr,
        }

    try:
        r_get = await client.get(login_url, timeout=timeout_s)
        final_login_url = str(r_get.url)
        body = r_get.text or ""

        log("AUTHBYPASS", f"login_url={login_url} final_login_url={final_login_url} status={r_get.status_code}")

        if not looks_like_login_page(final_login_url, body):
            log("AUTHBYPASS", "stop: not a login page")
            return findings

        forms = parse_login_forms(final_login_url, body)
        log("AUTHBYPASS", f"forms_found={len(forms)}")

        form = select_login_form(forms, final_login_url, body)
        if form is None:
            log("AUTHBYPASS", "stop: no form selected")
            return findings

        form_action = str(form.get("action") or "").strip()
        post_url = urljoin(final_login_url, form_action) if form_action else final_login_url

        base_payload = build_auth_payload_from_form(form, valid_username, "dummy")
        log("AUTHBYPASS", f"base_payload_keys={sorted(base_payload.keys())}")

        user_key = None
        pass_key = None
        for k in base_payload.keys():
            lk = str(k).lower()
            if lk in {"login", "username", "user", "email", "userid"} and user_key is None:
                user_key = k
            if lk in {"password", "pass", "passwd"} and pass_key is None:
                pass_key = k

        user_key = user_key or username_field
        pass_key = pass_key or password_field

        log("AUTHBYPASS", f"user_key={user_key} pass_key={pass_key} post_url={post_url}")

        def make_payload(
            user_value: str | None,
            pass_value: str | None,
            *,
            drop_user: bool = False,
            drop_pass: bool = False,
            drop_submit_like: bool = False,
        ) -> Dict[str, Any]:
            p = dict(base_payload)

            if drop_submit_like:
                p = _remove_submit_like_fields(p)

            if drop_user:
                p.pop(user_key, None)
            else:
                p[user_key] = "" if user_value is None else user_value

            if drop_pass:
                p.pop(pass_key, None)
            else:
                p[pass_key] = "" if pass_value is None else pass_value

            return p

        async def _submit_with_fresh_client(kind: str, payload: Any) -> tuple[httpx.Response, List[str]]:
            async with httpx.AsyncClient(follow_redirects=True, timeout=timeout_s) as probe_client:
                before = _cookie_jar_snapshot(probe_client)

                if kind == "form_dict":
                    r = await probe_client.post(
                        post_url,
                        data=payload,
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Referer": final_login_url,
                        },
                        timeout=timeout_s,
                    )
                elif kind == "form_tuples":
                    encoded = urlencode(payload, doseq=True)
                    r = await probe_client.post(
                        post_url,
                        content=encoded,
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Referer": final_login_url,
                        },
                        timeout=timeout_s,
                    )
                elif kind == "json":
                    r = await probe_client.post(
                        post_url,
                        content=json.dumps(payload),
                        headers={
                            "Content-Type": "application/json",
                            "Referer": final_login_url,
                        },
                        timeout=timeout_s,
                    )
                elif kind == "text":
                    r = await probe_client.post(
                        post_url,
                        content=str(payload),
                        headers={
                            "Content-Type": "text/plain",
                            "Referer": final_login_url,
                        },
                        timeout=timeout_s,
                    )
                else:
                    raise ValueError(f"unsupported kind={kind}")

                after = _cookie_jar_snapshot(probe_client)
                return r, _new_cookie_names(before, after)

        failure_sigs: List[Dict[str, Any]] = []

        r_fail1, fail1_new_cookies = await _submit_with_fresh_client(
            "form_dict",
            make_payload(valid_username, "clearly_wrong_password_!@#"),
        )
        failure_sigs.append(
            {
                "body": r_fail1.text or "",
                "final_path": urlparse(str(r_fail1.url)).path or "",
                "signals": _extract_visible_signals(r_fail1),
                "new_cookies": fail1_new_cookies,
            }
        )

        r_fail2, fail2_new_cookies = await _submit_with_fresh_client(
            "form_dict",
            make_payload("", ""),
        )
        failure_sigs.append(
            {
                "body": r_fail2.text or "",
                "final_path": urlparse(str(r_fail2.url)).path or "",
                "signals": _extract_visible_signals(r_fail2),
                "new_cookies": fail2_new_cookies,
            }
        )

        if not valid_password:
            log("AUTHBYPASS", "stop: valid_password missing, baseline success comparison unavailable")
            return findings

        r_success, success_new_cookies = await _submit_with_fresh_client(
            "form_dict",
            make_payload(valid_username, valid_password),
        )
        success_sig = {
            "body": r_success.text or "",
            "final_path": urlparse(str(r_success.url)).path or "",
            "signals": _extract_visible_signals(r_success),
            "new_cookies": success_new_cookies,
        }

        log(
            "AUTHBYPASS",
            f"baseline success status={r_success.status_code} final_url={str(r_success.url)} "
            f"success_markers={success_sig['signals']['markers']} success_new_cookies={success_new_cookies}"
        )
        log(
            "AUTHBYPASS",
            f"baseline fail1 status={r_fail1.status_code} final_url={str(r_fail1.url)} "
            f"markers={failure_sigs[0]['signals']['markers']} new_cookies={fail1_new_cookies}"
        )
        log(
            "AUTHBYPASS",
            f"baseline fail2 status={r_fail2.status_code} final_url={str(r_fail2.url)} "
            f"markers={failure_sigs[1]['signals']['markers']} new_cookies={fail2_new_cookies}"
        )

        attempts: List[Dict[str, Any]] = []

        attempts.extend(
            [
                {"kind": "form_dict", "payload": make_payload(valid_username, ""), "label": "blank_password"},
                {
                    "kind": "form_dict",
                    "payload": make_payload(valid_username, None, drop_pass=True),
                    "label": "missing_password",
                },
                {"kind": "form_dict", "payload": make_payload("", ""), "label": "blank_user_blank_password"},
                {
                    "kind": "form_dict",
                    "payload": make_payload(None, "", drop_user=True),
                    "label": "missing_user_blank_password",
                },
                {"kind": "form_dict", "payload": make_payload(valid_username, "0"), "label": "password_zero"},
                {"kind": "form_dict", "payload": make_payload(valid_username, "null"), "label": "password_null"},
                {"kind": "form_dict", "payload": make_payload(valid_username, "true"), "label": "password_true"},
                {
                    "kind": "form_dict",
                    "payload": make_payload(valid_username + "'--", "x"),
                    "label": "user_quote_comment",
                },
                {
                    "kind": "form_dict",
                    "payload": make_payload(valid_username + "#", "x"),
                    "label": "user_hash_comment",
                },
                {
                    "kind": "form_dict",
                    "payload": make_payload(valid_username, "", drop_submit_like=True),
                    "label": "drop_submit_like_fields",
                },
            ]
        )

        base_without_auth = [(k, v) for k, v in base_payload.items() if k not in {user_key, pass_key}]
        attempts.extend(
            [
                {
                    "kind": "form_tuples",
                    "payload": [
                        *base_without_auth,
                        (user_key, valid_username),
                        (user_key, valid_username + "_dup"),
                        (pass_key, "x"),
                    ],
                    "label": "dup_username",
                },
                {
                    "kind": "form_tuples",
                    "payload": [
                        *base_without_auth,
                        (user_key, valid_username),
                        (pass_key, "x"),
                        (pass_key, ""),
                    ],
                    "label": "dup_password",
                },
                {
                    "kind": "form_tuples",
                    "payload": [
                        *base_without_auth,
                        (user_key, valid_username),
                        (user_key, valid_username + "_dup"),
                        (pass_key, "x"),
                        (pass_key, ""),
                    ],
                    "label": "dup_user_and_password",
                },
            ]
        )

        attempts.extend(
            [
                {"kind": "json", "payload": {user_key: valid_username, pass_key: ""}, "label": "json_blank_password"},
                {"kind": "json", "payload": {user_key: valid_username, pass_key: "x"}, "label": "json_bad_password"},
                {
                    "kind": "json",
                    "payload": {user_key: valid_username + "'--", pass_key: "x"},
                    "label": "json_injection_style",
                },
            ]
        )

        attempts.extend(
            [
                {
                    "kind": "text",
                    "payload": f"{user_key}={valid_username}&{pass_key}=",
                    "label": "text_plain_blank_password",
                },
                {
                    "kind": "text",
                    "payload": f"{user_key}={valid_username}&{pass_key}=x",
                    "label": "text_plain_bad_password",
                },
            ]
        )

        for idx, attempt in enumerate(attempts, start=1):
            try:
                kind = attempt["kind"]
                payload = attempt["payload"]
                label = attempt["label"]

                r, new_cookie_names = await _submit_with_fresh_client(kind, payload)

                decision = _score_against_baselines(
                    resp=r,
                    success_sig=success_sig,
                    failure_sigs=failure_sigs,
                    new_cookie_names=new_cookie_names,
                )

                log(
                    "AUTHBYPASS",
                    f"payload[{idx}] label={label} kind={kind} status={r.status_code} final_url={str(r.url)} "
                    f"verdict={decision['verdict']} score={decision['score']} "
                    f"success_sim={decision['success_similarity']} fail_sim={decision['best_failure_similarity']} "
                    f"reasons={decision['reasons']} payload={payload}"
                )

                if decision["verdict"] == "CONFIRMED":
                    findings.append(
                        {
                            "type": "AUTH_BYPASS",
                            "severity": "High",
                            "title": "인증 우회 가능",
                            "family": "AUTHENTICATION",
                            "subtype": "auth_bypass",
                            "cwe": "CWE-287",
                            "owasp": "A07:2021 Identification and Authentication Failures",
                            "verification": {
                                "verdict": "CONFIRMED",
                                "reason": (
                                    "Malformed or incomplete authentication input produced a response "
                                    "closer to successful authentication baseline than to failure baseline."
                                ),
                            },
                            "evidence": {
                                "login_url": final_login_url,
                                "post_url": post_url,
                                "attempt_label": label,
                                "attempt_kind": kind,
                                "payload": str(payload),
                                "status_code": r.status_code,
                                "final_url": str(r.url),
                                "body_snippet": (r.text or "")[:500],
                                "authenticated_markers": decision["signals"]["markers"],
                                "decision_score": decision["score"],
                                "decision_reasons": decision["reasons"],
                                "success_similarity": decision["success_similarity"],
                                "best_failure_similarity": decision["best_failure_similarity"],
                                "new_cookie_names": new_cookie_names,
                                "baseline_success_final_path": success_sig["final_path"],
                                "baseline_failure_final_paths": [f["final_path"] for f in failure_sigs],
                            },
                        }
                    )
                    log("AUTHBYPASS", f"confirmed with payload[{idx}] label={label}")
                    break

            except Exception as e:
                log("AUTHBYPASS", f"payload[{idx}] exception={type(e).__name__}: {e}")
                continue

    except Exception as e:
        log("AUTHBYPASS", f"outer exception={type(e).__name__}: {e}")
        return findings

    return findings


async def verify_session_controls(
    *,
    target: str,
    auth: Dict[str, str],
    timeout_s: float,
    authenticate_fn: Callable[..., Awaitable[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    username = str(auth.get("username") or "").strip()
    password = str(auth.get("password") or "").strip()
    if not username or not password:
        return findings

    def _body_snippet(resp: httpx.Response, limit: int = 500) -> str:
        try:
            return (resp.text or "")[:limit]
        except Exception:
            return ""

    def _auth_markers(resp: httpx.Response) -> List[str]:
        try:
            return _authenticated_markers(resp.text or "", str(resp.url or ""))
        except Exception:
            return []

    def _looks_authenticated(resp: httpx.Response) -> bool:
        if _auth_required_like_response(resp):
            return False

        markers = _auth_markers(resp)
        if markers:
            return True

        body_l = (resp.text or "").lower()
        if any(tok in body_l for tok in ("logout", "log out", "sign out", "my account", "profile", "dashboard")):
            return True

        return False

    # ------------------------------------------------------------
    # separate session #1: verify unauthenticated landing access
    # ------------------------------------------------------------
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout_s,
            verify=False,
            trust_env=False,
            http2=False,
        ) as baseline_client:
            baseline_auth_result = await authenticate_fn(
                client=baseline_client,
                target=target,
                timeout_s=timeout_s,
                username=username,
                password=password,
            )

            if baseline_auth_result.get("ok"):
                landing_url = str(baseline_auth_result.get("landing_url") or "").strip()

                if landing_url:
                    async with httpx.AsyncClient(
                        follow_redirects=True,
                        timeout=timeout_s,
                        verify=False,
                        trust_env=False,
                        http2=False,
                    ) as anon_client:
                        anon_resp = await anon_client.get(landing_url)

                        if _looks_authenticated(anon_resp):
                            findings.append(
                                {
                                    "type": "AUTH_REQUIRED_BYPASS",
                                    "title": "인증 없이 보호 페이지 접근 가능",
                                    "severity": "High",
                                    "family": "AUTH_SESSION",
                                    "subtype": "unauthenticated_access",
                                    "owasp": "A01:2021 Broken Access Control",
                                    "cwe": "CWE-306",
                                    "verification": {
                                        "verdict": "CONFIRMED",
                                        "reason": "Authenticated landing page was reachable without any authenticated session.",
                                    },
                                    "evidence": {
                                        "landing_url": landing_url,
                                        "status_code": anon_resp.status_code,
                                        "final_url": str(anon_resp.url),
                                        "authenticated_markers": _auth_markers(anon_resp),
                                        "body_snippet": _body_snippet(anon_resp),
                                    },
                                }
                            )
    except Exception:
        pass

    # ------------------------------------------------------------
    # separate session #2: verify logout invalidation
    # IMPORTANT:
    # do NOT use the main scan client
    # ------------------------------------------------------------
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=timeout_s,
            verify=False,
            trust_env=False,
            http2=False,
        ) as session_client:
            auth_result = await authenticate_fn(
                client=session_client,
                target=target,
                timeout_s=timeout_s,
                username=username,
                password=password,
            )

            if auth_result.get("ok"):
                landing_url = str(auth_result.get("landing_url") or "").strip()
                if landing_url:
                    before_cookie_names = sorted(str(k) for k in session_client.cookies.keys())

                    logout_url = _protected_logout_url(landing_url)
                    logout_resp = await session_client.get(logout_url, follow_redirects=True, timeout=timeout_s)
                    after_resp = await session_client.get(landing_url, follow_redirects=True, timeout=timeout_s)

                    after_cookie_names = sorted(str(k) for k in session_client.cookies.keys())
                    markers = _auth_markers(after_resp)

                    if _looks_authenticated(after_resp):
                        findings.append(
                            {
                                "type": "SESSION_NOT_INVALIDATED",
                                "severity": "High",
                                "cwe": "CWE-613",
                                "title": "로그아웃 후에도 인증 세션이 유효함",
                                "family": "AUTH_SESSION",
                                "subtype": "logout_not_invalidated",
                                "owasp": "A07:2021 Identification and Authentication Failures",
                                "verification": {
                                    "verdict": "CONFIRMED",
                                    "reason": "After logout, the protected page still appeared authenticated based on post-login markers.",
                                },
                                "evidence": {
                                    "logout_url": logout_url,
                                    "check_url": landing_url,
                                    "logout_status": logout_resp.status_code,
                                    "post_logout_status": after_resp.status_code,
                                    "post_logout_final_url": str(after_resp.url),
                                    "post_logout_authenticated_markers": markers,
                                    "cookie_names_before_logout": before_cookie_names,
                                    "cookie_names_after_logout": after_cookie_names,
                                    "post_logout_body_snippet": _body_snippet(after_resp),
                                },
                            }
                        )
    except Exception:
        pass

    return findings



async def verify_session_fixation(
    *,
    target: str,
    auth: Dict[str, str],
    timeout_s: float,
    authenticate_fn: Callable[..., Awaitable[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    username = auth.get("username")
    password = auth.get("password")
    if not username or not password:
        return findings

    def _extract_cookie_jar(client: httpx.AsyncClient) -> Dict[str, str]:
        jar_values: Dict[str, str] = {}
        try:
            for c in client.cookies.jar:
                name = str(getattr(c, "name", "") or "").strip()
                value = str(getattr(c, "value", "") or "")
                if name:
                    jar_values[name] = value
        except Exception:
            pass
        return jar_values

    def _extract_observed_cookie_names(auth_result: Dict[str, Any]) -> List[str]:
        names: List[str] = []

        for obs in auth_result.get("cookie_observations") or []:
            if not isinstance(obs, dict):
                continue
            n = str(obs.get("cookie_name") or "").strip()
            if n:
                names.append(n)

        for item in auth_result.get("auth_snapshots") or []:
            if not isinstance(item, dict):
                continue
            snap = item.get("snapshot") or {}
            if not isinstance(snap, dict):
                continue
            for c in snap.get("set_cookie_objects") or []:
                if not isinstance(c, dict):
                    continue
                n = str(c.get("name") or "").strip()
                if n:
                    names.append(n)

        out: List[str] = []
        seen = set()
        for n in names:
            if not _is_sessionish_cookie_name(n):
                continue
            if n in seen:
                continue
            seen.add(n)
            out.append(n)
        return out

    fixed_value = "oai-fixed-session-id"

    # 먼저 정상 로그인에서 어떤 세션성 쿠키가 실제 관찰되는지 확인
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout_s) as baseline_client:
            baseline_auth_result = await authenticate_fn(
                client=baseline_client,
                target=target,
                timeout_s=timeout_s,
                username=username,
                password=password,
            )
    except Exception:
        return findings

    if not baseline_auth_result.get("ok"):
        return findings

    candidate_cookie_names = _extract_observed_cookie_names(baseline_auth_result)
    if not candidate_cookie_names:
        return findings

    for cookie_name in candidate_cookie_names:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=timeout_s) as fixation_client:
                fixation_client.cookies.set(cookie_name, fixed_value)

                before_login_jar = _extract_cookie_jar(fixation_client)

                auth_result = await authenticate_fn(
                    client=fixation_client,
                    target=target,
                    timeout_s=timeout_s,
                    username=username,
                    password=password,
                )

                if not auth_result.get("ok"):
                    continue

                after_login_jar = _extract_cookie_jar(fixation_client)
                actual_value = after_login_jar.get(cookie_name)

                observed_after_login = set(_extract_observed_cookie_names(auth_result))
                if cookie_name not in observed_after_login:
                    continue

                # 취약: 로그인 전 심어둔 값이 그대로 유지됨
                if actual_value == fixed_value:
                    findings.append(
                        {
                            "type": "SESSION_FIXATION",
                            "title": f"로그인 후 세션 쿠키 {cookie_name} 값이 재발급되지 않음",
                            "severity": "High",
                            "family": "AUTH_SESSION",
                            "subtype": "session_fixation",
                            "owasp": "A07:2021 Identification and Authentication Failures",
                            "cwe": "CWE-384",
                            "verification": {
                                "verdict": "CONFIRMED",
                                "reason": (
                                    "A pre-set session identifier for a server-observed session cookie "
                                    "remained unchanged across authentication."
                                ),
                            },
                            "evidence": {
                                "cookie_name": cookie_name,
                                "fixed_value_used": "<redacted>",
                                "landing_url": auth_result.get("landing_url"),
                                "cookie_present_before_login": cookie_name in before_login_jar,
                                "cookie_present_after_login": cookie_name in after_login_jar,
                            },
                        }
                    )
                    break

        except Exception:
            continue

    return findings


def _replay_safe_json_loads(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _flatten_json_scalars_for_replay(obj: Any, prefix: str = "") -> Dict[str, str]:
    out: Dict[str, str] = {}

    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.update(_flatten_json_scalars_for_replay(v, key))
        return out

    if isinstance(obj, list):
        for i, v in enumerate(obj[:10]):
            key = f"{prefix}[{i}]"
            out.update(_flatten_json_scalars_for_replay(v, key))
        return out

    if prefix:
        out[prefix] = str(obj)
    return out


def _replay_strip_auth_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        lk = str(k).lower().strip()
        if lk in {
            "authorization",
            "cookie",
            "proxy-authorization",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "content-length",
            "host",
        }:
            continue
        out[str(k)] = str(v)
    return out


def _replay_path(url: str) -> str:
    try:
        return (urlsplit(url).path or "").strip().lower()
    except Exception:
        return ""


def _replay_is_sensitive_path(url: str) -> bool:
    path = _replay_path(url)

    sensitive_tokens = (
        "/admin",
        "/account",
        "/profile",
        "/basket",
        "/order",
        "/orders",
        "/payment",
        "/wallet",
        "/delivery",
        "/address",
        "/users",
        "/user",
        "/securityanswers",
        "/cards",
        "/feedbacks",
        "/complaints",
        "/application-configuration",
        "/rest/admin",
        "/rest/user",
        "/api/",
        "/graphql",
    )

    explicit_public_tokens = (
        "/rest/captcha",
        "/captcha",
        "/rest/products",
        "/api/products",
        "/api/challenges",
        "/api/securityquestions",
        "/rest/memories",
        "/rest/chatbot",
        "/rest/track-order",
        "/rest/country-mapping",
        "/rest/continue-code",
        "/rest/continue-code-fixit",
        "/rest/continue-code-findit",
        "/rest/deluxe-membership",
        "/rest/repeat-notification",
        "/rest/user/security-question",
    )

    if any(tok in path for tok in explicit_public_tokens):
        return False

    return any(tok in path for tok in sensitive_tokens)


def _replay_is_json_like(content_type: str, body_text: str) -> bool:
    ct = str(content_type or "").lower()
    body_l = (body_text or "").lstrip().lower()

    if "application/json" in ct:
        return True
    return body_l.startswith("{") or body_l.startswith("[")


def _replay_json_indicators(body_text: str) -> List[str]:
    body_l = (body_text or "").lower()
    indicators: List[str] = []

    tokens = (
        '"email"',
        '"username"',
        '"user"',
        '"users"',
        '"role"',
        '"isadmin"',
        '"authentication"',
        '"token"',
        '"password"',
        '"basket"',
        '"address"',
        '"addresses"',
        '"card"',
        '"cards"',
        '"wallet"',
        '"payment"',
        '"delivery"',
        '"order"',
        '"orders"',
        '"securityanswer"',
        '"securityanswers"',
        '"whoami"',
    )

    for tok in tokens:
        if tok in body_l:
            indicators.append(tok)

    return sorted(set(indicators))


def _replay_meaningful_json_diff(auth_text: str, anon_text: str) -> List[str]:
    reasons: List[str] = []

    auth_obj = _replay_safe_json_loads(auth_text)
    anon_obj = _replay_safe_json_loads(anon_text)

    if auth_obj is None or anon_obj is None:
        return reasons

    auth_flat = _flatten_json_scalars_for_replay(auth_obj)
    anon_flat = _flatten_json_scalars_for_replay(anon_obj)

    auth_paths = set(auth_flat.keys())
    anon_paths = set(anon_flat.keys())

    ignore_path_tokens = (
        "captcha",
        "captchaid",
        "answer",
        "token",
        "nonce",
        "timestamp",
        "expires",
        "iat",
        "exp",
        "jti",
        "challenge",
        "code",
        "random",
        "image",
        "svg",
    )

    def _is_ignored(path: str) -> bool:
        p = path.lower()
        return any(tok in p for tok in ignore_path_tokens)

    extra_auth_paths = sorted(p for p in (auth_paths - anon_paths) if not _is_ignored(p))
    if extra_auth_paths:
        reasons.append(f"authenticated_json_extra_paths:{extra_auth_paths[:6]}")

    changed_values: List[str] = []
    for path in sorted(auth_paths.intersection(anon_paths)):
        if _is_ignored(path):
            continue
        if auth_flat.get(path, "") != anon_flat.get(path, ""):
            changed_values.append(path)
        if len(changed_values) >= 6:
            break

    if changed_values:
        reasons.append(f"authenticated_json_changed_values:{changed_values[:6]}")

    return reasons


def _load_raw_capture_for_replay(raw_ref: str) -> Optional[Dict[str, Any]]:
    if not raw_ref:
        return None

    try:
        path = Path(str(raw_ref))
    except Exception:
        return None

    candidate_paths = [path]

    try:
        if not path.is_absolute():
            candidate_paths.append(Path("/out") / path)
    except Exception:
        pass

    try:
        raw_ref_s = str(raw_ref)
        if raw_ref_s.startswith("/out/"):
            candidate_paths.append(Path(raw_ref_s))
    except Exception:
        pass

    loaded = None
    for p in candidate_paths:
        try:
            if p.exists() and p.is_file():
                with p.open("r", encoding="utf-8") as f:
                    loaded = json.load(f)
                break
        except Exception:
            continue

    if not isinstance(loaded, dict):
        return None

    request_block = (
        loaded.get("request")
        or loaded.get("req")
        or loaded.get("http_request")
        or {}
    )

    response_block = (
        loaded.get("response")
        or loaded.get("snapshot")
        or loaded.get("resp")
        or loaded.get("http_response")
        or {}
    )

    if not request_block and not response_block:
        if "status_code" in loaded or "headers" in loaded or "body_text" in loaded or "body_snippet" in loaded:
            response_block = loaded

    if not isinstance(request_block, dict):
        request_block = {}
    if not isinstance(response_block, dict):
        response_block = {}

    body_text = (
        response_block.get("body_text")
        or response_block.get("text")
        or response_block.get("body")
        or response_block.get("body_snippet")
        or ""
    )

    headers = response_block.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}

    return {
        "request": request_block,
        "response": response_block,
        "body_text": str(body_text),
        "headers": headers,
        "status_code": response_block.get("status_code"),
        "final_url": str(
            response_block.get("final_url")
            or response_block.get("url")
            or request_block.get("url")
            or ""
        ),
        "_raw": loaded,
    }


async def verify_protected_resource_access(
    *,
    target: str,
    authenticated_client: httpx.AsyncClient,
    authenticated_endpoints: List[Dict[str, Any]],
    anonymous_endpoints: List[Dict[str, Any]],
    auth_landing_url: str | None,
    timeout_s: float,
    raw_index: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    _ = authenticated_client
    _ = auth_landing_url
    _ = timeout_s
    _ = authenticated_endpoints

    def _extract_json_field_names(text: str, max_fields: int = 64) -> List[str]:
        import json

        fields: List[str] = []

        def _walk(obj: Any, depth: int = 0) -> None:
            if len(fields) >= max_fields or depth > 4:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key = str(k).strip().lower()
                    if key and key not in fields:
                        fields.append(key)
                    _walk(v, depth + 1)
            elif isinstance(obj, list):
                for item in obj[:10]:
                    _walk(item, depth + 1)

        try:
            parsed = json.loads(text)
        except Exception:
            return []

        _walk(parsed, 0)
        return fields[:max_fields]

    strong_sensitive = {
        "email", "role", "token", "authentication", "password",
        "secret", "key", "apikey", "api_key", "access_token",
        "refresh_token", "phone", "address", "addresses",
        "card", "cards", "payment", "payments", "wallet",
        "order", "orders", "invoice", "billing", "customer",
        "users", "userid", "account", "accounts", "basketitems",
        "securityanswer", "securityanswers", "answer", "isadmin",
    }

    def _norm_url(url: str) -> str:
        return normalize_url_for_dedup(url or "")

    def _norm_ct(value: str) -> str:
        return (value or "").split(";", 1)[0].strip().lower()

    def _body_norm(text: str) -> str:
        return " ".join((text or "").split())

    def _prefix_similarity(a: str, b: str, max_len: int = 1200) -> float:
        a = _body_norm(a)[:max_len]
        b = _body_norm(b)[:max_len]
        if not a or not b:
            return 0.0

        same = 0
        limit = min(len(a), len(b))
        for i in range(limit):
            if a[i] != b[i]:
                break
            same += 1
        return same / max(1, min(len(a), len(b)))

    def _length_similarity(a: str, b: str) -> float:
        la = len(a or "")
        lb = len(b or "")
        if la == 0 and lb == 0:
            return 1.0
        return min(la, lb) / max(1, max(la, lb))

    def _json_overlap_ratio(keys_a: List[str], keys_b: List[str]) -> float:
        sa = set(keys_a or [])
        sb = set(keys_b or [])
        if not sa or not sb:
            return 0.0
        return len(sa.intersection(sb)) / max(1, len(sa.union(sb)))

    def _path_only_key(url: str) -> str:
        try:
            parts = urlsplit(url or "")
            return normalize_url_for_dedup(f"{parts.scheme}://{parts.netloc}{parts.path or '/'}")
        except Exception:
            return normalize_url_for_dedup(url or "")

    def _query_pairs(url: str) -> List[tuple[str, str]]:
        try:
            return [
                (str(k).strip().lower(), str(v).strip())
                for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)
            ]
        except Exception:
            return []

    def _is_root_like(url: str) -> bool:
        try:
            path = (urlsplit(url).path or "/").strip().lower()
        except Exception:
            return True
        return path in {"", "/", "/api", "/api/", "/rest", "/rest/"}

    def _path_segments(url: str) -> List[str]:
        try:
            return [seg for seg in (urlsplit(url).path or "/").split("/") if seg]
        except Exception:
            return []

    def _is_identifier_segment(seg: str) -> bool:
        s = str(seg or "").strip()
        if not s:
            return False
        if re.fullmatch(r"\d+", s):
            return True
        if re.fullmatch(r"[a-f0-9]{8,}", s, re.I):
            return True
        if len(s) >= 12 and re.search(r"\d", s):
            return True
        if "@" in s:
            return True
        return False

    def _has_id_like_query(url: str) -> bool:
        id_like_names = {
            "id", "userid", "user_id", "accountid", "account_id",
            "orderid", "order_id", "cardid", "card_id", "addressid",
            "address_id", "basketid", "basket_id", "itemid", "item_id",
            "token", "uuid", "guid", "email",
        }
        ignore_names = {"session", "lang", "q", "sort", "page", "size"}
        for k, v in _query_pairs(url):
            if k in ignore_names:
                continue
            if k in id_like_names and v:
                return True
        return False

    def _is_object_like(url: str) -> bool:
        parts = _path_segments(url)
        if not parts:
            return False
        if len(parts) == 1 and _is_identifier_segment(parts[-1]):
            return False
        if _is_identifier_segment(parts[-1]):
            return True
        if _has_id_like_query(url):
            return True
        return False

    def _is_collection_like(url: str) -> bool:
        try:
            path = (urlsplit(url).path or "/").strip("/").lower()
        except Exception:
            return True

        if not path:
            return True

        parts = [p for p in path.split("/") if p]
        if not parts:
            return True

        last = parts[-1]

        if _is_identifier_segment(last):
            return False
        if _has_id_like_query(url):
            return False

        collectionish = {
            "api", "rest", "users", "user", "cards", "products", "recycles",
            "deliverys", "feedbacks", "quantitys", "securityquestions",
            "basketitems", "complaints", "hints", "challenges", "addresss",
            "orders", "payments", "wallets", "memories",
        }
        return last in collectionish

    def _is_explicit_public_path(url: str) -> bool:
        path = (urlsplit(url).path or "/").lower()
        explicit_public_tokens = (
            "/rest/captcha",
            "/captcha",
            "/rest/products",
            "/api/products",
            "/api/challenges",
            "/api/securityquestions",
            "/rest/memories",
            "/rest/chatbot",
            "/rest/track-order",
            "/rest/country-mapping",
            "/rest/continue-code",
            "/rest/continue-code-fixit",
            "/rest/continue-code-findit",
            "/rest/deluxe-membership",
            "/rest/repeat-notification",
            "/rest/user/security-question",
            "/api/hints",
            "/api/recycles",
            "/api/deliverys",
            "/api/feedbacks",
            "/api/quantitys",
            "/rest/image-captcha",
        )
        return any(tok in path for tok in explicit_public_tokens)

    def _looks_like_spa_shell_html(body_text: str) -> bool:
        body = (body_text or "").lower()
        spa_markers = [
            "<!doctype html",
            "<html",
            "<head",
            "<body",
            "<app-root",
            "<base href=",
            "<meta name=\"viewport\"",
            "owasp juice shop",
            "probably the most modern and sophisticated insecure web application",
            "data-beasties-container",
            "<script",
            "<title>",
        ]
        matched = sum(1 for marker in spa_markers if marker in body)
        return matched >= 5

    def _response_body_from_loaded_raw(raw_doc: Dict[str, Any]) -> str:
        if not isinstance(raw_doc, dict):
            return ""
        resp = raw_doc.get("response") or {}
        if not isinstance(resp, dict):
            resp = {}
        return str(
            resp.get("body_text")
            or resp.get("body_snippet")
            or resp.get("text")
            or resp.get("body")
            or ""
        )

    def _response_headers_from_loaded_raw(raw_doc: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw_doc, dict):
            return {}
        resp = raw_doc.get("response") or {}
        if not isinstance(resp, dict):
            resp = {}
        headers = resp.get("headers") or {}
        return headers if isinstance(headers, dict) else {}

    def _response_status_from_loaded_raw(raw_doc: Dict[str, Any], fallback: Any) -> Any:
        if not isinstance(raw_doc, dict):
            return fallback
        resp = raw_doc.get("response") or {}
        if not isinstance(resp, dict):
            resp = {}
        return resp.get("status_code", fallback)

    def _response_final_url_from_loaded_raw(raw_doc: Dict[str, Any], fallback: str) -> str:
        if not isinstance(raw_doc, dict):
            return fallback
        resp = raw_doc.get("response") or {}
        if not isinstance(resp, dict):
            resp = {}
        return str(resp.get("final_url") or resp.get("url") or fallback or "")

    def _is_api_or_rest_url(url: str) -> bool:
        path = (urlsplit(url).path or "/").lower()
        return "/api/" in path or "/rest/" in path

    def _meaningful_json_diff_reasons(auth_text: str, anon_text: str) -> List[str]:
        reasons: List[str] = []

        auth_obj = _replay_safe_json_loads(auth_text)
        anon_obj = _replay_safe_json_loads(anon_text)

        if auth_obj is None or anon_obj is None:
            return reasons

        auth_flat = _flatten_json_scalars_for_replay(auth_obj)
        anon_flat = _flatten_json_scalars_for_replay(anon_obj)

        auth_paths = set(auth_flat.keys())
        anon_paths = set(anon_flat.keys())

        ignore_tokens = (
            "captcha", "captchaid", "token", "nonce", "timestamp",
            "expires", "iat", "exp", "jti", "challenge", "code", "random",
        )

        def _ignored(path: str) -> bool:
            p = path.lower()
            return any(tok in p for tok in ignore_tokens)

        extra_auth_paths = sorted(p for p in (auth_paths - anon_paths) if not _ignored(p))
        if extra_auth_paths:
            reasons.append(f"authenticated_json_extra_paths:{extra_auth_paths[:6]}")

        changed_values: List[str] = []
        for path in sorted(auth_paths.intersection(anon_paths)):
            if _ignored(path):
                continue
            if auth_flat.get(path, "") != anon_flat.get(path, ""):
                changed_values.append(path)
            if len(changed_values) >= 6:
                break

        if changed_values:
            reasons.append(f"authenticated_json_changed_values:{changed_values[:6]}")

        return reasons

    anonymous_discovered_urls = {
        _norm_url(str(ep.get("url") or ""))
        for ep in (anonymous_endpoints or [])
        if isinstance(ep, dict) and str(ep.get("url") or "").strip()
    }
    anonymous_discovered_paths = {
        _path_only_key(str(ep.get("url") or ""))
        for ep in (anonymous_endpoints or [])
        if isinstance(ep, dict) and str(ep.get("url") or "").strip()
    }

    replay_pairs: Dict[tuple[str, str], Dict[str, Any]] = {}

    log("AUTH", f"verify_protected_resource_access start raw_index={len(raw_index)}")

    allowed_replay_families = {
        "access_control_replay",
        "request_access_control_replay",
        "object_access_control_replay",
    }

    for item in raw_index or []:
        if not isinstance(item, dict):
            continue

        family = str(item.get("family") or "")
        source = str(item.get("source") or "")

        if family not in allowed_replay_families:
            continue
        if source not in allowed_replay_families:
            continue

        auth_state = str(item.get("auth_state") or "").strip().lower()
        if auth_state not in {"authenticated", "anonymous"}:
            continue

        method = str(item.get("method") or "").upper().strip()
        req_url = str(item.get("url") or "").strip()
        replay_key = str(item.get("replay_key") or "").strip()

        if not replay_key:
            continue
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            continue
        if not req_url:
            continue

        pair_key = (method, replay_key)
        bucket = replay_pairs.setdefault(
            pair_key,
            {
                "method": method,
                "replay_key": replay_key,
                "url": req_url,
                "comparison_group": item.get("comparison_group"),
                "family": family,
                "authenticated": None,
                "anonymous": None,
            },
        )

        raw_doc = _load_raw_capture_for_replay(str(item.get("raw_ref") or ""))

        raw_body = _response_body_from_loaded_raw(raw_doc)
        raw_headers = _response_headers_from_loaded_raw(raw_doc)
        raw_status = _response_status_from_loaded_raw(raw_doc, item.get("status_code"))
        raw_final_url = _response_final_url_from_loaded_raw(raw_doc, str(item.get("final_url") or req_url))

        entry = {
            "item": item,
            "url": req_url,
            "final_url": raw_final_url,
            "status_code": raw_status,
            "headers": raw_headers,
            "body": raw_body,
            "content_type": str(raw_headers.get("content-type") or item.get("content_type") or ""),
            "body_len": len(raw_body) if raw_body else int(item.get("body_len") or 0),
            "ok": bool(item.get("ok")),
            "raw_ref": item.get("raw_ref"),
        }

        bucket[auth_state] = entry

    decision_stats = {
        "incomplete_pair": 0,
        "auth_not_accessible": 0,
        "likely_public": 0,
        "state_change_skipped": 0,
        "no_decision": 0,
        "confirmed": 0,
    }

    for (_method, _replay_key), pair in replay_pairs.items():
        auth_entry = pair.get("authenticated")
        anon_entry = pair.get("anonymous")

        if not auth_entry or not anon_entry:
            decision_stats["incomplete_pair"] += 1
            continue

        req_method = str(pair.get("method") or "").upper().strip()
        req_url = str(pair.get("url") or "").strip()
        replay_family = str(pair.get("family") or "")

        auth_status = auth_entry.get("status_code")
        anon_status = anon_entry.get("status_code")

        auth_final_url = str(auth_entry.get("final_url") or req_url)
        anon_final_url = str(anon_entry.get("final_url") or req_url)

        auth_content_type = str(auth_entry.get("content_type") or "")
        anon_content_type = str(anon_entry.get("content_type") or "")

        auth_body = str(auth_entry.get("body") or "")
        anon_body = str(anon_entry.get("body") or "")

        if auth_status in {401, 403}:
            decision_stats["auth_not_accessible"] += 1
            continue

        if req_method in {"POST", "PUT", "PATCH", "DELETE"}:
            decision_stats["state_change_skipped"] += 1
            continue

        auth_json = _replay_is_json_like(auth_content_type, auth_body)
        anon_json = _replay_is_json_like(anon_content_type, anon_body)

        auth_indicators = _extract_json_field_names(auth_body) if auth_json else []
        anon_indicators = _extract_json_field_names(anon_body) if anon_json else []

        ct_same = _norm_ct(auth_content_type) == _norm_ct(anon_content_type)
        final_url_same = _norm_url(auth_final_url) == _norm_url(anon_final_url)
        prefix_sim = _prefix_similarity(auth_body, anon_body)
        len_sim = _length_similarity(auth_body, anon_body)
        json_overlap = _json_overlap_ratio(auth_indicators, anon_indicators)

        object_like = _is_object_like(req_url)
        collection_like = _is_collection_like(req_url)
        explicit_public = _is_explicit_public_path(req_url)
        root_like = _is_root_like(req_url)
        seen_in_anonymous_crawl = _norm_url(req_url) in anonymous_discovered_urls
        same_path_seen_anonymously = _path_only_key(req_url) in anonymous_discovered_paths

        decision_reasons: List[str] = [
            f"auth_status:{auth_status}",
            f"anon_status:{anon_status}",
            f"replay_family:{replay_family}",
            f"object_like:{object_like}",
            f"collection_like:{collection_like}",
            f"explicit_public:{explicit_public}",
            f"root_like:{root_like}",
            f"seen_in_anonymous_crawl:{seen_in_anonymous_crawl}",
            f"same_path_seen_anonymously:{same_path_seen_anonymously}",
            f"ct_same:{ct_same}",
            f"final_url_same:{final_url_same}",
            f"prefix_similarity:{prefix_sim:.2f}",
            f"length_similarity:{len_sim:.2f}",
            f"json_overlap:{json_overlap:.2f}",
        ]

        verdict = None
        reason = None

        try:
            anon_status_int = int(anon_status) if anon_status is not None else None
        except Exception:
            anon_status_int = None

        # 익명 사용자가 차단되면 "취약점 없음"
        if anon_status_int in {401, 403, 404}:
            decision_stats["no_decision"] += 1
            decision_reasons.append("anonymous_blocked")
            continue

        # anon 5xx 도 취약점으로 보지 않음
        if anon_status_int is not None and anon_status_int >= 500:
            decision_stats["no_decision"] += 1
            decision_reasons.append("anonymous_server_error")
            continue

        if explicit_public or root_like:
            decision_stats["likely_public"] += 1
            continue

        auth_spa = _looks_like_spa_shell_html(auth_body)
        anon_spa = _looks_like_spa_shell_html(anon_body)
        if auth_spa and anon_spa:
            decision_stats["likely_public"] += 1
            decision_reasons.append("spa_shell_route_only")
            continue

        # 둘 다 성공했을 때만 anonymous exposure 판단
        if auth_status in {200, 201, 202, 204} and anon_status_int in {200, 201, 202, 204}:
            if auth_json and anon_json:
                auth_strong = sorted(set(auth_indicators).intersection(strong_sensitive))
                anon_strong = sorted(set(anon_indicators).intersection(strong_sensitive))
                json_diff_reasons = _meaningful_json_diff_reasons(auth_body, anon_body)

                if len(anon_strong) >= 2 and (is_api_or_rest_url(req_url) or object_like):
                    verdict = "CONFIRMED"
                    reason = "Anonymous request returned sensitive JSON/API fields from a resource that should require authentication."
                    decision_reasons.append(f"anonymous_sensitive_json:{anon_strong[:6]}")
                elif (
                    (object_like or replay_family in {"request_access_control_replay", "object_access_control_replay"})
                    and len(auth_strong) >= 1
                    and (json_overlap >= 0.75 or bool(json_diff_reasons))
                ):
                    verdict = "CONFIRMED"
                    reason = "Anonymous request returned a substantially similar sensitive JSON response."
                    decision_reasons.append("substantially_similar_sensitive_json_response")
                    decision_reasons.extend(json_diff_reasons[:6])
            else:
                if (
                    final_url_same
                    and ct_same
                    and prefix_sim >= 0.98
                    and len_sim >= 0.98
                ):
                    decision_stats["likely_public"] += 1
                    decision_reasons.append("same_public_response")
                    continue

        if not verdict:
            decision_stats["no_decision"] += 1
            continue

        decision_stats["confirmed"] += 1

        findings.append(
            {
                "type": "PROTECTED_RESOURCE_EXPOSURE",
                "title": "익명 사용자에게도 인증 필요 리소스 응답이 노출됨",
                "severity": "High",
                "family": "AUTH_SESSION",
                "subtype": "protected_resource_exposure",
                "owasp": "A01:2021 Broken Access Control",
                "cwe": "CWE-306",
                "trigger": {
                    "method": req_method,
                    "url": req_url,
                    "name": str(
                        (auth_entry.get("item") or {}).get("request_name")
                        or replay_family
                        or "access_control_replay"
                    ),
                },
                "verification": {
                    "verdict": verdict,
                    "reason": reason,
                },
                "evidence": {
                    "target": target,
                    "resource_url": req_url,
                    "comparison_group": pair.get("comparison_group"),
                    "replay_key": pair.get("replay_key"),
                    "replay_method": req_method,
                    "replay_family": replay_family,
                    "seen_in_anonymous_crawl": seen_in_anonymous_crawl,
                    "same_path_seen_anonymously": same_path_seen_anonymously,
                    "object_like": object_like,
                    "collection_like": collection_like,
                    "explicit_public": explicit_public,
                    "auth_status_code": auth_status,
                    "auth_final_url": auth_final_url,
                    "auth_content_type": auth_content_type,
                    "auth_is_json_like": auth_json,
                    "auth_json_indicators": auth_indicators,
                    "anon_status_code": anon_status,
                    "anon_final_url": anon_final_url,
                    "anon_content_type": anon_content_type,
                    "anon_is_json_like": anon_json,
                    "anon_json_indicators": anon_indicators,
                    "content_type_same": ct_same,
                    "final_url_same": final_url_same,
                    "prefix_similarity": round(prefix_sim, 3),
                    "length_similarity": round(len_sim, 3),
                    "json_overlap_ratio": round(json_overlap, 3),
                    "decision_reasons": decision_reasons,
                    "auth_raw_ref": auth_entry.get("raw_ref"),
                    "anon_raw_ref": anon_entry.get("raw_ref"),
                },
            }
        )

    log(
        "AUTH",
        f"verify_protected_resource_access findings={len(findings)} decision_stats={decision_stats}"
    )

    return findings
