from __future__ import annotations

import os
import random
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit, urlencode
from agent.core.scope import normalize_url_for_dedup
from agent.core.common import log

def rand_suffix(n: int = 8) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(alphabet) for _ in range(n))


@dataclass(frozen=True)
class RequestSpec:
    name: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[bytes] = None
    origin: Optional[str] = None
    probe: Optional[str] = None
    trace_marker: Optional[str] = None
    source: str = "static"
    family: str = "generic"
    mutation_class: str = "none"
    target_param: Optional[str] = None
    target_header: Optional[str] = None
    surface_hint: str = "unknown"
    expected_signal: Optional[str] = None
    comparison_group: Optional[str] = None

    # per-request redirect policy
    follow_redirects: Optional[bool] = None

    # ---- access control replay metadata ----
    auth_state: str = "inherit"  # inherit | anonymous | authenticated
    replay_key: Optional[str] = None
    replay_source_url: Optional[str] = None
    replay_source_state: Optional[str] = None
    replay_priority: int = 0


def _base_headers() -> Dict[str, str]:
    return {
        "User-Agent": "LLM-DAST-Agent/1.0",
        "Accept": "*/*",
        "Accept-Language": "en",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }


def _looks_like_object_identifier(value: str) -> bool:
    value = str(value or "").strip()
    if not value:
        return False
    if re.fullmatch(r"\d+", value):
        return True
    if re.fullmatch(r"[a-f0-9]{8,}", value, re.I):
        return True
    if re.fullmatch(r"[A-Za-z0-9_-]{12,}", value):
        return True
    return False

def _manual_auth_header_overrides() -> Dict[str, str]:
    raw = str(os.getenv("MANUAL_AUTH_HEADERS", "") or "").strip()
    out: Dict[str, str] = {}

    if not raw:
        return out

    for chunk in raw.split("|||"):
        piece = str(chunk or "").strip()
        if not piece or ":" not in piece:
            continue

        hk, hv = piece.split(":", 1)
        header_name = hk.strip()
        header_value = hv.strip()

        if not header_name:
            continue
        if header_name.lower() == "cookie":
            continue

        out[header_name] = header_value

    return out

def _merge_probe_headers(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    merged = dict(_base_headers())
    merged.update(_manual_auth_header_overrides())

    for k, v in (headers or {}).items():
        ks = str(k or "").strip()
        if not ks:
            continue
        merged[ks] = str(v or "")

    return merged


def _filter_replay_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        lk = str(k).strip().lower()
        if lk in {
            "authorization",
            "cookie",
            "proxy-authorization",
            "host",
            "content-length",
        }:
            continue
        out[str(k)] = str(v)
    return out


def _is_legacy_menu_post_target(url: str) -> bool:
    parts = urlsplit(str(url or "").strip())
    path_l = (parts.path or "").lower()

    if not any(path_l.endswith(ext) for ext in (".do", ".action", ".jsp")):
        return False

    qnames = {str(k).strip().lower() for k, _ in parse_qsl(parts.query, keep_blank_values=True)}
    return bool(qnames.intersection({"_menuid", "_menuf", "menuid", "menuf"}))


def _legacy_menu_request_shape(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    referer: Optional[str] = None,
) -> tuple[str, Dict[str, str], Optional[bytes], str]:
    parts = urlsplit(str(url or "").strip())
    body_pairs = parse_qsl(parts.query, keep_blank_values=True)

    post_url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    merged_headers = _merge_probe_headers(headers)
    origin = f"{parts.scheme}://{parts.netloc}"

    merged_headers["Content-Type"] = "application/x-www-form-urlencoded"
    merged_headers.setdefault("Origin", origin)
    merged_headers.setdefault("Upgrade-Insecure-Requests", "1")

    if referer:
        merged_headers["Referer"] = referer
    else:
        merged_headers.setdefault("Referer", post_url)

    body = urlencode(body_pairs, doseq=True).encode("utf-8") if body_pairs else None
    return post_url, merged_headers, body, "POST"

def _is_collection_like_segment(seg: str) -> bool:
    seg_l = str(seg or "").strip().lower()
    if not seg_l:
        return False

    generic_collection_words = {
        "api",
        "rest",
        "users",
        "user",
        "accounts",
        "account",
        "profiles",
        "profile",
        "cards",
        "addresses",
        "address",
        "orders",
        "order",
        "payments",
        "payment",
        "wallets",
        "wallet",
        "items",
        "products",
        "reviews",
        "customers",
        "invoices",
        "sessions",
        "tokens",
        "notifications",
        "messages",
        "files",
        "documents",
        "settings",
        "groups",
        "roles",
        "members",
        "teams",
        "projects",
    }
    return seg_l in generic_collection_words

def _mk_name(prefix: str, param: str, payload_label: str) -> str:
    return f"{prefix}_{param}_{payload_label}"

def _append_unique(plan: List[RequestSpec], seen: set, spec: RequestSpec) -> None:
    key = (
        spec.method,
        spec.url,
        tuple(sorted((spec.headers or {}).items())),
        spec.body,
        spec.probe,
        spec.trace_marker,
        spec.family,
        spec.mutation_class,
        spec.target_param,
        spec.target_header,
        spec.expected_signal,
        spec.comparison_group,
        spec.follow_redirects,
        spec.auth_state,
        spec.replay_key,
        spec.replay_source_url,
        spec.replay_source_state,
    )
    if key in seen:
        return
    seen.add(key)
    plan.append(spec)

def _endpoint_replay_norm_url(url: str) -> str:
    try:
        parts = urlsplit(str(url or "").strip())
        path = parts.path or "/"
        path = re.sub(r"/{2,}", "/", path)

        norm_parts = []
        for seg in path.split("/"):
            if not seg:
                continue
            if re.fullmatch(r"\d+", seg):
                norm_parts.append("{id}")
            elif re.fullmatch(r"[a-f0-9]{8,}", seg, re.I):
                norm_parts.append("{token}")
            else:
                norm_parts.append(seg)

        norm_path = "/" + "/".join(norm_parts)
        return urlunsplit((parts.scheme, parts.netloc, norm_path, "", ""))
    except Exception:
        return str(url or "").strip()


def _endpoint_replay_path_depth(url: str) -> int:
    try:
        path = urlsplit(str(url or "")).path or "/"
        return len([seg for seg in path.split("/") if seg])
    except Exception:
        return 0



def _endpoint_replay_is_excluded_path(url: str) -> bool:
    path_l = (urlsplit(str(url or "")).path or "/").lower().rstrip("/")

    if path_l in {"", "/", "/api", "/rest", "/graphql", "/login"}:
        return True

    excluded = (
        "/login",
        "/signin",
        "/sign-in",
        "/logout",
        "/register",
        "/signup",
        "/forgot",
        "/reset-password",
        "/reset",
        "/setup",
        "/swagger",
        "/openapi",
        "/docs",
        "/robots.txt",
        "/.well-known",
        "/health",
        "/status",
        "/metrics",
        "/favicon",
    )
    if any(tok in path_l for tok in excluded):
        return True

    publicish = (
        "/api/hints",
        "/api/challenges",
        "/api/securityquestions",
        "/rest/user/security-question",
        "/rest/products",
        "/api/products",
        "/captcha",
        "/rest/captcha",
        "/rest/memories",
        "/rest/chatbot",
        "/rest/web3",
    )
    if any(tok in path_l for tok in publicish):
        return True

    if path_l.endswith((
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".map", ".txt", ".md",
        ".pdf", ".zip", ".tar", ".gz",
    )):
        return True

    return False

def _endpoint_replay_has_identity_signal(url: str, ep: Dict[str, object]) -> bool:
    parts = urlsplit(str(url or ""))
    path = parts.path or "/"
    segments = [seg.strip() for seg in path.split("/") if seg.strip()]

    numeric_segments = 0
    token_segments = 0

    for seg in segments:
        if re.fullmatch(r"\d+", seg):
            numeric_segments += 1
        elif re.fullmatch(r"[a-f0-9]{8,}", seg, re.I):
            token_segments += 1

    query_names = {
        str(x).strip().lower()
        for x in (ep.get("query_param_names") or [])
        if str(x).strip()
    }
    field_names = {
        str(x).strip().lower()
        for x in (ep.get("field_names") or [])
        if str(x).strip()
    }

    strong_selector_names = {
        "id", "userid", "user_id", "accountid", "account_id",
        "orderid", "order_id", "cardid", "card_id", "addressid",
        "address_id", "basketid", "basket_id", "itemid", "item_id",
        "token", "uuid", "guid", "email",
    }

    if query_names.intersection(strong_selector_names):
        return True

    if field_names.intersection(strong_selector_names):
        return True

    # 단일 숫자 path (/10) 하나만으로는 object 신호로 보지 않음
    if len(segments) == 1 and numeric_segments == 1 and token_segments == 0:
        return False

    if numeric_segments >= 1 or token_segments >= 1:
        return True

    return False

def _endpoint_replay_collection_like(url: str) -> bool:
    try:
        path = (urlsplit(str(url or "")).path or "/").strip("/")
    except Exception:
        return True

    if not path:
        return True

    parts = [p for p in path.split("/") if p]
    if not parts:
        return True

    last = parts[-1].lower()

    if re.fullmatch(r"\d+", last):
        return False
    if re.fullmatch(r"[a-f0-9]{8,}", last, re.I):
        return False

    collectionish = {
        "api", "rest", "users", "cards", "products", "orders", "payments",
        "addresses", "profiles", "accounts", "basketitems", "feedbacks",
        "hints", "challenges", "securityquestions", "complaints",
    }
    return last in collectionish

def _endpoint_replay_candidate_score(
    ep: Dict[str, object],
    anonymous_replay_keys: set[str],
    auth_landing_url: Optional[str],
) -> int:
    url = str(ep.get("url") or "").strip()
    if not url:
        return -999

    if _endpoint_replay_is_excluded_path(url):
        return -999

    if _request_replay_is_static_like(url):
        return -999

    if auth_landing_url and _normalize_replay_key(url) == _normalize_replay_key(auth_landing_url):
        return -999

    replay_key = _endpoint_replay_norm_url(url)
    states = {str(x).strip().lower() for x in (ep.get("states") or [])}
    kind = str(ep.get("kind") or "").strip().lower()
    ep_score = int(ep.get("score", 0) or 0)

    path = urlsplit(url).path or "/"
    path_l = path.lower().rstrip("/")
    segments = [seg for seg in path.split("/") if seg]

    query_names = {
        str(x).strip().lower()
        for x in (ep.get("query_param_names") or [])
        if str(x).strip()
    }
    field_names = {
        str(x).strip().lower()
        for x in (ep.get("field_names") or [])
        if str(x).strip()
    }

    score = 0

    auth_only = "authenticated" in states and replay_key not in anonymous_replay_keys
    if auth_only:
        score += 20
    elif "authenticated" in states:
        score += 8
    else:
        return -999

    if kind == "form":
        score += 10
    elif kind == "page":
        score += 4
    elif kind == "static":
        return -999

    score += min(10, ep_score // 10)
    score += _sensitive_path_score(url)
    score -= max(0, _publicish_path_score(url) // 2)

    has_identity_signal = _endpoint_replay_has_identity_signal(url, ep)
    if has_identity_signal:
        score += 10

    if not _endpoint_replay_collection_like(url):
        score += 8
    else:
        score -= 8

    strong_selector_names = {
        "id",
        "userid",
        "user_id",
        "accountid",
        "account_id",
        "orderid",
        "order_id",
        "cardid",
        "card_id",
        "addressid",
        "address_id",
        "basketid",
        "basket_id",
        "itemid",
        "item_id",
        "email",
        "token",
    }
    if query_names.intersection(strong_selector_names):
        score += 8
    if field_names.intersection(strong_selector_names):
        score += 4

    depth = _endpoint_replay_path_depth(url)
    if depth == 0:
        return -999
    if depth == 1:
        score -= 4

    if len(segments) == 1 and re.fullmatch(r"\d+", segments[0]):
        score -= 18

    if _is_auth_flow_path(url):
        return -999

    if _is_self_context_path(url) and not has_identity_signal:
        return -999

    if (
        not has_identity_signal
        and _sensitive_path_score(url) == 0
        and not query_names
        and not field_names
    ):
        return -999

    if _publicish_path_score(url) > 0 and not has_identity_signal:
        score -= 12

    if path_l in {"", "/", "/api", "/rest"}:
        return -999

    return score

def _existing_query_pairs(url: str) -> List[tuple[str, str]]:
    try:
        return [(str(k), str(v)) for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except Exception:
        return []


def _merge_query_pairs(
    original: Sequence[tuple[str, str]],
    overrides: Sequence[tuple[str, str]],
) -> List[tuple[str, str]]:
    override_map = {str(k): str(v) for k, v in overrides}
    used = set()
    merged: List[tuple[str, str]] = []

    for k, v in original:
        ks = str(k)
        if ks in override_map:
            merged.append((ks, override_map[ks]))
            used.add(ks)
        else:
            merged.append((ks, str(v)))

    for k, v in overrides:
        ks = str(k)
        if ks not in used and not any(ks == ek for ek, _ in original):
            merged.append((ks, str(v)))

    return merged


def _replace_query(url: str, pairs: List[tuple[str, str]]) -> str:
    parts = urlsplit(url)
    query_items: List[str] = []

    for k, v in pairs:
        key = quote(str(k), safe="")
        value = str(v)
        query_items.append(f"{key}={value}")

    raw_query = "&".join(query_items)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, raw_query, ""))


def _append_path(url: str, suffix: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"

    if not path.endswith("/"):
        path = path.rstrip("/")

    if not suffix.startswith("/"):
        suffix = "/" + suffix

    return urlunsplit((parts.scheme, parts.netloc, path + suffix, parts.query, ""))


def _target_directory_prefixes(target_url: str) -> List[str]:
    parts = urlsplit(target_url)
    scheme_netloc = f"{parts.scheme}://{parts.netloc}"
    path = parts.path or "/"

    if not path or path == "/":
        return [scheme_netloc]

    segments = [seg for seg in path.split("/") if seg]

    if segments and "." in segments[-1]:
        segments = segments[:-1]

    prefixes: List[str] = []
    for i in range(len(segments), -1, -1):
        prefix_path = "/" + "/".join(segments[:i]) if i > 0 else ""
        prefixes.append(f"{scheme_netloc}{prefix_path}")

    out: List[str] = []
    seen = set()
    for p in prefixes:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _join_url(base: str, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return base.rstrip("/") + path

def _resource_exposure_specs(target_url: str, headers: Dict[str, str], intensity: str) -> List[RequestSpec]:
    prefixes = _target_directory_prefixes(target_url)

    # 중요: config 계열을 앞쪽에 둬야 resource budget에 안 잘림
    common_paths = [
        # highest-value config/debug exposures first
        "/config/config.inc.php.dist",
        "/config/config.inc.php",
        "/config/config.php",
        "/config.inc.php.dist",
        "/config.inc.php",
        "/config.php",
        "/.env",
        "/.env.local",
        "/.git/config",
        "/phpinfo.php",
        "/info.php",
        "/server-status",

        # common framework / app config guesses
        "/application.properties",
        "/application.yml",
        "/application.yaml",
        "/appsettings.json",
        "/web.config",
        "/WEB-INF/web.xml",

        # nested config-style guesses
        "/config/application.properties",
        "/config/application.yml",
        "/config/application.yaml",
        "/config/appsettings.json",

        # debug / ops
        "/debug",
        "/debug/",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/logs/",
        "/backup/",
        "/backup.zip",
        "/dump.sql",

        # platform roots
        "/api",
        "/api/",
        "/rest",
        "/rest/",
        "/robots.txt",
        "/.well-known/security.txt",
        "/ftp",
        "/ftp/",
        "/assets/public/",
    ]

    if intensity == "light":
        common_paths = [
            "/config/config.inc.php.dist",
            "/config.inc.php.dist",
            "/.env",
            "/.git/config",
            "/phpinfo.php",
            "/server-status",
            "/api/",
            "/rest/",
            "/robots.txt",
        ]
    elif intensity == "medium":
        common_paths = [
            "/config/config.inc.php.dist",
            "/config/config.inc.php",
            "/config/config.php",
            "/config.inc.php.dist",
            "/config.inc.php",
            "/config.php",
            "/.env",
            "/.env.local",
            "/.git/config",
            "/phpinfo.php",
            "/info.php",
            "/server-status",
            "/application.properties",
            "/appsettings.json",
            "/logs/",
            "/backup.zip",
            "/api",
            "/api/",
            "/rest",
            "/rest/",
            "/robots.txt",
            "/.well-known/security.txt",
            "/ftp/",
        ]

    specs: List[RequestSpec] = []
    seen_urls = set()

    for prefix in prefixes:
        for path in common_paths:
            full_url = _join_url(prefix, path)
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            label = path.strip("/").replace("/", "_").replace(".", "_") or "root"

            specs.append(
                RequestSpec(
                    name=f"resource_probe_{label}",
                    method="GET",
                    url=full_url,
                    headers=headers,
                    source="static",
                    family="default_resource",
                    mutation_class="resource_exposure_probe",
                    surface_hint="response.body",
                    expected_signal="config_debug_log_or_default_resource_exposure",
                    comparison_group="resource_exposure",
                )
            )

            if path in {
                "/phpinfo.php",
                "/server-status",
                "/.env",
                "/config.inc.php.dist",
                "/config/config.inc.php.dist",
                "/appsettings.json",
            }:
                specs.append(
                    RequestSpec(
                        name=f"resource_head_{label}",
                        method="HEAD",
                        url=full_url,
                        headers=headers,
                        source="static",
                        family="default_resource",
                        mutation_class="resource_exposure_head_probe",
                        surface_hint="response.headers",
                        expected_signal="resource_presence_or_banner",
                        comparison_group="resource_exposure",
                    )
                )

    return specs


def _directory_listing_specs(target_url: str, headers: Dict[str, str], intensity: str) -> List[RequestSpec]:
    prefixes = _target_directory_prefixes(target_url)

    candidate_dirs = [
        "/",
        "/assets/",
        "/assets/public/",
        "/static/",
        "/images/",
        "/img/",
        "/css/",
        "/js/",
        "/uploads/",
        "/upload/",
        "/files/",
        "/download/",
        "/downloads/",
        "/backup/",
        "/backups/",
        "/logs/",
        "/log/",
        "/api/",
        "/rest/",
        "/ftp/",
    ]

    if intensity == "light":
        candidate_dirs = ["/", "/uploads/", "/files/", "/logs/", "/api/", "/rest/"]
    elif intensity == "medium":
        candidate_dirs = ["/", "/static/", "/uploads/", "/files/", "/backup/", "/logs/", "/api/", "/rest/", "/ftp/"]

    specs: List[RequestSpec] = []
    seen_urls = set()

    for prefix in prefixes:
        for p in candidate_dirs:
            full_url = _join_url(prefix, p)
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            label = p.strip("/").replace("/", "_") or "root"
            specs.append(
                RequestSpec(
                    name=f"dir_list_{label}",
                    method="GET",
                    url=full_url,
                    headers=headers,
                    source="static",
                    family="directory_behavior",
                    mutation_class="directory_listing_probe",
                    surface_hint="response.body",
                    expected_signal="directory_listing",
                    comparison_group="directory_behavior",
                )
            )

    return specs

def _baseline_specs(target_url: str, headers: Dict[str, str]) -> List[RequestSpec]:
    existing = _existing_query_pairs(target_url)
    merged_query = _merge_query_pairs(existing, [("session", rand_suffix(6))])
    path_l = (urlsplit(target_url).path or "/").lower()

    allow_head = os.getenv("ENABLE_HEAD_BASELINE", "off").lower() == "on"

    specs = [
        RequestSpec(
            name="baseline_get",
            method="GET",
            url=target_url,
            headers=headers,
            source="static",
            family="baseline",
            mutation_class="baseline_get",
            surface_hint="general",
            expected_signal="baseline_response",
            comparison_group="baseline",
            follow_redirects=False,
        ),
        RequestSpec(
            name="baseline_query_session",
            method="GET",
            url=_replace_query(target_url, merged_query),
            headers=headers,
            source="static",
            family="baseline",
            mutation_class="benign_query_baseline",
            target_param="session",
            surface_hint="general",
            expected_signal="baseline_response",
            comparison_group="baseline_query",
            follow_redirects=False,
        ),
        RequestSpec(
            name="baseline_follow_get",
            method="GET",
            url=target_url,
            headers={
                **headers,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
            source="static",
            family="baseline",
            mutation_class="baseline_follow_get",
            surface_hint="response.body",
            expected_signal="baseline_final_html_body",
            comparison_group="baseline_follow",
            follow_redirects=True,
        ),
    ]

    if allow_head:
        specs.insert(
            1,
            RequestSpec(
                name="baseline_head",
                method="HEAD",
                url=target_url,
                headers=headers,
                source="static",
                family="baseline",
                mutation_class="baseline_head",
                surface_hint="response.headers",
                expected_signal="baseline_headers",
                comparison_group="baseline",
                follow_redirects=False,
            ),
        )

    diagnostic_probe_tokens = (
        "/setup",
        "/install",
        "/installer",
        "/status",
        "/debug",
        "/diagnostic",
        "/health",
        "/info",
    )
    if any(token in path_l for token in diagnostic_probe_tokens):
        for name, overrides in (
            ("baseline_query_verbose", [("verbose", "true")]),
            ("baseline_query_debug", [("debug", "1")]),
            ("baseline_query_diagnostic", [("diagnostic", "1")]),
        ):
            specs.append(
                RequestSpec(
                    name=name,
                    method="GET",
                    url=_replace_query(target_url, _merge_query_pairs(existing, overrides)),
                    headers=headers,
                    source="static",
                    family="baseline",
                    mutation_class="benign_diagnostic_query",
                    target_param=overrides[0][0],
                    surface_hint="response.body",
                    expected_signal="diagnostic_response_variation",
                    comparison_group="baseline_query",
                    follow_redirects=False,
                )
            )

    return specs



def _notfound_specs(base: str, headers: Dict[str, str]) -> List[RequestSpec]:
    nf1 = f"{base}/__nonexistent_{rand_suffix(10)}"
    nf2 = f"{base}/missing/{rand_suffix(8)}.jsp"

    return [
        RequestSpec(
            name="notfound_get_a",
            method="GET",
            url=nf1,
            headers=headers,
            source="static",
            family="comparison",
            mutation_class="notfound_baseline",
            surface_hint="error_page",
            expected_signal="404_or_custom_notfound",
            comparison_group="notfound",
        ),
        RequestSpec(
            name="notfound_head_a",
            method="HEAD",
            url=nf1,
            headers=headers,
            source="static",
            family="comparison",
            mutation_class="notfound_head_baseline",
            surface_hint="response.headers",
            expected_signal="404_headers",
            comparison_group="notfound",
        ),
        RequestSpec(
            name="notfound_get_jsp",
            method="GET",
            url=nf2,
            headers=headers,
            source="static",
            family="comparison",
            mutation_class="notfound_alt_extension",
            surface_hint="error_page",
            expected_signal="404_or_default_error_template",
            comparison_group="notfound",
        ),
    ]

def _risky_method_specs(target_url: str, headers: Dict[str, str]) -> List[RequestSpec]:
    if os.getenv("ENABLE_RISKY_METHOD_PROBES", "off").lower() != "on":
        return []

    methods = [
        ("OPTIONS", "options_probe"),
        ("TRACE", "unsafe_method_probe"),
        ("PUT", "unsafe_method_probe"),
        ("DELETE", "unsafe_method_probe"),
        ("PATCH", "unsafe_method_probe"),
    ]

    return [
        RequestSpec(
            name=f"method_{method.lower()}",
            method=method,
            url=target_url,
            headers=headers,
            source="static",
            family="method_behavior",
            mutation_class=mclass,
            surface_hint="response.headers",
            expected_signal="allow_header_or_status_change",
            comparison_group="method_matrix",
        )
        for method, mclass in methods
    ]

def _trace_echo_spec(target_url: str, headers: Dict[str, str]) -> RequestSpec:
    trace_marker = f"TRACE_MARKER_{rand_suffix(10)}"
    return RequestSpec(
        name="method_trace_echo",
        method="TRACE",
        url=target_url,
        headers={**headers, "Content-Type": "text/plain"},
        body=trace_marker.encode("utf-8"),
        probe="trace_echo",
        trace_marker=trace_marker,
        source="static",
        family="method_behavior",
        mutation_class="trace_reflection_probe",
        surface_hint="response.body",
        expected_signal="trace_body_reflection",
        comparison_group="method_matrix",
    )

def _cors_specs(target_url: str, headers: Dict[str, str]) -> List[RequestSpec]:
    if os.getenv("ENABLE_CORS_PROBES", "off").lower() != "on":
        return []

    cors_origins = [
        "https://evil.example",
        f"https://{rand_suffix(6)}.attacker.test",
        "null",
        "http://localhost:3000",
    ]

    specs: List[RequestSpec] = []

    for idx, origin in enumerate(cors_origins, start=1):
        specs.append(
            RequestSpec(
                name=f"cors_get_origin_{idx}",
                method="GET",
                url=target_url,
                headers={**headers, "Origin": origin},
                origin=origin,
                probe="cors",
                source="static",
                family="cors_behavior",
                mutation_class="origin_reflection_probe",
                target_header="Origin",
                surface_hint="response.headers",
                expected_signal="acao_reflection",
                comparison_group="cors_policy",
            )
        )

    return specs

def _header_mutation_specs(target_url: str, headers: Dict[str, str]) -> List[RequestSpec]:
    return [
        RequestSpec(
            name="hdr_x_forwarded_host",
            method="GET",
            url=target_url,
            headers={**headers, "X-Forwarded-Host": "evil.example"},
            source="static",
            family="header_behavior",
            mutation_class="forwarded_host_override",
            target_header="X-Forwarded-Host",
            surface_hint="response.headers",
            expected_signal="redirect_or_host_confusion_or_disclosure",
            comparison_group="header_mutation",
        ),
        RequestSpec(
            name="hdr_forwarded",
            method="GET",
            url=target_url,
            headers={**headers, "Forwarded": 'for=127.0.0.1;host="evil.example";proto=http'},
            source="static",
            family="header_behavior",
            mutation_class="forwarded_header_probe",
            target_header="Forwarded",
            surface_hint="response.headers",
            expected_signal="proxy_or_debug_behavior",
            comparison_group="header_mutation",
        ),
        RequestSpec(
            name="hdr_x_original_url",
            method="GET",
            url=target_url,
            headers={**headers, "X-Original-URL": "/"},
            source="static",
            family="header_behavior",
            mutation_class="rewrite_override_probe",
            target_header="X-Original-URL",
            surface_hint="response.headers",
            expected_signal="rewrite_or_disclosure",
            comparison_group="header_mutation",
        ),
        RequestSpec(
            name="hdr_x_rewrite_url",
            method="GET",
            url=target_url,
            headers={**headers, "X-Rewrite-URL": "/"},
            source="static",
            family="header_behavior",
            mutation_class="rewrite_override_probe",
            target_header="X-Rewrite-URL",
            surface_hint="response.headers",
            expected_signal="rewrite_or_disclosure",
            comparison_group="header_mutation",
        ),
        RequestSpec(
            name="hdr_accept_json",
            method="GET",
            url=target_url,
            headers={**headers, "Accept": "application/json"},
            source="static",
            family="header_behavior",
            mutation_class="accept_negotiation_probe",
            target_header="Accept",
            surface_hint="response.body",
            expected_signal="alternate_error_or_debug_format",
            comparison_group="content_negotiation",
        ),
        RequestSpec(
            name="hdr_accept_text",
            method="GET",
            url=target_url,
            headers={**headers, "Accept": "text/plain"},
            source="static",
            family="header_behavior",
            mutation_class="accept_negotiation_probe",
            target_header="Accept",
            surface_hint="response.body",
            expected_signal="alternate_error_or_debug_format",
            comparison_group="content_negotiation",
        ),
        RequestSpec(
            name="hdr_lang_ko",
            method="GET",
            url=target_url,
            headers={**headers, "Accept-Language": "ko-KR,ko;q=0.9"},
            source="static",
            family="header_behavior",
            mutation_class="language_negotiation_probe",
            target_header="Accept-Language",
            surface_hint="response.body",
            expected_signal="localized_error_template",
            comparison_group="content_negotiation",
        ),
    ]


def _body_format_specs(target_url: str, headers: Dict[str, str]) -> List[RequestSpec]:
    return [
        RequestSpec(
            name="body_get_with_body",
            method="GET",
            url=target_url,
            headers={**headers, "Content-Type": "text/plain"},
            body=b"probe=get-body",
            source="static",
            family="body_behavior",
            mutation_class="get_with_body_probe",
            surface_hint="response.body",
            expected_signal="unexpected_method_or_parser_behavior",
            comparison_group="body_format",
        ),
    ]


def _query_param_candidates(intensity: str) -> List[str]:
    common = [
        "q", "id", "page", "file", "path", "search", "sort", "lang",
        "url", "next", "redirect", "returnUrl", "callback", "template",
        "resource", "download", "image",
    ]
    if intensity == "light":
        return ["file", "path", "q", "id", "lang"]
    if intensity == "medium":
        return ["file", "path", "q", "id", "lang", "page", "url", "redirect", "template"]
    return common


def _error_query_specs(target_url: str, headers: Dict[str, str], intensity: str) -> List[RequestSpec]:
    specs: List[RequestSpec] = []
    params = _query_param_candidates(intensity)
    original_pairs = _existing_query_pairs(target_url)

    mutation_payloads = [
        ("pct", "%", "reserved_char_query", "400_or_parser_error"),
        ("pipe", "|", "reserved_char_query", "400_or_parser_error"),
        ("badenc", "%ZZ", "bad_percent_encoding_query", "400_or_parser_error"),
        ("nul", "%00", "null_byte_like_query", "400_or_parser_error"),
        ("lt", "<", "angle_bracket_query", "validation_or_error_page"),
        ("gt", ">", "angle_bracket_query", "validation_or_error_page"),
        ("dq", "\"", "quote_query", "validation_or_error_page"),
        ("sq", "'", "quote_query", "validation_or_error_page"),
        ("dotdot_slash", "%2e%2e%2f", "path_normalization_query", "error_or_template_change"),
        ("slash_enc", "%2f", "encoded_slash_query", "error_or_template_change"),
    ]

    if intensity == "light":
        mutation_payloads = mutation_payloads[:4]
    elif intensity == "medium":
        mutation_payloads = mutation_payloads[:8]

    for param in params:
        for label, payload, mclass, expected in mutation_payloads:
            merged = _merge_query_pairs(original_pairs, [(param, payload)])
            specs.append(
                RequestSpec(
                    name=_mk_name("qs", param, label),
                    method="GET",
                    url=_replace_query(target_url, merged),
                    headers=headers,
                    source="static",
                    family="error_query",
                    mutation_class=mclass,
                    target_param=param,
                    surface_hint="error_page",
                    expected_signal=expected,
                    comparison_group="query_mutation",
                )
            )

    if intensity in {"medium", "full"}:
        dup_pairs = list(original_pairs) + [("id", "1"), ("id", "%ZZ")]
        specs.append(
            RequestSpec(
                name="qs_dup_param_conflict",
                method="GET",
                url=_replace_query(target_url, dup_pairs),
                headers=headers,
                source="static",
                family="error_query",
                mutation_class="duplicate_param_conflict",
                target_param="id",
                surface_hint="error_page",
                expected_signal="parser_or_validation_error",
                comparison_group="query_mutation",
            )
        )

        merged_empty = _merge_query_pairs(original_pairs, [("file", "")])
        specs.append(
            RequestSpec(
                name="qs_empty_value",
                method="GET",
                url=_replace_query(target_url, merged_empty),
                headers=headers,
                source="static",
                family="error_query",
                mutation_class="empty_value_query",
                target_param="file",
                surface_hint="response.body",
                expected_signal="validation_difference",
                comparison_group="query_mutation",
            )
        )

        merged_oversized = _merge_query_pairs(original_pairs, [("q", "A" * 2048)])
        specs.append(
            RequestSpec(
                name="qs_oversized_value",
                method="GET",
                url=_replace_query(target_url, merged_oversized),
                headers=headers,
                source="static",
                family="error_query",
                mutation_class="oversized_query_value",
                target_param="q",
                surface_hint="error_page",
                expected_signal="414_or_validation_or_parser_error",
                comparison_group="query_mutation",
            )
        )

    if intensity == "full":
        combo_specs = [
            ("combo_file_path_pipe", [("file", "|"), ("path", "|")], "combo_reserved_chars", "400_or_error_page"),
            ("combo_q_lang_badenc", [("q", "%ZZ"), ("lang", "%ZZ")], "combo_bad_encoding", "400_or_error_page"),
            ("combo_page_sort_mixed", [("page", "%00"), ("sort", "%2e%2e%2f")], "combo_parser_confusion", "error_template_change"),
        ]
        for name, pairs, mclass, expected in combo_specs:
            merged = _merge_query_pairs(original_pairs, pairs)
            specs.append(
                RequestSpec(
                    name=name,
                    method="GET",
                    url=_replace_query(target_url, merged),
                    headers=headers,
                    source="static",
                    family="error_query",
                    mutation_class=mclass,
                    surface_hint="error_page",
                    expected_signal=expected,
                    comparison_group="query_mutation",
                )
            )

    return specs


def _error_path_specs(target_url: str, headers: Dict[str, str], intensity: str) -> List[RequestSpec]:
    specs: List[RequestSpec] = []

    payloads = [
        ("pct", "%", "reserved_char_path", "400_or_parser_error"),
        ("pipe", "%7C", "reserved_char_path", "400_or_parser_error"),
        ("badenc", "%ZZ", "bad_percent_encoding_path", "400_or_parser_error"),
        ("lt", "<", "angle_bracket_path", "error_or_template_change"),
        ("gt", ">", "angle_bracket_path", "error_or_template_change"),
        ("dq", "\"", "quote_path", "error_or_template_change"),
        ("sq", "'", "quote_path", "error_or_template_change"),
        ("nul", "%00", "null_byte_like_path", "400_or_parser_error"),
        ("dotdot_slash", "%2e%2e%2f", "path_normalization_probe", "error_or_template_change"),
        ("double_slash", "//", "duplicate_slash_probe", "routing_difference"),
        ("backslash", "\\", "backslash_path_probe", "routing_difference_or_error"),
        ("semi_path", "..;/", "semicolon_matrix_probe", "routing_difference_or_error"),
        ("dot", ".", "dot_segment_probe", "routing_difference_or_error"),
        ("dot_dir", "./", "dot_segment_probe", "routing_difference_or_error"),
        ("trailing_semicolon", "test;", "semicolon_matrix_probe", "routing_difference_or_error"),
    ]

    if intensity == "light":
        payloads = [
            ("badenc", "%ZZ", "bad_percent_encoding_path", "400_or_parser_error"),
            ("pct", "%", "reserved_char_path", "400_or_parser_error"),
            ("nul", "%00", "null_byte_like_path", "400_or_parser_error"),
        ]
    elif intensity == "medium":
        payloads = [
            ("badenc", "%ZZ", "bad_percent_encoding_path", "400_or_parser_error"),
            ("pct", "%", "reserved_char_path", "400_or_parser_error"),
            ("pipe", "%7C", "reserved_char_path", "400_or_parser_error"),
            ("nul", "%00", "null_byte_like_path", "400_or_parser_error"),
            ("double_slash", "//", "duplicate_slash_probe", "routing_difference"),
            ("dotdot_slash", "%2e%2e%2f", "path_normalization_probe", "error_or_template_change"),
        ]

    for label, payload, mclass, expected in payloads:
        specs.append(
            RequestSpec(
                name=f"path_{label}",
                method="GET",
                url=_append_path(target_url, payload),
                headers=headers,
                source="static",
                family="error_path",
                mutation_class=mclass,
                surface_hint="error_page",
                expected_signal=expected,
                comparison_group="path_mutation",
            )
        )

    return specs


# -------------------------------------------------------------------------
# Access control replay helpers
# -------------------------------------------------------------------------

_REPLAY_HIGH_VALUE_TOKENS = (
    "/admin",
    "/profile",
    "/account",
    "/basket",
    "/order",
    "/orders",
    "/address",
    "/payment",
    "/wallet",
    "/api/",
    "/rest/",
    "/ftp",
    "/upload",
    "/downloads",
    "/delivery",
    "/complaint",
    "/users",
    "/user/",
)

_REPLAY_EXCLUDE_TOKENS = (
    "/login",
    "/signin",
    "/logout",
    "/setup",
    "/register",
    "/forgot-password",
    "/reset-password",
)

def _path_parts(value: str) -> List[str]:
    raw = str(value or "")
    if "://" in raw:
        raw = urlsplit(raw).path or "/"
    return [part for part in re.split(r"[/_\-.]+", raw.lower()) if part]


def _contains_any_path_token(value: str, tokens: Sequence[str]) -> bool:
    parts = _path_parts(value)
    token_set = {str(t).lower() for t in tokens}
    return any(part in token_set for part in parts)


def _publicish_path_score(url: str) -> int:
    publicish_tokens = (
        "public",
        "static",
        "assets",
        "images",
        "img",
        "css",
        "js",
        "favicon",
        "robots",
        "health",
        "status",
        "metrics",
        "version",
        "ping",
        "captcha",
        "challenge",
        "hint",
        "help",
        "faq",
        "docs",
        "swagger",
        "openapi",
        "product",
        "products",
        "catalog",
        "search",
        "categories",
    )
    parts = _path_parts(url)
    matches = sum(1 for part in parts if part in publicish_tokens)
    if matches >= 2:
        return 12
    if matches == 1:
        return 8
    return 0


def _sensitive_path_score(url: str) -> int:
    sensitive_tokens = (
        "admin",
        "account",
        "accounts",
        "profile",
        "profiles",
        "user",
        "users",
        "address",
        "addresses",
        "card",
        "cards",
        "wallet",
        "payment",
        "payments",
        "basket",
        "cart",
        "order",
        "orders",
        "invoice",
        "customer",
        "member",
        "members",
        "billing",
        "checkout",
        "subscription",
        "token",
        "session",
        "owner",
        "owners",
        "complaint",
        "complaints",
        "record",
        "records",
        "object",
        "objects",
    )
    parts = _path_parts(url)
    matches = sum(1 for part in parts if part in sensitive_tokens)
    if matches >= 2:
        return 10
    if matches == 1:
        return 6
    return 0


def _is_auth_flow_path(url: str) -> bool:
    auth_tokens = (
        "login",
        "signin",
        "sign-in",
        "logout",
        "register",
        "signup",
        "sign-up",
        "forgot",
        "reset",
        "auth",
        "oauth",
        "sso",
        "token",
        "refresh",
    )
    return _contains_any_path_token(url, auth_tokens)


def _is_self_context_path(url: str) -> bool:
    self_tokens = (
        "me",
        "whoami",
        "profile",
        "account",
        "authentication-details",
        "change-password",
        "reset-password",
        "session",
        "current-user",
        "my-account",
        "my-profile",
        "preferences",
        "settings",
        "dashboard",
    )
    return _contains_any_path_token(url, self_tokens)


def _safe_json_loads_for_replay(value: str) -> Any:
    import json

    try:
        return json.loads(value)
    except Exception:
        return None


def _flatten_object_scalars(obj: Any, prefix: str = "") -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []

    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.extend(_flatten_object_scalars(v, key))
        return out

    if isinstance(obj, list):
        for i, item in enumerate(obj[:20]):
            key = f"{prefix}[{i}]"
            out.extend(_flatten_object_scalars(item, key))
        return out

    if prefix:
        out.append((prefix, str(obj)))
    return out


def _looks_like_numeric_id(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,12}", str(value or "").strip()))


def _looks_like_uuidish(value: str) -> bool:
    s = str(value or "").strip()
    return bool(
        re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", s, re.I)
        or re.fullmatch(r"[0-9a-f]{16,64}", s, re.I)
    )


def _looks_like_object_id_value(value: str) -> bool:
    s = str(value or "").strip()
    if not s:
        return False
    if _looks_like_numeric_id(s):
        return True
    if _looks_like_uuidish(s):
        return True
    if re.fullmatch(r"[A-Za-z0-9_\-]{6,64}", s):
        return True
    return False


def _objectish_key_score(path_key: str) -> int:
    k = str(path_key or "").lower()

    strong = (
        "userid", "user_id",
        "accountid", "account_id",
        "orderid", "order_id",
        "cardid", "card_id",
        "addressid", "address_id",
        "basketid", "basket_id",
        "paymentid", "payment_id",
        "walletid", "wallet_id",
        "profileid", "profile_id",
        "customerid", "customer_id",
        "ownerid", "owner_id",
        "complaintid", "complaint_id",
    )
    medium = (
        ".id", "[0].id", " id",
        "user", "account", "order", "card", "address", "basket",
        "payment", "wallet", "profile", "customer", "owner", "complaint",
    )
    weak = (
        "productid", "product_id", "challengeid", "challenge_id",
        "quantityid", "quantity_id", "deliveryid", "delivery_id",
    )

    score = 0
    if any(tok in k for tok in strong):
        score += 10
    elif any(tok in k for tok in medium):
        score += 6
    elif any(tok in k for tok in weak):
        score += 2

    if k.endswith(".id") or k == "id":
        score += 2

    return score

def _publicish_path_penalty(url: str) -> int:
    return _publicish_path_score(url)

def _is_publicish_collection_url(url: str) -> bool:
    path = (urlsplit(url).path or "/").lower().rstrip("/")
    if path in {"", "/", "/api", "/rest"}:
        return True
    return _publicish_path_score(url) > 0

def _extract_object_candidates_from_raw_index(
    raw_index: List[Dict[str, Any]],
    *,
    max_candidates: int = 100,
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    seen = set()

    strong_object_query_names = {
        "id", "ids",
        "userid", "user_id",
        "accountid", "account_id",
        "orderid", "order_id",
        "cardid", "card_id",
        "addressid", "address_id",
        "basketid", "basket_id",
        "itemid", "item_id",
        "paymentid", "payment_id",
        "walletid", "wallet_id",
        "invoiceid", "invoice_id",
        "docid", "doc_id",
        "reqid", "req_id",
        "seq", "no", "num",
        "memberid", "member_id",
        "recordid", "record_id",
        "objectid", "object_id",
    }

    excluded_non_object_query_names = {
        "_menuid", "menuid", "_menuf", "menuf",
        "bbsid", "pageid", "lang", "view", "tab",
        "search", "q", "sort", "filter", "returnurl",
        "callback", "redirect", "next", "type", "mode",
    }

    for item in raw_index or []:
        if not isinstance(item, dict):
            continue

        auth_state = str(item.get("auth_state") or "").strip().lower()
        if auth_state != "authenticated":
            continue

        if not bool(item.get("ok")):
            continue

        method = str(item.get("method") or "").upper().strip()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            continue

        url = str(item.get("url") or "").strip()
        if not url:
            continue

        if _request_replay_is_static_like(url):
            continue
        if _is_auth_flow_path(url):
            continue

        status = item.get("status_code")
        if status not in {200, 201, 202, 204}:
            continue

        content_type = str(item.get("content_type") or "").lower()
        body_text = str(item.get("body_text") or "")

        try:
            query_pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        except Exception:
            query_pairs = []

        for qk, qv in query_pairs:
            key_l = str(qk or "").strip().lower()
            value = str(qv or "").strip()

            if not value:
                continue
            if key_l in excluded_non_object_query_names:
                continue
            if key_l not in strong_object_query_names and _objectish_key_score(key_l) < 6:
                continue

            if not (
                _looks_like_numeric_id(value)
                or _looks_like_uuidish(value)
                or _looks_like_object_id_value(value)
            ):
                continue

            key_score = 10 if key_l in strong_object_query_names else _objectish_key_score(key_l)
            if key_score <= 0:
                continue

            dedupe_key = ("query", url, key_l, value)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            candidates.append(
                {
                    "source_url": url,
                    "source_method": method,
                    "source_status": status,
                    "content_type": content_type,
                    "path_key": key_l,
                    "value": value,
                    "key_score": key_score,
                    "source_kind": "query_param",
                }
            )

            if len(candidates) >= max_candidates:
                return candidates

        if body_text.strip():
            parsed = _safe_json_loads_for_replay(body_text)
            if parsed is not None:
                flattened = _flatten_object_scalars(parsed)
                for path_key, value in flattened:
                    v = str(value or "").strip()
                    if not v:
                        continue

                    key_score = _objectish_key_score(path_key)
                    if key_score <= 0:
                        continue

                    if not (
                        _looks_like_numeric_id(v)
                        or _looks_like_uuidish(v)
                        or (_looks_like_object_id_value(v) and key_score >= 6)
                    ):
                        continue

                    dedupe_key = ("json", url, str(path_key).lower(), v)
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)

                    candidates.append(
                        {
                            "source_url": url,
                            "source_method": method,
                            "source_status": status,
                            "content_type": content_type,
                            "path_key": path_key,
                            "value": v,
                            "key_score": key_score,
                            "source_kind": "json_body",
                        }
                    )

                    if len(candidates) >= max_candidates:
                        return candidates

    return candidates


def _derive_object_replay_urls(source_url: str, object_value: str) -> List[Tuple[str, str]]:
    """
    Returns:
        [(candidate_url, derivation_kind), ...]

    범용 정책:
    - 기존 query에 이미 id-like selector가 있을 때만 replacement 허용
    - 무작정 accountId/userId 등을 새로 추가하지 않음
    - path append는 허용하되, 최종 build 단계에서 object-like 필터를 다시 적용
    """
    out: List[Tuple[str, str]] = []
    seen = set()

    parts = urlsplit(source_url)
    base_path = parts.path or "/"
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)

    id_like_names = {
        "id", "ids",
        "userid", "user_id", "userid[]",
        "accountid", "account_id",
        "orderid", "order_id",
        "cardid", "card_id",
        "addressid", "address_id",
        "basketid", "basket_id",
        "itemid", "item_id",
        "paymentid", "payment_id",
        "walletid", "wallet_id",
        "profileid", "profile_id",
        "customerid", "customer_id",
        "ownerid", "owner_id",
        "memberid", "member_id",
        "recordid", "record_id",
        "objectid", "object_id",
        "uuid", "guid",
        "email",
    }

    def _add(url: str, kind: str) -> None:
        if not url or url in seen:
            return
        seen.add(url)
        out.append((url, kind))

    # 1) 기존 query에 id-like selector가 이미 있을 때만 replacement
    for qk, _qv in query_pairs:
        qk_l = str(qk).strip().lower()
        if qk_l not in id_like_names:
            continue

        replaced = []
        for ek, ev in query_pairs:
            if str(ek) == str(qk):
                replaced.append((ek, object_value))
            else:
                replaced.append((ek, ev))
        _add(_replace_query(source_url, replaced), f"query:replace_{qk}")

    # 2) path append
    normalized_path = (base_path or "/").rstrip("/")
    if not normalized_path.endswith("/" + object_value):
        _add(_append_path(source_url, object_value), "path:append_object")

    return out[:4]

def _score_object_replay_candidate(
    *,
    source_url: str,
    candidate_url: str,
    object_key: str,
    object_value: str,
    authenticated_endpoints: List[Dict[str, Any]],
    anonymous_endpoints: List[Dict[str, Any]],
) -> int:
    score = 0

    source_path = (urlsplit(source_url).path or "/").lower()
    cand_path = (urlsplit(candidate_url).path or "/").lower()

    score += _objectish_key_score(object_key)

    if _looks_like_numeric_id(object_value):
        score += 4
    elif _looks_like_uuidish(object_value):
        score += 5
    elif _looks_like_object_id_value(object_value):
        score += 2
    else:
        return -999

    score += _sensitive_path_score(candidate_url)
    score += max(0, _sensitive_path_score(source_url) - 2)

    auth_keys = {
        _normalize_replay_key(str(ep.get("url") or ""))
        for ep in (authenticated_endpoints or [])
        if isinstance(ep, dict) and str(ep.get("url") or "").strip()
    }
    anon_keys = {
        _normalize_replay_key(str(ep.get("url") or ""))
        for ep in (anonymous_endpoints or [])
        if isinstance(ep, dict) and str(ep.get("url") or "").strip()
    }

    cand_key = _normalize_replay_key(candidate_url)

    if cand_key in auth_keys and cand_key not in anon_keys:
        score += 10
    elif cand_key in auth_keys:
        score += 4

    if _request_replay_has_id_like_signal(candidate_url):
        score += 6

    if not _request_replay_collection_like(candidate_url):
        score += 6
    else:
        score -= 10

    score -= _publicish_path_penalty(candidate_url)

    if _is_publicish_collection_url(candidate_url) and not _request_replay_has_id_like_signal(candidate_url):
        score -= 10

    if _is_self_context_path(candidate_url):
        score -= 20

    if _is_auth_flow_path(candidate_url):
        score -= 20

    if cand_path in {"", "/"}:
        score -= 20

    if len([seg for seg in cand_path.split("/") if seg]) >= 2:
        score += 2

    if source_path == cand_path:
        score -= 2

    return score


def _normalize_replay_key(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    path = re.sub(r"/+", "/", path)

    norm_parts = []
    for seg in path.split("/"):
        if not seg:
            continue
        if re.fullmatch(r"\d+", seg):
            norm_parts.append("{id}")
        elif re.fullmatch(r"[a-f0-9]{8,}", seg, re.I):
            norm_parts.append("{token}")
        else:
            norm_parts.append(seg)

    norm_path = "/" + "/".join(norm_parts)
    return f"{parts.scheme}://{parts.netloc}{norm_path}"


def build_access_control_replay_plan(
    *,
    authenticated_endpoints: List[Dict[str, object]],
    anonymous_endpoints: List[Dict[str, object]],
    auth_landing_url: Optional[str] = None,
    max_targets: Optional[int] = None,
) -> Dict[str, List[RequestSpec]]:
    base_headers = _merge_probe_headers()
    seen = set()

    if max_targets is None:
        max_targets = int(os.getenv("ACCESS_CONTROL_REPLAY_MAX_TARGETS", "20"))

    anon_keys = {
        _normalize_replay_key(str(ep.get("url") or ""))
        for ep in (anonymous_endpoints or [])
        if isinstance(ep, dict) and str(ep.get("url") or "").strip()
    }

    ranked: List[tuple[int, str, Dict[str, object], str]] = []

    for ep in authenticated_endpoints or []:
        if not isinstance(ep, dict):
            continue

        url = str(ep.get("url") or "").strip()
        if not url:
            continue

        if _request_replay_is_static_like(url):
            continue
        if _is_auth_flow_path(url):
            continue

        replay_key = _normalize_replay_key(url)
        score = _endpoint_replay_candidate_score(ep, anon_keys, auth_landing_url)
        if score < 0:
            continue

        states = {str(x).strip().lower() for x in (ep.get("states") or [])}

        if replay_key not in anon_keys:
            score += 10

        if urlsplit(url).query:
            score += 2

        if _is_self_context_path(url):
            score -= 8

        if _publicish_path_score(url) > 0 and replay_key in anon_keys:
            score -= 10

        if auth_landing_url and normalize_url_for_dedup(url) == normalize_url_for_dedup(auth_landing_url):
            score -= 20

        if "authenticated" not in states:
            continue

        if score < 10:
            continue

        ranked.append((score, url, ep, replay_key))

    ranked.sort(key=lambda x: (-x[0], len(urlsplit(x[1]).path), x[1]))

    auth_plan: List[RequestSpec] = []
    anon_plan: List[RequestSpec] = []
    used_replay_keys = set()

    for idx, (score, url, ep, replay_key) in enumerate(ranked, start=1):
        if replay_key in used_replay_keys:
            continue
        used_replay_keys.add(replay_key)

        states = ",".join(sorted(set(str(x) for x in (ep.get("states") or [])))) or "authenticated"
        group = f"acl_replay::{replay_key}"

        ep_method = str(ep.get("method") or "GET").upper().strip()
        shaped_method = "GET"
        shaped_url = url
        shaped_headers = dict(base_headers)
        shaped_body: Optional[bytes] = None

        if ep_method == "POST" and _is_legacy_menu_post_target(url):
            referer = str(ep.get("source") or "").strip() or None
            shaped_url, shaped_headers, shaped_body, shaped_method = _legacy_menu_request_shape(
                url,
                headers=base_headers,
                referer=referer,
            )

        auth_spec = RequestSpec(
            name=f"acl_replay_auth_{idx}",
            method=shaped_method,
            url=shaped_url,
            headers=shaped_headers,
            body=shaped_body,
            source="access_control_replay",
            family="access_control_replay",
            mutation_class="authenticated_replay",
            surface_hint="status_headers_body",
            expected_signal="authenticated_view_of_protected_resource",
            comparison_group=group,
            auth_state="authenticated",
            replay_key=replay_key,
            replay_source_url=url,
            replay_source_state=states,
            replay_priority=score,
        )
        anon_spec = RequestSpec(
            name=f"acl_replay_anon_{idx}",
            method=shaped_method,
            url=shaped_url,
            headers=shaped_headers,
            body=shaped_body,
            source="access_control_replay",
            family="access_control_replay",
            mutation_class="anonymous_replay",
            surface_hint="status_headers_body",
            expected_signal="anonymous_access_to_authenticated_resource",
            comparison_group=group,
            auth_state="anonymous",
            replay_key=replay_key,
            replay_source_url=url,
            replay_source_state=states,
            replay_priority=score,
        )

        _append_unique(auth_plan, seen, auth_spec)
        _append_unique(anon_plan, seen, anon_spec)

        if len(auth_plan) >= max_targets:
            break

    return {
        "authenticated": auth_plan,
        "anonymous": anon_plan,
    }



def _request_replay_norm_url(url: str) -> str:
    try:
        parts = urlsplit(str(url or "").strip())
        path = parts.path or "/"
        path = re.sub(r"/{2,}", "/", path)

        norm_parts = []
        for seg in path.split("/"):
            if not seg:
                continue
            if re.fullmatch(r"\d+", seg):
                norm_parts.append("{id}")
            elif re.fullmatch(r"[a-f0-9]{8,}", seg, re.I):
                norm_parts.append("{token}")
            else:
                norm_parts.append(seg)

        norm_path = "/" + "/".join(norm_parts)
        return urlunsplit((parts.scheme, parts.netloc, norm_path, "", ""))
    except Exception:
        return str(url or "").strip()



def _request_replay_is_static_like(url: str) -> bool:
    path = (urlsplit(str(url or "")).path or "").lower()
    return path.endswith((
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
        ".ico", ".woff", ".woff2", ".map", ".txt", ".md",
        ".pdf", ".zip", ".tar", ".gz",
    ))


def _request_replay_query_keys(url: str) -> List[str]:
    try:
        return [str(k).strip().lower() for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except Exception:
        return []


def _request_replay_has_id_like_signal(url: str) -> bool:
    parts = urlsplit(str(url or ""))
    path = parts.path or "/"
    query_keys = set(_request_replay_query_keys(url))

    id_like_query_keys = {
        "id", "ids",
        "user", "userid", "user_id",
        "account", "accountid", "account_id",
        "email", "token", "session",
        "addressid", "address_id",
        "cardid", "card_id",
        "basketid", "basket_id",
        "orderid", "order_id",
        "itemid", "item_id",
        "paymentid", "payment_id",
        "walletid", "wallet_id",
        "invoiceid", "invoice_id",
    }

    if query_keys.intersection(id_like_query_keys):
        return True

    for seg in path.split("/"):
        s = seg.strip()
        if not s:
            continue
        if re.fullmatch(r"\d+", s):
            return True
        if re.fullmatch(r"[a-f0-9]{8,}", s, re.I):
            return True

    return False

def _request_replay_collection_like(url: str) -> bool:
    try:
        path = (urlsplit(str(url or "")).path or "/").strip("/")
    except Exception:
        return True

    if not path:
        return True

    parts = [p for p in path.split("/") if p]
    if not parts:
        return True

    last = parts[-1].lower()

    if re.fullmatch(r"\d+", last):
        return False
    if re.fullmatch(r"[a-f0-9]{8,}", last, re.I):
        return False

    collectionish = {
        "api",
        "rest",
        "users",
        "user",
        "accounts",
        "account",
        "profiles",
        "profile",
        "cards",
        "addresses",
        "address",
        "orders",
        "order",
        "payments",
        "payment",
        "wallets",
        "wallet",
        "items",
        "products",
        "reviews",
        "customers",
        "invoices",
        "sessions",
        "tokens",
        "notifications",
        "messages",
        "files",
        "documents",
        "settings",
        "groups",
        "roles",
        "members",
        "teams",
        "projects",
        "basketitems",
        "complaints",
    }
    return last in collectionish


def _build_request_replay_spec(
    *,
    idx: int,
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    replay_key: str,
    priority: int,
    auth_state: str,
) -> RequestSpec:
    is_auth = auth_state == "authenticated"

    return RequestSpec(
        name=f"req_replay_{'auth' if is_auth else 'anon'}_{idx}",
        method=method,
        url=url,
        headers=headers,
        body=body,
        source="request_access_control_replay",
        family="request_access_control_replay",
        mutation_class="request_authenticated_replay" if is_auth else "request_anonymous_replay",
        surface_hint="status_headers_body",
        expected_signal="authenticated_request_replay" if is_auth else "anonymous_request_replay",
        comparison_group=f"req_replay::{replay_key}",
        auth_state=auth_state,
        replay_key=replay_key,
        replay_source_url=url,
        replay_source_state="authenticated",
        replay_priority=priority,
    )


def _request_replay_candidate_score(item: Dict[str, Any]) -> int:
    method = str(item.get("method") or "").upper().strip()
    url = str(item.get("url") or "").strip()
    source = str(item.get("source") or "").strip().lower()
    family = str(item.get("family") or "").strip().lower()
    auth_state = str(item.get("auth_state") or "").strip().lower()
    status = item.get("status_code")

    if not url:
        return -999

    parts = urlsplit(url)
    path = (parts.path or "/").strip()
    path_l = path.lower()
    query_pairs = _existing_query_pairs(url)
    query_names = {str(k).strip().lower() for k, _ in query_pairs if str(k).strip()}

    if source == "auth" or family == "authentication":
        return -999

    if auth_state != "authenticated":
        return -999

    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return -999

    if status is None or status >= 500:
        return -999

    if path_l in {"", "/"}:
        return -999

    if _is_auth_flow_path(url):
        return -999

    if _request_replay_is_static_like(url):
        return -999

    segments = [seg for seg in path.split("/") if seg]
    depth = len(segments)
    last = segments[-1].lower() if segments else ""

    objectish_query_names = {
        "id",
        "userid",
        "user_id",
        "email",
        "token",
        "addressid",
        "address_id",
        "cardid",
        "card_id",
        "basketid",
        "basket_id",
        "orderid",
        "order_id",
        "itemid",
        "item_id",
        "invoiceid",
        "invoice_id",
        "accountid",
        "account_id",
        "paymentid",
        "payment_id",
        "walletid",
        "wallet_id",
    }
    weak_query_names = {"session", "lang", "page", "sort", "q", "search"}

    score = 0

    if method in {"PUT", "PATCH", "DELETE"}:
        score += 8
    elif method == "POST":
        score += 6
    elif method == "GET":
        score += 2

    if status in {200, 201, 202, 204}:
        score += 4
    elif status in {301, 302, 303, 307, 308, 401, 403, 404, 405}:
        score -= 6

    if depth >= 3:
        score += 3
    elif depth == 2:
        score += 1

    score += _sensitive_path_score(url)

    if query_names.intersection(objectish_query_names):
        score += 5

    if query_names and query_names.issubset(weak_query_names):
        score -= 6

    if segments and _looks_like_object_identifier(segments[-1]):
        score += 7
    elif last and _is_collection_like_segment(last):
        score -= 8

    if method == "GET" and last and _is_collection_like_segment(last) and not query_names.intersection(objectish_query_names):
        score -= 10

    if method in {"PUT", "PATCH", "DELETE"} and depth <= 1:
        score -= 20

    if method == "POST" and _is_auth_flow_path(url):
        score -= 20

    if _publicish_path_score(url) > 0 and not _request_replay_has_id_like_signal(url):
        score -= 8

    return score


def build_object_access_control_replay_plan(
    *,
    raw_index: List[Dict[str, object]],
    authenticated_endpoints: Optional[List[Dict[str, object]]] = None,
    anonymous_endpoints: Optional[List[Dict[str, object]]] = None,
    auth_landing_url: Optional[str] = None,
    max_targets: Optional[int] = None,
) -> Dict[str, List[RequestSpec]]:
    headers = _base_headers()
    seen = set()

    if max_targets is None:
        max_targets = int(os.getenv("ACCESS_CONTROL_OBJECT_REPLAY_MAX_TARGETS", "10"))

    authenticated_endpoints = authenticated_endpoints or []
    anonymous_endpoints = anonymous_endpoints or []

    def _path_l(url: str) -> str:
        return (urlsplit(url).path or "/").lower()

    def _segments(url: str) -> List[str]:
        return [seg for seg in (urlsplit(url).path or "/").split("/") if seg]

    def _is_business_route_like(url: str) -> bool:
        path_l = _path_l(url)
        query_names = {str(k).strip().lower() for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}

        if "/api/" in path_l or "/rest/" in path_l:
            return True

        if any(tok in path_l for tok in (
            ".do", ".action", ".jsp", ".php",
            "/project/", "/change/", "/member", "/contract", "/board/",
            "/account/", "/profile/", "/order/", "/payment/", "/wallet/",
        )):
            return True

        if query_names.intersection({
            "id", "userid", "user_id", "accountid", "account_id",
            "orderid", "order_id", "cardid", "card_id", "addressid",
            "address_id", "basketid", "basket_id", "itemid", "item_id",
            "paymentid", "payment_id", "walletid", "wallet_id",
            "docid", "doc_id", "reqid", "req_id", "seq", "no", "num",
            "memberid", "member_id",
        }):
            return True

        return False

    def _legacy_do_like(url: str) -> bool:
        path_l = _path_l(url)
        return any(tok in path_l for tok in (".do", ".action", ".jsp"))

    def _auth_only_endpoint_key_set(endpoints: List[Dict[str, object]]) -> set[str]:
        out = set()
        for ep in endpoints or []:
            if not isinstance(ep, dict):
                continue
            url = str(ep.get("url") or "").strip()
            if not url:
                continue
            out.add(_normalize_replay_key(url))
        return out

    authenticated_keys = _auth_only_endpoint_key_set(authenticated_endpoints)
    anonymous_keys = _auth_only_endpoint_key_set(anonymous_endpoints)

    object_candidates = _extract_object_candidates_from_raw_index(
        raw_index,
        max_candidates=max_targets * 50,
    )

    ranked: List[tuple[int, str, str, str, str, str]] = []
    seen_rank_keys = set()

    for obj in object_candidates:
        source_url = str(obj.get("source_url") or "").strip()
        source_method = str(obj.get("source_method") or "").upper().strip()
        path_key = str(obj.get("path_key") or "").strip().lower()
        value = str(obj.get("value") or "").strip()
        key_score = int(obj.get("key_score") or 0)

        if not source_url or not value:
            continue
        if source_method != "GET":
            continue
        if _request_replay_is_static_like(source_url):
            continue
        if not _is_business_route_like(source_url):
            continue
        if _is_auth_flow_path(source_url):
            continue
        if _is_self_context_path(source_url):
            continue

        if path_key in {"_menuid", "menuid", "_menuf", "menuf", "bbsid", "pageid"}:
            continue

        source_path_l = _path_l(source_url)

        source_has_object_hint = (
            _request_replay_has_id_like_signal(source_url)
            or _objectish_key_score(path_key) >= 6
            or _sensitive_path_score(source_url) > 0
            or any(tok in source_path_l for tok in (
                "user", "account", "profile", "address", "card", "basket",
                "order", "payment", "wallet", "customer", "owner", "invoice",
                "member", "record", "object", "project", "contract", "nda",
                "board", "change",
            ))
        )
        if not source_has_object_hint:
            continue

        derived = _derive_object_replay_urls(source_url, value)

        # legacy .do 계열은 path append 제거, query replacement만 허용
        if _legacy_do_like(source_url):
            derived = [(u, k) for (u, k) in derived if k.startswith("query:replace_")]

        for candidate_url, derivation_kind in derived:
            if not candidate_url:
                continue
            if _request_replay_is_static_like(candidate_url):
                continue
            if not _is_business_route_like(candidate_url):
                continue
            if _is_auth_flow_path(candidate_url):
                continue
            if _is_self_context_path(candidate_url):
                continue

            cand_key_norm = _normalize_replay_key(candidate_url)

            score = _score_object_replay_candidate(
                source_url=source_url,
                candidate_url=candidate_url,
                object_key=path_key,
                object_value=value,
                authenticated_endpoints=authenticated_endpoints,
                anonymous_endpoints=anonymous_endpoints,
            )

            if score < 0:
                continue

            score += min(8, key_score)

            if derivation_kind.startswith("path:"):
                score += 4
            elif derivation_kind.startswith("query:replace_"):
                score += 8

            if cand_key_norm in authenticated_keys and cand_key_norm not in anonymous_keys:
                score += 8
            elif cand_key_norm in authenticated_keys:
                score += 3

            segs = _segments(candidate_url)
            if len(segs) <= 1 and not urlsplit(candidate_url).query:
                score -= 10
            elif len(segs) >= 2:
                score += 2

            if _normalize_replay_key(source_url) == cand_key_norm and _request_replay_collection_like(candidate_url):
                continue

            if auth_landing_url and normalize_url_for_dedup(candidate_url) == normalize_url_for_dedup(auth_landing_url):
                continue

            if _publicish_path_score(candidate_url) > 0 and not _request_replay_has_id_like_signal(candidate_url):
                continue

            if score < 16:
                continue

            replay_key = f"GET:{cand_key_norm}"
            rank_key = (replay_key, value)
            if rank_key in seen_rank_keys:
                continue
            seen_rank_keys.add(rank_key)

            ranked.append((
                score,
                candidate_url,
                replay_key,
                source_url,
                path_key,
                derivation_kind,
            ))

    ranked.sort(key=lambda x: (-x[0], len(urlsplit(x[1]).path), x[1]))

    auth_plan: List[RequestSpec] = []
    anon_plan: List[RequestSpec] = []
    used_replay_keys = set()

    for idx, (score, url, replay_key, source_url, path_key, derivation_kind) in enumerate(ranked, start=1):
        if replay_key in used_replay_keys:
            continue
        used_replay_keys.add(replay_key)

        comparison_group = f"obj_acl_replay::{replay_key}"

        auth_spec = RequestSpec(
            name=f"obj_acl_replay_auth_{idx}",
            method="GET",
            url=url,
            headers=headers,
            source="object_access_control_replay",
            family="object_access_control_replay",
            mutation_class=f"authenticated_object_replay::{derivation_kind}",
            surface_hint="status_headers_body",
            expected_signal="authenticated_object_response",
            comparison_group=comparison_group,
            auth_state="authenticated",
            replay_key=replay_key,
            replay_source_url=source_url,
            replay_source_state="authenticated",
            replay_priority=score,
        )
        anon_spec = RequestSpec(
            name=f"obj_acl_replay_anon_{idx}",
            method="GET",
            url=url,
            headers=headers,
            source="object_access_control_replay",
            family="object_access_control_replay",
            mutation_class=f"anonymous_object_replay::{derivation_kind}",
            surface_hint="status_headers_body",
            expected_signal="anonymous_object_response",
            comparison_group=comparison_group,
            auth_state="anonymous",
            replay_key=replay_key,
            replay_source_url=source_url,
            replay_source_state="authenticated",
            replay_priority=score,
        )

        _append_unique(auth_plan, seen, auth_spec)
        _append_unique(anon_plan, seen, anon_spec)

        if len(auth_plan) >= max_targets:
            break

    return {
        "authenticated": auth_plan,
        "anonymous": anon_plan,
    }

def _build_authenticated_business_probe_spec(
    *,
    idx: int,
    url: str,
    headers: Dict[str, str],
    priority: int,
) -> RequestSpec:
    replay_key = _normalize_replay_key(url)

    if _is_legacy_menu_post_target(url):
        shaped_url, shaped_headers, shaped_body, shaped_method = _legacy_menu_request_shape(
            url,
            headers=headers,
        )
        return RequestSpec(
            name=f"auth_business_post_{idx}",
            method=shaped_method,
            url=shaped_url,
            headers=shaped_headers,
            body=shaped_body,
            source="authenticated_business_probe",
            family="authenticated_business_probe",
            mutation_class="authenticated_business_seed_legacy_post",
            surface_hint="status_headers_body",
            expected_signal="authenticated_business_response",
            comparison_group=f"auth_business::{replay_key}",
            auth_state="authenticated",
            replay_key=replay_key,
            replay_source_url=url,
            replay_source_state="authenticated",
            replay_priority=priority,
        )

    return RequestSpec(
        name=f"auth_business_get_{idx}",
        method="GET",
        url=url,
        headers=_merge_probe_headers(headers),
        source="authenticated_business_probe",
        family="authenticated_business_probe",
        mutation_class="authenticated_business_seed",
        surface_hint="status_headers_body",
        expected_signal="authenticated_business_response",
        comparison_group=f"auth_business::{replay_key}",
        auth_state="authenticated",
        replay_key=replay_key,
        replay_source_url=url,
        replay_source_state="authenticated",
        replay_priority=priority,
    )



def build_authenticated_business_probe_plan(
    *,
    authenticated_endpoints: List[Dict[str, object]],
    anonymous_endpoints: Optional[List[Dict[str, object]]] = None,
    max_targets: Optional[int] = None,
) -> List[RequestSpec]:
    headers = _base_headers()
    seen = set()
    plan: List[RequestSpec] = []

    if max_targets is None:
        max_targets = int(os.getenv("AUTHENTICATED_BUSINESS_PROBE_MAX_TARGETS", "20"))

    anonymous_norm_paths = set()
    for ep in anonymous_endpoints or []:
        if not isinstance(ep, dict):
            continue
        url = str(ep.get("url") or "").strip()
        if not url:
            continue
        anonymous_norm_paths.add(_normalize_replay_key(url))

    def _path(url: str) -> str:
        try:
            return (urlsplit(url).path or "/").strip()
        except Exception:
            return "/"

    def _query_keys(url: str) -> set[str]:
        try:
            return {str(k).strip().lower() for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}
        except Exception:
            return set()

    def _looks_like_identifier_segment(seg: str) -> bool:
        s = str(seg or "").strip()
        if not s:
            return False
        if re.fullmatch(r"\d{1,12}", s):
            return True
        if re.fullmatch(r"[0-9a-f]{8,}", s, re.I):
            return True
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f\-]{27,}", s, re.I):
            return True
        if "@" in s:
            return True
        return False

    def _objectish(url: str) -> bool:
        path = _path(url).strip("/")
        parts = [p for p in path.split("/") if p]
        if parts and _looks_like_identifier_segment(parts[-1]):
            return True

        qkeys = _query_keys(url)
        if qkeys.intersection({
            "id", "userid", "user_id", "accountid", "account_id",
            "orderid", "order_id", "cardid", "card_id", "addressid",
            "address_id", "basketid", "basket_id", "itemid", "item_id",
            "email", "paymentid", "payment_id", "walletid", "wallet_id",
        }):
            return True
        return False

    def _score(ep: Dict[str, object]) -> int:
        url = str(ep.get("url") or "").strip()
        if not url:
            return -999

        norm_path = _normalize_replay_key(url)
        states = {str(x).strip().lower() for x in (ep.get("states") or [])}
        kind = str(ep.get("kind") or "").strip().lower()
        crawler_score = int(ep.get("score", 0) or 0)
        qkeys = _query_keys(url)
        path = _path(url)
        parts = [p for p in path.split("/") if p]

        if _request_replay_is_static_like(url):
            return -999
        if _is_auth_flow_path(url):
            return -999
        if _is_publicish_collection_url(url) and not _request_replay_has_id_like_signal(url):
            return -999

        # /10 같은 SPA route 제거
        if len(parts) == 1 and parts and _looks_like_identifier_segment(parts[0]):
            return -999

        if "authenticated" not in states:
            return -999

        score = 0

        if norm_path not in anonymous_norm_paths:
            score += 20
        else:
            score += 6

        if kind == "form":
            score += 10
        elif kind == "page":
            score += 4
        elif kind == "static":
            return -999

        score += min(10, crawler_score // 10)
        score += _sensitive_path_score(url)
        score -= max(0, _publicish_path_score(url) // 2)

        if _objectish(url):
            score += 12
        elif _request_replay_has_id_like_signal(url):
            score += 8

        if qkeys.intersection({
            "id", "userid", "user_id", "accountid", "account_id",
            "orderid", "order_id", "cardid", "card_id", "addressid",
            "address_id", "basketid", "basket_id", "itemid", "item_id",
            "email", "paymentid", "payment_id", "walletid", "wallet_id",
        }):
            score += 8

        depth = len(parts)
        if depth == 0:
            return -999
        if depth == 1:
            score -= 4
        else:
            score += min(depth, 5)

        if _is_self_context_path(url):
            score -= 6

        if _publicish_path_score(url) > 0 and _sensitive_path_score(url) == 0 and not _objectish(url):
            return -999

        if _sensitive_path_score(url) == 0 and not _objectish(url) and not qkeys:
            return -999

        return score

    ranked: List[tuple[int, Dict[str, object]]] = []
    for ep in authenticated_endpoints or []:
        if not isinstance(ep, dict):
            continue
        score = _score(ep)
        if score < 0:
            continue
        ranked.append((score, ep))

    ranked.sort(key=lambda x: (-x[0], str(x[1].get("url") or "")))

    for idx, (priority, ep) in enumerate(ranked, start=1):
        url = str(ep.get("url") or "").strip()
        if not url:
            continue

        spec = _build_authenticated_business_probe_spec(
            idx=idx,
            url=url,
            headers=headers,
            priority=priority,
        )
        _append_unique(plan, seen, spec)

        if len(plan) >= max_targets:
            break

    return plan

def build_probe_plan(target: str, intensity: str = "full") -> List[RequestSpec]:
    if target.endswith("/"):
        base = target[:-1]
        with_slash = target
    else:
        base = target
        with_slash = target

    headers = _base_headers()
    plan: List[RequestSpec] = []
    seen = set()

    is_static_mode = intensity == "static"
    target_path_l = urlsplit(with_slash).path.lower()

    legacy_business_target = any(tok in target_path_l for tok in (".do", ".action", ".jsp"))

    http_sensitive_target = any(
        tok in target_path_l
        for tok in (
            "/api",
            "/rest",
            "/graphql",
            "/ftp",
            "/admin",
            "/debug",
            "/actuator",
            "/upload",
            "/uploads",
            "/file",
            "/files",
            "/download",
            "/downloads",
            ".do",
            ".action",
            ".jsp",
            "/common",   # NDA 같은 enterprise portal root도 민감 대상으로 본다
        )
    )

    if is_static_mode:
        category_limits = {
            "baseline": 2,
            "notfound": 0,
            "resources": 0,
            "directory": 0,
            "methods": 0,
            "cors": 0,
            "headers": 0,
            "path": 0,
            "query": 0,
            "body": 0,
        }
        total_budget = int(os.getenv("STATIC_REQUEST_BUDGET", "6"))

    elif legacy_business_target:
        category_limits = {
            "baseline": 3,
            "notfound": 0,
            "resources": 2,
            "directory": 0,
            "methods": 0,
            "cors": 0,
            "headers": 0,
            "path": 2,   # 기존 0 -> 2
            "query": 2,  # 기존 0 -> 2
            "body": 0,
        }
        total_budget = int(os.getenv("LEGACY_DO_REQUEST_BUDGET", "10"))

    elif intensity == "light":
        category_limits = {
            "baseline": 4,
            "notfound": 2,
            "resources": 4,
            "directory": 1,
            "methods": 1 if http_sensitive_target else 0,
            "cors": 0,
            "headers": 1 if http_sensitive_target else 0,
            "path": 1 if http_sensitive_target else 0,
            "query": 1 if http_sensitive_target else 0,
            "body": 0,
        }
        total_budget = int(os.getenv("LIGHT_REQUEST_BUDGET", "12"))

    elif intensity == "medium":
        category_limits = {
            "baseline": 4,
            "notfound": 2,
            "resources": 6,
            "directory": 2,
            "methods": 2 if http_sensitive_target else 0,
            "cors": 0,
            "headers": 2 if http_sensitive_target else 1,
            "path": 2 if http_sensitive_target else 0,
            "query": 2 if http_sensitive_target else 0,
            "body": 0,
        }
        total_budget = int(os.getenv("MEDIUM_REQUEST_BUDGET", "24"))

    else:
        category_limits = {
            "baseline": 4,
            "notfound": 2,
            "resources": 8,
            "directory": 3,
            "methods": 3 if http_sensitive_target else 0,
            "cors": 0,
            "headers": 3 if http_sensitive_target else 1,
            "path": 4 if http_sensitive_target else 0,
            "query": 4 if http_sensitive_target else 0,
            "body": 0,
        }
        total_budget = int(os.getenv("FULL_REQUEST_BUDGET", "36"))

    def add_limited(specs: List[RequestSpec], limit: int) -> None:
        if limit <= 0:
            return
        count = 0
        for spec in specs:
            before = len(plan)
            _append_unique(plan, seen, spec)
            if len(plan) > before:
                count += 1
            if count >= limit or len(plan) >= total_budget:
                break

    add_limited(_baseline_specs(with_slash, headers), category_limits["baseline"])
    add_limited(_notfound_specs(base, headers), category_limits["notfound"])
    add_limited(_resource_exposure_specs(with_slash, headers, intensity), category_limits["resources"])
    add_limited(_directory_listing_specs(with_slash, headers, intensity), category_limits["directory"])
    add_limited(_risky_method_specs(with_slash, headers), category_limits["methods"])
    add_limited(_cors_specs(with_slash, headers), category_limits["cors"])

    if not is_static_mode:
        # header/body mutation은 legacy에서는 계속 보수적으로
        if not legacy_business_target:
            add_limited(_header_mutation_specs(with_slash, headers), category_limits["headers"])
            add_limited(_body_format_specs(with_slash, headers), category_limits["body"])

        # path/query mutation은 legacy에서도 제한적으로 허용
        mutation_intensity = "light" if legacy_business_target else intensity
        add_limited(_error_path_specs(with_slash, headers, mutation_intensity), category_limits["path"])
        add_limited(_error_query_specs(with_slash, headers, mutation_intensity), category_limits["query"])
    try:
        names = [spec.name for spec in plan]
        path_specs = [n for n in names if n.startswith("path_")]
        query_specs = [n for n in names if n.startswith("qs_")]

    except Exception as e:
        log("PROBE", f"[build_probe_plan] debug_error={e}")

    return plan[: min(len(plan), total_budget)]


def _is_request_replay_candidate(
    item: Dict[str, object],
    *,
    excluded_sources: set[str],
    excluded_families: set[str],
    scanner_name_tokens: tuple[str, ...],
) -> bool:
    auth_state = str(item.get("auth_state") or "").strip().lower()
    method = str(item.get("method") or "").strip().upper()
    url = str(item.get("url") or "").strip()
    status = item.get("status_code")
    source = str(item.get("source") or "").strip().lower()
    family = str(item.get("family") or "").strip().lower()
    request_name = str(item.get("request_name") or "").strip().lower()

    if auth_state != "authenticated":
        return False
    if not url:
        return False
    if method not in {"GET", "POST"}:
        return False
    if status not in {200, 201, 202, 204}:
        return False
    if source in excluded_sources:
        return False
    if family in excluded_families:
        return False
    if any(tok in request_name for tok in scanner_name_tokens):
        return False
    if _request_replay_is_static_like(url):
        return False

    path = (urlsplit(str(url or "")).path or "/").strip().lower()
    if path in {"", "/", "/api", "/api/", "/rest", "/rest/"}:
        return False

    if _is_auth_flow_path(url):
        return False

    return True


def build_authenticated_request_replay_plan(
    *,
    raw_index: List[Dict[str, object]],
    max_targets: int = 20,
) -> Dict[str, List[RequestSpec]]:
    auth_plan: List[RequestSpec] = []
    anon_plan: List[RequestSpec] = []
    seen = set()

    excluded_sources = {
        "auth",
        "access_control_replay",
        "request_access_control_replay",
        "object_access_control_replay",
    }
    excluded_families = {
        "authentication",
        "access_control_replay",
        "request_access_control_replay",
        "object_access_control_replay",
        "baseline",
        "comparison",
        "default_resource",
        "directory_behavior",
        "method_behavior",
        "cors_behavior",
        "header_behavior",
        "error_path",
        "error_query",
        "body_behavior",
    }
    scanner_name_tokens = (
        "baseline",
        "notfound",
        "resource_probe",
        "resource_head",
        "dir_list",
        "method_",
        "cors_",
        "hdr_",
        "path_",
        "qs_",
        "body_",
        "__nonexistent_",
        ".env",
        ".git/config",
        "phpinfo.php",
        "server-status",
    )

    def _is_root_like(url: str) -> bool:
        path = (urlsplit(str(url or "")).path or "/").strip().lower()
        return path in {"", "/", "/api", "/api/", "/rest", "/rest/"}

    def _is_business_page_like(url: str) -> bool:
        path_l = (urlsplit(url).path or "/").lower()
        query_names = {str(k).strip().lower() for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}

        if any(tok in path_l for tok in (
            ".do", ".action", ".jsp", ".php",
            "/project/", "/change/", "/member", "/contract", "/board/",
            "/account/", "/profile/", "/order/", "/payment/", "/wallet/",
            "/user/", "/users/",
        )):
            return True

        if query_names.intersection({
            "id", "userid", "user_id", "accountid", "account_id",
            "orderid", "order_id", "cardid", "card_id", "addressid",
            "address_id", "basketid", "basket_id", "itemid", "item_id",
            "paymentid", "payment_id", "walletid", "wallet_id",
            "docid", "doc_id", "reqid", "req_id", "seq", "no", "num",
            "memberid", "member_id",
        }):
            return True

        return False

    def _is_explicit_public(item: Dict[str, object]) -> bool:
        url = str(item.get("url") or "").strip()
        content_type = str(item.get("content_type") or "").lower()
        body_len = int(item.get("body_len") or 0)
        request_name = str(item.get("request_name") or "").strip().lower()

        if not url:
            return False

        if _publicish_path_score(url) > 0 and not _request_replay_has_id_like_signal(url) and not _is_business_page_like(url):
            return True

        if any(tok in request_name for tok in (
            "captcha", "challenge", "hint", "health", "status", "version",
        )):
            return True

        if (
            _request_replay_collection_like(url)
            and "json" in content_type
            and body_len > 0
            and not _is_business_page_like(url)
        ):
            return True

        return False

    ranked: List[tuple[int, Dict[str, object]]] = []

    for item in raw_index or []:
        if not isinstance(item, dict):
            continue

        url = str(item.get("url") or "").strip()
        content_type = str(item.get("content_type") or "").lower()

        if not _is_request_replay_candidate(
            item,
            excluded_sources=excluded_sources,
            excluded_families=excluded_families,
            scanner_name_tokens=scanner_name_tokens,
        ):
            continue

        if _is_root_like(url):
            continue
        if _is_auth_flow_path(url):
            continue
        if _is_self_context_path(url):
            continue
        if _is_explicit_public(item):
            continue

        score = _request_replay_candidate_score(item)
        if score < 0:
            continue

        score += _request_replay_path_bias_score(
            url=url,
            content_type=content_type,
        )

        if _is_business_page_like(url):
            score += 6
        if _request_replay_has_id_like_signal(url):
            score += 4
        if _sensitive_path_score(url) > 0:
            score += 4

        if score < 6:
            continue

        ranked.append((score, item))

    ranked.sort(
        key=lambda x: (
            -x[0],
            len(urlsplit(str(x[1].get("url") or "")).path),
            str(x[1].get("url") or ""),
        )
    )

    used_keys = set()

    for idx, (priority, item) in enumerate(ranked, start=1):
        raw_method = str(item.get("method") or "").upper().strip()
        raw_url = str(item.get("url") or "").strip()
        raw_request_headers = item.get("request_headers") or {}
        raw_request_body_text = str(item.get("request_body_text") or "")

        shaped_headers = _merge_probe_headers(_filter_replay_headers(raw_request_headers if isinstance(raw_request_headers, dict) else {}))
        shaped_url = raw_url
        shaped_method = raw_method
        shaped_body: Optional[bytes] = raw_request_body_text.encode("utf-8") if raw_request_body_text else None

        # legacy NDA 메뉴형 POST는 query -> form body fallback
        if raw_method == "POST" and not raw_request_body_text and _is_legacy_menu_post_target(raw_url):
            referer = None
            if isinstance(raw_request_headers, dict):
                referer = str(raw_request_headers.get("Referer") or raw_request_headers.get("referer") or "").strip() or None
            shaped_url, shaped_headers, shaped_body, shaped_method = _legacy_menu_request_shape(
                raw_url,
                headers=shaped_headers,
                referer=referer,
            )

        replay_key = f"{shaped_method}:{_normalize_replay_key(shaped_url)}"

        if replay_key in used_keys:
            continue
        used_keys.add(replay_key)

        auth_spec = _build_request_replay_spec(
            idx=idx,
            method=shaped_method,
            url=shaped_url,
            headers=shaped_headers,
            body=shaped_body,
            replay_key=replay_key,
            priority=priority,
            auth_state="authenticated",
        )

        anon_spec = _build_request_replay_spec(
            idx=idx,
            method=shaped_method,
            url=shaped_url,
            headers=shaped_headers,
            body=shaped_body,
            replay_key=replay_key,
            priority=priority,
            auth_state="anonymous",
        )

        _append_unique(auth_plan, seen, auth_spec)
        _append_unique(anon_plan, seen, anon_spec)

        if len(auth_plan) >= max_targets:
            break

    return {
        "authenticated": auth_plan,
        "anonymous": anon_plan,
    }

def _request_replay_path_bias_score(
    *,
    url: str,
    content_type: str,
) -> int:
    path_l = (urlsplit(url).path or "/").lower()
    score = 0

    if "/api/" in path_l or "/rest/" in path_l:
        score += 5

    if _request_replay_has_id_like_signal(url):
        score += 6

    if not _request_replay_collection_like(url):
        score += 6
    else:
        if "json" in content_type:
            score += 2
        else:
            score -= 6

    score += max(0, _sensitive_path_score(url) - 2)
    score -= max(0, _publicish_path_score(url) // 2)

    return score
