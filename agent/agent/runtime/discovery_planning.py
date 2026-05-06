from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit

from agent.core.common import log
from agent.planning.probes import RequestSpec
from agent.runtime.scan_profile import (
    endpoint_bucket_limit,
    is_html_breadth_profile,
    is_meaningful_html_path,
    is_spa_method_profile,
    is_spa_high_value_path,
    resolve_scan_profile,
)


LOW_VALUE_FILE_HINTS = (
    "readme",
    "changelog",
    "license",
    "copying",
    "authors",
    "contributing",
)

LOW_VALUE_EXTS = (
    ".md",
    ".rst",
    ".txt",
)


def endpoint_url(ep: Any) -> str:
    if isinstance(ep, dict):
        return str(ep.get("url") or "")
    return str(ep or "")


def endpoint_kind(ep: Any) -> str:
    if isinstance(ep, dict):
        return str(ep.get("kind") or "page")
    return "page"


def endpoint_states(ep: Any) -> List[str]:
    if not isinstance(ep, dict):
        return []
    states = ep.get("states") or []
    out: List[str] = []
    seen = set()
    for state in states:
        value = str(state or "").strip().lower()
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    state = str(ep.get("state") or "").strip().lower()
    if state and state not in seen:
        out.append(state)
    return out


def canonical_endpoint_sort_key(ep: Any) -> tuple:
    url = endpoint_url(ep)
    parts = urlsplit(url)
    states = ",".join(endpoint_states(ep))
    kind = endpoint_kind(ep)
    method = str(ep.get("method") or "GET").upper() if isinstance(ep, dict) else "GET"
    score = int(ep.get("score", 0) or 0) if isinstance(ep, dict) else 0
    depth = int(ep.get("depth", 9999) or 9999) if isinstance(ep, dict) else 9999
    return (
        bool(is_session_destructive_endpoint(ep)),
        -score,
        kind == "static",
        depth,
        len(parts.path or "/"),
        parts.path or "/",
        parts.query or "",
        method,
        states,
        parts.scheme.lower(),
        parts.netloc.lower(),
    )


def is_authenticated_only_endpoint(ep: Any) -> bool:
    states = set(endpoint_states(ep))
    return "authenticated" in states and "anonymous" not in states


def is_session_destructive_endpoint(ep: Any) -> bool:
    return isinstance(ep, dict) and bool(ep.get("is_session_destructive"))


def discovered_endpoint_urls(endpoints: List[Any]) -> List[str]:
    out: List[str] = []
    for endpoint in endpoints or []:
        if isinstance(endpoint, dict):
            url = str(endpoint.get("url") or "")
            if url:
                out.append(url)
        elif isinstance(endpoint, str):
            out.append(endpoint)
    return out


def choose_probe_intensity_for_rank(rank: int) -> str:
    full_count = int(os.getenv("CRAWL_FULL_ENDPOINTS", "1"))
    medium_count = int(os.getenv("CRAWL_MEDIUM_ENDPOINTS", "2"))
    if rank < full_count:
        return "full"
    if rank < full_count + medium_count:
        return "medium"
    return "light"


def choose_probe_intensity_for_endpoint(rank: int, ep: Dict[str, Any]) -> str:
    profile = resolve_scan_profile()
    kind = endpoint_kind(ep)
    score = int(ep.get("score", 0) or 0)
    url = endpoint_url(ep).lower()
    path = urlsplit(url).path or "/"
    query = urlsplit(url).query or ""

    states = {str(x).strip().lower() for x in (ep.get("states") or [])}
    auth_only = "authenticated" in states and "anonymous" not in states
    has_query = bool(query)

    if kind == "static" or is_session_destructive_endpoint(ep):
        return "static"
    if path in {"", "/"}:
        return "medium"
    if kind == "asset_js":
        if is_html_breadth_profile(profile):
            return "light"
        if any(token in path for token in ("chunk-vendors", "/app.js", "/main.js", "/runtime.js", "/vendors", "vendor", "app.", "main.")):
            return "medium"
        return "light"
    if is_html_breadth_profile(profile) and is_meaningful_html_path(path):
        return "full" if auth_only or has_query else "medium"
    if is_spa_high_value_path(path):
        return "full" if auth_only or has_query else "medium"

    high_signal_tokens = (
        "phpinfo",
        "config",
        "compose",
        "log",
        "backup",
        ".env",
        ".git",
        "debug",
        "actuator",
        "server-status",
        "server-info",
    )
    if any(token in url for token in high_signal_tokens):
        return "medium"

    if auth_only and has_query and any(token in path for token in (".do", ".action", ".php", "/api/", "/rest/")):
        return "full" if is_spa_high_value_path(path) else "medium"

    if any(token in url for token in ("/login", "/signin", "/logout")):
        return "light"

    medium_value_tokens = (
        "/api/",
        "/rest/",
        "/admin",
        "/upload",
        "/fi/",
        "include.php",
        "/setup",
        "/security",
        "/instructions",
    )
    if any(token in url for token in medium_value_tokens):
        return "medium"

    if any(token in url for token in ("/admin/admission", "/admin/acadmgmt", "/admin/")):
        return "medium"

    if auth_only:
        if kind == "form" or has_query:
            return "medium"

    if kind == "form":
        return "medium" if score >= 50 else "light"
    if score >= 70:
        return "medium"
    return choose_probe_intensity_for_rank(rank)


def merge_discovered_endpoints(*endpoint_lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for endpoints in endpoint_lists:
        for endpoint in endpoints or []:
            if not isinstance(endpoint, dict):
                continue
            url = endpoint_url(endpoint)
            if not url:
                continue

            existing = merged.get(url)
            if existing is None:
                merged[url] = dict(endpoint)
                states = endpoint.get("states") or []
                if endpoint.get("state") and endpoint["state"] not in states:
                    states = list(states) + [endpoint["state"]]
                merged[url]["states"] = sorted(set(states))
                merged[url]["is_session_destructive"] = bool(endpoint.get("is_session_destructive"))
                continue

            existing["score"] = max(existing.get("score", 0), endpoint.get("score", 0))
            existing["depth"] = min(existing.get("depth", 9999), endpoint.get("depth", 9999))

            if endpoint.get("kind") == "form":
                existing["kind"] = "form"
            elif existing.get("kind") != "form" and endpoint.get("kind") == "page":
                existing["kind"] = "page"

            existing["field_names"] = list(
                dict.fromkeys((existing.get("field_names") or []) + (endpoint.get("field_names") or []))
            )
            existing["query_param_names"] = list(
                dict.fromkeys((existing.get("query_param_names") or []) + (endpoint.get("query_param_names") or []))
            )

            existing_states = set(existing.get("states") or [])
            incoming_states = set(endpoint.get("states") or [])
            if endpoint.get("state"):
                incoming_states.add(endpoint["state"])
            existing["states"] = sorted(existing_states.union(incoming_states))

            if endpoint.get("is_redirect_target"):
                existing["is_redirect_target"] = True
            if endpoint.get("is_session_destructive"):
                existing["is_session_destructive"] = True
            if not existing.get("source") and endpoint.get("source"):
                existing["source"] = endpoint["source"]

    ranked = sorted(merged.values(), key=canonical_endpoint_sort_key)
    return ranked


def same_origin(url_a: str, url_b: str) -> bool:
    pa = urlsplit(url_a)
    pb = urlsplit(url_b)
    return (pa.scheme.lower(), pa.netloc.lower()) == (pb.scheme.lower(), pb.netloc.lower())


def _url_in_allowed_app_scope(url: str, allowed_prefixes: List[str], base_target: str) -> bool:
    if not url or not same_origin(url, base_target):
        return False

    path = re.sub(r"/+", "/", urlsplit(url).path or "/").rstrip("/")
    if not path:
        path = "/"

    # SPA targets often serve the authenticated shell under /admin or /common
    # while loading same-origin bundles from root-level asset prefixes such as
    # /static/js/app.js. Keep those JS bundle assets in scope so downstream
    # client-bundle disclosure checks are not pruned away.
    lower_path = path.lower()
    if lower_path.endswith((".js", ".mjs")) and lower_path.startswith(
        ("/static/", "/assets/", "/js/")
    ):
        return True

    normalized_prefixes: List[str] = []
    for prefix in allowed_prefixes or []:
        value = re.sub(r"/+", "/", str(prefix or "")).rstrip("/")
        normalized_prefixes.append(value or "/")

    for prefix in normalized_prefixes:
        if prefix == "/":
            return True
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def filter_endpoints_by_app_scope(
    endpoints: List[Dict[str, Any]],
    *,
    base_target: str,
    allowed_prefixes: List[str],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for endpoint in endpoints or []:
        if not isinstance(endpoint, dict):
            continue
        url = endpoint_url(endpoint)
        if not url or not same_origin(url, base_target):
            continue
        if _url_in_allowed_app_scope(url, allowed_prefixes, base_target):
            out.append(endpoint)
    return out


def filter_request_specs_by_app_scope(
    plan: List[RequestSpec],
    *,
    base_target: str,
    allowed_prefixes: List[str],
) -> List[RequestSpec]:
    out: List[RequestSpec] = []
    for spec in plan or []:
        spec_url = str(getattr(spec, "url", "") or "")
        if not spec_url or not same_origin(spec_url, base_target):
            continue
        if _url_in_allowed_app_scope(spec_url, allowed_prefixes, base_target):
            out.append(spec)
    return out


def derive_allowed_app_prefixes(
    *,
    target: str,
    auth_landing_url: str | None,
    seed_urls: List[str] | None,
) -> List[str]:
    def _first_path_prefix(url: str | None) -> str | None:
        if not url:
            return None
        path = urlsplit(url).path or "/"
        path = re.sub(r"/+", "/", path)
        if path == "/":
            return "/"
        segments = [seg for seg in path.split("/") if seg]
        if len(segments) == 1 and "." in segments[0]:
            return "/"
        return "/" + segments[0] if segments else "/"

    prefixes: List[str] = []
    for candidate in [target, auth_landing_url, *(seed_urls or [])]:
        prefix = _first_path_prefix(candidate)
        if prefix:
            prefixes.append(prefix)

    cleaned: List[str] = []
    seen = set()
    for prefix in prefixes:
        value = re.sub(r"/+", "/", prefix).rstrip("/")
        if not value:
            value = "/"
        if value not in seen:
            seen.add(value)
            cleaned.append(value)

    if "/" in seen:
        return ["/"]

    cleaned.sort(key=lambda value: (len(value), value))
    return cleaned or ["/"]


def normalize_target_name(name: str) -> str:
    value = name.strip().lower()
    value = re.sub(r"[^\w]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_")


def prepare_output_path(base_out_dir: str, target_name: str) -> str:
    base = Path(base_out_dir) / target_name
    base.mkdir(parents=True, exist_ok=True)
    return str(base / "results.json")


def should_drop_low_value_endpoint(ep: Dict[str, Any]) -> bool:
    url = endpoint_url(ep).lower()
    path = urlsplit(url).path.lower()
    filename = path.split("/")[-1]
    kind = str(ep.get("kind") or "").strip().lower()
    if kind == "asset_js":
        return False
    if path.endswith((".html", ".htm")):
        return False
    if filename.endswith(LOW_VALUE_EXTS):
        return True
    if filename.startswith("readme"):
        return True
    return any(item in filename for item in LOW_VALUE_FILE_HINTS)


def _endpoint_bucket(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    normalized_parts = []
    for segment in path.split("/"):
        if not segment:
            continue
        if re.fullmatch(r"\d+", segment):
            normalized_parts.append("{id}")
        elif re.fullmatch(r"[a-f0-9]{8,}", segment, re.I):
            normalized_parts.append("{token}")
        else:
            normalized_parts.append(segment)
    norm = "/" + "/".join(normalized_parts)
    return f"{parts.scheme}://{parts.netloc}{norm}"


def _priority_static_bundle_urls(
    endpoint_map: Dict[str, Dict[str, Any]],
    *,
    profile: str,
) -> List[str]:
    candidates: List[tuple[int, int, int, str]] = []
    max_keep = int(
        os.getenv(
            "PRIORITY_JS_ENDPOINTS",
            "8" if is_spa_method_profile(profile) else ("2" if is_html_breadth_profile(profile) else "4"),
        )
    )
    if max_keep <= 0:
        return []

    for url, endpoint in (endpoint_map or {}).items():
        if endpoint_kind(endpoint) != "asset_js":
            continue

        path = (urlsplit(url).path or "/").lower()
        score = int(endpoint.get("score", 0) or 0) if isinstance(endpoint, dict) else 0
        depth = int(endpoint.get("depth", 9999) or 9999) if isinstance(endpoint, dict) else 9999
        priority = 0

        if any(token in path for token in ("chunk-vendors", "/app.js", "/main.js", "/runtime.js", "/vendors", "vendor", "app.", "main.")):
            priority += 10
        if any(token in path for token in ("/static/js/", "/assets/", "/js/", "chunk")):
            priority += 6
        if is_spa_high_value_path(path):
            priority += 4

        if priority <= 0:
            continue
        candidates.append((-priority, -score, depth, url))

    return [url for _, _, _, url in sorted(candidates)[:max_keep]]


def _priority_meaningful_html_urls(
    endpoint_map: Dict[str, Dict[str, Any]],
    *,
    profile: str,
) -> List[str]:
    candidates: List[tuple[int, int, int, str]] = []
    max_keep = int(
        os.getenv(
            "PRIORITY_HTML_ENDPOINTS",
            "8" if is_html_breadth_profile(profile) else "3",
        )
    )
    if max_keep <= 0:
        return []

    for url, endpoint in (endpoint_map or {}).items():
        path = (urlsplit(url).path or "/").lower()
        score = int(endpoint.get("score", 0) or 0) if isinstance(endpoint, dict) else 0
        depth = int(endpoint.get("depth", 9999) or 9999) if isinstance(endpoint, dict) else 9999
        kind = endpoint_kind(endpoint)

        priority = 0
        if is_meaningful_html_path(path):
            priority += 12
        if path.endswith((".html", ".htm")) and "/common/" in path:
            priority += 8
        if any(token in path for token in ("/portal/", "nda", "privacy", "policy", "notice")):
            priority += 6
        if kind == "form":
            priority += 2

        if priority <= 0:
            continue
        candidates.append((priority, score, -depth, url))

    candidates.sort(key=lambda item: (-item[0], -item[1], item[2], item[3]))
    return [url for _, _, _, url in candidates[:max_keep]]


def _semantic_html_seed_urls(
    *,
    endpoint_map: Dict[str, Dict[str, Any]],
    target: str,
    allowed_prefixes: List[str],
    profile: str,
) -> List[str]:
    if not is_html_breadth_profile(profile):
        return []

    parts = urlsplit(target)
    root = f"{parts.scheme}://{parts.netloc}"
    out: List[str] = []
    seen = set()
    meaningful_tokens = {
        "index",
        "main",
        "home",
        "portal",
        "privacy",
        "policy",
        "terms",
        "notice",
        "member",
        "profile",
        "about",
        "help",
        "guide",
        "intro",
        "agreement",
        "contract",
        "nda",
    }

    def _add(path: str, *, score: int = 0) -> None:
        normalized_path = re.sub(r"/+", "/", str(path or "/")).strip()
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path
        url = f"{root}{normalized_path}"
        if url in seen:
            return
        seen.add(url)
        out.append(url)

    def _path_tokens(raw_path: str) -> List[str]:
        path = re.sub(r"/+", "/", str(raw_path or "/"))
        segments = [segment for segment in path.split("/") if segment]
        tokens: List[str] = []
        for segment in segments:
            base = re.sub(r"\.[A-Za-z0-9]+$", "", segment)
            for piece in re.split(r"[_\-.]+", base):
                piece = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", piece)
                for token in piece.split():
                    normalized = token.strip().lower()
                    if normalized:
                        tokens.append(normalized)
        return list(dict.fromkeys(tokens))

    def _parent_dirs(raw_path: str) -> List[str]:
        path = re.sub(r"/+", "/", str(raw_path or "/"))
        segments = [segment for segment in path.split("/") if segment]
        dirs: List[str] = ["/"]
        if not segments:
            return dirs
        stop = len(segments)
        if "." in segments[-1]:
            stop -= 1
        prefix_segments: List[str] = []
        for idx in range(stop):
            prefix_segments.append(segments[idx])
            dirs.append("/" + "/".join(prefix_segments))
        return list(dict.fromkeys(dirs))

    discovered_paths = {
        re.sub(r"/+", "/", urlsplit(str(url or "")).path or "/")
        for url in endpoint_map.keys()
    }

    # Keep the discovered HTML-like routes themselves sticky.
    for path in discovered_paths:
        lower_path = path.lower()
        if is_meaningful_html_path(lower_path):
            _add(path, score=100)

    # Derive nearby semantic HTML siblings from discovered route names instead
    # of hardcoding target-specific files.
    candidate_specs: List[tuple[int, str]] = []
    for path in discovered_paths:
        lower_path = path.lower()
        if lower_path.endswith((".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".mp4", ".pdf", ".zip")):
            continue

        dirs = _parent_dirs(path)
        tokens = [token for token in _path_tokens(path) if token in meaningful_tokens]
        if not tokens:
            continue

        for directory in dirs:
            normalized_dir = directory.rstrip("/") or "/"
            for token in tokens:
                if token in {"index", "main", "home"}:
                    candidate_specs.append((80, f"{normalized_dir}/{token}.html" if normalized_dir != "/" else f"/{token}.html"))
                else:
                    candidate_specs.append((95 if token in {"privacy", "nda"} else 85, f"{normalized_dir}/{token}.html" if normalized_dir != "/" else f"/{token}.html"))

            if any(token in tokens for token in {"portal", "main", "home"}):
                candidate_specs.append((78, f"{normalized_dir}/index.html" if normalized_dir != "/" else "/index.html"))

    candidate_specs.sort(key=lambda item: (-item[0], item[1]))

    normalized_prefixes: List[str] = []
    for prefix in allowed_prefixes or []:
        value = re.sub(r"/+", "/", str(prefix or "")).rstrip("/")
        normalized_prefixes.append(value or "/")

    for prefix in normalized_prefixes:
        if prefix != "/":
            _add(prefix, score=60)

    max_keep = int(os.getenv("SEMANTIC_HTML_SEED_MAX_TARGETS", "10"))
    kept = 0
    for _score, candidate_path in candidate_specs:
        normalized_candidate_path = re.sub(r"/+", "/", candidate_path)
        if max_keep > 0 and kept >= max_keep:
            break
        if not normalized_candidate_path.startswith("/"):
            normalized_candidate_path = "/" + normalized_candidate_path
        candidate_url = f"{root}{normalized_candidate_path}"
        if not _url_in_allowed_app_scope(candidate_url, allowed_prefixes, target):
            continue
        if normalized_candidate_path not in discovered_paths:
            _add(normalized_candidate_path, score=_score)
            kept += 1

    return out


def prune_discovered_endpoints(urls: List[str], max_endpoints: int = 30) -> List[str]:
    profile = resolve_scan_profile()
    unique_urls: List[str] = []
    seen_exact = set()
    for url in urls:
        value = str(url or "").strip()
        if not value or value in seen_exact:
            continue
        seen_exact.add(value)
        unique_urls.append(value)

    def score(url: str) -> tuple[int, int, int, str]:
        parts = urlsplit(url)
        path = (parts.path or "/").lower()
        query = parts.query or ""
        priority = 0
        meaningful_html = is_meaningful_html_path(path)
        spa_high_value = is_spa_high_value_path(path)

        if any(token in path for token in (".mvc", ".do", ".action", ".php", "/api/", "/rest/", "/admin")):
            priority += 4
        if query:
            priority += 3
        if any(
            token in path
            for token in (
                "/setup",
                "/instructions",
                "/config",
                "/debug",
                "/actuator",
                "/upload",
                "/downloads",
                "/account",
                "/profile",
                "/user",
                "/order",
                "/payment",
                "/wallet",
                "/admin",
                "/api/",
                "/rest/",
            )
        ):
            priority += 4
        if path.endswith((".html", ".htm")):
            priority += 4
            if meaningful_html:
                priority += 6
            if "/common/" in path:
                priority += 2
        if path.endswith((".js", ".mjs")):
            priority += 2
            if any(token in path for token in ("/static/js/", "/assets/", "/js/", "chunk", "vendor", "app.", "main.")):
                priority += 2
            if any(token in path for token in ("chunk-vendors", "/app.js", "/main.js", "/runtime.js", "/vendors", "vendor", "app.", "main.")):
                priority += 2
        if spa_high_value:
            priority += 8
        if is_html_breadth_profile(profile):
            if meaningful_html:
                priority += 8
            if path.endswith((".html", ".htm", ".do", ".action")):
                priority += 2
            if path.endswith((".js", ".mjs")):
                priority -= 2
        if path.endswith((".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
            priority -= 3

        depth = len([segment for segment in path.split("/") if segment])
        return (-priority, -int(bool(query)), depth, url)

    ranked = sorted(unique_urls, key=score)
    out: List[str] = []
    seen_buckets: Dict[str, int] = {}

    for url in ranked:
        bucket = _endpoint_bucket(url)
        count = seen_buckets.get(bucket, 0)
        has_query = bool(urlsplit(url).query)
        path = (urlsplit(url).path or "/").lower()
        dynamic_like = any(token in path for token in (".do", ".action", ".php", "/api/", "/rest/"))
        static_js_like = path.endswith((".js", ".mjs"))
        app_html_like = path.endswith((".html", ".htm"))
        allow_per_bucket = endpoint_bucket_limit(
            path=path,
            has_query=has_query,
            dynamic_like=dynamic_like,
            static_js_like=static_js_like,
            app_html_like=app_html_like,
            profile=profile,
        )
        if count >= allow_per_bucket:
            continue

        seen_buckets[bucket] = count + 1
        out.append(url)
        if len(out) >= max_endpoints:
            break

    return out


def filter_out_session_destructive_authenticated_endpoints(
    endpoints: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    removed = 0
    for endpoint in endpoints or []:
        if is_session_destructive_endpoint(endpoint):
            removed += 1
            continue
        out.append(endpoint)
    if removed:
        log("CRAWL", f"Skipping session-destructive authenticated endpoints: {removed}")
    return out


def prepare_discovered_endpoints(
    *,
    target: str,
    anonymous_endpoints: List[Dict[str, Any]],
    authenticated_endpoints: List[Dict[str, Any]],
    allowed_app_prefixes: List[str],
    max_endpoints: int,
    seed_urls: List[str] | None = None,
) -> tuple[List[Dict[str, Any]], int, List[Dict[str, Any]], List[Dict[str, Any]]]:
    profile = resolve_scan_profile()
    filtered_anonymous_endpoints = filter_endpoints_by_app_scope(
        anonymous_endpoints,
        base_target=target,
        allowed_prefixes=allowed_app_prefixes,
    )
    filtered_authenticated_endpoints = filter_endpoints_by_app_scope(
        authenticated_endpoints,
        base_target=target,
        allowed_prefixes=allowed_app_prefixes,
    )
    filtered_authenticated_endpoints = filter_out_session_destructive_authenticated_endpoints(
        filtered_authenticated_endpoints
    )

    log("CRAWL", f"Anonymous endpoints in app scope: {len(filtered_anonymous_endpoints)} / {len(anonymous_endpoints)}")
    log("CRAWL", f"Authenticated endpoints in app scope: {len(filtered_authenticated_endpoints)} / {len(authenticated_endpoints)}")

    discovered_endpoints = merge_discovered_endpoints(
        filtered_anonymous_endpoints,
        filtered_authenticated_endpoints,
    )
    if not discovered_endpoints:
        discovered_endpoints = [{
            "url": target,
            "kind": "page",
            "source": None,
            "depth": 0,
            "method": "GET",
            "field_names": [],
            "query_param_names": [],
            "is_redirect_target": False,
            "is_session_destructive": False,
            "score": 0,
            "state": "anonymous",
            "states": ["anonymous"],
        }]

    original_discovered_count = len(discovered_endpoints)
    log("CRAWL", f"Discovered endpoints before pruning: {original_discovered_count}")

    discovered_endpoints = [endpoint for endpoint in discovered_endpoints if not should_drop_low_value_endpoint(endpoint)]
    log("CRAWL", f"Endpoints after low-value filtering: {len(discovered_endpoints)}")

    discovered_endpoint_map = {
        endpoint_url(endpoint): endpoint
        for endpoint in discovered_endpoints
        if endpoint_url(endpoint)
    }

    explicit_seed_urls: List[str] = []
    seen_seed_urls = set()
    for raw_seed in seed_urls or []:
        seed = str(raw_seed or "").strip()
        if not seed or seed in seen_seed_urls:
            continue
        seen_seed_urls.add(seed)
        if not _url_in_allowed_app_scope(seed, allowed_app_prefixes, target):
            continue
        explicit_seed_urls.append(seed)
        discovered_endpoint_map.setdefault(
            seed,
            {
                "url": seed,
                "kind": "page",
                "source": "explicit_seed",
                "depth": 0,
                "method": "GET",
                "field_names": [],
                "query_param_names": [],
                "is_redirect_target": False,
                "is_session_destructive": False,
                "score": 100,
                "state": "seeded",
                "states": ["seeded"],
            },
        )

    for generated_seed in _semantic_html_seed_urls(
        endpoint_map=discovered_endpoint_map,
        target=target,
        allowed_prefixes=allowed_app_prefixes,
        profile=profile,
    ):
        if generated_seed in seen_seed_urls:
            continue
        seen_seed_urls.add(generated_seed)
        if not _url_in_allowed_app_scope(generated_seed, allowed_app_prefixes, target):
            continue
        explicit_seed_urls.append(generated_seed)
        discovered_endpoint_map.setdefault(
            generated_seed,
            {
                "url": generated_seed,
                "kind": "page",
                "source": "profile_seed",
                "depth": 0,
                "method": "GET",
                "field_names": [],
                "query_param_names": [],
                "is_redirect_target": False,
                "is_session_destructive": False,
                "score": 95,
                "state": "seeded",
                "states": ["seeded"],
            },
        )

    preferred_static_bundle_urls = _priority_static_bundle_urls(
        discovered_endpoint_map,
        profile=profile,
    )
    preferred_meaningful_html_urls = _priority_meaningful_html_urls(
        discovered_endpoint_map,
        profile=profile,
    )

    pruned_urls = prune_discovered_endpoints(
        list(discovered_endpoint_map.keys()),
        max_endpoints=max_endpoints,
    )
    for html_url in reversed(preferred_meaningful_html_urls):
        if html_url in pruned_urls:
            continue
        pruned_urls.insert(0, html_url)
    for bundle_url in reversed(preferred_static_bundle_urls):
        if bundle_url in pruned_urls:
            continue
        pruned_urls.insert(0, bundle_url)
    for seed in reversed(explicit_seed_urls):
        if seed in pruned_urls:
            continue
        pruned_urls.insert(0, seed)
    if len(pruned_urls) > max_endpoints:
        keep = set(explicit_seed_urls) | set(preferred_static_bundle_urls) | set(preferred_meaningful_html_urls)
        trimmed: List[str] = []
        for url in pruned_urls:
            if len(trimmed) >= max_endpoints:
                break
            if url in keep or url not in trimmed:
                trimmed.append(url)
        pruned_urls = trimmed[:max_endpoints]
    if target not in pruned_urls:
        pruned_urls = [target] + pruned_urls
    if len(pruned_urls) > max_endpoints:
        must_keep = {target, *explicit_seed_urls, *preferred_static_bundle_urls, *preferred_meaningful_html_urls}
        trimmed: List[str] = []
        for url in pruned_urls:
            if url in trimmed:
                continue
            if len(trimmed) < max_endpoints or url in must_keep:
                trimmed.append(url)
        if len(trimmed) > max_endpoints:
            preferred = [url for url in trimmed if url in must_keep]
            others = [url for url in trimmed if url not in must_keep]
            trimmed = (preferred + others)[:max_endpoints]
        pruned_urls = trimmed[:max_endpoints]

    discovered_endpoints = [
        discovered_endpoint_map.get(
            url,
            {
                "url": url,
                "kind": "page",
                "source": None,
                "depth": 0,
                "method": "GET",
                "field_names": [],
                "query_param_names": [],
                "is_redirect_target": False,
                "is_session_destructive": False,
                "score": 0,
                "state": "anonymous",
                "states": ["anonymous"],
            },
        )
        for url in pruned_urls
    ]
    discovered_endpoints = sorted(discovered_endpoints, key=canonical_endpoint_sort_key)
    log("CRAWL", f"Endpoints after pruning: {len(discovered_endpoints)}")
    return (
        discovered_endpoints,
        original_discovered_count,
        filtered_anonymous_endpoints,
        filtered_authenticated_endpoints,
    )
