from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlsplit

from agent.core.common import log
from agent.planning.probes import RequestSpec


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
        return "light"

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
        return "medium"

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


def prune_discovered_endpoints(urls: List[str], max_endpoints: int = 30) -> List[str]:
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
        if path.endswith((".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")):
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

        allow_per_bucket = 2 if (has_query or dynamic_like) else 1
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
) -> tuple[List[Dict[str, Any]], int, List[Dict[str, Any]], List[Dict[str, Any]]]:
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

    pruned_urls = prune_discovered_endpoints(
        list(discovered_endpoint_map.keys()),
        max_endpoints=max_endpoints,
    )
    if target not in pruned_urls:
        pruned_urls = [target] + pruned_urls
        pruned_urls = pruned_urls[:max_endpoints]

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
