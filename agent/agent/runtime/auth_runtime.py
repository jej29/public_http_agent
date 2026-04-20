from __future__ import annotations

import os
from typing import Any, Dict, List
from urllib.parse import urlparse

import httpx

from agent.core.common import log
from agent.crawler import (
    _is_session_destructive_url,
    classify_url_kind,
    discover_endpoints,
    extract_js_style_endpoints,
    extract_navigation,
)
from agent.http.http_session import clear_cookie_name_from_client, preferred_cookie_path_for_url
from agent.runtime.discovery_planning import normalize_target_name, same_origin


def build_effective_seed_urls(
    *,
    target: str,
    auth_landing_url: str | None,
    seed_urls: List[str] | None,
) -> List[str]:
    target_value = str(target or "").strip()
    effective_seed_urls: List[str] = []
    for candidate in [target, auth_landing_url, *(seed_urls or [])]:
        value = str(candidate or "").strip()
        if value and value not in effective_seed_urls:
            effective_seed_urls.append(value)

    if not effective_seed_urls:
        return []

    explicit_seeds = {str(seed or "").strip() for seed in (seed_urls or []) if str(seed or "").strip()}

    def _seed_sort_key(url: str) -> tuple:
        parsed = urlparse(url)
        path = parsed.path or "/"
        is_target = url == target_value
        is_seed = url in explicit_seeds
        return (
            0 if is_target else 1 if is_seed else 2,
            len(path),
            path,
            parsed.query or "",
            parsed.netloc.lower(),
        )

    return sorted(effective_seed_urls, key=_seed_sort_key)


async def discover_authenticated_endpoints(
    *,
    client: httpx.AsyncClient,
    target: str,
    auth_landing_url: str | None,
    seed_urls: List[str] | None,
    timeout_s: float,
    crawl_depth: int,
    crawl_max_pages: int,
    crawl_enable_js: bool,
) -> List[Dict[str, Any]]:
    effective_seed_urls = build_effective_seed_urls(
        target=target,
        auth_landing_url=auth_landing_url,
        seed_urls=seed_urls,
    )
    log("CRAWL", f"Authenticated crawl seeds: {effective_seed_urls}")
    log("CRAWL", "Re-running discovery with authenticated session")
    return await discover_endpoints(
        client=client,
        seed_url=target,
        timeout_s=timeout_s,
        max_depth=crawl_depth,
        max_pages=crawl_max_pages,
        include_js_string_paths=crawl_enable_js,
        extra_seed_urls=effective_seed_urls,
        crawl_state="authenticated",
    )


def apply_manual_auth_to_client(
    *,
    client: httpx.AsyncClient,
    target: str,
) -> Dict[str, Any]:
    applied_cookie_names: List[str] = []
    applied_header_names: List[str] = []

    manual_cookie_raw = str(os.getenv("MANUAL_AUTH_COOKIE", "") or "").strip()
    manual_headers_raw = str(os.getenv("MANUAL_AUTH_HEADERS", "") or "").strip()

    preferred_path = preferred_cookie_path_for_url(target)
    host = (urlparse(target).hostname or "").strip() or None

    if manual_cookie_raw:
        cookie_parts = [item.strip() for item in manual_cookie_raw.split(";") if item.strip()]
        for part in cookie_parts:
            if "=" not in part:
                continue
            cookie_name, cookie_value = (chunk.strip() for chunk in part.split("=", 1))
            if not cookie_name:
                continue

            clear_cookie_name_from_client(client, cookie_name)
            try:
                if host:
                    client.cookies.set(cookie_name, cookie_value, domain=host, path=preferred_path)
                else:
                    client.cookies.set(cookie_name, cookie_value, path=preferred_path)
            except Exception:
                pass
            applied_cookie_names.append(cookie_name)

    if manual_headers_raw:
        for chunk in manual_headers_raw.split("|||"):
            piece = str(chunk or "").strip()
            if not piece or ":" not in piece:
                continue
            header_name, header_value = (item.strip() for item in piece.split(":", 1))
            if not header_name or header_name.lower() == "cookie":
                continue
            client.headers[header_name] = header_value
            applied_header_names.append(header_name)

    if applied_cookie_names:
        log("AUTH", f"Applied manual auth cookies: {sorted(set(applied_cookie_names))}")
    if applied_header_names:
        log("AUTH", f"Applied manual auth headers: {sorted(set(applied_header_names))}")

    return {
        "manual_auth_enabled": bool(applied_cookie_names or applied_header_names),
        "manual_cookie_names": sorted(set(applied_cookie_names)),
        "manual_header_names": sorted(set(applied_header_names)),
    }


def build_anonymous_replay_client(
    *,
    limits: httpx.Limits,
    client_timeout: httpx.Timeout,
    follow_redirects: bool,
) -> httpx.AsyncClient:
    anonymous_transport = httpx.AsyncHTTPTransport(
        retries=0,
        verify=False,
        http2=False,
    )
    anonymous_limits = httpx.Limits(
        max_connections=limits.max_connections,
        max_keepalive_connections=max(0, min(1, limits.max_connections or 1)),
        keepalive_expiry=2.0,
    )
    anonymous_timeout = httpx.Timeout(
        client_timeout.read if client_timeout.read is not None else 10.0,
        connect=client_timeout.connect if client_timeout.connect is not None else 3.0,
        read=client_timeout.read if client_timeout.read is not None else 10.0,
        write=client_timeout.write if client_timeout.write is not None else 10.0,
        pool=client_timeout.pool if client_timeout.pool is not None else 3.0,
    )
    return httpx.AsyncClient(
        limits=anonymous_limits,
        timeout=anonymous_timeout,
        transport=anonymous_transport,
        verify=False,
        trust_env=False,
        http2=False,
        follow_redirects=follow_redirects,
    )


def extract_authenticated_endpoints_from_auth_snapshots(
    *,
    auth_result: Dict[str, Any],
    target: str,
) -> List[Dict[str, Any]]:
    auth_snaps_raw = auth_result.get("auth_snapshots") or []
    if not isinstance(auth_snaps_raw, list) or not auth_snaps_raw:
        return []

    def _normalize_auth_snapshot_items(raw_items: Any) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not isinstance(raw_items, list):
            return out
        for entry in raw_items:
            if isinstance(entry, dict):
                spec = entry.get("spec")
                snap = entry.get("snapshot")
                if isinstance(spec, list) and spec:
                    spec = spec[0]
                if isinstance(snap, list) and snap:
                    snap = snap[0]
                if spec is not None and isinstance(snap, dict):
                    out.append({"spec": spec, "snapshot": snap})
                continue
            if isinstance(entry, list) and len(entry) >= 2:
                spec = entry[0]
                snap = entry[1]
                if isinstance(spec, list) and spec:
                    spec = spec[0]
                if isinstance(snap, list) and snap:
                    snap = snap[0]
                if spec is not None and isinstance(snap, dict):
                    out.append({"spec": spec, "snapshot": snap})
        return out

    def _mk_endpoint(
        url: str,
        *,
        kind: str,
        source: str | None,
        method: str = "GET",
        field_names: List[str] | None = None,
    ) -> Dict[str, Any]:
        normalized_url = str(url or "").strip()
        return {
            "url": normalized_url,
            "kind": kind,
            "source": source,
            "depth": 1,
            "method": str(method or "GET").upper(),
            "field_names": list(field_names or []),
            "query_param_names": [],
            "is_redirect_target": False,
            "is_session_destructive": _is_session_destructive_url(normalized_url),
            "score": 0,
            "state": "authenticated",
            "states": ["authenticated"],
        }

    auth_snaps = _normalize_auth_snapshot_items(auth_snaps_raw)
    out_by_url: Dict[str, Dict[str, Any]] = {}
    for item in auth_snaps:
        snap = item.get("snapshot") or {}
        if not isinstance(snap, dict):
            continue

        final_url = str(snap.get("final_url") or "").strip()
        body_text = str(snap.get("body_text") or snap.get("body_snippet") or "")
        if not final_url or not body_text or not same_origin(final_url, target):
            continue

        nav = extract_navigation(final_url, body_text)
        js_links = extract_js_style_endpoints(final_url, body_text)

        for link in sorted(set(nav.get("links") or set()).union(js_links)):
            if link and same_origin(link, target):
                ep = _mk_endpoint(link, kind=classify_url_kind(link), source=final_url, method="GET")
                out_by_url[ep["url"]] = ep

        for src in sorted(set(nav.get("scripts") or set())):
            if src and same_origin(src, target):
                ep = _mk_endpoint(src, kind=classify_url_kind(src, "asset_js"), source=final_url, method="GET")
                out_by_url[ep["url"]] = ep

        for form_def in nav.get("forms") or []:
            form_url = str(form_def.get("url") or "").strip()
            if form_url and same_origin(form_url, target):
                ep = _mk_endpoint(
                    form_url,
                    kind="form",
                    source=final_url,
                    method=form_def.get("method", "GET"),
                    field_names=form_def.get("field_names") or [],
                )
                out_by_url[ep["url"]] = ep

    harvested = list(out_by_url.values())
    if harvested:
        log("CRAWL", f"Authenticated endpoints harvested from auth snapshots: {len(harvested)}")
    return harvested


def build_auth_args(args: Any) -> Dict[str, str] | None:
    if getattr(args, "auth_username", None) and getattr(args, "auth_password", None):
        return {
            "username": args.auth_username,
            "password": args.auth_password,
        }
    return None


def resolve_target_name(target: str, target_name: str | None) -> str:
    if target_name:
        return normalize_target_name(target_name)
    host = urlparse(target).hostname or "target"
    return normalize_target_name(host)
