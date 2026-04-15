from __future__ import annotations

import os
from typing import Any, Dict
from urllib.parse import urlsplit

import httpx


SESSION_COOKIE_NAMES = {
    "jsessionid",
    "phpsessid",
    "session",
    "sessionid",
    "sid",
    "asp.net_sessionid",
    "connect.sid",
}


def parse_manual_auth_cookie_pairs() -> Dict[str, str]:
    raw = str(os.getenv("MANUAL_AUTH_COOKIE", "") or "").strip()
    out: Dict[str, str] = {}

    if not raw:
        return out

    for part in raw.split(";"):
        piece = str(part or "").strip()
        if not piece or "=" not in piece:
            continue
        key, value = piece.split("=", 1)
        name = key.strip()
        cookie_value = value.strip()
        if name:
            out[name] = cookie_value
    return out


def preferred_cookie_path_for_url(url: str) -> str:
    path = urlsplit(str(url or "")).path or "/"
    segments = [segment for segment in path.split("/") if segment]
    if segments:
        return "/" + segments[0]
    return "/"


def clear_cookie_name_from_client(client: httpx.AsyncClient, cookie_name: str) -> None:
    jar = getattr(client.cookies, "jar", None)
    if jar is None:
        return

    to_clear = []
    try:
        for cookie in list(jar):
            if str(getattr(cookie, "name", "") or "").lower() == cookie_name.lower():
                to_clear.append(
                    (
                        getattr(cookie, "domain", None),
                        getattr(cookie, "path", None),
                        getattr(cookie, "name", None),
                    )
                )
    except Exception:
        return

    for domain, path, name in to_clear:
        try:
            jar.clear(domain, path, name)
        except Exception:
            pass


def sanitize_request_headers_and_cookie_jar(
    client: httpx.AsyncClient,
    url: str,
    headers: Dict[str, str],
) -> Dict[str, str]:
    safe_headers: Dict[str, str] = {}
    for key, value in (headers or {}).items():
        if str(key).lower() == "cookie":
            continue
        safe_headers[str(key)] = str(value)

    manual_pairs = parse_manual_auth_cookie_pairs()
    preferred_path = preferred_cookie_path_for_url(url)
    host = (urlsplit(url).hostname or "").strip() or None

    for name, value in manual_pairs.items():
        if name.lower() not in SESSION_COOKIE_NAMES:
            continue

        clear_cookie_name_from_client(client, name)

        try:
            if host:
                client.cookies.set(name, value, domain=host, path=preferred_path)
            else:
                client.cookies.set(name, value, path=preferred_path)
        except Exception:
            pass

    return safe_headers


def snapshot_cookie_jar(client: httpx.AsyncClient) -> Dict[str, str]:
    out: Dict[str, str] = {}

    try:
        for cookie in client.cookies.jar:
            name = str(getattr(cookie, "name", "") or "")
            value = str(getattr(cookie, "value", "") or "")
            if not name:
                continue
            out[name] = value
    except Exception:
        try:
            for name in client.cookies.keys():
                out[str(name)] = ""
        except Exception:
            pass

    return out


def cookie_jar_delta(before: Dict[str, str], after: Dict[str, str]) -> Dict[str, Any]:
    before_keys = set(before.keys())
    after_keys = set(after.keys())

    added = sorted(after_keys - before_keys)
    removed = sorted(before_keys - after_keys)

    return {
        "cookie_jar_before_names": sorted(before_keys),
        "cookie_jar_after_names": sorted(after_keys),
        "cookie_jar_added_names": added,
        "cookie_jar_removed_names": removed,
        "cookie_jar_changed": bool(added or removed),
        "cookie_jar_observed": bool(after_keys),
    }
