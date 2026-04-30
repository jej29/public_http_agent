from __future__ import annotations

import os


HTML_BREADTH_PROFILES = {"server_html_broad", "html_broad", "nda"}
SPA_METHOD_PROFILES = {"spa_auth_heavy", "spa", "ssit"}


def resolve_scan_profile() -> str:
    return (os.getenv("SCAN_PROFILE") or "balanced").strip().lower()


def is_html_breadth_profile(profile: str | None = None) -> bool:
    resolved = (profile or resolve_scan_profile()).strip().lower()
    return resolved in HTML_BREADTH_PROFILES


def is_spa_method_profile(profile: str | None = None) -> bool:
    resolved = (profile or resolve_scan_profile()).strip().lower()
    return resolved in SPA_METHOD_PROFILES


def is_meaningful_html_path(path: str) -> bool:
    normalized = (path or "/").lower()
    return normalized.endswith((".html", ".htm")) and any(
        token in normalized
        for token in (
            "nda",
            "privacy",
            "policy",
            "terms",
            "notice",
            "portal",
            "main",
            "index",
            "member",
            "profile",
            "/common/",
        )
    )


def is_spa_high_value_path(path: str) -> bool:
    normalized = (path or "/").lower()
    return any(
        token in normalized
        for token in (
            "/admin",
            "/admission",
            "/acadmgmt",
            "/api/",
            "/rest/",
            ".jsp",
        )
    )


def is_method_heavy_target(path: str, profile: str | None = None) -> bool:
    normalized = (path or "/").lower()
    resolved = (profile or resolve_scan_profile()).strip().lower()

    if is_html_breadth_profile(resolved):
        return any(
            token in normalized
            for token in ("/api/", "/rest/", "/admin/admission", "/admin/acadmgmt")
        )

    if is_spa_method_profile(resolved):
        return is_spa_high_value_path(normalized) or any(
            token in normalized for token in (".do", ".action")
        )

    return any(
        token in normalized
        for token in (
            "/admin",
            "/admission",
            "/acadmgmt",
            "/api/",
            "/rest/",
            ".do",
            ".action",
            ".jsp",
        )
    )


def endpoint_bucket_limit(
    *,
    path: str,
    has_query: bool,
    dynamic_like: bool,
    static_js_like: bool,
    app_html_like: bool,
    profile: str | None = None,
) -> int:
    resolved = (profile or resolve_scan_profile()).strip().lower()
    normalized = (path or "/").lower()
    meaningful_html = is_meaningful_html_path(normalized)
    spa_high_value = is_spa_high_value_path(normalized)

    if is_html_breadth_profile(resolved):
        if meaningful_html:
            return 5
        if has_query or dynamic_like:
            return 4
        if app_html_like:
            return 4
        if static_js_like:
            return 2
        return 2

    if is_spa_method_profile(resolved):
        if spa_high_value:
            return 5
        if has_query or dynamic_like:
            return 4
        if static_js_like:
            return 4
        if app_html_like:
            return 2
        return 2

    if has_query or dynamic_like:
        return 4
    if static_js_like or app_html_like:
        return 3
    return 2
