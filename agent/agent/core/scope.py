from __future__ import annotations

from typing import Any, Dict
from urllib.parse import urlparse, urlunparse


def normalize_url_for_dedup(url: str) -> str:
    if not url:
        return ""

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"

    # remove duplicate slashes
    while "//" in path:
        path = path.replace("//", "/")

    # remove trailing slash (except root)
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    return urlunparse((scheme, netloc, path, "", "", ""))


def host_scope_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}/"


def route_scope_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def resource_scope_url(url: str) -> str:
    return normalize_url_for_dedup(url)


def misconfig_scope_url(finding: Dict[str, Any]) -> str:
    evidence = finding.get("evidence") or {}
    url = (
        evidence.get("final_url")
        or finding.get("normalized_url")
        or finding.get("url")
        or ""
    )

    scope_hint = str(finding.get("scope_hint") or "")

    if scope_hint == "host-wide":
        return host_scope_url(url)

    if scope_hint == "route-specific":
        return route_scope_url(url)

    return normalize_url_for_dedup(url)


def disclosure_scope_url(finding: Dict[str, Any]) -> str:
    evidence = finding.get("evidence") or {}
    url = (
        evidence.get("final_url")
        or finding.get("normalized_url")
        or finding.get("url")
        or ""
    )

    scope_hint = str(finding.get("scope_hint") or "")

    if scope_hint == "host-wide":
        return host_scope_url(url)

    if scope_hint == "route-specific":
        return route_scope_url(url)

    return normalize_url_for_dedup(url)


def canonical_finding_url(finding: Dict[str, Any]) -> str:
    ftype = str(finding.get("type") or "")

    if ftype in {
        "SECURITY_HEADERS_MISSING",
        "CORS_MISCONFIG",
        "HTTPS_REDIRECT_MISSING",
        "HSTS_MISSING",
    }:
        return misconfig_scope_url(finding)

    if "EXPOSURE" in ftype or "DISCLOSURE" in ftype:
        return disclosure_scope_url(finding)

    return normalize_url_for_dedup(
        finding.get("normalized_url")
        or finding.get("url")
        or ""
    )

