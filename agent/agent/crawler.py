from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx
import os

JS_ENDPOINT_RE = re.compile(
    r"""
    ["'`]
    (
        (?:
            # absolute-style same-origin path
            /[A-Za-z0-9_\-./?=&%#:@~+]+

            |

            # relative dynamic/server-side route
            [A-Za-z0-9_\-./]+(?:\.php|\.do|\.action|\.mvc|/)(?:\?[A-Za-z0-9_\-./?=&%#:@~+]*)?

            |

            # relative API-ish path without leading slash
            (?:api|rest|graphql|ftp|admin|account|profile|user|users|order|orders|payment|payments|wallet|basket|security|setup|instructions|config|debug|upload|download|downloads|files|search)
            /[A-Za-z0-9_\-./?=&%#:@~+]*

            |

            # common data-like resources
            [A-Za-z0-9_\-./]+(?:\.json|\.xml|\.txt|\.csv)(?:\?[A-Za-z0-9_\-./?=&%#:@~+]*)?
        )
    )
    ["'`]
    """,
    re.VERBOSE | re.IGNORECASE,
)

HIGH_VALUE_HINTS = [
    "login", "signin", "auth", "account", "admin", "user", "session",
    "api", "rest", "graphql", "search", "query", "file", "download",
    "upload", "report", "export", "import", "config", "setting",
    "security", "setup",
]

LOW_VALUE_HINTS = [
    "logout", "help", "about", "docs", "faq", "health", "status",
]

LOW_VALUE_FILE_HINTS = (
    "readme", "changelog", "license", "copying", "authors", "contributing",
)

LOW_VALUE_EXTS = (
    ".md", ".rst", ".txt",
)

STATIC_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".zip", ".tar", ".gz",
    ".mp4", ".mp3", ".avi", ".mov",
)

JS_EXTS = (".js",)
TEXT_LIKE_TYPES = (
    "text/",
    "application/json",
    "application/javascript",
    "application/x-javascript",
    "application/xml",
    "text/xml",
    "application/xhtml+xml",
    "application/graphql",
)


def _normalize_url(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _same_origin(a: str, b: str) -> bool:
    pa = urlsplit(a)
    pb = urlsplit(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def _should_keep_url(seed_url: str, candidate: str) -> bool:
    if not candidate:
        return False

    c = candidate.strip()
    if not c:
        return False

    lowered = c.lower()
    if lowered.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return False

    if not _same_origin(seed_url, candidate):
        return False

    return True


def _is_probably_html_response(content_type: str | None, text: str) -> bool:
    ct = (content_type or "").lower()
    if "text/html" in ct:
        return True
    snippet = (text or "")[:1000].lower()
    return (
        "<html" in snippet
        or "<body" in snippet
        or "<a " in snippet
        or "<form" in snippet
        or "<input" in snippet
    )


def _looks_like_static_asset(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(STATIC_EXTS)


def _looks_like_js_asset(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(JS_EXTS)

COMMON_SPA_SEED_PATHS = [
    "/api",
    "/api/",
    "/rest",
    "/rest/",
    "/graphql",
    "/ftp",
    "/ftp/",
    "/robots.txt",
    "/.well-known/security.txt",
]


def _is_probably_javascript_response(url: str, content_type: str | None, text: str) -> bool:
    ct = (content_type or "").lower()
    if "javascript" in ct or "ecmascript" in ct:
        return True
    if _looks_like_js_asset(url):
        return True

    snippet = (text or "")[:500].lower()
    return (
        "function(" in snippet
        or "=>{" in snippet
        or "webpack" in snippet
        or "__webpack_require__" in snippet
        or "use strict" in snippet
    )

def _looks_like_endpoint_candidate(raw: str) -> bool:
    s = str(raw or "").strip()
    if not s:
        return False

    lower = s.lower()

    if lower.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return False

    if lower.startswith("//"):
        return False

    if lower.startswith(("/#", "#")):
        return False

    # 정적 리소스는 제외
    if any(lower.endswith(ext) for ext in STATIC_EXTS):
        return False

    low_signal_prefixes = (
        "/assets/",
        "/static/",
        "/styles/",
        "/css/",
        "/js/",
        "/images/",
        "/img/",
        "/fonts/",
        "/favicon",
        "assets/",
        "static/",
        "styles/",
        "css/",
        "js/",
        "images/",
        "img/",
        "fonts/",
        "favicon",
    )
    if lower.startswith(low_signal_prefixes):
        return False

    # 절대경로
    if s.startswith("/"):
        return True

    # 상대경로이지만 서버 라우트처럼 보이면 허용
    if re.search(r"(?:\.php|\.do|\.action|\.mvc)(?:\?|$)", s, re.I):
        return True

    # 디렉토리형 relative route도 허용
    if "/" in s and not s.startswith(("http://", "https://")):
        return True

    return False


def _is_probably_text_like_response(content_type: str | None, text: str) -> bool:
    ct = (content_type or "").lower()
    if any(token in ct for token in TEXT_LIKE_TYPES):
        return True
    snippet = (text or "")[:400].strip()
    return bool(snippet) and any(ch in snippet for ch in ("{", "}", "<", "/", ":", "[", "]"))

def _spa_seed_urls(seed_url: str, *, crawl_state: str = "anonymous") -> List[str]:
    base = _normalize_url(seed_url)
    parts = urlsplit(base)
    root = urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    out: List[str] = [base]

    include_common_root_guesses = os.getenv("CRAWL_INCLUDE_COMMON_ROOT_GUESSES", "off").lower() == "on"
    normalized_state = str(crawl_state or "anonymous").strip().lower()

    # authenticated recrawl에서는 low-cost common paths를 기본 비활성화
    # 이유:
    # - robots/security.txt가 crawl budget을 먼저 소모해서
    #   실제 앱 내부 링크(setup.php, instructions.php, /vulnerabilities/api/)를
    #   큐에서 처리하기 전에 max_pages에 도달할 수 있음
    if normalized_state != "authenticated":
        low_cost_common_paths = [
            "/robots.txt",
            "/.well-known/security.txt",
        ]
        for p in low_cost_common_paths:
            out.append(_normalize_url(urljoin(root.rstrip("/") + "/", p.lstrip("/"))))

    # 공용 /api /rest /graphql /ftp 추정 seed는 기본 비활성화
    # 필요할 때만 env로 켜기
    if include_common_root_guesses:
        for p in ["/api", "/api/", "/rest", "/rest/", "/graphql", "/ftp", "/ftp/"]:
            out.append(_normalize_url(urljoin(root.rstrip("/") + "/", p.lstrip("/"))))

    deduped: List[str] = []
    seen = set()
    for u in out:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped



def classify_url_kind(url: str, explicit_kind: Optional[str] = None) -> str:
    if explicit_kind:
        return explicit_kind
    if _looks_like_static_asset(url):
        return "static"
    if _looks_like_js_asset(url):
        return "asset_js"
    return "page"


def _query_param_names(url: str) -> List[str]:
    try:
        return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except Exception:
        return []

def _is_session_destructive_url(url: str) -> bool:
    path = (urlsplit(url).path or "/").lower()
    query = (urlsplit(url).query or "").lower()
    whole = f"{path}?{query}" if query else path

    destructive_tokens = (
        "logout",
        "log-out",
        "log_out",
        "signout",
        "sign-out",
        "sign_out",
        "logoff",
        "log-off",
        "log_off",
        "signoff",
        "sign-off",
        "sign_off",
        "invalidate",
        "destroy_session",
        "destroy-session",
        "kill_session",
        "end_session",
        "session_destroy",
        "session-destroy",
        "session_invalidate",
        "session-invalidate",
        "invalidate_session",
        "terminate_session",
    )

    for tok in destructive_tokens:
        if tok in whole:
            return True

    # query parameter 기반 logout도 일부 커버
    destructive_param_names = {
        "logout", "signout", "sign_off", "logoff",
        "invalidate", "destroy", "terminate",
        "session_destroy", "session_invalidate",
    }
    try:
        for k, v in parse_qsl(query, keep_blank_values=True):
            lk = str(k or "").strip().lower()
            lv = str(v or "").strip().lower()
            if lk in destructive_param_names:
                return True
            if lk in {"action", "mode", "cmd", "do"} and lv in destructive_param_names:
                return True
    except Exception:
        pass

    return False

class LinkExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: Set[str] = set()
        self.scripts: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        attr_map = dict(attrs)
        tag = tag.lower()

        candidate_attr_names = {
            "href",
            "src",
            "action",
            "formaction",
            "data-href",
            "data-url",
            "data-endpoint",
            "data-api",
            "data-action",
            "routerlink",
            "to",
            "hx-get",
            "hx-post",
            "hx-put",
            "hx-delete",
            "hx-patch",
            "xlink:href",
        }
        for attr_name, attr_value in attr_map.items():
            if not attr_value:
                continue
            if attr_name.lower() not in candidate_attr_names:
                continue
            abs_url = _normalize_url(urljoin(self.base_url, attr_value))
            if attr_name.lower() == "src" and tag == "script":
                self.scripts.add(abs_url)
            else:
                self.links.add(abs_url)

        if tag == "form":
            action = attr_map.get("action") or self.base_url
            method = (attr_map.get("method") or "GET").upper()
            self._current_form = {
                "url": _normalize_url(urljoin(self.base_url, action)),
                "kind": "form",
                "method": method,
                "field_names": [],
                "field_defaults": {},
            }
    
        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            name = attr_map.get("name")
            if name:
                self._current_form["field_names"].append(name)
    
                if tag == "input":
                    input_type = str(attr_map.get("type") or "text").lower()
                    value = attr_map.get("value") or ""
    
                    if input_type in {"hidden", "text", "search", "email"}:
                        self._current_form["field_defaults"][name] = value
                    elif input_type in {"checkbox", "radio"} and attr_map.get("checked") is not None:
                        self._current_form["field_defaults"][name] = value or "on"

        if tag == "button" and self._current_form is not None:
            button_action = attr_map.get("formaction")
            if button_action:
                self.links.add(_normalize_url(urljoin(self.base_url, button_action)))
            name = attr_map.get("name")
            if name:
                self._current_form["field_names"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)


def _regex_extract_urls_from_html(base_url: str, text: str) -> Set[str]:
    out: Set[str] = set()
    body = text or ""

    patterns = [
        r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""",
        r"""location(?:\.href)?\s*=\s*["']([^"'#]+)["']""",
        r"""window\.open\(\s*["']([^"'#]+)["']""",
        r"""url\(\s*["']?([^"')#]+)["']?\s*\)""",
        r"""content\s*=\s*["'][^"']*url=([^"'>]+)["']""",
    ]

    for pattern in patterns:
        for m in re.finditer(pattern, body, re.I):
            raw = (m.group(1) or "").strip()
            if not raw:
                continue
            if not _looks_like_endpoint_candidate(raw):
                continue

            abs_url = _normalize_url(urljoin(base_url, raw))
            out.add(abs_url)

    return out


def _extract_header_endpoints(base_url: str, headers: Dict[str, str]) -> Set[str]:
    out: Set[str] = set()
    for key, value in (headers or {}).items():
        header_name = str(key or "").strip().lower()
        header_value = str(value or "").strip()
        if not header_value:
            continue

        if header_name in {"location", "content-location", "x-rewrite-url", "x-accel-redirect"}:
            if _looks_like_endpoint_candidate(header_value):
                out.add(_normalize_url(urljoin(base_url, header_value)))
            continue

        if header_name == "link":
            for match in re.finditer(r"<([^>]+)>", header_value):
                raw = str(match.group(1) or "").strip()
                if raw and _looks_like_endpoint_candidate(raw):
                    out.add(_normalize_url(urljoin(base_url, raw)))
            continue

        if header_name == "refresh":
            refresh_match = re.search(r"url=([^;]+)$", header_value, re.I)
            if refresh_match:
                raw = str(refresh_match.group(1) or "").strip()
                if raw and _looks_like_endpoint_candidate(raw):
                    out.add(_normalize_url(urljoin(base_url, raw)))

    return out


def _extract_robots_or_sitemap_endpoints(base_url: str, text: str) -> Set[str]:
    out: Set[str] = set()
    body = text or ""

    for match in re.finditer(r"(?im)^\s*(?:allow|disallow|sitemap)\s*:\s*(\S+)\s*$", body):
        raw = str(match.group(1) or "").strip()
        if not raw or raw == "/":
            continue
        if _looks_like_endpoint_candidate(raw) or raw.startswith(("http://", "https://", "/")):
            out.add(_normalize_url(urljoin(base_url, raw)))

    for match in re.finditer(r"(?is)<loc>\s*([^<]+?)\s*</loc>", body):
        raw = str(match.group(1) or "").strip()
        if raw and _looks_like_endpoint_candidate(raw):
            out.add(_normalize_url(urljoin(base_url, raw)))

    return out


def _extract_textual_endpoints(base_url: str, text: str) -> Set[str]:
    out = extract_js_style_endpoints(base_url, text)
    out |= _regex_extract_urls_from_html(base_url, text)
    out |= _extract_robots_or_sitemap_endpoints(base_url, text)
    return out


def extract_navigation(base_url: str, html: str) -> Dict[str, Any]:
    parser = LinkExtractor(base_url)
    try:
        parser.feed(html or "")
    except Exception:
        pass

    return {
        "links": parser.links,
        "scripts": parser.scripts,
        "forms": parser.forms,
    }


def extract_js_style_endpoints(base_url: str, text: str) -> Set[str]:
    out: Set[str] = set()

    for m in JS_ENDPOINT_RE.finditer(text or ""):
        raw = m.group(1)
        if not raw:
            continue

        raw = raw.strip()
        if not _looks_like_endpoint_candidate(raw):
            continue

        abs_url = _normalize_url(urljoin(base_url, raw))
        out.add(abs_url)

    return out


async def fetch_text(
    client: httpx.AsyncClient,
    url: str,
    timeout_s: float,
) -> Tuple[int | None, Dict[str, str], str, str | None]:
    try:
        r = await client.get(url, follow_redirects=True, timeout=timeout_s)
        return r.status_code, dict(r.headers), r.text or "", str(r.url)
    except Exception:
        return None, {}, "", None

def score_endpoint(ep: Dict[str, Any], seed_url: str) -> int:
    url = ep["url"]
    kind = ep.get("kind", "page")

    parts = urlsplit(url)
    seed_parts = urlsplit(seed_url)

    score = 0
    path = parts.path.lower()
    query = parts.query.lower()
    filename = parts.path.lower().split("/")[-1]

    if filename.endswith(LOW_VALUE_EXTS):
        score -= 40
    if any(hint in filename for hint in LOW_VALUE_FILE_HINTS):
        score -= 40

    if ep.get("is_session_destructive"):
        score -= 120

    if kind in {"page", "form", "action"}:
        score += 20
    elif kind == "asset_js":
        score += 6
    elif kind == "static":
        score -= 50

    if path == seed_parts.path:
        score += 10
    if path in {"/", seed_parts.path.rstrip("/"), seed_parts.path.rstrip("/") + "/"}:
        score += 8

    for hint in HIGH_VALUE_HINTS:
        if hint in path or hint in query:
            score += 10

    if "/vulnerabilities/" in path:
        score += 25
    if any(x in path for x in ("/phpinfo", "/config/", "/backup", "/debug", "/log", "/viewer")):
        score += 15

    for hint in LOW_VALUE_HINTS:
        if hint in path:
            score -= 10

    if "/api/" in path or "/rest/" in path or path.endswith(".mvc"):
        score += 15

    if parts.query:
        score += 5

    depth = len([x for x in path.split("/") if x])
    if depth == 1:
        score += 6
    elif depth == 2:
        score += 4
    elif depth >= 5:
        score -= 4

    if ep.get("is_redirect_target"):
        score += 10

    if ep.get("field_names"):
        score += 10

    if _looks_like_static_asset(url):
        score -= 100

    return score

def _make_endpoint(
    url: str,
    *,
    kind: str,
    source: Optional[str],
    depth: int,
    method: str = "GET",
    field_names: Optional[List[str]] = None,
    is_redirect_target: bool = False,
    state: str = "anonymous",
) -> Dict[str, Any]:
    normalized_url = _normalize_url(url)
    normalized_kind = classify_url_kind(normalized_url, kind)

    safe_method = str(method or "GET").upper().strip() or "GET"

    dedup_field_names: List[str] = []
    seen_fields = set()
    for name in field_names or []:
        s = str(name or "").strip()
        if not s or s in seen_fields:
            continue
        seen_fields.add(s)
        dedup_field_names.append(s)

    query_param_names = []
    seen_query_params = set()
    for name in _query_param_names(normalized_url):
        s = str(name or "").strip()
        if not s or s in seen_query_params:
            continue
        seen_query_params.add(s)
        query_param_names.append(s)

    safe_state = str(state or "anonymous").strip().lower() or "anonymous"
    is_session_destructive = _is_session_destructive_url(normalized_url)

    return {
        "url": normalized_url,
        "kind": normalized_kind,
        "source": source,
        "depth": int(depth),
        "method": safe_method,
        "field_names": dedup_field_names,
        "query_param_names": query_param_names,
        "is_redirect_target": bool(is_redirect_target),
        "is_session_destructive": is_session_destructive,
        "state": safe_state,
        "states": [safe_state],
        "score": 0,
    }

async def discover_endpoints(
    client: httpx.AsyncClient,
    seed_url: str,
    timeout_s: float,
    max_depth: int = 2,
    max_pages: int = 20,
    include_js_string_paths: bool = True,
    extra_seed_urls: Optional[List[str]] = None,
    crawl_state: str = "anonymous",
) -> List[Dict[str, Any]]:
    seed_url = _normalize_url(seed_url)

    start_urls = _spa_seed_urls(seed_url, crawl_state=crawl_state)
    for x in extra_seed_urls or []:
        x = _normalize_url(x)
        if _same_origin(seed_url, x):
            start_urls.append(x)

    start_urls = list(dict.fromkeys(start_urls))

    allowed_origins = {
        (urlsplit(u).scheme, urlsplit(u).netloc)
        for u in start_urls
        if u
    }

    visited: Set[str] = set()
    discovered_by_url: Dict[str, Dict[str, Any]] = {}
    queue = deque([(_normalize_url(u), 0, None) for u in start_urls])

    authenticated_mode = str(crawl_state or "").strip().lower() == "authenticated"

    def _enqueue_candidate(url: str, next_depth: int, source_url: str | None) -> None:
        normalized = _normalize_url(url)

        if normalized in visited:
            return

        if authenticated_mode and _is_session_destructive_url(normalized):
            return

        if authenticated_mode:
            queue.appendleft((normalized, next_depth, source_url))
        else:
            queue.append((normalized, next_depth, source_url))

    def _is_allowed_candidate(url: str) -> bool:
        if not url:
            return False

        c = str(url).strip()
        if not c:
            return False

        lowered = c.lower()
        if lowered.startswith(("javascript:", "mailto:", "tel:", "data:")):
            return False

        parts = urlsplit(c)
        return (parts.scheme, parts.netloc) in allowed_origins

    def _merge_state(existing: Dict[str, Any], state: str) -> None:
        states = set(existing.get("states") or [])
        prior_state = str(existing.get("state") or "").strip()
        if prior_state:
            states.add(prior_state)
        if state:
            states.add(state)
        existing["states"] = sorted(states)

    def _merge_endpoint(existing: Dict[str, Any], incoming: Dict[str, Any]) -> None:
        existing["depth"] = min(int(existing.get("depth", 9999)), int(incoming.get("depth", 9999)))
        existing["score"] = max(int(existing.get("score", 0) or 0), int(incoming.get("score", 0) or 0))

        incoming_kind = str(incoming.get("kind") or "page")
        existing_kind = str(existing.get("kind") or "page")

        if incoming_kind == "form":
            existing["kind"] = "form"
        elif existing_kind != "form" and incoming_kind == "page":
            existing["kind"] = "page"
        elif existing_kind not in {"form", "page"}:
            existing["kind"] = incoming_kind

        existing["field_names"] = list(dict.fromkeys(
            (existing.get("field_names") or []) + (incoming.get("field_names") or [])
        ))
        existing["query_param_names"] = list(dict.fromkeys(
            (existing.get("query_param_names") or []) + (incoming.get("query_param_names") or [])
        ))

        if incoming.get("is_redirect_target"):
            existing["is_redirect_target"] = True

        if incoming.get("is_session_destructive"):
            existing["is_session_destructive"] = True

        if not existing.get("source") and incoming.get("source"):
            existing["source"] = incoming.get("source")

        _merge_state(existing, str(incoming.get("state") or crawl_state))

    def _register_endpoint(ep: Dict[str, Any]) -> None:
        url = str(ep.get("url") or "").strip()
        if not url:
            return

        existing = discovered_by_url.get(url)
        if existing is None:
            ep = dict(ep)
            ep.setdefault("score", 0)
            ep.setdefault("states", [str(ep.get("state") or crawl_state)])
            discovered_by_url[url] = ep
            return

        _merge_endpoint(existing, ep)

    for u in start_urls:
        _register_endpoint(
            _make_endpoint(
                u,
                kind=classify_url_kind(u),
                source=None,
                depth=0,
                state=crawl_state,
            )
        )

    while queue and len(visited) < max_pages:
        current, depth, source = queue.popleft()
        if current in visited:
            continue
        visited.add(current)

        status, headers, text, final_url = await fetch_text(client, current, timeout_s)
        if status is None:
            continue

        resolved_url = _normalize_url(final_url or current)
        header_links = _extract_header_endpoints(resolved_url, headers)

        if _is_allowed_candidate(resolved_url):
            resolved_ep = _make_endpoint(
                resolved_url,
                kind=classify_url_kind(resolved_url),
                source=current,
                depth=depth,
                is_redirect_target=(resolved_url != current),
                state=crawl_state,
            )
            _register_endpoint(resolved_ep)

            if (
                depth + 1 <= max_depth
                and resolved_url not in visited
                and not _looks_like_static_asset(resolved_url)
                and not (authenticated_mode and resolved_ep.get("is_session_destructive"))
                ):
                    _enqueue_candidate(resolved_url, depth + 1, current)

        content_type = headers.get("content-type", "")
        is_html = _is_probably_html_response(content_type, text)
        is_js = _is_probably_javascript_response(resolved_url, content_type, text)
        is_text_like = _is_probably_text_like_response(content_type, text)

        for link in header_links:
            link = _normalize_url(link)
            if not _is_allowed_candidate(link):
                continue

            ep = _make_endpoint(
                link,
                kind=classify_url_kind(link),
                source=resolved_url,
                depth=depth + 1,
                is_redirect_target=True,
                state=crawl_state,
            )
            _register_endpoint(ep)

            if (
                depth + 1 <= max_depth
                and link not in visited
                and not _looks_like_static_asset(link)
                and not (authenticated_mode and ep.get("is_session_destructive"))
            ):
                _enqueue_candidate(link, depth + 1, resolved_url)

        if include_js_string_paths and is_js:
            js_links = extract_js_style_endpoints(resolved_url, text)
            for link in js_links:
                link = _normalize_url(link)
                if not _is_allowed_candidate(link):
                    continue

                ep = _make_endpoint(
                    link,
                    kind=classify_url_kind(link),
                    source=resolved_url,
                    depth=depth + 1,
                    state=crawl_state,
                )
                _register_endpoint(ep)

                if (
                    depth + 1 <= max_depth
                    and link not in visited
                    and not _looks_like_static_asset(link)
                    and not (authenticated_mode and ep.get("is_session_destructive"))
                ):
                    _enqueue_candidate(link, depth + 1, resolved_url)

        if is_text_like and not is_html and not is_js:
            textual_links = _extract_textual_endpoints(resolved_url, text)
            for link in textual_links:
                link = _normalize_url(link)
                if not _is_allowed_candidate(link):
                    continue

                ep = _make_endpoint(
                    link,
                    kind=classify_url_kind(link),
                    source=resolved_url,
                    depth=depth + 1,
                    state=crawl_state,
                )
                _register_endpoint(ep)

                if (
                    depth + 1 <= max_depth
                    and link not in visited
                    and not _looks_like_static_asset(link)
                    and not (authenticated_mode and ep.get("is_session_destructive"))
                ):
                    _enqueue_candidate(link, depth + 1, resolved_url)

        if not is_html:
            continue

        nav = extract_navigation(resolved_url, text)
        html_links = set(nav["links"])
        script_links = set(nav["scripts"])
        form_defs = nav["forms"]

        js_links = extract_js_style_endpoints(resolved_url, text) if include_js_string_paths else set()
        regex_links = _regex_extract_urls_from_html(resolved_url, text)

        html_links |= regex_links

        for link in html_links.union(js_links):
            link = _normalize_url(link)
            if not _is_allowed_candidate(link):
                continue

            ep = _make_endpoint(
                link,
                kind=classify_url_kind(link),
                source=resolved_url,
                depth=depth + 1,
                state=crawl_state,
            )
            _register_endpoint(ep)

            if (
                depth + 1 <= max_depth
                and link not in visited
                and not _looks_like_static_asset(link)
                and not (authenticated_mode and ep.get("is_session_destructive"))
            ):
                _enqueue_candidate(link, depth + 1, resolved_url)

        for src in script_links:
            src = _normalize_url(src)
            if not _is_allowed_candidate(src):
                continue

            ep = _make_endpoint(
                src,
                kind="asset_js" if _looks_like_js_asset(src) else classify_url_kind(src),
                source=resolved_url,
                depth=depth + 1,
                state=crawl_state,
            )
            _register_endpoint(ep)

            if (
                depth + 1 <= max_depth
                and src not in visited
                and not _looks_like_static_asset(src)
                and not (authenticated_mode and ep.get("is_session_destructive"))
            ):
                _enqueue_candidate(src, depth + 1, resolved_url)

        for form_def in form_defs:
            action = _normalize_url(form_def["url"])
            if not _is_allowed_candidate(action):
                continue

            ep = _make_endpoint(
                action,
                kind="form",
                source=resolved_url,
                depth=depth + 1,
                method=form_def.get("method", "GET"),
                field_names=form_def.get("field_names") or [],
                state=crawl_state,
            )
            _register_endpoint(ep)

            if (
                depth + 1 <= max_depth
                and action not in visited
                and not _looks_like_static_asset(action)
                and not (authenticated_mode and ep.get("is_session_destructive"))
            ):
                _enqueue_candidate(action, depth + 1, resolved_url)

    ranked = list(discovered_by_url.values())
    for ep in ranked:
        ep["score"] = score_endpoint(ep, seed_url)
        if "states" not in ep or not ep["states"]:
            ep["states"] = [crawl_state]
        ep.setdefault("is_session_destructive", _is_session_destructive_url(ep.get("url") or ""))
    ranked.sort(
        key=lambda ep: (
            bool(ep.get("is_session_destructive")),
            -ep["score"],
            ep.get("kind") == "static",
            len(urlsplit(ep["url"]).path),
            urlsplit(ep["url"]).path,
            urlsplit(ep["url"]).query,
        )
    )
    return ranked
