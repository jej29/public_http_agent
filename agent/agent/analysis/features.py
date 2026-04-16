from __future__ import annotations

import posixpath
import re
from typing import Any, Dict, List
from urllib.parse import parse_qsl, urlsplit
from agent.core.common import log


CONFIG_NAME_HINTS = {
    "config", "settings", "application", "appsettings", "database", "db", ".env",
}
SAMPLE_EXTENSIONS = {".dist", ".example", ".sample", ".template"}
BACKUP_EXTENSIONS = {".bak", ".old", ".orig", ".save", "~"}
CONFIG_EXTENSIONS = {
    ".ini", ".conf", ".cfg", ".env", ".yaml", ".yml", ".json", ".xml", ".properties",
}
STATIC_EXTENSIONS = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map",
)
SENSITIVE_SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
]
RISKY_HTTP_METHODS = {
    "TRACE", "PUT", "DELETE", "CONNECT", "PROPFIND", "SEARCH", "BREW", "FOO", "PATCH",
}
FILEISH_PARAM_NAMES = {"file", "path", "page", "template", "include", "inc", "doc", "document", "folder"}
REDIRECT_PARAM_NAMES = {"redirect", "url", "next", "return", "returnto", "dest", "destination", "goto", "continue"}

STRONG_VERSION_PATTERNS = [
    re.compile(r"\b(?:apache|nginx|iis|caddy|envoy)/\d[\w.\-]*\b", re.I),
    re.compile(r"\b(?:tomcat|jetty|jboss|wildfly|weblogic|websphere|glassfish)/\d[\w.\-]*\b", re.I),
    re.compile(r"\b(?:gunicorn|uwsgi|werkzeug|uvicorn|hypercorn)/\d[\w.\-]*\b", re.I),
    re.compile(r"\b(?:django|flask|spring boot|laravel|rails|asp\.net(?: core)?|php)/\d[\w.\-]*\b", re.I),
]
GENERIC_PRODUCT_PATTERNS = [
    re.compile(r"\bapache\b", re.I),
    re.compile(r"\btomcat\b", re.I),
    re.compile(r"\bnginx\b", re.I),
    re.compile(r"\bphp\b", re.I),
    re.compile(r"\bflask\b", re.I),
    re.compile(r"\bdjango\b", re.I),
    re.compile(r"\bspring\b", re.I),
]
SERVER_VERSION_PATTERNS = [
    re.compile(r"\b(?:apache(?:/[\d.]+)?|nginx(?:/[\d.]+)?|iis(?:/[\d.]+)?|caddy(?:/[\d.]+)?|envoy(?:/[\d.]+)?)\b", re.I),
    re.compile(r"\b(?:tomcat|jetty|jboss|wildfly|weblogic|websphere|glassfish)(?:/[\d.]+)?\b", re.I),
    re.compile(r"\b(?:gunicorn|uwsgi|werkzeug|uvicorn|hypercorn)(?:/[\d.]+)?\b", re.I),
    re.compile(r"\b(?:express|koa|hapi|nestjs|next\.js|nuxt)(?:/[\d.]+)?\b", re.I),
    re.compile(r"\b(?:spring boot|spring mvc|django|flask|rails|sinatra|laravel|symfony|asp\.net|asp\.net core|php)(?:/[\d.]+)?\b", re.I),
]
STACK_TRACE_PATTERNS = [
    re.compile(r"\bat\s+[a-zA-Z0-9_.$]+\([A-Za-z0-9_.]+:\d+\)"),
    re.compile(r"Traceback \(most recent call last\):", re.I),
    re.compile(r'\bFile "[^"]+", line \d+, in ', re.I),
    re.compile(r"\bFatal error\b", re.I),
    re.compile(r"\bStack trace:\b", re.I),
    re.compile(r"\bTypeError:\b|\bReferenceError:\b|\bSyntaxError:\b", re.I),
    re.compile(r"\bUnhandled Exception:\b", re.I),
]
FILE_PATH_PATTERNS = [
    re.compile(r"(?:[A-Za-z]:\\(?:[^\\\r\n]+\\)+[^\\\r\n]*)"),
    re.compile(r"(?:/(?:[^/\s<>:\"'|?*]+/)+[^/\s<>:\"'|?*]*)"),
]
LOCAL_UNIX_ROOT_HINTS = {
    "bin", "boot", "dev", "etc", "home", "lib", "lib32", "lib64", "media", "mnt", "opt", "proc", "root", "run",
    "sbin", "srv", "sys", "tmp", "usr", "var", "www", "app", "workspace",
}
URLISH_FIRST_SEGMENT_SUFFIXES = {
    ".com", ".org", ".net", ".io", ".dev", ".ai", ".co", ".kr", ".jp", ".cn", ".uk", ".de", ".fr", ".edu", ".gov", ".mil"
}
INTERNAL_IP_PATTERNS = [
    re.compile(r"\b10(?:\.\d{1,3}){3}\b"),
    re.compile(r"\b192\.168(?:\.\d{1,3}){2}\b"),
    re.compile(r"\b172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}\b"),
    re.compile(r"\b127(?:\.\d{1,3}){3}\b"),
]
DB_ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*MySQL", re.I),
    re.compile(r"Warning.*mysql_", re.I),
    re.compile(r"MySqlException", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"PG::[A-Za-z]+", re.I),
    re.compile(r"org\.postgresql\.", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"Oracle error", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"SQLServerException", re.I),
    re.compile(r"Unclosed quotation mark after the character string", re.I),
    re.compile(r"SQLite/JDBCDriver", re.I),
    re.compile(r"sqlite3\.", re.I),
]
FRAMEWORK_HINT_PATTERNS = [
    re.compile(r"\bSpring\b|\bWhitelabel Error Page\b", re.I),
    re.compile(r"\bDjango\b", re.I),
    re.compile(r"\bFlask\b|\bWerkzeug\b", re.I),
    re.compile(r"\bExpress\b", re.I),
    re.compile(r"\bRuby on Rails\b", re.I),
    re.compile(r"\bLaravel\b", re.I),
    re.compile(r"\bASP\.NET\b|\bViewState\b", re.I),
    re.compile(r"\bNext\.js\b|\bNuxt\b", re.I),
]
DEBUG_HINT_PATTERNS = [
    re.compile(r"\bdevelopment mode\b", re.I),
    re.compile(r"\bverbose error\b", re.I),
    re.compile(r"\bexception report\b", re.I),
    re.compile(r"\bdebug (?:mode|page|toolbar)\b", re.I),
    re.compile(r"\brunning in debug\b", re.I),
]
DIRECTORY_LISTING_PATTERNS = [
    re.compile(r"\bIndex of /", re.I),
    re.compile(r"\bParent Directory\b", re.I),
    re.compile(r"<title>\s*Index of ", re.I),
]
DEFAULT_FILE_PATTERNS = [
    re.compile(r"/\.git(?:/|$)", re.I),
    re.compile(r"/\.env(?:$|[?#])", re.I),
    re.compile(r"/phpinfo(?:\.php)?(?:$|[?#])", re.I),
    re.compile(r"/server-status(?:$|[?#])", re.I),
    re.compile(r"/actuator(?:/|$)", re.I),
    re.compile(r"/debug(?:$|[?#])", re.I),
]
DEFAULT_ERROR_PAGE_HINTS = [
    ("default_tomcat_error_page", re.compile(r"Apache Tomcat(?:/[\d.]+)?", re.I)),
    ("default_nginx_error_page", re.compile(r"<center>\s*nginx(?:/[\d.]+)?\s*</center>", re.I)),
    ("default_apache_error_page", re.compile(r"Apache Server at .* Port \d+", re.I)),
    ("spring_whitelabel_error_page", re.compile(r"Whitelabel Error Page", re.I)),
]
PHPINFO_INDICATORS = [
    "phpinfo()", "php version", "loaded modules", "server api", "php variables", "php license",
]
CONFIG_EXPOSURE_MARKERS = [
    "db_password", "mysql_password", "database", "db_host", "db_user", "secret", "api_key", "access_key",
    "private_key", "connection_string", "aws_access_key", "aws_secret", "redis", "postgres", "mysql",
    "mariadb", "services:", "environment:", "volumes:", "image:",
]
# =========================
# CONFIG VALUE EXTRACTOR (GENERIC)
# =========================

CONFIG_KEY_PATTERNS = [
    r"db[_\-]?host",
    r"db[_\-]?name",
    r"db[_\-]?user",
    r"db[_\-]?pass(word)?",
    r"database[_\-\s]server",
    r"database[_\-\s]host",
    r"database[_\-\s]name",
    r"database[_\-\s]user(name)?",
    r"database[_\-\s]pass(word)?",
    r"database[_\-]?(url|uri|name|host|user|password)",
    r"redis[_\-]?(host|password)",
    r"api[_\-]?key",
    r"secret",
    r"token",
    r"access[_\-]?key",
    r"private[_\-]?key",
    r"client[_\-]?secret",
    r"auth[_\-]?token",
]

MASKED_VALUE_PATTERNS = [
    r"^\*+$",
    r"^x+$",
    r"^masked$",
    r"^hidden$",
    r"^redacted$",
]

KV_REGEXES = [
    re.compile(r"(?i)\b([A-Z0-9_\-\.]{3,})\s*=\s*['\"]?([^'\"\n]+)['\"]?"),  # .env
    re.compile(r"(?i)[\"']([a-zA-Z0-9_\-\.]{3,})[\"']\s*:\s*[\"']([^\"']+)[\"']"),  # json
    re.compile(r"(?i)\b([a-zA-Z0-9_\-\.]{3,})\s*:\s*([^\n#]+)"),  # yaml
    re.compile(r"(?i)define\s*\(\s*[\"']([A-Z0-9_\-]+)[\"']\s*,\s*[\"']([^\"']+)[\"']\s*\)"),  # php define
    re.compile(r"(?i)\$([a-zA-Z0-9_\-]+)\s*=\s*[\"']([^\"']+)[\"']"),  # php var
]

HTML_LABEL_VALUE_REGEXES = [
    re.compile(
        r"(?is)<tr[^>]*>\s*(?:<t[dh][^>]*>\s*){1,2}([^<]{2,80}?)\s*</t[dh]>\s*<t[dh][^>]*>\s*([^<]{1,200}?)\s*</t[dh]>\s*</tr>"
    ),
    re.compile(
        r"(?is)<(?:li|p|div|span|td|th)[^>]*>\s*(database(?:\s+server|\s+host|\s+name|\s+username|\s+user|\s+password)?|db[_\-\s]?(?:host|name|user|username|password|pass|port))\s*[:=]\s*([^<\n]{1,200})"
    ),
]


def _is_masked_value(value: str) -> bool:
    v = value.strip().lower()
    for p in MASKED_VALUE_PATTERNS:
        if re.match(p, v):
            return True
    return False


def _is_interesting_secret(value: str) -> bool:
    if not value or len(value) < 4:
        return False

    # high entropy-like
    if re.search(r"[A-Za-z0-9]{16,}", value):
        return True

    # typical secret keywords
    if re.search(r"(key|token|secret|pass)", value.lower()):
        return True

    return False


def _extract_config_values(body: str) -> List[Dict[str, Any]]:
    if not body:
        return []

    findings: List[Dict[str, Any]] = []

    def _normalize_label_key(raw_key: str) -> str:
        key_l = str(raw_key or "").strip().lower()
        key_l = re.sub(r"<[^>]+>", " ", key_l)
        key_l = re.sub(r"&nbsp;|&#160;", " ", key_l)
        key_l = re.sub(r"[\s_\-]+", " ", key_l).strip()

        mapping = [
            (r"\bdatabase server\b", "db_host"),
            (r"\bdatabase host\b", "db_host"),
            (r"\bdb host\b", "db_host"),
            (r"\bdatabase name\b", "db_name"),
            (r"\bdb name\b", "db_name"),
            (r"\bdatabase username\b", "db_user"),
            (r"\bdatabase user\b", "db_user"),
            (r"\bdb username\b", "db_user"),
            (r"\bdb user\b", "db_user"),
            (r"\bdatabase password\b", "db_password"),
            (r"\bdb password\b", "db_password"),
            (r"\bdb pass\b", "db_password"),
            (r"\bdatabase port\b", "db_port"),
            (r"\bdb port\b", "db_port"),
        ]
        for pattern, normalized in mapping:
            if re.search(pattern, key_l):
                return normalized
        return key_l.replace(" ", "_")

    def _clean_value(raw_value: str) -> str:
        value = str(raw_value or "").strip()
        value = re.sub(r"<[^>]+>", " ", value)
        value = value.replace("&nbsp;", " ").replace("&#160;", " ")
        value = re.sub(r"\s+", " ", value).strip(" :\t\r\n")
        return value

    def _append_candidate(key: str, value: str) -> None:
        key_norm = _normalize_label_key(key)
        value_norm = _clean_value(value)
        if not key_norm or not value_norm:
            return
        if len(value_norm) > 200:
            value_norm = value_norm[:200]
        if not any(re.search(p, key_norm) for p in CONFIG_KEY_PATTERNS):
            return

        masked = _is_masked_value(value_norm)
        interesting = _is_interesting_secret(value_norm)
        findings.append(
            {
                "key": key_norm,
                "value": value_norm,
                "masked": masked,
                "interesting": interesting,
            }
        )

    for regex in KV_REGEXES:
        for match in regex.findall(body):
            if len(match) != 2:
                continue

            _append_candidate(match[0], match[1])

    for regex in HTML_LABEL_VALUE_REGEXES:
        for match in regex.findall(body):
            if len(match) != 2:
                continue
            _append_candidate(match[0], match[1])

    # dedup
    seen = set()
    out = []
    for f in findings:
        sig = (f["key"], f["value"])
        if sig in seen:
            continue
        seen.add(sig)
        out.append(f)

    return out[:20]


LOG_EXPOSURE_PATTERNS = [
    re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\s+-\s+-\s+\[[^\]]+\]\s+"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^"]+\s+HTTP/[0-9.]+"\s+\d{3}\b', re.I),
    re.compile(r'\[(?:\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4})\]\s+"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+', re.I),
    re.compile(r'\b(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b.{0,80}\b(?:[A-Za-z0-9_.]+\.)+[A-Za-z0-9_$]+\b', re.I),
    re.compile(r'\b(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b.{0,120}(?:exception|stack trace|traceback|caused by)\b', re.I),
    re.compile(r'\b(?:org\.|com\.|net\.|io\.)[A-Za-z0-9_.\$]{6,}\b.{0,80}\b(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b', re.I),
]


def fingerprint_response(resp) -> dict:
    tech = set()
    clues = []

    if isinstance(resp, dict):
        headers = resp.get("headers") or {}
        body = str(resp.get("text") or resp.get("body") or "").lower()
        url = str(resp.get("url") or resp.get("final_url") or "")
        status_code = resp.get("status_code")
    else:
        headers = getattr(resp, "headers", None) or {}
        body = str(getattr(resp, "text", "") or "").lower()
        url = str(getattr(resp, "url", "") or "")
        status_code = getattr(resp, "status_code", None)

    if not isinstance(headers, dict):
        try:
            headers = dict(headers)
        except Exception:
            headers = {}

    headers_lc = {str(k).lower(): str(v).lower() for k, v in headers.items()}

    server = headers_lc.get("server", "")
    powered = headers_lc.get("x-powered-by", "")
    via = headers_lc.get("via", "")
    content_type = headers_lc.get("content-type", "")

    if "apache" in server:
        tech.add("apache")
        clues.append("server_header")
    if "nginx" in server:
        tech.add("nginx")
        clues.append("server_header")
    if "iis" in server:
        tech.add("iis")
        clues.append("server_header")
    if "tomcat" in server:
        tech.add("tomcat")
        clues.append("server_header")
    if "jetty" in server:
        tech.add("jetty")
        clues.append("server_header")
    if "openresty" in server:
        tech.add("openresty")
        tech.add("nginx")
        clues.append("server_header")

    if "php" in powered:
        tech.add("php")
        clues.append("x_powered_by")
    if "asp.net" in powered:
        tech.add("asp.net")
        clues.append("x_powered_by")
    if "next.js" in powered:
        tech.add("nextjs")
        clues.append("x_powered_by")

    if "cloudflare" in server or "cloudflare" in via:
        clues.append("reverse_proxy_cloudflare")
    if "envoy" in server or "envoy" in via:
        tech.add("envoy")
        clues.append("reverse_proxy_envoy")

    if "<app-root" in body or "ng-version" in body:
        tech.add("angular")
        tech.add("spa")
        clues.append("frontend_angular")
    if "__next" in body or '"buildid"' in body:
        tech.add("nextjs")
        tech.add("react")
        tech.add("spa")
        clues.append("frontend_nextjs")
    if "_nuxt" in body:
        tech.add("nuxt")
        tech.add("vue")
        tech.add("spa")
        clues.append("frontend_nuxt")
    if "react" in body and ("__next" in body or "data-reactroot" in body):
        tech.add("react")
        clues.append("frontend_react")
    if "vue" in body and ("__nuxt" in body or 'id="app"' in body):
        tech.add("vue")
        clues.append("frontend_vue")

    if "juice shop" in body or "owasp juice shop" in body:
        clues.append("juice_shop_like")

    if "application/json" in content_type:
        clues.append("json_api")
    if "text/html" in content_type:
        clues.append("html_response")

    url_l = url.lower()
    if "/static/" in url_l or "/assets/" in url_l:
        clues.append("static_path")
    if "/api/" in url_l or "/rest/" in url_l:
        clues.append("api_path")
    if "/graphql" in url_l:
        clues.append("graphql_path")

    if isinstance(status_code, int):
        if status_code >= 500:
            clues.append("server_error")
        elif status_code in {401, 403}:
            clues.append("access_control_enforced")

    return {
        "tech": sorted(tech),
        "clues": sorted(set(clues)),
    }


def _dedup(items: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for x in items or []:
        s = str(x or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def _dedup_preserve_order(items: List[str]) -> List[str]:
    return _dedup(items)


def _headers_lc(headers: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in (headers or {}).items():
        key = str(k).lower()
        out.setdefault(key, [])
        if isinstance(v, list):
            out[key].extend(str(x) for x in v)
        else:
            out[key].append(str(v))
    return out


def _header_first(headers_lc: Dict[str, Any], name: str) -> str | None:
    vals = headers_lc.get(name.lower()) or []
    return str(vals[0]) if vals else None


def _header_all(headers_lc: Dict[str, Any], name: str) -> List[str]:
    return [str(x) for x in (headers_lc.get(name.lower()) or []) if str(x).strip()]


def _find_matches(patterns: List[re.Pattern], text: str, limit: int = 10) -> List[str]:
    if not text:
        return []
    out: List[str] = []
    seen = set()
    for pat in patterns:
        for m in pat.finditer(text):
            val = str(m.group(0)).strip()
            if not val or val in seen:
                continue
            seen.add(val)
            out.append(val)
            if len(out) >= limit:
                return out
    return out


def _status_family(status_code: Any) -> str:
    if not isinstance(status_code, int):
        return "unknown"
    if 100 <= status_code < 200:
        return "1xx"
    if 200 <= status_code < 300:
        return "2xx"
    if 300 <= status_code < 400:
        return "3xx"
    if 400 <= status_code < 500:
        return "4xx"
    if 500 <= status_code < 600:
        return "5xx"
    return "unknown"


def _looks_like_static_asset_url(url: str) -> bool:
    return (urlsplit(url).path or "").lower().endswith(STATIC_EXTENSIONS)


def _classify_response_kind(request_meta: Dict[str, Any], headers_lc: Dict[str, Any]) -> str:
    url = str(request_meta.get("url") or "")
    if _looks_like_static_asset_url(url):
        return "static_asset"

    ct = (_header_first(headers_lc, "content-type") or "").lower()
    if "text/html" in ct:
        return "html"
    if "application/json" in ct:
        return "json"
    if "text/plain" in ct:
        return "text"
    if "javascript" in ct:
        return "javascript"
    if "text/css" in ct:
        return "css"
    return "other"


def _normalize_product_family(token: str) -> str:
    s = (token or "").lower()
    mapping = [
        ("tomcat", "tomcat"), ("nginx", "nginx"), ("apache", "apache"), ("php", "php"),
        ("django", "django"), ("flask", "flask"), ("spring", "spring"), ("asp.net", "asp.net"),
        ("iis", "iis"), ("gunicorn", "gunicorn"), ("uwsgi", "uwsgi"), ("werkzeug", "werkzeug"),
        ("uvicorn", "uvicorn"), ("express", "express"),
    ]
    for needle, normalized in mapping:
        if needle in s:
            return normalized
    return s.strip() or "unknown"


def _build_header_disclosures(headers_lc: Dict[str, Any]) -> List[Dict[str, Any]]:
    header_map = {
        "server": "server_header",
        "x-powered-by": "x_powered_by",
        "via": "via_header",
        "x-aspnet-version": "x_aspnet_version",
        "x-aspnetmvc-version": "x_aspnetmvc_version",
    }

    out: List[Dict[str, Any]] = []
    for header_name, subtype in header_map.items():
        for value in _header_all(headers_lc, header_name):
            out.append(
                {
                    "header": header_name,
                    "value": value,
                    "subtype": subtype,
                    "product_family": _normalize_product_family(value),
                    "has_version": bool(re.search(r"\d", value)),
                }
            )
    return out


def _extract_header_version_tokens(header_disclosures: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in header_disclosures or []:
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        m = re.search(r"\b([A-Za-z][A-Za-z0-9_.\- ]{0,30})/(\d[\w.\-]*)\b", value)
        if m:
            family = _normalize_product_family(m.group(1).strip())
            token = f"{family}/{m.group(2).strip()}"
            if token not in seen:
                seen.add(token)
                out.append(token)
    return out[:10]


def _split_product_version(token: str) -> tuple[str, str | None]:
    s = str(token or "").strip().lower()
    if not s:
        return "", None
    if "/" in s:
        name, ver = s.split("/", 1)
        name = name.strip()
        ver = ver.strip()
        if name:
            return name, ver or None
    return s, None


def _normalize_technology_fingerprint(tokens: List[str]) -> List[str]:
    ordered = _dedup_preserve_order([str(t).strip().lower() for t in (tokens or []) if str(t).strip()])
    if not ordered:
        return []

    seen_versioned_by_name: Dict[str, str] = {}
    for tok in ordered:
        name, ver = _split_product_version(tok)
        if name and ver and name not in seen_versioned_by_name:
            seen_versioned_by_name[name] = tok

    out: List[str] = []
    added = set()

    for tok in ordered:
        name, ver = _split_product_version(tok)
        if not name:
            continue

        if ver:
            if tok not in added:
                out.append(tok)
                added.add(tok)
            continue

        if name in seen_versioned_by_name:
            continue

        if tok not in added:
            out.append(tok)
            added.add(tok)

    return out[:12]


def _technology_fingerprint(header_disclosures: List[Dict[str, Any]], body_tokens: List[str], framework_hints: List[str]) -> List[str]:
    techs: List[str] = []

    for item in header_disclosures:
        pf = item.get("product_family") or ""
        if pf:
            techs.append(str(pf))

    for token in _extract_header_version_tokens(header_disclosures):
        techs.append(token)
        techs.append(_normalize_product_family(token))

    for token in body_tokens:
        techs.append(token.lower())
        techs.append(_normalize_product_family(token))

    for hint in framework_hints:
        techs.append(_normalize_product_family(hint))

    cleaned = [t for t in techs if t and t != "unknown"]
    return _normalize_technology_fingerprint(cleaned)


def _detect_default_error_hint(text: str) -> str | None:
    for name, pat in DEFAULT_ERROR_PAGE_HINTS:
        if pat.search(text or ""):
            return name
    return None


def _detect_default_file_hints(url: str, body: str) -> List[str]:
    hints: List[str] = []
    for pat in DEFAULT_FILE_PATTERNS:
        if pat.search(url or ""):
            hints.append(pat.pattern)

    body_l = (body or "").lower()
    if "php version" in body_l and "phpinfo()" in body_l:
        hints.append("phpinfo_like_page")
    if "repositoryformatversion" in body_l or "[core]" in body_l:
        hints.append("git_repository_hint")
    return _dedup(hints)[:10]


def _is_https_url(url: str) -> bool:
    return urlsplit(url or "").scheme.lower() == "https"


def _parse_cookie_names_from_cookie_header(raw_cookie: str) -> List[str]:
    out: List[str] = []
    seen = set()

    raw = str(raw_cookie or "").strip()
    if not raw:
        return out

    for part in raw.split(";"):
        token = str(part or "").strip()
        if not token or "=" not in token:
            continue
        name = token.split("=", 1)[0].strip()
        if not name or name in seen:
            continue
        seen.add(name)
        out.append(name)

    return out


def _extract_request_cookie_names(snapshot: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    seen = set()

    request_blocks = [
        snapshot.get("request") or {},
        snapshot.get("actual_request") or {},
    ]

    for req in request_blocks:
        if not isinstance(req, dict):
            continue

        headers = req.get("headers") or {}
        if not isinstance(headers, dict):
            continue

        raw_cookie = ""
        for k, v in headers.items():
            if str(k).lower().strip() == "cookie":
                raw_cookie = str(v or "")
                break

        for name in _parse_cookie_names_from_cookie_header(raw_cookie):
            if name not in seen:
                seen.add(name)
                names.append(name)

    return names


def _looks_like_non_sensitive_context_cookie(name: str) -> bool:
    n = str(name or "").strip().lower()
    if not n:
        return False

    exact_names = {
        "language",
        "lang",
        "locale",
        "returnpath",
        "returnurl",
        "redirect",
        "redirecturl",
        "lastactivitytime",
        "last_access_time",
        "lastaccesstime",
        "menuid",
        "_menuid",
        "_menuf",
        "search_arguments_data",
        "search_arguments_path",
    }
    if n in exact_names:
        return True

    weak_tokens = (
        "lang",
        "locale",
        "theme",
        "timezone",
        "lastactivity",
        "returnpath",
        "returnurl",
        "search_",
        "menu",
        "viewmode",
        "notice",
        "banner",
        "popup",
    )
    return any(tok in n for tok in weak_tokens)

def _is_cookie_name_sensitive(name: str) -> bool:
    n = str(name or "").strip().lower()
    if not n:
        return False

    if _looks_like_non_sensitive_context_cookie(n):
        return False

    strong_exact_names = {
        "jsessionid",
        "phpsessid",
        "sessionid",
        "session",
        "sid",
        "connect.sid",
        "connect_sid",
        "aspsessionid",
        "asp.net_sessionid",
        "aspnet_sessionid",
    }
    if n in strong_exact_names:
        return True

    strong_tokens = (
        "sess",
        "session",
        "sid",
        "auth",
        "token",
        "jwt",
        "bearer",
        "sso",
        "ltpa",
        "rememberme",
        "remember_me",
        "login",
    )
    if any(tok in n for tok in strong_tokens):
        return True

    csrf_only_tokens = ("csrf", "xsrf", "csrftoken")
    if any(tok in n for tok in csrf_only_tokens):
        return True

    return False

def _parse_cookie_prefix(name: str) -> str:
    n = str(name or "").strip()
    if n.startswith("__Host-"):
        return "__Host-"
    if n.startswith("__Secure-"):
        return "__Secure-"
    return ""


def _cookie_has_expires_or_max_age(raw: str) -> bool:
    raw_l = str(raw or "").lower()
    return "expires=" in raw_l or "max-age=" in raw_l

def _extract_cookie_objects(snapshot: Dict[str, Any], headers_lc: Dict[str, Any]) -> Dict[str, Any]:
    structured = snapshot.get("set_cookie_objects")
    final_url = str(snapshot.get("final_url") or "")
    is_https = _is_https_url(final_url)

    request_cookie_names = _extract_request_cookie_names(snapshot)
    request_cookie_name_set = {str(x).strip().lower() for x in request_cookie_names if str(x).strip()}

    def _build_cookie_row(
        *,
        name: str,
        raw: str,
        httponly: bool,
        secure: bool,
        samesite: bool,
        persistent: bool,
    ) -> Dict[str, Any]:
        prefix = _parse_cookie_prefix(name)

        sensitive_by_name = _is_cookie_name_sensitive(name)
        request_present = str(name).strip().lower() in request_cookie_name_set
        request_sensitive_candidate = request_present and sensitive_by_name

        sensitive_reason = []
        if sensitive_by_name:
            sensitive_reason.append("name_pattern")
        if prefix in {"__Host-", "__Secure-"}:
            sensitive_reason.append("cookie_prefix")
        if request_sensitive_candidate:
            sensitive_reason.append("present_in_request_auth_cookie")

        return {
            "name": name,
            "raw": raw,
            "httponly": httponly,
            "secure": secure,
            "samesite": samesite,
            "persistent": persistent,
            "sensitive": bool(sensitive_by_name or prefix in {"__Host-", "__Secure-"}),
            "request_present": request_present,
            "request_sensitive_candidate": request_sensitive_candidate,
            "sensitive_reason": sensitive_reason,
            "prefix": prefix,
            "is_https_response": is_https,
        }

    if isinstance(structured, list) and structured:
        cookie_objects: List[Dict[str, Any]] = []
        for item in structured:
            name = str(item.get("name") or "").strip()
            if not name:
                continue

            raw = str(item.get("raw") or f"{name}=<redacted>")
            httponly = bool(item.get("httponly"))
            secure = bool(item.get("secure"))
            samesite = bool(item.get("samesite"))
            persistent = bool(item.get("persistent")) if item.get("persistent") is not None else _cookie_has_expires_or_max_age(raw)

            cookie_objects.append(
                _build_cookie_row(
                    name=name,
                    raw=raw,
                    httponly=httponly,
                    secure=secure,
                    samesite=samesite,
                    persistent=persistent,
                )
            )

        return {
            "set_cookie_observed": bool(cookie_objects),
            "cookies": cookie_objects,
            "request_cookie_names": request_cookie_names,
        }

    raw_cookies = _header_all(headers_lc, "set-cookie")
    cookie_objects: List[Dict[str, Any]] = []

    for raw in raw_cookies:
        first = raw.split(";", 1)[0].strip()
        name = first.split("=", 1)[0].strip() if "=" in first else first.strip()
        raw_l = raw.lower()

        cookie_objects.append(
            _build_cookie_row(
                name=name,
                raw=raw,
                httponly="httponly" in raw_l,
                secure="secure" in raw_l,
                samesite="samesite" in raw_l,
                persistent=_cookie_has_expires_or_max_age(raw),
            )
        )

    return {
        "set_cookie_observed": bool(raw_cookies),
        "cookies": cookie_objects,
        "request_cookie_names": request_cookie_names,
    }

def _extract_allowed_methods(headers_lc: Dict[str, Any]) -> List[str]:
    allow = _header_first(headers_lc, "allow") or ""
    methods: List[str] = []
    for item in allow.split(","):
        m = item.strip().upper()
        if m and m not in methods:
            methods.append(m)
    return methods


def _query_param_names(url: str) -> List[str]:
    try:
        return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    except Exception:
        return []

def _detect_phpinfo_indicators(body: str) -> List[str]:
    text = str(body or "")
    body_l = text.lower()

    if not body_l.strip():
        return []

    indicators: List[str] = []

    strong_tokens = [
        "phpinfo()",
        "php version",
        "loaded modules",
        "server api",
        "php variables",
        "php license",
        "zend engine",
        "configuration file (php.ini) path",
        "loaded configuration file",
        "scan this dir for additional .ini files",
        "additional .ini files parsed",
        "php core",
        "apache2handler",
    ]

    weak_tokens = [
        "include_path",
        "document_root",
        "server software",
        "remote address",
        "http user agent",
        "_server[",
        "_get[",
        "_post[",
        "_cookie[",
        "_request[",
        "_files[",
        "_env[",
        "_session[",
    ]

    for tok in strong_tokens:
        if tok in body_l:
            indicators.append(tok)

    weak_hits = [tok for tok in weak_tokens if tok in body_l]

    has_phpinfo_title = (
        "<title>phpinfo()" in body_l
        or "<title>php " in body_l
        or ("php version" in body_l and "<title>" in body_l)
    )

    has_phpinfo_table_shape = (
        "<table" in body_l
        and (
            "php core" in body_l
            or "apache2handler" in body_l
            or "module authors" in body_l
            or "environment" in body_l
        )
    )

    if has_phpinfo_title:
        indicators.append("phpinfo_title")
    if has_phpinfo_table_shape:
        indicators.append("phpinfo_table_shape")

    # weak token은 strong context가 있을 때만 의미 부여
    if indicators:
        indicators.extend(weak_hits[:6])

    return _dedup(indicators)[:12]


def _detect_config_exposure_markers(body: str) -> List[str]:
    body_l = (body or "").lower()
    return [x for x in CONFIG_EXPOSURE_MARKERS if x in body_l][:10]

def _filter_meaningful_internal_ips(ips: List[str]) -> List[str]:
    out: List[str] = []
    for ip in ips or []:
        s = str(ip or "").strip()
        if not s:
            continue

        # loopback은 너무 약해서 시스템 정보 노출로 보지 않음
        if s.startswith("127."):
            continue

        # 0.0.0.0 도 제외
        if s == "0.0.0.0":
            continue

        out.append(s)

    return _dedup(out)

def _detect_log_exposure_patterns(body: str) -> List[str]:
    text = str(body or "")
    if not text.strip():
        return []

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return []

    timestamp_like_re = re.compile(r"\b(?:20\d{2}[-/]\d{2}[-/]\d{2}[ t]\d{2}:\d{2}:\d{2}|\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})\b", re.I)
    level_like_re = re.compile(r"\b(?:TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b", re.I)
    logger_name_re = re.compile(r"\b(?:org\.|com\.|net\.|io\.)[A-Za-z0-9_.\$]{6,}\b")
    access_log_re = re.compile(
        r'\b\d{1,3}(?:\.\d{1,3}){3}\b.{0,40}"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+[^"]+\s+HTTP/[0-9.]+"\s+\d{3}\b',
        re.I,
    )

    matched_patterns: List[str] = []
    for pat in LOG_EXPOSURE_PATTERNS:
        if pat.search(text):
            matched_patterns.append(pat.pattern)

    timestamp_lines = 0
    level_lines = 0
    access_lines = 0
    logger_lines = 0

    for line in lines[:200]:
        if timestamp_like_re.search(line):
            timestamp_lines += 1
        if level_like_re.search(line):
            level_lines += 1
        if access_log_re.search(line):
            access_lines += 1
        if logger_name_re.search(line):
            logger_lines += 1

    repeated_log_lines = sum(
        1
        for line in lines[:200]
        if sum(
            bool(rx.search(line))
            for rx in (timestamp_like_re, level_like_re, access_log_re, logger_name_re)
        ) >= 2
    )

    strong_log_context = (
        access_lines >= 1
        or repeated_log_lines >= 2
        or (timestamp_lines >= 2 and level_lines >= 1)
        or (level_lines >= 2 and logger_lines >= 1)
    )

    if not strong_log_context:
        return []

    return _dedup_preserve_order(matched_patterns)[:10]

def _body_content_type_hint(headers_lc: Dict[str, Any], body: str) -> str:
    ct = (_header_first(headers_lc, "content-type") or "").lower()
    if "json" in ct:
        return "json"
    if "xml" in ct:
        return "xml"
    if "yaml" in ct or "yml" in ct:
        return "yaml"

    body_l = (body or "").lower().strip()
    if body_l.startswith("{") or body_l.startswith("["):
        return "json_like"
    if body_l.startswith("<?xml") or body_l.startswith("<xml"):
        return "xml_like"
    if "services:" in body_l and "image:" in body_l:
        return "yaml_like"
    if "=" in body_l and "\n" in body_l and any(k in body_l for k in ("password", "db_", "host=", "user=")):
        return "properties_like"
    return "unknown"


def _normalize_path_only(url: str) -> str:
    path = urlsplit(url or "").path or "/"
    return posixpath.normpath(path)


def _looks_like_url_derived_path(path: str) -> bool:
    s = str(path or "").strip()
    if not s.startswith("/"):
        return False

    stripped = s.strip("/")
    if not stripped:
        return False

    first = stripped.split("/", 1)[0].lower()
    if "." in first:
        if any(first.endswith(sfx) for sfx in URLISH_FIRST_SEGMENT_SUFFIXES):
            return True
        if first.startswith(("www.", "raw.", "api.", "docs.", "cdn.", "gist.")):
            return True
    return False


def _looks_like_local_unix_path(path: str) -> bool:
    s = str(path or "").strip()
    if not s.startswith("/"):
        return False
    stripped = s.strip("/")
    if not stripped:
        return False
    first = stripped.split("/", 1)[0].lower()
    return first in LOCAL_UNIX_ROOT_HINTS


def _looks_like_local_windows_path(path: str) -> bool:
    return bool(re.match(r"^[A-Za-z]:\\", str(path or "").strip()))


def _looks_like_local_filesystem_path(path: str) -> bool:
    s = str(path or "").strip()
    if not s:
        return False
    return _looks_like_local_windows_path(s) or _looks_like_local_unix_path(s)


def _is_same_or_child_request_path(candidate_path: str, request_url: str, final_url: str) -> bool:
    cand = (candidate_path or "").strip()
    if not cand.startswith("/"):
        return False
    req_path = _normalize_path_only(request_url)
    fin_path = _normalize_path_only(final_url)
    cand_norm = posixpath.normpath(cand)
    return (
        cand_norm == req_path
        or cand_norm == fin_path
        or cand_norm.startswith(req_path.rstrip("/") + "/")
        or cand_norm.startswith(fin_path.rstrip("/") + "/")
    )


def _clean_file_paths(file_paths: List[str], request_url: str, final_url: str) -> List[str]:
    out: List[str] = []

    for p in file_paths or []:
        s = str(p or "").strip()
        if not s:
            continue

        s_l = s.lower()
        if (
            s_l.startswith("http://")
            or s_l.startswith("https://")
            or s_l.startswith("//")
            or "w3.org" in s_l
            or ".dtd" in s_l
            or "xhtml" in s_l
        ):
            continue

        if re.fullmatch(r"[A-Za-z]:\\?", s):
            continue
        if s in {"/"}:
            continue
        if _looks_like_url_derived_path(s):
            continue
        if not _looks_like_local_filesystem_path(s):
            continue
        if _is_same_or_child_request_path(s, request_url, final_url):
            continue

        out.append(s)

    return _dedup(out)


def _csp_has_frame_ancestors(headers_lc: Dict[str, Any]) -> bool:
    return any("frame-ancestors" in x.lower() for x in _header_all(headers_lc, "content-security-policy"))


def _is_sensitive_cacheable(*, response_kind: str, status_code: Any, headers_lc: Dict[str, Any]) -> bool:
    if not isinstance(status_code, int) or status_code >= 400:
        return False
    if response_kind not in {"html", "json", "text"}:
        return False

    joined = " | ".join(
        [x.lower() for x in _header_all(headers_lc, "cache-control")] +
        [x.lower() for x in _header_all(headers_lc, "pragma")]
    )
    if not joined:
        return True
    if "no-store" in joined or "private" in joined:
        return False
    if any(x in joined for x in ("public", "max-age", "s-maxage", "immutable")):
        return True
    return False


def _detect_error_exposure_class(
    status_code: Any,
    stack_traces: List[str],
    file_paths: List[str],
    db_errors: List[str],
    debug_hints: List[str],
) -> str | None:
    if not isinstance(status_code, int):
        return None

    local_paths = [p for p in (file_paths or []) if _looks_like_local_filesystem_path(p)]

    # 가장 강한 시그널
    if stack_traces:
        return "stack_trace"

    # 파일 경로 노출은 기본적으로 error context(4xx/5xx)에서만 인정
    if status_code >= 400 and local_paths:
        return "file_path"

    # DB 오류는 너무 쉽게 과탐되므로 더 보수적으로
    if db_errors:
        # 4xx/5xx에서 보이면 인정
        if status_code >= 400:
            return "db_error"

        # 2xx라도 stack/file/debug context가 같이 있을 때만 인정
        if local_paths:
            return "db_error"

        if len(db_errors) >= 2 and len(debug_hints or []) >= 1:
            return "db_error"

    # 디버그 에러 페이지도 error context에서만
    if status_code >= 400 and len(debug_hints or []) >= 2:
        return "debug_error_page"

    return None

def _make_error_template_fingerprint(default_error_hint: str | None, error_exposure_class: str | None, technology_fingerprint: List[str], status_family: str) -> str | None:
    if not error_exposure_class:
        return None
    tech = technology_fingerprint[0] if technology_fingerprint else "unknown"
    return f"{default_error_hint or 'no_default_hint'}|{error_exposure_class}|{tech}|{status_family}"


def extract_features(request_meta: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
    headers_lc = _headers_lc(snapshot.get("headers") or {})

    body = str(
        snapshot.get("body_text")
        or snapshot.get("body_snippet")
        or snapshot.get("body")
        or ""
    )

    status_code = snapshot.get("status_code")
    status_family = _status_family(status_code)

    requested_url = str(request_meta.get("url") or "")
    final_url = str(snapshot.get("final_url") or requested_url or "")
    response_kind = _classify_response_kind(request_meta, headers_lc)

    try:
        fp_input = type("RespLike", (), {
            "headers": snapshot.get("headers") or {},
            "text": body,
            "url": final_url,
            "status_code": status_code,
        })()
        fp = fingerprint_response(fp_input)
    except Exception as e:
        log("FP", f"fingerprint_response exception: {type(e).__name__}: {e}")
        fp = {"tech": [], "clues": []}

    fingerprint_tech = _dedup_preserve_order(fp.get("tech") or [])
    fingerprint_clues = _dedup_preserve_order(fp.get("clues") or [])

    header_disclosures = _build_header_disclosures(headers_lc)
    header_version_tokens = _extract_header_version_tokens(header_disclosures)

    strong_versions_raw = _find_matches(STRONG_VERSION_PATTERNS, body, 10)
    generic_product_tokens = _find_matches(GENERIC_PRODUCT_PATTERNS, body, 10)
    technology_tokens = _find_matches(SERVER_VERSION_PATTERNS, body, 10)

    stack_traces = _find_matches(STACK_TRACE_PATTERNS, body, 10)
    raw_file_paths = _find_matches(FILE_PATH_PATTERNS, body, 20)
    file_paths = _clean_file_paths(raw_file_paths, requested_url, final_url)
    local_file_paths = [p for p in file_paths if _looks_like_local_filesystem_path(p)]
    internal_ips = _filter_meaningful_internal_ips(_find_matches(INTERNAL_IP_PATTERNS, body, 10))
    db_errors = _find_matches(DB_ERROR_PATTERNS, body, 10)
    framework_hints = _find_matches(FRAMEWORK_HINT_PATTERNS, body, 10)
    debug_hints = _find_matches(DEBUG_HINT_PATTERNS, body, 10)
    directory_listing_hints = _find_matches(DIRECTORY_LISTING_PATTERNS, body, 10)
    default_file_hints = _detect_default_file_hints(final_url, body)
    default_error_hint = _detect_default_error_hint(body)

    strong_version_tokens_in_body = strong_versions_raw[:]
    version_tokens_in_body = _dedup(strong_version_tokens_in_body + generic_product_tokens)[:10]
    all_version_tokens = _dedup_preserve_order(header_version_tokens + version_tokens_in_body)[:12]

    technology_fingerprint = _technology_fingerprint(
        header_disclosures=header_disclosures,
        body_tokens=technology_tokens + version_tokens_in_body + fingerprint_tech,
        framework_hints=framework_hints + fingerprint_tech,
    )

    error_exposure_class = _detect_error_exposure_class(
        status_code=status_code,
        stack_traces=stack_traces,
        file_paths=local_file_paths,
        db_errors=db_errors,
        debug_hints=debug_hints,
    )

    error_template_fingerprint = _make_error_template_fingerprint(
        default_error_hint=default_error_hint,
        error_exposure_class=error_exposure_class,
        technology_fingerprint=technology_fingerprint,
        status_family=status_family,
    )

    phpinfo_indicators = _detect_phpinfo_indicators(body)
    config_exposure_markers = _detect_config_exposure_markers(body)
    log_exposure_patterns = _detect_log_exposure_patterns(body)
    config_extracted_values = _extract_config_values(body)

    query_param_names = _query_param_names(requested_url)
    file_path_parameter_names = [x for x in query_param_names if x.lower() in FILEISH_PARAM_NAMES]
    redirect_parameter_names = [x for x in query_param_names if x.lower() in REDIRECT_PARAM_NAMES]

    csp_present = bool(_header_first(headers_lc, "content-security-policy"))
    x_frame_options_present = bool(_header_first(headers_lc, "x-frame-options"))
    x_content_type_options_present = bool(_header_first(headers_lc, "x-content-type-options"))
    referrer_policy_present = bool(_header_first(headers_lc, "referrer-policy"))
    permissions_policy_present = bool(_header_first(headers_lc, "permissions-policy"))
    csp_frame_ancestors_present = _csp_has_frame_ancestors(headers_lc)
    clickjacking_protection_present = x_frame_options_present or csp_frame_ancestors_present

    present_security_headers = [h for h in SENSITIVE_SECURITY_HEADERS if _header_first(headers_lc, h)]
    missing_security_headers = [h for h in SENSITIVE_SECURITY_HEADERS if not _header_first(headers_lc, h)]

    cache_control_values = _header_all(headers_lc, "cache-control")
    pragma_values = _header_all(headers_lc, "pragma")
    sensitive_cacheable = _is_sensitive_cacheable(
        response_kind=response_kind,
        status_code=status_code,
        headers_lc=headers_lc,
    )

    cookie_info = _extract_cookie_objects(snapshot, headers_lc)

    request_cookie_names = cookie_info.get("request_cookie_names") or []
    request_sensitive_cookie_names = [
        name
        for name in request_cookie_names
        if _is_cookie_name_sensitive(name)
    ]

    response_cookie_names = [
        str(c.get("name") or "").strip()
        for c in (cookie_info.get("cookies") or [])
        if str(c.get("name") or "").strip()
    ]
    response_cookie_name_set = {x.lower() for x in response_cookie_names}
    request_sensitive_cookie_names_missing_in_response = [
        name
        for name in request_sensitive_cookie_names
        if str(name).strip().lower() not in response_cookie_name_set
    ]

    origin = request_meta.get("origin")
    cors = {
        "request_origin": origin,
        "acao": _header_first(headers_lc, "access-control-allow-origin"),
        "acac": _header_first(headers_lc, "access-control-allow-credentials"),
        "acam": _header_first(headers_lc, "access-control-allow-methods"),
        "acah": _header_first(headers_lc, "access-control-allow-headers"),
        "vary": _header_first(headers_lc, "vary"),
    }

    allowed_methods = _extract_allowed_methods(headers_lc)
    risky_methods_enabled = [m for m in allowed_methods if m in RISKY_HTTP_METHODS]

    trace_marker = request_meta.get("trace_marker")
    trace_reflected = bool(trace_marker and trace_marker in body)

    req_parts = urlsplit(requested_url)
    fin_parts = urlsplit(final_url)

    hsts_missing = req_parts.scheme.lower() == "https" and not _header_first(headers_lc, "strict-transport-security")
    https_redirect_missing = req_parts.scheme.lower() == "http" and fin_parts.scheme.lower() == "http"

    body_l = body.lower()

    document_like = any(
        tok in body_l
        for tok in (
            "installation",
            "instructions",
            "readme",
            "license",
            "copying",
            "download",
            "docker",
            "virtualbox",
            "vmware",
            "github",
        )
    )

    spa_shell_markers = [
        "<!doctype html",
        "<html",
        "<head",
        "<body",
        "<app-root",
        "<base href=",
        "<meta name=\"viewport\"",
        "<script",
        "<title>",
    ]
    spa_shell_hit_count = sum(1 for marker in spa_shell_markers if marker in body_l)
    looks_like_spa_shell = spa_shell_hit_count >= 5

    login_like = any(
        tok in body_l
        for tok in (
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
    ) or any(tok in final_url.lower() for tok in ("/login", "/signin", "/auth", "/sso"))

    generic_notfound_like = False
    generic_markers = [
        "page not found",
        "not found",
        "페이지를 찾을 수가 없습니다",
        "the requested url was not found",
        "requested resource",
        "this system is strictly restricted to authorized users only",
    ]
    generic_hit_count = sum(1 for marker in generic_markers if marker in body_l)
    if status_code in {404, 200} and generic_hit_count >= 2:
        generic_notfound_like = True
    if "<title>page not found" in body_l:
        generic_notfound_like = True

    public_download_like = (
        response_kind == "other"
        and (
            ".pdf" in final_url.lower()
            or ".doc" in final_url.lower()
            or ".docx" in final_url.lower()
            or ".xls" in final_url.lower()
            or ".xlsx" in final_url.lower()
            or ".zip" in final_url.lower()
        )
    )

    low_signal_body = len(body.strip()) < 80

    response_noise_flags = {
        "is_static_asset": response_kind == "static_asset",
        "is_probable_documentation": document_like,
        "is_probable_spa_shell": looks_like_spa_shell,
        "is_login_like": login_like,
        "is_generic_notfound_template": generic_notfound_like,
        "is_public_download_like": public_download_like,
        "is_low_signal_body": low_signal_body,
    }

    info_signal_summary = {
        "has_header_disclosure": bool(header_disclosures),
        "has_error_disclosure": bool(error_exposure_class or stack_traces or db_errors or local_file_paths),
        "has_body_system_disclosure": bool(
            strong_version_tokens_in_body
            or internal_ips
            or framework_hints
            or debug_hints
        ),
        "has_config_exposure": bool(config_extracted_values or config_exposure_markers),
        "has_log_exposure": bool(log_exposure_patterns),
        "has_default_resource_exposure": bool(default_file_hints or phpinfo_indicators),
        "has_directory_listing": bool(directory_listing_hints),
        "has_file_path_anomaly": bool(file_path_parameter_names and (local_file_paths or stack_traces)),
        "has_request_sensitive_cookies": bool(request_sensitive_cookie_names),
        "has_response_cookie_for_request_sensitive_cookie": bool(
            set(str(x).lower() for x in request_sensitive_cookie_names)
            & set(str(x).lower() for x in response_cookie_names)
        ),
    }

    reasons: List[str] = []

    if isinstance(status_code, int) and status_code >= 400:
        reasons.append("status>=400")
    if version_tokens_in_body:
        reasons.append("version_token_in_body")
    if header_version_tokens:
        reasons.append("header_version_token")
    if stack_traces:
        reasons.append("stack_trace")
    if local_file_paths:
        reasons.append("file_path")
    if internal_ips:
        reasons.append("internal_ip")
    if db_errors:
        reasons.append("database_error")
    if framework_hints:
        reasons.append("framework_hint")
    if debug_hints:
        reasons.append("debug_hint")
    if default_error_hint:
        reasons.append(default_error_hint)
    if directory_listing_hints:
        reasons.append("directory_listing")
    if default_file_hints:
        reasons.append("default_file_hint")
    if header_disclosures:
        reasons.append("header_disclosure")
    if phpinfo_indicators:
        reasons.append("phpinfo_indicator")
    if config_exposure_markers:
        reasons.append("config_exposure_marker")
    if log_exposure_patterns:
        reasons.append("log_exposure_pattern")
    if file_path_parameter_names:
        reasons.append("file_path_parameter")
    if redirect_parameter_names:
        reasons.append("redirect_parameter")
    if not clickjacking_protection_present:
        reasons.append("clickjacking_protection_missing")
    if not csp_present:
        reasons.append("csp_missing")
    if not x_content_type_options_present:
        reasons.append("x_content_type_options_missing")
    if not referrer_policy_present:
        reasons.append("referrer_policy_missing")
    if not permissions_policy_present:
        reasons.append("permissions_policy_missing")
    if sensitive_cacheable:
        reasons.append("sensitive_cacheable")
    if risky_methods_enabled:
        reasons.append("risky_methods_enabled")
    if trace_reflected:
        reasons.append("trace_reflected")
    if hsts_missing:
        reasons.append("hsts_missing")
    if https_redirect_missing:
        reasons.append("https_redirect_missing")
    if cookie_info["set_cookie_observed"]:
        reasons.append("set_cookie_observed")
    if request_sensitive_cookie_names:
        reasons.append("request_sensitive_cookie_present")
    if request_sensitive_cookie_names_missing_in_response:
        reasons.append("request_sensitive_cookie_missing_in_response")
    if fingerprint_tech:
        reasons.append("fingerprint_tech")
    if fingerprint_clues:
        reasons.append("fingerprint_clues")
    if document_like:
        reasons.append("document_like")
    if looks_like_spa_shell:
        reasons.append("spa_shell_like")
    if login_like:
        reasons.append("login_like")
    if generic_notfound_like:
        reasons.append("generic_notfound_like")

    request_cookie_names = cookie_info.get("request_cookie_names") or []
    response_cookie_names = [
        str(c.get("name") or "").strip()
        for c in (cookie_info.get("cookies") or [])
        if str(c.get("name") or "").strip()
    ]

    request_sensitive_cookie_names = [
        str(name).strip()
        for name in request_cookie_names
        if _is_cookie_name_sensitive(name)
    ]

    request_sensitive_cookie_names_missing_in_response = [
        name
        for name in request_sensitive_cookie_names
        if name not in response_cookie_names
    ]

    return {
        "status_code": status_code,
        "status_family": status_family,
        "response_kind": response_kind,
        "final_url": final_url,
        "body_text": body,

        "header_disclosures": header_disclosures,
        "version_tokens_in_body": version_tokens_in_body,
        "strong_version_tokens_in_body": strong_version_tokens_in_body,
        "generic_product_tokens_in_body": generic_product_tokens,
        "technology_tokens_in_body": technology_tokens,
        "technology_fingerprint": technology_fingerprint,
        "fingerprint_tech": fingerprint_tech,
        "fingerprint_clues": fingerprint_clues,

        "stack_traces": stack_traces,
        "file_paths": local_file_paths,
        "file_paths_all_candidates": file_paths,
        "internal_ips": internal_ips,
        "db_errors": db_errors,
        "framework_hints": framework_hints,
        "debug_hints": debug_hints,
        "default_error_hint": default_error_hint,
        "error_exposure_class": error_exposure_class,
        "error_template_fingerprint": error_template_fingerprint,

        "directory_listing_hints": directory_listing_hints,
        "default_file_hints": default_file_hints,
        "phpinfo_indicators": phpinfo_indicators,
        "config_exposure_markers": config_exposure_markers,
        "log_exposure_patterns": log_exposure_patterns,
        "config_extracted_values": config_extracted_values,

        "allowed_methods": allowed_methods,
        "risky_methods_enabled": risky_methods_enabled,
        "trace_reflected": trace_reflected,

        "security_headers_present": present_security_headers,
        "security_headers_missing": missing_security_headers,
        "header_version_tokens": header_version_tokens,
        "all_version_tokens": all_version_tokens,

        "set_cookie_observed": cookie_info["set_cookie_observed"],
        "cookie_objects": cookie_info["cookies"],
        "request_cookie_names": request_cookie_names,
        "request_sensitive_cookie_names": request_sensitive_cookie_names,
        "response_cookie_names": response_cookie_names,
        "request_sensitive_cookie_names_missing_in_response": request_sensitive_cookie_names_missing_in_response,
        "cors": cors,

        "https_redirect_missing": https_redirect_missing,
        "hsts_missing": hsts_missing,
        "csp_present": csp_present,
        "csp_frame_ancestors_present": csp_frame_ancestors_present,
        "x_frame_options_present": x_frame_options_present,
        "x_content_type_options_present": x_content_type_options_present,
        "referrer_policy_present": referrer_policy_present,
        "permissions_policy_present": permissions_policy_present,
        "clickjacking_protection_present": clickjacking_protection_present,

        "cache_control_values": cache_control_values,
        "pragma_values": pragma_values,
        "sensitive_cacheable": sensitive_cacheable,

        "query_param_names": query_param_names,
        "file_path_parameter_names": file_path_parameter_names,
        "redirect_parameter_names": redirect_parameter_names,
        "body_content_type_hint": _body_content_type_hint(headers_lc, body),

        "trigger_context": {
            "probe_family": request_meta.get("family"),
            "mutation_class": request_meta.get("mutation_class"),
            "expected_signal": request_meta.get("expected_signal"),
        },

        "response_noise_flags": response_noise_flags,
        "info_signal_summary": info_signal_summary,
        "reasons": _dedup(reasons),
    }
