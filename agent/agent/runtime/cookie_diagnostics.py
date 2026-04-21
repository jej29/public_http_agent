from __future__ import annotations

from typing import Any, Dict, List


SENSITIVE_COOKIE_NAME_HINTS = (
    "session",
    "sess",
    "sid",
    "jsessionid",
    "phpsessid",
    "token",
    "auth",
)


def _cookie_name_is_sensitive(name: str) -> bool:
    name_l = str(name or "").strip().lower()
    return any(hint in name_l for hint in SENSITIVE_COOKIE_NAME_HINTS)


def cookie_names_from_header(value: Any) -> List[str]:
    """Return only cookie names from a Cookie header; never retain values."""
    raw = str(value or "").strip()
    if not raw:
        return []

    names: List[str] = []
    seen = set()
    for part in raw.split(";"):
        if "=" not in part:
            continue
        name = part.split("=", 1)[0].strip()
        if not name or name in seen:
            continue
        seen.add(name)
        names.append(name)
    return names


def safe_set_cookie_flag_summary(snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Summarize Set-Cookie attributes without raw headers or cookie values."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for item in snapshot.get("set_cookie_objects") or []:
        if isinstance(item, dict):
            name = str(item.get("name") or "").strip()
            secure = bool(item.get("secure"))
            httponly = bool(item.get("httponly"))
            samesite = str(item.get("samesite") or "").strip() or None
            persistent = bool(item.get("persistent"))
            prefix = str(item.get("prefix") or "").strip() or None
            sensitive = bool(item.get("sensitive")) or _cookie_name_is_sensitive(name)
        else:
            raw = str(item or "").strip()
            if not raw or "=" not in raw:
                continue
            first, *attrs = raw.split(";")
            name = first.split("=", 1)[0].strip()
            attr_l = [attr.strip().lower() for attr in attrs]
            secure = "secure" in attr_l
            httponly = "httponly" in attr_l
            samesite = None
            for attr in attrs:
                if attr.strip().lower().startswith("samesite="):
                    samesite = attr.split("=", 1)[1].strip() or None
                    break
            persistent = any(attr.startswith("expires=") or attr.startswith("max-age=") for attr in attr_l)
            prefix = "__host-" if name.lower().startswith("__host-") else "__secure-" if name.lower().startswith("__secure-") else None
            sensitive = _cookie_name_is_sensitive(name)

        if not name or name in seen:
            continue
        seen.add(name)
        out.append(
            {
                "name": name,
                "sensitive": sensitive,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
                "persistent": persistent,
                "prefix": prefix,
            }
        )
    return out


def raw_index_cookie_observation_fields(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    actual_request = snapshot.get("actual_request") or {}
    request_headers = actual_request.get("headers") if isinstance(actual_request, dict) else {}
    if not isinstance(request_headers, dict):
        request_headers = {}

    cookie_header = ""
    for key, value in request_headers.items():
        if str(key).strip().lower() == "cookie":
            cookie_header = str(value or "")
            break

    set_cookie_summary = safe_set_cookie_flag_summary(snapshot)
    set_cookie_names = [item["name"] for item in set_cookie_summary]
    sensitive_set_cookie_names = [item["name"] for item in set_cookie_summary if item.get("sensitive")]

    return {
        "request_cookie_names": cookie_names_from_header(cookie_header),
        "set_cookie_present": bool(snapshot.get("set_cookie_present")) or bool(set_cookie_summary),
        "set_cookie_names": set_cookie_names,
        "sensitive_set_cookie_names": sensitive_set_cookie_names,
        "set_cookie_flag_summary": set_cookie_summary,
    }
