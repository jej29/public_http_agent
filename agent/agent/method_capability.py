from __future__ import annotations

import posixpath
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit


RISKY_METHODS = {"PUT", "DELETE", "MOVE", "COPY", "PROPFIND", "PROPPATCH", "MKCOL", "PATCH"}
PUT_SUCCESS_CODES = {200, 201, 204}
DELETE_SUCCESS_CODES = {200, 202, 204}
VERIFY_ABSENT_CODES = {404, 410}

DEFAULT_UPLOAD_DIR_HINTS = (
    "/uploads/",
    "/upload/",
    "/uploaded/",
    "/files/",
    "/file/",
    "/attachments/",
    "/attachment/",
    "/images/",
    "/img/",
    "/static/",
    "/assets/",
    "/public/",
    "/content/",
    "/media/",
    "/tmp/",
    "/temp/",
    "/dav/",
    "/webdav/",
    "/ftp/",
    "/download/",
    "/downloads/",
    "/export/",
    "/imports/",
)

UPLOADISH_TOKENS = (
    "upload",
    "uploads",
    "uploaded",
    "file",
    "files",
    "attachment",
    "attachments",
    "image",
    "images",
    "img",
    "asset",
    "assets",
    "content",
    "media",
    "dav",
    "webdav",
)

CANARY_CONTENT_TYPE = "text/plain; charset=utf-8"
CANARY_PREFIX = ".dast_canary"
MAX_CANDIDATE_DIRS = 24
MAX_CANDIDATE_URLS = 40

OWASP_ONLY_NO_CWE_MAPPING = "OWASP_ONLY_NO_CWE_MAPPING"
OWASP_ONLY_NO_CWE_REASON = (
    "OWASP category is applicable, but no precise single CWE mapping is used for this finding."
)


@dataclass
class HTTPResult:
    method: str
    url: str
    status_code: int
    headers: Dict[str, str]
    text: str
    content: bytes
    final_url: str


@dataclass
class CapabilityEvidence:
    candidate_url: str
    allow_header: str = ""
    dav_header: str = ""
    put_status: Optional[int] = None
    get_status: Optional[int] = None
    delete_status: Optional[int] = None
    verify_delete_status: Optional[int] = None
    marker: str = ""
    uploaded_bytes: int = 0
    retrieved_marker_present: bool = False
    delete_verified_absent: bool = False
    notes: List[str] | None = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if data["notes"] is None:
            data["notes"] = []
        return data


def _candidate_observed_urls_from_candidate(candidate: Dict[str, Any]) -> List[str]:
    evidence = candidate.get("evidence") or {}
    trigger = candidate.get("trigger") or {}

    urls: List[str] = []

    for value in (
        trigger.get("url"),
        evidence.get("final_url"),
        candidate.get("where"),
    ):
        s = str(value or "").strip()
        if s.startswith("http://") or s.startswith("https://"):
            urls.append(s)

    for item in evidence.get("final_urls") or []:
        s = str(item or "").strip()
        if s.startswith("http://") or s.startswith("https://"):
            urls.append(s)

    return _dedupe_keep_order(urls)


def _lower_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        out[str(k).lower()] = str(v)
    return out


def _header(headers: Dict[str, Any], name: str) -> str:
    return _lower_headers(headers).get(name.lower(), "")


def _dedupe_keep_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if not item:
            continue
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _normalize_dir_path(path: str) -> str:
    if not path:
        return "/"

    if not path.startswith("/"):
        path = "/" + path

    if path.endswith("/"):
        return path

    # file-like path면 부모 디렉터리로
    if _path_is_file_like(path):
        head = path.rsplit("/", 1)[0] if "/" in path else ""
        if not head:
            return "/"
        if not head.startswith("/"):
            head = "/" + head
        return head.rstrip("/") + "/"

    # route-like path면 그 자체를 디렉터리 후보로 유지
    return path.rstrip("/") + "/"


def _join_url(base_url: str, path: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _origin_root(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/"


def _path_is_file_like(path: str) -> bool:
    leaf = (path.rsplit("/", 1)[-1] or "").strip().lower()
    if not leaf or "." not in leaf:
        return False
    if leaf.startswith(".") and leaf.count(".") == 1:
        return False
    return True


def _strip_query_and_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def _directory_ancestors(path: str) -> List[str]:
    path = _normalize_dir_path(path)
    out: List[str] = [path]

    current = path.rstrip("/")
    while current:
        if not current.startswith("/"):
            current = "/" + current
        parent = current.rsplit("/", 1)[0]
        if not parent:
            parent = "/"
        else:
            parent = parent.rstrip("/") + "/"
        if parent not in out:
            out.append(parent)
        if parent == "/":
            break
        current = parent.rstrip("/")

    if "/" not in out:
        out.append("/")
    return out


def _looks_uploadish_path(path: str) -> bool:
    p = (path or "").lower()
    return any(tok in p for tok in UPLOADISH_TOKENS)

def _extract_candidate_dirs(base_url: str, observed_urls: Sequence[str]) -> List[str]:
    dirs: List[str] = list(DEFAULT_UPLOAD_DIR_HINTS)

    parts = urlsplit(base_url)
    base_path = parts.path or "/"
    dirs.extend(_directory_ancestors(base_path))

    for raw in observed_urls or []:
        try:
            p = urlsplit(raw)
        except Exception:
            continue

        path = p.path or "/"
        if not path.startswith("/"):
            path = "/" + path

        dirs.extend(_directory_ancestors(path))

        if _looks_uploadish_path(path):
            dirs.append(_normalize_dir_path(path))

        leaf = (path.rsplit("/", 1)[-1] or "").strip().lower()
        if leaf in {
            "upload",
            "uploads",
            "uploaded",
            "file",
            "files",
            "attachment",
            "attachments",
            "image",
            "images",
            "img",
            "asset",
            "assets",
            "media",
            "content",
            "dav",
            "webdav",
            "ftp",
            "api",
            "rest",
        }:
            dirs.append(_normalize_dir_path(path + "/"))

    # 루트도 항상 포함
    dirs.append("/")

    # 정규화 + dedupe
    normalized: List[str] = []
    seen: Set[str] = set()
    for d in dirs:
        nd = _normalize_dir_path(d)
        if nd not in seen:
            seen.add(nd)
            normalized.append(nd)

    # 업로드 가능성 높은 경로 우선 정렬
    def _score_dir(d: str) -> tuple[int, int, str]:
        dl = d.lower()
        score = 0
        if any(tok in dl for tok in ("upload", "uploads", "uploaded")):
            score += 10
        if any(tok in dl for tok in ("file", "files", "attachment", "attachments")):
            score += 8
        if any(tok in dl for tok in ("image", "images", "img", "asset", "assets", "media", "content")):
            score += 6
        if any(tok in dl for tok in ("dav", "webdav")):
            score += 7
        if dl in {"/", ""}:
            score -= 3
        depth = len([x for x in dl.split("/") if x])
        return (-score, depth, dl)

    normalized.sort(key=_score_dir)
    return normalized[:MAX_CANDIDATE_DIRS]
def _make_canary_filename(marker: str, ext: str = ".txt") -> str:
    return f"{marker}{ext}"


def _make_canary_url(base_url: str, dir_path: str, ext: str = ".txt") -> Tuple[str, str]:
    marker = f"{CANARY_PREFIX}_{uuid.uuid4().hex}"
    filename = _make_canary_filename(marker, ext=ext)
    target_path = posixpath.join(dir_path, filename)
    return _join_url(base_url, target_path), marker

def _candidate_target_urls(base_url: str, observed_urls: Sequence[str]) -> List[Tuple[str, str]]:
    """
    Candidate canary URLs for PUT testing.

    Strategy:
    - derive candidate directories from observed URLs and generic upload-ish hints
    - generate canary files under those directories
    - try small extension set that is broadly retrievable but low-risk
    """
    dirs = _extract_candidate_dirs(base_url, observed_urls)

    extensions = (".txt", ".html")
    out: List[Tuple[str, str]] = []

    for dir_path in dirs:
        for ext in extensions:
            out.append(_make_canary_url(base_url, dir_path, ext=ext))

    deduped: List[Tuple[str, str]] = []
    seen_urls: Set[str] = set()

    for candidate_url, marker in out:
        clean = _strip_query_and_fragment(candidate_url)
        if clean in seen_urls:
            continue
        seen_urls.add(clean)
        deduped.append((candidate_url, marker))

    return deduped[:MAX_CANDIDATE_URLS]

def _string_list(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for v in values or []:
        s = str(v or "").strip()
        if s:
            out.append(s)
    return out


def _observed_methods_from_candidate(candidate: Dict[str, Any]) -> List[str]:
    evidence = candidate.get("evidence") or {}
    methods = evidence.get("risky_methods_enabled") or evidence.get("allowed_methods") or []
    return sorted(
        {
            str(m).upper().strip()
            for m in methods
            if str(m).strip() and str(m).upper().strip() != "TRACE"
        }
    )


def _root_target_url(candidate: Dict[str, Any]) -> str:
    evidence = candidate.get("evidence") or {}
    trigger = candidate.get("trigger") or {}

    url = str(
        trigger.get("url")
        or evidence.get("final_url")
        or candidate.get("where")
        or ""
    ).strip()

    if not url:
        return ""

    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return url
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"


def _root_scope_url(candidate: Dict[str, Any]) -> str:
    target_url = _root_target_url(candidate)
    return _origin_root(target_url) if target_url else ""


def _base_root_evidence(candidate: Dict[str, Any]) -> Dict[str, Any]:
    evidence = dict(candidate.get("evidence") or {})
    root_target = _root_target_url(candidate)
    cleaned: Dict[str, Any] = {}

    for field in (
        "allow_header",
        "public_header",
        "dav_header",
        "advertised_risky_methods",
        "options_status",
        "allowed_methods",
        "risky_methods_enabled",
        "confirmed_method_capabilities",
        "method_capability_signals",
    ):
        if evidence.get(field) not in (None, "", [], {}):
            cleaned[field] = evidence.get(field)

    if root_target:
        cleaned["final_url"] = root_target

    return cleaned


def _build_finding(
    finding_type: str,
    severity: str,
    title: str,
    url: str,
    evidence: Dict[str, Any],
    *,
    confidence: float = 0.9,
    description: str = "",
    remediation: str = "",
    family: str = "HTTP_METHOD_SECURITY",
    subtype: str = "",
    owasp: str = "A05:2021 Security Misconfiguration",
    scope_hint: str = "host-wide",
    policy_object: str = "Allow",
) -> Dict[str, Any]:
    finding = {
        "type": finding_type,
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": [remediation] if remediation else [],
        "where": "response.headers" if finding_type == "RISKY_HTTP_METHODS_ENABLED" else url,
        "trigger": {
            "url": url,
            "method": "OPTIONS" if finding_type == "RISKY_HTTP_METHODS_ENABLED" else ("PUT" if finding_type == "HTTP_PUT_UPLOAD_CAPABILITY" else "DELETE"),
        },
        "evidence": evidence,
        "classification": "security_misconfiguration",
        "confidence": confidence,
        "family": family,
        "subtype": subtype,
        "owasp": owasp,
        "scope_hint": scope_hint,
        "policy_object": policy_object,
    }

    if finding_type in {"RISKY_HTTP_METHODS_ENABLED", "HTTP_PUT_UPLOAD_CAPABILITY", "HTTP_DELETE_CAPABILITY"}:
        finding["cwe_mapping_status"] = OWASP_ONLY_NO_CWE_MAPPING
        finding["cwe_mapping_reason"] = OWASP_ONLY_NO_CWE_REASON

    return finding


async def http_send(
    client: Any,
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    data: Optional[bytes] = None,
    allow_redirects: bool = False,
    timeout: float = 10.0,
) -> HTTPResult:
    resp = await client.request(
        method=method,
        url=url,
        headers=headers or {},
        content=data,
        follow_redirects=allow_redirects,
        timeout=timeout,
    )

    text = ""
    content = b""
    try:
        text = resp.text or ""
    except Exception:
        text = ""
    try:
        content = resp.content or b""
    except Exception:
        content = b""

    return HTTPResult(
        method=method.upper(),
        url=url,
        status_code=resp.status_code,
        headers=dict(resp.headers or {}),
        text=text,
        content=content,
        final_url=str(getattr(resp, "url", url)),
    )

def _cache_busted_url(url: str) -> str:
    parts = urlsplit(url)
    q = parts.query
    if q:
        q = q + f"&_dastcb={uuid.uuid4().hex}"
    else:
        q = f"_dastcb={uuid.uuid4().hex}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, q, ""))


def _candidate_verification_urls(candidate_url: str, put_resp: HTTPResult) -> List[str]:
    urls: List[str] = [candidate_url]

    location = _header(put_resp.headers, "Location").strip()
    if location:
        try:
            urls.append(urljoin(candidate_url, location))
        except Exception:
            pass

    final_url = str(put_resp.final_url or "").strip()
    if final_url.startswith(("http://", "https://")):
        urls.append(final_url)

    out: List[str] = []
    seen = set()
    for u in urls:
        if not u:
            continue
        clean = _strip_query_and_fragment(u)
        if clean in seen:
            continue
        seen.add(clean)
        out.append(u)
    return out


async def _attempt_put_upload(
    client: Any,
    candidate_url: str,
    marker: str,
    *,
    timeout_s: float,
) -> CapabilityEvidence:
    body = (marker + "\n").encode("utf-8")
    ev = CapabilityEvidence(
        candidate_url=candidate_url,
        marker=marker,
        uploaded_bytes=len(body),
        notes=[],
    )

    headers = {
        "Content-Type": CANARY_CONTENT_TYPE,
        "If-None-Match": "*",
    }

    try:
        put_resp = await http_send(
            client,
            "PUT",
            candidate_url,
            headers=headers,
            data=body,
            allow_redirects=False,
            timeout=timeout_s,
        )
        ev.put_status = put_resp.status_code
        ev.allow_header = _header(put_resp.headers, "Allow")
        ev.dav_header = _header(put_resp.headers, "DAV")
    except Exception as exc:
        ev.notes.append(f"PUT request failed: {exc}")
        return ev

    if put_resp.status_code not in PUT_SUCCESS_CODES:
        ev.notes.append(f"PUT did not return success code: {put_resp.status_code}")
        return ev

    try:
        get_resp = await http_send(
            client,
            "GET",
            candidate_url,
            allow_redirects=False,
            timeout=timeout_s,
        )
        ev.get_status = get_resp.status_code
    except Exception as exc:
        ev.notes.append(f"GET verification failed: {exc}")
        return ev

    # 1차: 직접 200 + marker
    if get_resp.status_code == 200 and marker in (get_resp.text or ""):
        ev.retrieved_marker_present = True
        return ev

    # 2차: HEAD도 확인
    try:
        head_resp = await http_send(
            client,
            "HEAD",
            candidate_url,
            allow_redirects=False,
            timeout=timeout_s,
        )
        if ev.get_status is None:
            ev.get_status = head_resp.status_code
    except Exception as exc:
        ev.notes.append(f"HEAD verification failed: {exc}")

    # 3차: redirect면 final_url GET 재검증
    if get_resp.status_code in {301, 302, 303, 307, 308} and get_resp.final_url and get_resp.final_url != candidate_url:
        try:
            follow_resp = await http_send(
                client,
                "GET",
                get_resp.final_url,
                allow_redirects=False,
                timeout=timeout_s,
            )
            if follow_resp.status_code == 200 and marker in (follow_resp.text or ""):
                ev.retrieved_marker_present = True
                ev.notes.append(f"PUT target redirected to retrievable resource: {get_resp.final_url}")
                return ev
        except Exception as exc:
            ev.notes.append(f"Redirect-follow verification failed: {exc}")

    ev.notes.append(
        f"PUT returned success, but GET verification did not confirm uploaded marker. "
        f"get_status={ev.get_status}"
    )
    return ev

async def _attempt_delete(
    client: Any,
    candidate_url: str,
    ev: CapabilityEvidence,
    *,
    timeout_s: float,
) -> CapabilityEvidence:
    try:
        del_resp = await http_send(
            client,
            "DELETE",
            candidate_url,
            allow_redirects=False,
            timeout=timeout_s,
        )
        ev.delete_status = del_resp.status_code
        if not ev.allow_header:
            ev.allow_header = _header(del_resp.headers, "Allow")
        if not ev.dav_header:
            ev.dav_header = _header(del_resp.headers, "DAV")
    except Exception as exc:
        ev.notes.append(f"DELETE request failed: {exc}")
        return ev

    if ev.delete_status not in DELETE_SUCCESS_CODES:
        ev.notes.append(f"DELETE did not return success code: {ev.delete_status}")
        return ev

    try:
        verify_resp = await http_send(
            client,
            "GET",
            candidate_url,
            allow_redirects=False,
            timeout=timeout_s,
        )
        ev.verify_delete_status = verify_resp.status_code
    except Exception as exc:
        ev.notes.append(f"DELETE verification GET failed: {exc}")
        return ev

    if ev.verify_delete_status in VERIFY_ABSENT_CODES:
        ev.delete_verified_absent = True
        return ev

    if ev.verify_delete_status == 200:
        body = verify_resp.text or ""
        if ev.marker and ev.marker not in body:
            ev.delete_verified_absent = True
            ev.notes.append("GET 200 after DELETE, but original marker disappeared.")
            return ev

    if ev.verify_delete_status in {301, 302, 303, 307, 308}:
        ev.notes.append(f"DELETE verification returned redirect: {ev.verify_delete_status}")
        return ev

    ev.notes.append(
        f"DELETE returned success, but resource still appears accessible. "
        f"verify_status={ev.verify_delete_status}"
    )
    return ev

def _build_root_risky_finding(
    candidate: Dict[str, Any],
    observed_methods: List[str],
    confirmed_method_capabilities: List[str],
    method_capability_signals: List[str],
) -> Dict[str, Any]:
    root_url = _root_scope_url(candidate) or _root_target_url(candidate) or "/"
    root_evidence = _base_root_evidence(candidate)

    root_evidence["risky_methods_enabled"] = observed_methods
    if confirmed_method_capabilities:
        root_evidence["confirmed_method_capabilities"] = confirmed_method_capabilities
    if method_capability_signals:
        root_evidence["method_capability_signals"] = method_capability_signals
    if root_url and "final_url" not in root_evidence:
        root_evidence["final_url"] = root_url

    finding = _build_finding(
        finding_type="RISKY_HTTP_METHODS_ENABLED",
        severity="Info",
        title="Risky HTTP methods appear enabled but exploitability was not confirmed",
        url=root_url,
        confidence=0.9,
        description=(
            "Server responded to risky HTTP methods or advertised them, but active exploit capability "
            "was not confirmed strongly enough to treat this root finding as exploit-proven."
        ),
        remediation="필요한 메서드만 허용하고, PUT/DELETE/WebDAV 계열은 불필요하면 전 구간에서 비활성화한다.",
        evidence=root_evidence,
        subtype="risky_methods_enabled",
        scope_hint="host-wide",
        policy_object="Allow",
    )

    finding["verification"] = {
        "verdict": "INFORMATIONAL",
        "reason": (
            "Observed risky HTTP method handling without confirmed exploitability."
            + (f" Observed methods: {', '.join(observed_methods)}." if observed_methods else "")
        ),
    }
    finding["reason"] = finding["verification"]["reason"]
    finding["root_cause_signature"] = "methods:" + ",".join(observed_methods)
    finding["exposed_information"] = (
        [f"Allowed or handled risky method: {m}" for m in observed_methods]
        + ([f"Observed methods: {', '.join(observed_methods)}"] if observed_methods else [])
    )
    return finding


def _build_put_finding(ev: CapabilityEvidence) -> Dict[str, Any]:
    finding = _build_finding(
        finding_type="HTTP_PUT_UPLOAD_CAPABILITY",
        severity="Medium",
        title="HTTP PUT allows arbitrary file upload to a web-accessible location",
        url=ev.candidate_url,
        confidence=0.98,
        description=(
            "The scanner successfully uploaded a canary file using HTTP PUT and then "
            "retrieved the same file via HTTP GET with the original marker intact."
        ),
        remediation="HTTP PUT이 불필요하면 비활성화하고, 필요한 경우 인증/인가/경로 제한/업로드 검증을 강제한다.",
        evidence=ev.to_dict(),
        subtype="put_upload_capability",
        scope_hint="route-specific",
        policy_object="PUT",
    )
    finding["verification"] = {
        "verdict": "CONFIRMED",
        "reason": "Confirmed arbitrary upload capability via HTTP PUT using a retrievable canary resource.",
    }
    finding["reason"] = finding["verification"]["reason"]
    finding["root_cause_signature"] = f"put-upload:{ev.candidate_url}"
    finding["exposed_information"] = [
        f"PUT upload succeeded at: {ev.candidate_url}",
        "Uploaded marker was retrieved successfully via GET",
    ]
    finding["where"] = ev.candidate_url
    return finding


def _build_delete_finding(ev: CapabilityEvidence) -> Dict[str, Any]:
    finding = _build_finding(
        finding_type="HTTP_DELETE_CAPABILITY",
        severity="Medium",
        title="HTTP DELETE can remove a web-accessible resource",
        url=ev.candidate_url,
        confidence=0.98,
        description=(
            "The scanner deleted a previously created canary resource using HTTP DELETE "
            "and confirmed that the resource was no longer accessible afterward."
        ),
        remediation="HTTP DELETE가 불필요하면 비활성화하고, 필요한 경우 인증/인가/소유권 검증을 강제한다.",
        evidence=ev.to_dict(),
        subtype="delete_capability",
        scope_hint="route-specific",
        policy_object="DELETE",
    )
    finding["verification"] = {
        "verdict": "CONFIRMED",
        "reason": "Confirmed delete capability via HTTP DELETE by removing a scanner-created canary resource.",
    }
    finding["reason"] = finding["verification"]["reason"]
    finding["root_cause_signature"] = f"delete-capability:{ev.candidate_url}"
    finding["exposed_information"] = [
        f"DELETE succeeded at: {ev.candidate_url}",
        "Deleted resource was confirmed absent after verification",
    ]
    finding["where"] = ev.candidate_url
    return finding

async def verify_risky_http_methods_capability(
    *,
    client: Any,
    candidate: Dict[str, Any],
    timeout_s: float,
) -> List[Dict[str, Any]]:
    observed_methods = _observed_methods_from_candidate(candidate)
    method_capability_signals: List[str] = _string_list(
        (candidate.get("evidence") or {}).get("method_capability_signals") or []
    )
    confirmed_method_capabilities: List[str] = []

    root_target = _root_target_url(candidate)
    root_scope = _root_scope_url(candidate)

    findings: List[Dict[str, Any]] = []

    if not root_scope and not root_target:
        findings.append(_build_root_risky_finding(candidate, observed_methods, [], method_capability_signals))
        return findings

    observed_urls = _candidate_observed_urls_from_candidate(candidate)
    if root_target and root_target not in observed_urls:
        observed_urls.append(root_target)

    candidate_targets = _candidate_target_urls(root_scope or root_target, observed_urls)

    put_finding: Dict[str, Any] | None = None
    delete_finding: Dict[str, Any] | None = None

    for canary_url, marker in candidate_targets:
        put_ev = await _attempt_put_upload(
            client,
            canary_url,
            marker,
            timeout_s=timeout_s,
        )

        if not put_ev.retrieved_marker_present:
            if put_ev.put_status in {301, 302, 303, 307, 308}:
                method_capability_signals.append(
                    f"PUT returned redirect ({put_ev.put_status}), treated as non-confirmed for {canary_url}"
                )
            elif put_ev.put_status is not None:
                method_capability_signals.append(
                    f"PUT returned status {put_ev.put_status}, capability not confirmed for {canary_url}"
                )
            if put_ev.notes:
                method_capability_signals.extend(_string_list(put_ev.notes))
            continue

        confirmed_method_capabilities.append("PUT")
        method_capability_signals.append(
            f"PUT confirmed: uploaded canary and retrieved marker from {put_ev.candidate_url}"
        )
        put_finding = _build_put_finding(put_ev)

        del_ev = await _attempt_delete(
            client,
            put_ev.candidate_url,
            put_ev,
            timeout_s=timeout_s,
        )

        if del_ev.delete_verified_absent:
            confirmed_method_capabilities.append("DELETE")
            method_capability_signals.append(
                f"DELETE confirmed: removed canary and verified absence at {del_ev.candidate_url}"
            )
            delete_finding = _build_delete_finding(del_ev)
        else:
            if del_ev.delete_status in {301, 302, 303, 307, 308}:
                method_capability_signals.append(
                    f"DELETE returned redirect ({del_ev.delete_status}), treated as non-confirmed for {del_ev.candidate_url}"
                )
            elif del_ev.delete_status is not None:
                method_capability_signals.append(
                    f"DELETE returned status {del_ev.delete_status}, capability not confirmed for {del_ev.candidate_url}"
                )
            if del_ev.notes:
                method_capability_signals.extend(_string_list(del_ev.notes))

        # exploit-confirmed target 하나면 충분
        break

    root_finding = _build_root_risky_finding(
        candidate,
        observed_methods,
        sorted(set(confirmed_method_capabilities)),
        list(dict.fromkeys(method_capability_signals)),
    )
    findings.append(root_finding)

    if put_finding is not None:
        findings.append(put_finding)
    if delete_finding is not None:
        findings.append(delete_finding)

    return findings