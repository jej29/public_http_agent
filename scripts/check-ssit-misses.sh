#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <run_dir> [--json]" >&2
  exit 1
fi

RUN_DIR="$1"
OUTPUT_MODE="${2:-text}"

if [[ ! -d "$RUN_DIR" ]]; then
  echo "Run directory not found: $RUN_DIR" >&2
  exit 1
fi

if [[ ! -f "$RUN_DIR/results.json" ]]; then
  echo "results.json not found under: $RUN_DIR" >&2
  exit 1
fi

python3 - "$RUN_DIR" "$OUTPUT_MODE" <<'PY'
import glob
import json
import os
import re
import sys
from collections import defaultdict

run_dir = sys.argv[1]
output_mode = sys.argv[2]

results_path = os.path.join(run_dir, "results.json")
live_path = os.path.join(run_dir, "live", "findings_live.jsonl")
raw_dir = os.path.join(run_dir, "raw")

DB_MARKERS = [
    "ora-",
    "preparedstatementcallback",
    "sqlintegrityconstraintviolationexception",
    "insert into",
    "ssit_spring_session_attributes",
    "sql [",
]
STACK_MARKERS = [
    "exception",
    "traceback",
    "stack trace",
    "caused by:",
]
CONFIG_TOKENS = [
    "productgroupid",
    "productid",
    "productphase",
    "applicationservers",
    "rumservertype",
    "serverurl",
    "console.trace",
    "addlabels",
]
SOURCEURL_MARKERS = [
    "sourceurl=webpack:///",
    "webpack:///",
]
URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)


def load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(path):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    return rows


def item_raw_refs(item):
    refs = []
    raw_ref = item.get("raw_ref")
    if raw_ref:
        refs.append(raw_ref)
    for ref in item.get("raw_refs") or []:
        if ref:
            refs.append(ref)
    for event in item.get("events") or []:
        ref = (event or {}).get("raw_ref")
        if ref:
            refs.append(ref)
    return list(dict.fromkeys(refs))


def basename_set(item):
    return {os.path.basename(ref) for ref in item_raw_refs(item)}


def normalized_url(item):
    return str(item.get("normalized_url") or "").strip()


def compact(text, limit=140):
    value = " ".join(str(text or "").split())
    return value if len(value) <= limit else value[: limit - 3] + "..."


results = load_json(results_path)
confirmed = list(results.get("findings_confirmed") or [])
informational = list(results.get("findings_informational") or [])
candidate_signals = list(results.get("candidate_signals") or [])
live_rows = load_jsonl(live_path)
live_findings = [row.get("finding") or {} for row in live_rows if isinstance(row, dict)]

result_items = confirmed + informational + candidate_signals

by_raw_ref = defaultdict(list)
by_url = defaultdict(list)
for item in result_items + live_findings:
    for name in basename_set(item):
        by_raw_ref[name].append(item)
    url = normalized_url(item)
    if url:
        by_url[url].append(item)


def classify_db_raw(path, data):
    request = data.get("request") or {}
    response = data.get("response") or {}
    url = str(request.get("url") or "")
    body = str(response.get("body_text") or "")
    status = int(response.get("status_code") or 0)
    body_l = body.lower()
    marker_hits = [marker for marker in DB_MARKERS if marker in body_l]
    if status < 500:
        return None
    if len(marker_hits) < 2:
        return None
    return {
        "kind": "db_error",
        "raw_file": os.path.basename(path),
        "url": url,
        "status_code": status,
        "marker_hits": marker_hits,
        "body_excerpt": compact(body, 220),
    }


def classify_client_bundle_raw(path, data):
    request = data.get("request") or {}
    response = data.get("response") or {}
    url = str(request.get("url") or "")
    body = str(response.get("body_text") or "")
    content_type = str(response.get("content_type") or "").lower()
    if not (url.endswith(".js") or "javascript" in content_type):
        return None
    body_l = body.lower()
    sourceurl_hits = sum(1 for token in SOURCEURL_MARKERS if token in body_l)
    config_hits = sorted({token for token in CONFIG_TOKENS if token in body_l})
    urls = [value for value in URL_RE.findall(body) if len(value) < 180]
    internal_urls = [value for value in urls if any(key in value.lower() for key in (
        "samsungds.net",
        "localhost",
        "devpaas",
        "sharedsvc",
        "apm.elastic",
        "itplatform",
    ))]
    if sourceurl_hits == 0:
        return None
    if len(config_hits) < 2 and not internal_urls:
        return None
    return {
        "kind": "client_bundle",
        "raw_file": os.path.basename(path),
        "url": url,
        "status_code": int(response.get("status_code") or 0),
        "config_hits": config_hits,
        "internal_urls": internal_urls[:5],
        "body_excerpt": compact(body, 220),
    }


def classify_cookie_raw(path, data):
    response = data.get("response") or {}
    request = data.get("request") or {}
    headers = response.get("headers") or {}
    if not isinstance(headers, dict):
        return None
    set_cookie_values = []
    for key, value in headers.items():
        if str(key).lower() == "set-cookie":
            if isinstance(value, list):
                set_cookie_values.extend(str(v) for v in value)
            else:
                set_cookie_values.append(str(value))
    if not set_cookie_values:
        return None
    findings = []
    for cookie in set_cookie_values:
        cookie_l = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip()
        if "secure" not in cookie_l:
            findings.append(f"{cookie_name}:secure_missing")
        if "samesite" not in cookie_l:
            findings.append(f"{cookie_name}:samesite_missing")
    if not findings:
        return None
    return {
        "kind": "cookie_attr",
        "raw_file": os.path.basename(path),
        "url": str(request.get("url") or response.get("final_url") or ""),
        "status_code": int(response.get("status_code") or 0),
        "cookie_findings": findings,
        "set_cookie": set_cookie_values,
    }


raw_candidates = []
for path in sorted(glob.glob(os.path.join(raw_dir, "*.json"))):
    try:
        data = load_json(path)
    except Exception:
        continue
    for classifier in (classify_db_raw, classify_client_bundle_raw, classify_cookie_raw):
        result = classifier(path, data)
        if result:
            raw_candidates.append(result)


def summarize_matches(candidate):
    matches = list(by_raw_ref.get(candidate["raw_file"], []))
    if not matches and candidate.get("url"):
        matches = list(by_url.get(candidate["url"], []))
    return matches


def db_assessment(candidate, matches):
    error_items = [m for m in matches if str(m.get("type") or "") == "HTTP_ERROR_INFO_EXPOSURE"]
    confirmed_db = [
        m for m in error_items
        if ((m.get("verification") or {}).get("verdict") or "").upper() == "CONFIRMED"
        and "db_error" in str(m.get("subtype") or "")
    ]
    if confirmed_db:
        return "ok_confirmed", confirmed_db[0]
    if not error_items:
        return "likely_missed", None
    db_like = [
        m for m in error_items
        if "db_error" in str(m.get("subtype") or "")
        or "ora-" in json.dumps(m.get("evidence") or {}, ensure_ascii=False).lower()
        or "database error" in " ".join(m.get("exposed_information") or []).lower()
    ]
    if db_like:
        return "likely_underclassified", db_like[0]
    return "likely_underclassified", error_items[0]


def bundle_assessment(candidate, matches):
    bundle_items = [m for m in matches if str(m.get("type") or "") == "HTTP_SYSTEM_INFO_EXPOSURE"]
    if not bundle_items:
        return "likely_missed", None
    info_items = [
        m for m in bundle_items
        if ((m.get("verification") or {}).get("verdict") or "").upper() == "INFORMATIONAL"
    ]
    if len(candidate.get("config_hits") or []) >= 3 and candidate.get("internal_urls") and info_items:
        return "review_underclassified", info_items[0]
    return "ok_present", bundle_items[0]


def cookie_assessment(candidate, matches):
    cookie_items = [
        m for m in matches
        if str(m.get("type") or "") in {"COOKIE_SECURE_MISSING", "COOKIE_SAMESITE_MISSING"}
    ]
    expected = set(candidate.get("cookie_findings") or [])
    found = set()
    for item in cookie_items:
        cookie_name = str(item.get("policy_object") or "")
        subtype = str(item.get("subtype") or "")
        if subtype == "secure_missing":
            found.add(f"{cookie_name}:secure_missing")
        if subtype == "samesite_missing":
            found.add(f"{cookie_name}:samesite_missing")
    if expected.issubset(found):
        return "ok_present", None
    if cookie_items:
        return "likely_underclassified", None
    return "likely_missed", None


summary = {
    "run_dir": run_dir,
    "results_confirmed": len(confirmed),
    "results_informational": len(informational),
    "candidate_signals": len(candidate_signals),
    "live_events": len(live_rows),
    "raw_candidates": len(raw_candidates),
}

sections = {
    "db_error": [],
    "client_bundle": [],
    "cookie_attr": [],
}

for candidate in raw_candidates:
    matches = summarize_matches(candidate)
    if candidate["kind"] == "db_error":
        state, item = db_assessment(candidate, matches)
    elif candidate["kind"] == "client_bundle":
        state, item = bundle_assessment(candidate, matches)
    else:
        state, item = cookie_assessment(candidate, matches)
    entry = {
        "state": state,
        "raw_file": candidate["raw_file"],
        "url": candidate["url"],
        "status_code": candidate["status_code"],
        "matched_count": len(matches),
        "result_type": str((item or {}).get("type") or ""),
        "result_subtype": str((item or {}).get("subtype") or ""),
        "result_verdict": str(((item or {}).get("verification") or {}).get("verdict") or ""),
        "result_severity": str((item or {}).get("final_severity") or (item or {}).get("severity") or ""),
    }
    if candidate["kind"] == "db_error":
        entry["marker_hits"] = candidate["marker_hits"]
        entry["body_excerpt"] = candidate["body_excerpt"]
    elif candidate["kind"] == "client_bundle":
        entry["config_hits"] = candidate["config_hits"]
        entry["internal_urls"] = candidate["internal_urls"]
    else:
        entry["cookie_findings"] = candidate["cookie_findings"]
        entry["set_cookie"] = candidate["set_cookie"]
    sections[candidate["kind"]].append(entry)


if output_mode == "--json":
    print(json.dumps({"summary": summary, "sections": sections}, ensure_ascii=False, indent=2))
    sys.exit(0)

print("== SSIT Miss Check ==")
print(f"run_dir: {summary['run_dir']}")
print(
    f"results: confirmed={summary['results_confirmed']} informational={summary['results_informational']} "
    f"candidate_signals={summary['candidate_signals']} live_events={summary['live_events']}"
)
print(f"raw signal candidates: {summary['raw_candidates']}")

def print_section(title, items):
    print()
    print(f"[{title}]")
    if not items:
        print("  none")
        return
    for item in items:
        print(
            f"  - state={item['state']} raw={item['raw_file']} status={item['status_code']} "
            f"url={item['url']}"
        )
        if item["result_type"]:
            print(
                f"    result={item['result_type']} subtype={item['result_subtype']} "
                f"verdict={item['result_verdict']} severity={item['result_severity']}"
            )
        if "marker_hits" in item:
            print(f"    markers={', '.join(item['marker_hits'])}")
            print(f"    excerpt={item['body_excerpt']}")
        if "config_hits" in item:
            print(f"    config_hits={', '.join(item['config_hits']) or '-'}")
            print(f"    internal_urls={', '.join(item['internal_urls']) or '-'}")
        if "cookie_findings" in item:
            print(f"    cookie_findings={', '.join(item['cookie_findings'])}")

print_section("DB Errors", sections["db_error"])
print_section("Client Bundle Review", sections["client_bundle"])
print_section("Cookie Attributes", sections["cookie_attr"])

interesting = {
    "likely_missed": [],
    "likely_underclassified": [],
    "review_underclassified": [],
}
for kind, items in sections.items():
    for item in items:
        if item["state"] in interesting:
            interesting[item["state"]].append((kind, item))

print()
print("[Review Summary]")
for state, items in interesting.items():
    print(f"  {state}: {len(items)}")
    for kind, item in items[:10]:
        print(f"    - {kind} {item['raw_file']} {item['url']}")
PY
