
from __future__ import annotations

import json
import zoneinfo
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


def log(stage: str, msg: str) -> None:
    print(f"[{stage}] {msg}", flush=True)


def now_utc_iso() -> str:
    return datetime.now(zoneinfo.ZoneInfo("Asia/Seoul")).isoformat()


def run_id_utc() -> str:
    kst = zoneinfo.ZoneInfo("Asia/Seoul")
    return datetime.now(kst).strftime("%Y%m%d_%H%M%S")


def prune_empty(value: Any) -> Any:
    """
    Recursively remove:
    - None
    - empty string
    - empty list
    - empty dict

    Keep:
    - 0
    - False
    """
    if isinstance(value, dict):
        cleaned = {}
        for k, v in value.items():
            pv = prune_empty(v)
            if pv in (None, "", [], {}):
                continue
            cleaned[k] = pv
        return cleaned

    if isinstance(value, list):
        cleaned = [prune_empty(v) for v in value]
        cleaned = [v for v in cleaned if v not in (None, "", [], {})]
        return cleaned

    return value


def save_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(prune_empty(data), indent=2, ensure_ascii=False), encoding="utf-8")


def mask_headers(h: Dict[str, str]) -> Dict[str, str]:
    try:
        return dict(h or {})
    except Exception:
        out: Dict[str, str] = {}
        try:
            for k, v in (h or {}).items():
                out[str(k)] = "" if v is None else str(v)
        except Exception:
            return {}
        return out


def compact_trigger(trigger: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(trigger, dict):
        return {}
    compact = {
        "name": trigger.get("name"),
        "method": trigger.get("method"),
        "url": trigger.get("url"),
    }
    return {k: v for k, v in compact.items() if v not in (None, "", [], {})}
