from __future__ import annotations

from typing import List


def split_manual_auth_header_chunks(raw: str) -> List[str]:
    raw = str(raw or "").strip()
    if not raw:
        return []
    if "|||" in raw:
        return [piece.strip() for piece in raw.split("|||") if piece.strip()]
    return [piece.strip() for piece in raw.replace("\r\n", "\n").split("\n") if piece.strip()]
