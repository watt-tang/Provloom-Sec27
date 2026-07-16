from __future__ import annotations

import json
from typing import Any


def stable_id(prefix: str, *parts: Any) -> str:
    import hashlib

    payload = json.dumps(parts, ensure_ascii=False, sort_keys=True)
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:16]}"


def dedupe(items: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        cleaned = str(item or "").strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result
