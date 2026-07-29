from __future__ import annotations

import json
from typing import Any

from app.explanation.models import UnifiedExplanationResult


def to_json_dict(result: UnifiedExplanationResult | dict[str, Any]) -> dict[str, Any]:
    return result.to_dict() if hasattr(result, "to_dict") else dict(result)


def dumps(result: UnifiedExplanationResult | dict[str, Any], *, indent: int = 2) -> str:
    return json.dumps(to_json_dict(result), ensure_ascii=False, indent=indent)

