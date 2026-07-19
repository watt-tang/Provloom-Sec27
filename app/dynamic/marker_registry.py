from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.parse
from dataclasses import dataclass
from typing import Any

from app.dynamic.config import MarkerConfig
from app.dynamic.models import TaintSource
from app.taint.source_registry import normalize_path


@dataclass(frozen=True)
class MarkerMatch:
    taint_id: str
    variant_name: str
    evidence_level: str
    derived: bool = False


class TaintRegistry:
    """Audit-side registry for synthetic sensitive sources and marker variants."""

    def __init__(self, *, run_id: str, config: MarkerConfig | None = None, seed: str | None = None) -> None:
        self.run_id = run_id
        self.config = config or MarkerConfig()
        self.seed = seed
        self.sources: dict[str, TaintSource] = {}
        self._variant_to_taint: dict[str, MarkerMatch] = {}

    def register_source(
        self,
        *,
        source_type: str,
        source_location: str,
        created_at: float = 0.0,
        allowed_sinks: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> TaintSource:
        taint_id = f"T{len(self.sources) + 1:03d}"
        marker = self._marker_for(taint_id, source_location)
        variants = marker_variants(marker, include_hash_derivatives=self.config.include_hash_derivatives)
        source = TaintSource(
            taint_id=taint_id,
            source_type=source_type,
            source_location=normalize_path(source_location) or source_location,
            marker=marker,
            created_at=created_at,
            allowed_sinks=list(allowed_sinks or []),
            metadata=dict(metadata or {}),
            variants=variants,
        )
        self.sources[taint_id] = source
        for name, value in variants.items():
            if not value:
                continue
            derived = name.startswith("sha256")
            self._variant_to_taint[value] = MarkerMatch(
                taint_id=taint_id,
                variant_name=name,
                evidence_level="conservative" if derived else "confirmed",
                derived=derived,
            )
        return source

    def ensure_source_for_path(self, path: str, *, source_type: str = "secret_file", timestamp: float = 0.0) -> TaintSource:
        normalized = normalize_path(path) or path
        for source in self.sources.values():
            if source.source_location == normalized:
                return source
        return self.register_source(source_type=source_type, source_location=normalized, created_at=timestamp)

    def detect(self, value: Any) -> list[MarkerMatch]:
        text = _stringify(value)
        if not text:
            return []
        matches: list[MarkerMatch] = []
        seen: set[tuple[str, str]] = set()
        for variant, match in self._variant_to_taint.items():
            if variant and variant in text and (match.taint_id, match.variant_name) not in seen:
                seen.add((match.taint_id, match.variant_name))
                matches.append(match)
        return matches

    def source_dicts(self) -> list[dict[str, Any]]:
        return [source.to_dict() for source in self.sources.values()]

    def _marker_for(self, taint_id: str, source_location: str) -> str:
        if self.seed is not None:
            digest = hashlib.sha256(f"{self.seed}:{self.run_id}:{taint_id}:{source_location}".encode("utf-8")).hexdigest()
            entropy = digest[: self.config.bytes_of_entropy * 2].upper()
        else:
            entropy = secrets.token_hex(self.config.bytes_of_entropy).upper()
        return f"{self.config.prefix}_{taint_id}_{entropy}"


def marker_variants(marker: str, *, include_hash_derivatives: bool = True) -> dict[str, str]:
    raw_bytes = marker.encode("utf-8")
    mid = max(1, len(marker) // 2)
    variants = {
        "raw": marker,
        "base64": base64.b64encode(raw_bytes).decode("ascii"),
        "hex": raw_bytes.hex(),
        "url_encoded": urllib.parse.quote(marker, safe=""),
        "json_escaped": json.dumps(marker)[1:-1],
        "split_concat": marker[:mid] + marker[mid:],
    }
    if include_hash_derivatives:
        variants["sha256"] = hashlib.sha256(raw_bytes).hexdigest()
    return variants


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:
        return str(value)
