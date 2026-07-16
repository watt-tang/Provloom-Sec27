from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

from app.taint.models import TaintSet


BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def classify_http_sink(config: dict, taint_ids: TaintSet) -> dict:
    method = str(config.get("method", "GET")).upper()
    url = str(config.get("url", ""))
    parsed = urlparse(url)
    has_query = bool(parsed.query and parse_qsl(parsed.query, keep_blank_values=True))
    has_body = config.get("body") not in (None, "")
    if taint_ids.is_empty():
        return {"is_sink": False, "sink_type": "none", "payload_size": 0, "payload_hash": ""}
    if method in BODY_METHODS and has_body:
        body = str(config.get("body", ""))
        return {
            "is_sink": True,
            "sink_type": "http_body",
            "payload_size": len(body.encode("utf-8")),
            "payload_hash": "",
        }
    if has_query:
        return {
            "is_sink": True,
            "sink_type": "http_query",
            "payload_size": len(parsed.query.encode("utf-8")),
            "payload_hash": "",
        }
    return {"is_sink": False, "sink_type": "connection_metadata", "payload_size": 0, "payload_hash": ""}
