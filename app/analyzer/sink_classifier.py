from __future__ import annotations

from urllib.parse import urlparse

from app.analyzer.risk_model import SinkAssessment, SinkSemantics


def classify_sink(primary_chain: list[dict], tool_calls: list[object], network_events: list[object]) -> SinkAssessment:
    """Classify the best available sink candidate for outbound-risk decisions."""

    chain_sink = next((node for node in reversed(primary_chain) if node.get("node_type") == "network_endpoint"), None)
    if chain_sink is not None:
        label = str(chain_sink.get("label", ""))
        return _assessment_for_url(
            url=label,
            method=_method_for_url(label, tool_calls),
            declared_endpoint=True,
            tool_linked_http_action=bool(_matching_http_tool(label, tool_calls)),
        )

    http_tools = [
        event for event in tool_calls
        if getattr(event, "event", "") == "start" and getattr(event, "tool_type", "") == "http_request"
    ]
    if http_tools:
        tool = http_tools[-1]
        config = getattr(tool, "metadata", {}).get("config", {})
        return _assessment_for_url(
            url=str(config.get("url", "")),
            method=str(config.get("method", "GET")).upper(),
            declared_endpoint=True,
            tool_linked_http_action=True,
        )

    if network_events:
        address = str(getattr(network_events[-1], "address", ""))
        return _assessment_for_url(
            url=address,
            method="",
            declared_endpoint=False,
            tool_linked_http_action=False,
        )

    return SinkAssessment(reasons=["No network sink candidate could be established."])


def _assessment_for_url(
    *,
    url: str,
    method: str,
    declared_endpoint: bool,
    tool_linked_http_action: bool,
) -> SinkAssessment:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    is_internal = host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".internal")
    reasons: list[str] = []

    if is_internal:
        semantics = SinkSemantics.TOOL_INTERNAL_ENDPOINT
        reasons.append("Sink resolves to a local or internal-only endpoint.")
    elif any(token in url.lower() for token in {"webhook", "callback", "hook"}):
        semantics = SinkSemantics.CALLBACK_OR_WEBHOOK
        reasons.append("URL contains callback/webhook markers.")
    elif method == "GET":
        semantics = SinkSemantics.PUBLIC_FETCH_ONLY
        reasons.append("HTTP method is GET, so the observed sink is a fetch-only endpoint.")
    elif method in {"POST", "PUT", "PATCH"}:
        semantics = SinkSemantics.PUBLIC_UPLOAD_OR_POST
        reasons.append("HTTP method is outward-facing upload/post semantics.")
    else:
        semantics = SinkSemantics.UNKNOWN_NETWORK_SINK
        reasons.append("Sink lacks enough HTTP semantics to be classified more precisely.")

    return SinkAssessment(
        label=url,
        semantics=semantics,
        method=method,
        reasons=reasons,
        declared_endpoint=declared_endpoint,
        tool_linked_http_action=tool_linked_http_action,
        is_external=not is_internal and bool(url),
    )


def _matching_http_tool(url: str, tool_calls: list[object]) -> object | None:
    for event in tool_calls:
        if getattr(event, "event", "") != "start" or getattr(event, "tool_type", "") != "http_request":
            continue
        if str(getattr(event, "metadata", {}).get("config", {}).get("url", "")) == url:
            return event
    return None


def _method_for_url(url: str, tool_calls: list[object]) -> str:
    tool = _matching_http_tool(url, tool_calls)
    if tool is None:
        return ""
    return str(getattr(tool, "metadata", {}).get("config", {}).get("method", "GET")).upper()
