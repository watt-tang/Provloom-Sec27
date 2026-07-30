from __future__ import annotations

import fnmatch
from urllib.parse import urlparse

from app.dynamic.config import DynamicAnalysisConfig
from app.dynamic.models import PolicyViolation, RuntimeChain, RuntimeEvent


class PolicyEngine:
    def __init__(self, config: DynamicAnalysisConfig | None = None) -> None:
        self.config = config or DynamicAnalysisConfig()

    def evaluate(self, *, chains: list[RuntimeChain], events: list[RuntimeEvent]) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        for chain in chains:
            if chain.chain_type == "confidentiality_confirmed" and chain.sink and not self._chain_is_permitted(chain, events):
                violations.append(
                    PolicyViolation(
                        policy_type="confidentiality",
                        violation_id=f"PV-{chain.chain_id}",
                        evidence_level=chain.evidence_level,
                        chain_id=chain.chain_id,
                        taint_ids=list(chain.taint_ids),
                        reason="Sensitive source reached a non-allowlisted external sink with concrete carrier evidence.",
                        event_ids=list(chain.supporting_event_ids),
                        metadata={
                            "chain_type": chain.chain_type,
                            "evidence_strengths": list(chain.evidence_strengths),
                            "carrier_types": list(chain.metadata.get("carrier_types", [])),
                        },
                    )
                )
            if chain.chain_type == "persistence_confirmed":
                violations.append(
                    PolicyViolation(
                        policy_type="integrity",
                        violation_id=f"PV-{chain.chain_id}",
                        evidence_level=chain.evidence_level,
                        chain_id=chain.chain_id,
                        taint_ids=list(chain.taint_ids),
                        reason="Runtime wrote or registered a persistence/instruction target outside explicit allowlist evidence.",
                        event_ids=list(chain.supporting_event_ids),
                    )
                )
        for event in events:
            credential_flow = self._classify_credential_flow(event)
            if credential_flow:
                event.metadata["credential_flow_classification"] = credential_flow
            if event.operation == "exec" and event.object_path and not self._is_allowed_executable(event.object_path):
                violations.append(
                    PolicyViolation(
                        policy_type="integrity",
                        violation_id=f"PV-{event.event_id}",
                        evidence_level=event.evidence_level if event.evidence_level != "unknown" else "candidate",
                        chain_id=None,
                        taint_ids=list(event.taint_ids),
                        reason="Execution target is not on the executable allowlist.",
                        event_ids=[event.event_id],
                        metadata={"object_path": event.object_path},
                    )
                )
        return violations

    def _chain_is_permitted(self, chain: RuntimeChain, events: list[RuntimeEvent]) -> bool:
        if chain.chain_type != "confidentiality_confirmed":
            return True
        if chain.instrumentation_gaps:
            return True
        if "hash_derived" in set(chain.evidence_strengths):
            return True
        chain_events = [event for event in events if event.event_id in set(chain.supporting_event_ids)]
        if any(event.derived_from_hash for event in chain_events):
            return True
        if any(event.metadata.get("fixture_mock_sink") for event in chain_events):
            return self._is_permitted_pair(chain)
        if chain.sink and self._is_trusted_sink(chain.sink):
            return True
        if self._is_trusted_llm_context(chain_events):
            return True
        if self._is_trusted_authentication(chain, chain_events):
            return True
        return self._is_permitted_pair(chain)

    def _is_trusted_sink(self, sink: str) -> bool:
        parsed = urlparse(sink.replace("network:NET:", ""))
        host = parsed.hostname or sink.rsplit(":", 1)[0].replace("network:NET:", "")
        if host in self.config.trusted_domains:
            return True
        return any(fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(sink, pattern) for pattern in self.config.trusted_egress_allowlist)

    def _is_allowed_executable(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.config.executable_allowlist)

    def _is_trusted_authentication(self, chain: RuntimeChain, events: list[RuntimeEvent]) -> bool:
        carrier_types = set(chain.metadata.get("carrier_types", []))
        if "http_header" not in carrier_types:
            return False
        auth_events = [event for event in events if _is_auth_header_event(event)]
        if not auth_events:
            return False
        return bool(chain.sink and self._is_trusted_sink(chain.sink))

    def _is_trusted_llm_context(self, events: list[RuntimeEvent]) -> bool:
        llm_events = [event for event in events if event.carrier_type == "llm_context"]
        if not llm_events:
            return False
        for event in llm_events:
            provider = str(event.metadata.get("provider") or event.metadata.get("llm_provider_name") or "").lower()
            host = str(event.metadata.get("endpoint_host") or "").lower()
            if provider and any(fnmatch.fnmatch(provider, pattern.lower()) for pattern in self.config.trusted_llm_providers):
                return True
            if host and any(fnmatch.fnmatch(host, pattern.lower()) for pattern in self.config.trusted_llm_provider_domains):
                return True
        return False

    def _is_permitted_pair(self, chain: RuntimeChain) -> bool:
        if not chain.source or not chain.sink:
            return False
        for pair in self.config.permitted_source_to_sink_pairs:
            source_pattern = pair.get("source") or pair.get("source_pattern") or ""
            sink_pattern = pair.get("sink") or pair.get("sink_pattern") or ""
            if source_pattern and sink_pattern and fnmatch.fnmatch(chain.source, source_pattern) and fnmatch.fnmatch(chain.sink, sink_pattern):
                return True
        return False

    def _classify_credential_flow(self, event: RuntimeEvent) -> str | None:
        if not event.taint_ids or event.carrier_type != "http_header":
            return None
        if _is_auth_header_event(event):
            return "credential_authentication" if self._is_trusted_sink(event.object_id) else "credential_exposure"
        if event.object_type == "network":
            return "credential_exfiltration"
        return None


def _is_auth_header_event(event: RuntimeEvent) -> bool:
    location = str(event.carrier_location or "").lower()
    headers = event.metadata.get("headers", {})
    if location in {"authorization", "cookie", "headers.authorization", "headers.cookie"}:
        return True
    if isinstance(headers, dict):
        return any(str(key).lower() in {"authorization", "cookie"} for key in headers)
    return False
