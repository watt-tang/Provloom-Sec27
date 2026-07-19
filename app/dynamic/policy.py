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
            if chain.chain_type == "confidentiality" and chain.sink and not self._is_trusted_sink(chain.sink):
                violations.append(
                    PolicyViolation(
                        policy_type="confidentiality",
                        violation_id=f"PV-{chain.chain_id}",
                        evidence_level=chain.evidence_level,
                        chain_id=chain.chain_id,
                        taint_ids=list(chain.taint_ids),
                        reason="Sensitive source reached a non-allowlisted external sink with provenance evidence.",
                        event_ids=list(chain.supporting_event_ids),
                    )
                )
            if chain.chain_type == "persistence":
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

    def _is_trusted_sink(self, sink: str) -> bool:
        parsed = urlparse(sink.replace("network:NET:", ""))
        host = parsed.hostname or sink.rsplit(":", 1)[0].replace("network:NET:", "")
        if host in self.config.trusted_domains:
            return True
        return any(fnmatch.fnmatch(host, pattern) or fnmatch.fnmatch(sink, pattern) for pattern in self.config.trusted_egress_allowlist)

    def _is_allowed_executable(self, path: str) -> bool:
        return any(fnmatch.fnmatch(path, pattern) for pattern in self.config.executable_allowlist)
