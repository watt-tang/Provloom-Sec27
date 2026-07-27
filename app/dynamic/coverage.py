from __future__ import annotations

from app.dynamic.config import COVERAGE_STATES
from app.dynamic.models import CoverageReport, RuntimeChain, RuntimeEvent


class CoverageAnalyzer:
    def analyze(self, *, events: list[RuntimeEvent], chains: list[RuntimeChain], timed_out: bool = False, exit_code: int | None = 0) -> CoverageReport:
        if timed_out or any(event.event_type == "timeout" for event in events):
            return CoverageReport("timeout", ["runtime timed out"], len(events), metadata={"exit_code": exit_code})
        if any(event.event_type == "analysis_error" for event in events):
            return CoverageReport("execution_failed", ["analysis event stream contains an error"], len(events), metadata={"exit_code": exit_code, "legacy_coverage_state": "analysis_error"})
        if exit_code not in (0, None):
            return CoverageReport("execution_failed", [f"runtime exited with code {exit_code}"], len(events), metadata={"exit_code": exit_code})

        explicit = _explicit_state(events)
        if explicit:
            return CoverageReport(_canonical_state(explicit), [f"explicit coverage event: {explicit}"], len(events), metadata={"exit_code": exit_code, "legacy_coverage_state": explicit})

        confirmed = [chain for chain in chains if chain.chain_type.endswith("_confirmed") and chain.evidence_level in {"confirmed", "conservative"}]
        if confirmed:
            missing = sorted({point for chain in chains for point in chain.missing_observation_points})
            state = "instrumentation_gap" if missing else "runtime_confirmed"
            legacy = "triggered_but_partially_observed" if missing else "triggered_and_observed"
            return CoverageReport(state, ["runtime behavior observed with canonical provenance chain"], len(events), missing_observations=missing, metadata={"legacy_coverage_state": legacy})

        instrumentation_gaps = sorted(
            {
                str(event.instrumentation_visibility)
                for event in events
                if event.instrumentation_visibility not in {"", "observed", "payload_preview_observed"}
            }
            | {"encrypted_payload_invisible" for event in events if event.metadata.get("encrypted_payload_invisible")}
            | {gap for chain in chains for gap in chain.instrumentation_gaps}
        )
        if instrumentation_gaps and (chains or _has_tainted_sink_visibility_gap(events)):
            return CoverageReport(
                "instrumentation_gap",
                ["runtime path reached but key payload or carrier visibility is incomplete"],
                len(events),
                missing_observations=instrumentation_gaps,
                metadata={"legacy_coverage_state": "triggered_but_partially_observed"},
            )

        if any(event.event_type == "candidate_dependency" for event in events):
            return CoverageReport(
                "insufficient_coverage",
                ["candidate dependency observed without payload/file/tool propagation evidence"],
                len(events),
                missing_observations=["network_payload_or_upload"],
                metadata={"legacy_coverage_state": "triggered_but_partially_observed"},
            )

        if any(event.event_type == "runtime_instruction_seen" for event in events):
            return CoverageReport("insufficient_coverage", ["runtime instruction artifact was simulated but no real follow-on Agent/tool execution was observed"], len(events), metadata={"legacy_coverage_state": "instruction_seen_but_not_executed"})

        if not events:
            return CoverageReport("path_not_triggered", ["no runtime events were observed"], 0, metadata={"legacy_coverage_state": "not_triggered"})

        if _target_reached_no_flow(events):
            return CoverageReport(
                "target_reached_no_flow",
                ["target action and instrumentation were observed but no supported sensitive flow chain closed"],
                len(events),
                metadata={"legacy_coverage_state": "triggered_and_observed"},
            )

        return CoverageReport("insufficient_coverage", ["runtime emitted events but no canonical sensitive flow chain closed"], len(events), metadata={"legacy_coverage_state": "triggered_but_partially_observed"})


def _explicit_state(events: list[RuntimeEvent]) -> str | None:
    for event in events:
        state = str(event.metadata.get("coverage_state", ""))
        if state in COVERAGE_STATES:
            return state
        if event.event_type in COVERAGE_STATES:
            return event.event_type
    return None


def _canonical_state(state: str) -> str:
    return {
        "not_triggered": "path_not_triggered",
        "unsupported_tool": "unsupported_operation",
        "unsupported_environment": "environment_missing",
        "external_state_missing": "environment_missing",
        "endpoint_unavailable": "sink_unavailable",
        "analysis_error": "execution_failed",
        "triggered_and_observed": "runtime_confirmed",
        "triggered_but_partially_observed": "insufficient_coverage",
        "instruction_seen_but_not_executed": "insufficient_coverage",
    }.get(state, state)


def _target_reached_no_flow(events: list[RuntimeEvent]) -> bool:
    if not events:
        return False
    has_action = any(event.event_type.startswith(("tool_", "network_", "file_", "process_")) for event in events)
    instrumentation_complete = all(
        event.instrumentation_visibility in {"", "observed", "payload_preview_observed", "endpoint_only"}
        for event in events
    )
    return has_action and instrumentation_complete


def _has_tainted_sink_visibility_gap(events: list[RuntimeEvent]) -> bool:
    sink_operations = {"send", "upload", "connect"}
    for event in events:
        if event.operation in {"send", "upload"} and event.metadata.get("encrypted_payload_invisible"):
            return True
        if not event.taint_ids:
            continue
        if event.object_type == "network" or event.operation in sink_operations:
            if event.instrumentation_visibility not in {"", "observed", "payload_preview_observed"}:
                return True
            if event.metadata.get("encrypted_payload_invisible"):
                return True
    return False
