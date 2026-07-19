from __future__ import annotations

from app.dynamic.config import COVERAGE_STATES
from app.dynamic.models import CoverageReport, RuntimeChain, RuntimeEvent


class CoverageAnalyzer:
    def analyze(self, *, events: list[RuntimeEvent], chains: list[RuntimeChain], timed_out: bool = False, exit_code: int | None = 0) -> CoverageReport:
        if timed_out or any(event.event_type == "timeout" for event in events):
            return CoverageReport("timeout", ["runtime timed out"], len(events), metadata={"exit_code": exit_code})
        if any(event.event_type == "analysis_error" for event in events):
            return CoverageReport("analysis_error", ["analysis event stream contains an error"], len(events), metadata={"exit_code": exit_code})
        if exit_code not in (0, None):
            return CoverageReport("execution_failed", [f"runtime exited with code {exit_code}"], len(events), metadata={"exit_code": exit_code})

        explicit = _explicit_state(events)
        if explicit:
            return CoverageReport(explicit, [f"explicit coverage event: {explicit}"], len(events), metadata={"exit_code": exit_code})

        if any(chain.evidence_level in {"confirmed", "conservative"} for chain in chains):
            missing = sorted({point for chain in chains for point in chain.missing_observation_points})
            state = "triggered_but_partially_observed" if missing else "triggered_and_observed"
            return CoverageReport(state, ["runtime behavior observed with provenance chain"], len(events), missing_observations=missing)

        if any(event.event_type == "candidate_dependency" for event in events):
            return CoverageReport(
                "triggered_but_partially_observed",
                ["candidate dependency observed without payload/file/tool propagation evidence"],
                len(events),
                missing_observations=["network_payload_or_upload"],
            )

        if any(event.event_type == "runtime_instruction_seen" for event in events):
            return CoverageReport("instruction_seen_but_not_executed", ["runtime instruction artifact was seen but no follow-on execution was observed"], len(events))

        if not events:
            return CoverageReport("not_triggered", ["no runtime events were observed"], 0)

        return CoverageReport("triggered_and_observed", ["runtime emitted events but no supported sensitive flow chain closed"], len(events))


def _explicit_state(events: list[RuntimeEvent]) -> str | None:
    for event in events:
        state = str(event.metadata.get("coverage_state", ""))
        if state in COVERAGE_STATES:
            return state
        if event.event_type in COVERAGE_STATES:
            return event.event_type
    return None
