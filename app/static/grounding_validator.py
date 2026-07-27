from __future__ import annotations

from app.static.action_schema import ACTION_TYPES, MODALITIES, StaticAction
from app.static.artifact_schema import LoadedArtifact, SemanticUnit
from app.static.entity_schema import Mention


class GroundingValidator:
    def validate(
        self,
        actions: list[StaticAction],
        *,
        artifacts: list[LoadedArtifact],
        units: list[SemanticUnit],
        mentions: list[Mention],
    ) -> tuple[list[StaticAction], list[dict]]:
        unit_by_id = {unit.unit_id: unit for unit in units}
        mention_by_id = {mention.mention_id: mention for mention in mentions}
        validated: list[StaticAction] = []
        reports: list[dict] = []
        for action in actions:
            notes: list[str] = []
            status = "valid"
            if action.action_type not in ACTION_TYPES:
                status = "unsupported"
                notes.append("action_type_not_in_closed_enum")
            if action.modality not in MODALITIES:
                status = "ambiguous"
                notes.append("modality_not_in_closed_enum")
            if action.evidence is None or action.evidence.unit_id not in unit_by_id:
                status = "unsupported"
                notes.append("missing_evidence_unit")
            else:
                unit = unit_by_id[action.evidence.unit_id]
                if action.evidence.exact_text not in unit.text and unit.text not in action.evidence.exact_text:
                    status = "conflicting"
                    notes.append("exact_text_not_found_in_unit")
                for mention_id in action.object_mentions + action.source_mentions + action.destination_mentions + action.tool_mentions:
                    mention = mention_by_id.get(mention_id)
                    if mention is None:
                        status = "partially_grounded"
                        notes.append(f"missing_mention:{mention_id}")
                    elif mention.unit_id != unit.unit_id:
                        if action.extractor == "deterministic_flow":
                            notes.append(f"deterministic_flow_cross_unit_mention:{mention_id}")
                        else:
                            status = "partially_grounded"
                            notes.append(f"mention_outside_evidence_unit:{mention_id}")
            action.grounding_status = status
            action.validation_notes = sorted(set(action.validation_notes + notes))
            reports.append({"action_id": action.action_id, "grounding_status": status, "validation_notes": action.validation_notes})
            if status != "unsupported":
                validated.append(action)
        return validated, reports
