from __future__ import annotations

from app.instruction.models import Action, Entity, InstructionEdge, TypedInstructionGraph, ValidatedInstructionPath
from app.instruction.path_rules import ALLOWED_MODALITIES, CONDITIONAL_MODALITIES, CONTROL_TRANSFER_OPS, IMPACT_OPS, SUPPRESSED_MODALITIES, TRUST_BOUNDARY_ENTITY_TYPES, VALID_CONTEXTS
from app.instruction.serialization import stable_id


class PathValidator:
    def validate(
        self,
        *,
        actions: list[Action],
        entities: list[Entity],
        graph: TypedInstructionGraph,
    ) -> tuple[list[ValidatedInstructionPath], list[ValidatedInstructionPath], list[str]]:
        entity_by_id = {entity.entity_id: entity for entity in entities}
        edge_by_pair = {(edge.source_node_id, edge.target_node_id, edge.edge_type): edge for edge in graph.edges}
        validated: list[ValidatedInstructionPath] = []
        partial: list[ValidatedInstructionPath] = []
        abstentions: list[str] = []

        active_actions = [action for action in actions if action.modality not in SUPPRESSED_MODALITIES]
        suppressed_count = len(actions) - len(active_actions)
        if suppressed_count:
            abstentions.append(f"suppressed_{suppressed_count}_prohibited_example_or_defensive_actions")

        for path_type in [
            "remote_fetch_execute",
            "supply_chain_persistence",
            "global_environment_modification",
            "credential_or_account_risk",
            "bulk_update_authority",
            "instruction_candidate_exfiltration",
        ]:
            path = self._find_path(path_type, active_actions, entity_by_id, edge_by_pair)
            if path is None:
                continue
            if path.completeness == "closed":
                validated.append(path)
            else:
                partial.append(path)

        if not validated and not partial:
            abstentions.append("no_supported_instruction_path")
        return validated, partial, abstentions

    def _find_path(
        self,
        path_type: str,
        actions: list[Action],
        entity_by_id: dict[str, Entity],
        edge_by_pair: dict[tuple[str, str, str], InstructionEdge],
    ) -> ValidatedInstructionPath | None:
        trust = [action for action in actions if self._crosses_trust_boundary(action, entity_by_id)]
        control = [action for action in actions if action.operation in CONTROL_TRANSFER_OPS]
        impact = [action for action in actions if action.operation in IMPACT_OPS]

        if path_type == "remote_fetch_execute":
            trust = [action for action in trust if action.operation in {"download", "fetch", "install"}]
            control = [action for action in control if action.operation in {"execute", "install"}]
            control = sorted(control, key=lambda action: 0 if action.operation == "execute" else 1)
            impact = control
        elif path_type == "supply_chain_persistence":
            trust = [action for action in trust if action.operation in {"download", "fetch", "install"}]
            impact = [action for action in actions if action.operation in {"register_cron", "register_service", "persist"}]
            control = [action for action in control if action.operation in {"execute", "install", "extract"}]
        elif path_type == "global_environment_modification":
            trust = [action for action in trust if action.operation in {"download", "fetch", "install"}]
            impact = [action for action in actions if action.operation in {"modify_environment", "modify_configuration"}]
        elif path_type == "credential_or_account_risk":
            trust = [action for action in actions if action.operation in {"authenticate", "connect_account", "access_credential"}]
            control = [action for action in actions if action.operation in {"connect_account", "authenticate"}]
            impact = [action for action in actions if action.operation in {"grant_permission", "connect_account"}]
        elif path_type == "bulk_update_authority":
            trust = [action for action in trust if action.operation in {"download", "fetch", "install"}]
            control = [action for action in actions if action.operation in {"register_cron", "persist", "install"}]
            impact = [action for action in actions if action.operation in {"update", "replace"}]
        elif path_type == "instruction_candidate_exfiltration":
            trust = [action for action in actions if action.operation in {"access_credential", "read"}]
            control = [action for action in actions if action.operation in {"send", "upload"}]
            impact = control

        if not trust or not control or not impact:
            return self._partial_path(path_type, trust, control, impact)

        trust_action = trust[0]
        control_action = self._first_related(trust_action, control) or control[0]
        impact_action = self._first_related(control_action, impact) or impact[0]
        actions = [trust_action, control_action, impact_action]
        limitations = self._limitations(actions)
        if path_type == "bulk_update_authority":
            limitations = [item for item in limitations if item != "conditional_step_requires_runtime_or_config_confirmation"]
        completeness = "closed" if not limitations and self._objects_related(actions, entity_by_id) else "partial"
        if path_type == "instruction_candidate_exfiltration" and completeness == "closed":
            completeness = "candidate"
            limitations.append("static_only_candidate_exfiltration_requires_runtime_confirmation")
        confidence = min(action.confidence for action in actions)
        if completeness != "closed":
            confidence = min(confidence, 0.62)
        node_ids = [action.action_id for action in actions]
        evidence_span_ids = _dedupe([span for action in actions for span in action.evidence_span_ids])
        edge_ids = [edge.edge_id for edge in self._edges_for_actions(actions, edge_by_pair)]
        return ValidatedInstructionPath(
            path_id=stable_id("ipath", path_type, node_ids),
            path_type=path_type,
            node_ids=node_ids,
            edge_ids=edge_ids,
            trust_boundary_node=trust_action.action_id,
            control_transfer_node=control_action.action_id,
            impact_sink_node=impact_action.action_id,
            evidence_span_ids=evidence_span_ids,
            confidence=confidence,
            completeness=completeness,
            limitations=limitations,
            metadata={"action_operations": [action.operation for action in actions]},
        )

    def _partial_path(self, path_type: str, trust: list[Action], control: list[Action], impact: list[Action]) -> ValidatedInstructionPath | None:
        present = trust + control + impact
        if not present:
            return None
        limitations = []
        if not trust:
            limitations.append("missing_trust_boundary")
        if not control:
            limitations.append("missing_control_transfer")
        if not impact:
            limitations.append("missing_security_impact_sink")
        limitations.extend(item for item in self._limitations(present) if item not in limitations)
        return ValidatedInstructionPath(
            path_id=stable_id("ipath", path_type, [action.action_id for action in present], limitations),
            path_type=path_type,
            node_ids=[action.action_id for action in present],
            edge_ids=[],
            trust_boundary_node=trust[0].action_id if trust else None,
            control_transfer_node=control[0].action_id if control else None,
            impact_sink_node=impact[0].action_id if impact else None,
            evidence_span_ids=_dedupe([span for action in present for span in action.evidence_span_ids]),
            confidence=min([action.confidence for action in present] or [0.0]),
            completeness="partial",
            limitations=limitations,
            metadata={"action_operations": [action.operation for action in present]},
        )

    @staticmethod
    def _crosses_trust_boundary(action: Action, entity_by_id: dict[str, Entity]) -> bool:
        candidates = [action.source_entity_id, action.destination_entity_id, action.object_entity_id]
        for entity_id in candidates:
            entity = entity_by_id.get(entity_id or "")
            if entity and entity.entity_type in TRUST_BOUNDARY_ENTITY_TYPES:
                return True
            if entity and entity.attributes.get("remote") is True:
                return True
        return bool(action.metadata.get("agent_install"))

    @staticmethod
    def _first_related(source: Action, candidates: list[Action]) -> Action | None:
        source_entities = {source.object_entity_id, source.source_entity_id, source.destination_entity_id}
        source_entities.discard(None)
        for candidate in candidates:
            if candidate.action_id == source.action_id:
                continue
            candidate_entities = {candidate.object_entity_id, candidate.source_entity_id, candidate.destination_entity_id}
            candidate_entities.discard(None)
            if source_entities & candidate_entities:
                return candidate
            if set(source.evidence_span_ids) & set(candidate.evidence_span_ids):
                return candidate
        return None

    @staticmethod
    def _objects_related(actions: list[Action], entity_by_id: dict[str, Entity]) -> bool:
        entity_sets = []
        for action in actions:
            entities = {action.object_entity_id, action.source_entity_id, action.destination_entity_id}
            entities.discard(None)
            entity_sets.append(entities)
        if entity_sets[0] & entity_sets[1] or entity_sets[1] & entity_sets[2] or entity_sets[0] & entity_sets[2]:
            return True
        entity_names = [
            {_entity_name(entity_by_id, entity_id) for entity_id in entities}
            for entities in entity_sets
        ]
        if _archive_to_extracted_path_related(entity_names[0], entity_names[1] | entity_names[2]):
            return True
        span_sets = [set(action.evidence_span_ids) for action in actions]
        control_like = {"execute", "register_cron", "register_service", "persist", "update", "replace", "modify_environment", "modify_configuration"}
        return bool(
            span_sets[0] & span_sets[1]
            and span_sets[1] & span_sets[2]
            and any(action.operation in control_like for action in actions)
        )

    @staticmethod
    def _limitations(actions: list[Action]) -> list[str]:
        limitations: list[str] = []
        if any(action.modality in CONDITIONAL_MODALITIES for action in actions):
            limitations.append("conditional_step_requires_runtime_or_config_confirmation")
        if any(action.modality not in ALLOWED_MODALITIES | CONDITIONAL_MODALITIES for action in actions):
            limitations.append("modality_not_strong_enough")
        if any(action.context not in VALID_CONTEXTS for action in actions):
            limitations.append("context_not_setup_install_update_or_maintenance")
        if any(not action.evidence_span_ids for action in actions):
            limitations.append("missing_evidence_span")
        return limitations

    @staticmethod
    def _edges_for_actions(actions: list[Action], edge_by_pair: dict[tuple[str, str, str], InstructionEdge]) -> list[InstructionEdge]:
        edges: list[InstructionEdge] = []
        for action in actions:
            for entity_id in [action.object_entity_id, action.source_entity_id, action.destination_entity_id, action.instrument_entity_id]:
                if not entity_id:
                    continue
                for (source, target, _), edge in edge_by_pair.items():
                    if source == action.action_id and target == entity_id:
                        edges.append(edge)
        return edges


def _dedupe(items: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _entity_name(entity_by_id: dict[str, Entity], entity_id: str) -> str:
    entity = entity_by_id.get(entity_id)
    return entity.canonical_name if entity else ""


def _archive_to_extracted_path_related(archives: set[str], candidates: set[str]) -> bool:
    for archive in archives:
        if not archive:
            continue
        archive_root = archive
        for suffix in [".tar.gz", ".tgz", ".zip", ".tar", ".gz", ".7z"]:
            if archive_root.lower().endswith(suffix):
                archive_root = archive_root[: -len(suffix)]
                break
        for candidate in candidates:
            if candidate and candidate.startswith(archive_root.rstrip("/") + "/"):
                return True
    return False
