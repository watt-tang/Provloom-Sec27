from __future__ import annotations

from app.instruction.models import Action, Entity, EntityLink


REFERENCE_TERMS = {
    "the archive",
    "downloaded archive",
    "the downloaded file",
    "downloaded file",
    "the executable",
    "the installer",
    "the cli",
    "this tool",
    "it",
}


class EntityLinker:
    def link(self, actions: list[Action], entities: list[Entity]) -> tuple[list[Action], list[EntityLink]]:
        links: list[EntityLink] = []
        by_id = {entity.entity_id: entity for entity in entities}
        last_remote_artifact: str | None = None
        last_local_artifact: str | None = None

        for action in actions:
            if action.operation in {"download", "fetch", "install"}:
                if action.source_entity_id:
                    last_remote_artifact = action.source_entity_id
                local_candidate = action.destination_entity_id or action.object_entity_id
                if local_candidate and _is_local_artifact(by_id.get(local_candidate)):
                    last_local_artifact = local_candidate
            if action.operation in {"extract", "execute", "register_cron", "register_service", "persist", "update", "replace"}:
                if action.object_entity_id is None and last_local_artifact:
                    action.object_entity_id = last_local_artifact
                    links.append(
                        EntityLink(
                            source_entity_id=last_local_artifact,
                            target_entity_id=last_local_artifact,
                            relation="implicit_object_from_previous_artifact",
                            evidence=list(action.evidence_span_ids),
                            method="adjacent_action_coreference",
                            confidence=0.66,
                        )
                    )
                if action.source_entity_id is None and last_remote_artifact and action.operation == "install":
                    action.source_entity_id = last_remote_artifact
                if action.source_entity_id is None and last_remote_artifact and action.operation == "update" and _looks_like_artifact_update(action):
                    action.source_entity_id = last_remote_artifact

            self._link_aliases(action, entities, links)

        links.extend(self._same_canonical_links(entities))
        return actions, links

    def _link_aliases(self, action: Action, entities: list[Entity], links: list[EntityLink]) -> None:
        text = " ".join(str(value) for value in action.metadata.values()).lower()
        if not any(term in text for term in REFERENCE_TERMS):
            return
        compatible = [
            entity for entity in entities
            if entity.entity_type in {"archive", "script", "executable", "package", "local_file"}
        ]
        if not compatible:
            return
        target = compatible[-1]
        if action.object_entity_id is None:
            action.object_entity_id = target.entity_id
            links.append(
                EntityLink(
                    source_entity_id=target.entity_id,
                    target_entity_id=target.entity_id,
                    relation="coreference_candidate",
                    evidence=list(action.evidence_span_ids),
                    method="deterministic_reference_term",
                    confidence=0.55,
                )
            )

    @staticmethod
    def _same_canonical_links(entities: list[Entity]) -> list[EntityLink]:
        links: list[EntityLink] = []
        by_name: dict[str, list[Entity]] = {}
        for entity in entities:
            by_name.setdefault(entity.canonical_name.lower(), []).append(entity)
        for group in by_name.values():
            if len(group) < 2:
                continue
            root = group[0]
            for other in group[1:]:
                links.append(
                    EntityLink(
                        source_entity_id=root.entity_id,
                        target_entity_id=other.entity_id,
                        relation="alias",
                        evidence=list(set(root.evidence_span_ids + other.evidence_span_ids)),
                        method="same_canonical_name",
                        confidence=0.9,
                    )
                )
        return links


def _is_local_artifact(entity: Entity | None) -> bool:
    return bool(entity and entity.entity_type in {"archive", "script", "executable", "package", "local_file", "directory"})


def _looks_like_artifact_update(action: Action) -> bool:
    text = " ".join(
        str(action.metadata.get(key, ""))
        for key in ["raw_snippet", "command", "script_name"]
    ).lower()
    return any(token in text for token in {"downloaded", "archive", "agent", "skill", "sync", "updater", "installed"})
