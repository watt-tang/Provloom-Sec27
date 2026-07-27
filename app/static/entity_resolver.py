from __future__ import annotations

import posixpath
from pathlib import PurePosixPath
from urllib.parse import urlparse

from app.static.action_schema import StaticAction
from app.static.entity_schema import EntityResolution, Mention, StaticEntity


class EntityResolver:
    def resolve(self, mentions: list[Mention], actions: list[StaticAction]) -> tuple[list[StaticEntity], list[EntityResolution]]:
        entities: list[StaticEntity] = []
        entity_by_key: dict[tuple[str, str], StaticEntity] = {}
        mention_to_entity: dict[str, str] = {}
        for mention in mentions:
            entity_type = _entity_type_for_mention(mention)
            canonical = _canonical_for_mention(mention)
            key = (entity_type, canonical.lower())
            entity = entity_by_key.get(key)
            if entity is None:
                entity = StaticEntity(
                    entity_id=f"ENT{len(entities) + 1:04d}",
                    entity_type=entity_type,
                    canonical_value=canonical,
                    aliases=[mention.raw_value],
                    mentions=[mention.mention_id],
                    resolution_method=[mention.extractor],
                    runtime_alignment_keys=_alignment_keys(entity_type, canonical),
                )
                entity_by_key[key] = entity
                entities.append(entity)
            else:
                if mention.raw_value not in entity.aliases:
                    entity.aliases.append(mention.raw_value)
                entity.mentions.append(mention.mention_id)
            mention_to_entity[mention.mention_id] = entity.entity_id

        resolutions: list[EntityResolution] = []
        resolutions.extend(self._download_target_resolutions(actions, mentions, mention_to_entity, entities))
        resolutions.extend(self._archive_extract_resolutions(actions, mention_to_entity))
        resolutions.extend(self._pronoun_resolutions(actions, entities))
        resolutions.extend(self._basename_conflicts(entities, {mention.mention_id: mention for mention in mentions}))
        return entities, resolutions

    def _download_target_resolutions(self, actions: list[StaticAction], mentions: list[Mention], mention_to_entity: dict[str, str], entities: list[StaticEntity]) -> list[EntityResolution]:
        results: list[EntityResolution] = []
        for action in actions:
            if action.action_type != "DOWNLOAD" or not action.source_mentions or not action.destination_mentions:
                continue
            a = mention_to_entity.get(action.source_mentions[0])
            b = mention_to_entity.get(action.destination_mentions[0])
            if a and b:
                results.append(_resolution(len(results), a, b, "downloaded_as", "deterministic", [action.evidence.unit_id if action.evidence else ""], 0.95, "confirmed", "strong"))
        return results

    def _archive_extract_resolutions(self, actions: list[StaticAction], mention_to_entity: dict[str, str]) -> list[EntityResolution]:
        results: list[EntityResolution] = []
        last_archive: str | None = None
        for action in actions:
            if action.action_type == "DOWNLOAD":
                for mention_id in action.object_mentions + action.destination_mentions:
                    ent = mention_to_entity.get(mention_id)
                    if ent:
                        last_archive = ent
            if action.action_type == "EXTRACT" and last_archive:
                for mention_id in action.object_mentions:
                    target = mention_to_entity.get(mention_id)
                    if target and target != last_archive:
                        results.append(_resolution(1000 + len(results), last_archive, target, "extracts_to", "deterministic", [action.evidence.unit_id if action.evidence else ""], 0.8, "probable", "strong"))
        return results

    def _pronoun_resolutions(self, actions: list[StaticAction], entities: list[StaticEntity]) -> list[EntityResolution]:
        results: list[EntityResolution] = []
        last_artifact = next((entity for entity in reversed(entities) if entity.entity_type in {"File", "Script", "Archive"}), None)
        if last_artifact is None:
            return results
        for action in actions:
            text = action.evidence.exact_text.lower() if action.evidence else ""
            if any(term in text for term in {"it", "downloaded script", "the updater", "the archive"}):
                action.metadata.setdefault("coreference_entity_id", last_artifact.entity_id)
                results.append(_resolution(2000 + len(results), last_artifact.entity_id, last_artifact.entity_id, "refers_to", "deterministic_coreference", [action.evidence.unit_id if action.evidence else ""], 0.66, "probable", "medium"))
        return results

    def _basename_conflicts(self, entities: list[StaticEntity], mention_by_id: dict[str, Mention]) -> list[EntityResolution]:
        results: list[EntityResolution] = []
        by_base: dict[str, list[StaticEntity]] = {}
        for entity in entities:
            if entity.entity_type not in {"File", "Script", "Archive"}:
                continue
            by_base.setdefault(posixpath.basename(entity.canonical_value), []).append(entity)
        for group in by_base.values():
            if len(group) <= 1:
                continue
            values = {item.canonical_value for item in group}
            if len(values) <= 1:
                continue
            for entity in group:
                entity.resolution_status = "ambiguous"
                entity.confidence = min(entity.confidence, 0.55)
            units = sorted({mention_by_id[m].unit_id for e in group for m in e.mentions if m in mention_by_id})
            results.append(_resolution(3000 + len(results), group[0].entity_id, group[1].entity_id, "same_basename_conflict", "deterministic_conflict", units, 0.35, "rejected", "weak"))
        return results


def _entity_type_for_mention(mention: Mention) -> str:
    if mention.mention_type in {"url", "domain", "ip"}:
        return "NetworkEndpoint"
    if mention.mention_type == "environment_variable":
        return "EnvironmentVariable"
    if mention.mention_type == "credential_pattern":
        return "Credential"
    if mention.mention_type == "permission":
        return "Permission"
    if mention.mention_type == "persistence_location":
        return "PersistenceTarget"
    if mention.mention_type == "shell_command":
        return "Executable"
    if mention.mention_type == "local_file_reference":
        return "RuntimeAlignableObject"
    if mention.mention_type == "file_path":
        suffix = PurePosixPath(mention.normalized_value).suffix.lower()
        if suffix in {".zip", ".tar", ".gz", ".tgz", ".7z"}:
            return "Archive"
        if suffix in {".py", ".sh", ".js", ".ts", ".ps1"}:
            return "Script"
        if any(token in mention.normalized_value.lower() for token in {"credential", "secret", "token", "id_rsa", ".env"}):
            return "SensitiveResource"
        return "File"
    return "UnknownEntity"


def _canonical_for_mention(mention: Mention) -> str:
    return mention.normalized_value


def _alignment_keys(entity_type: str, value: str) -> dict:
    if entity_type == "NetworkEndpoint":
        parsed = urlparse(value)
        return {"scheme": parsed.scheme, "domain": parsed.hostname, "port": parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None), "path": parsed.path}
    if entity_type in {"File", "Script", "Archive", "SensitiveResource"}:
        return {"relative_path": value if not value.startswith("/") else "", "basename": posixpath.basename(value), "normalized_path": value}
    if entity_type == "EnvironmentVariable":
        return {"name": value}
    if entity_type == "Executable":
        return {"command": value.split()[0] if value else value, "script": value}
    if entity_type == "RuntimeAlignableObject":
        return {"alias": value.lower()}
    return {}


def _resolution(index: int, a: str, b: str, relation: str, method: str, units: list[str], confidence: float, status: str, strength: str) -> EntityResolution:
    return EntityResolution(
        f"R{index + 1:04d}",
        a,
        b,
        relation,
        method,
        [u for u in units if u],
        confidence,
        status,
        {"resolution_strength": strength, "ambiguities": [] if status != "rejected" else ["basename_conflict"]},
    )
