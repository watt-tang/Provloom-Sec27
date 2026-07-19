from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.static.action_schema import StaticAction
from app.static.entity_schema import StaticEntity
from app.static.instruction_graph import InstructionProvenanceGraph, StaticGraphEdge
from app.static.static_config import StaticAnalysisConfig
from app.static.static_scoring import review_priority


SUPPRESSED_MODALITIES = {"prohibited", "example_only", "hypothetical", "quoted_untrusted", "descriptive"}


@dataclass
class StaticChain:
    chain_id: str
    chain_type: str
    status: str
    review_priority: str
    source_entity: str | None
    sink_entity: str | None
    ordered_nodes: list[str]
    ordered_edges: list[str]
    evidence_unit_ids: list[str]
    unresolved_links: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    modality_summary: str = "unknown"
    explanation: str = ""
    limitations: list[str] = field(default_factory=list)
    priority_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StaticPathValidator:
    def __init__(self, config: StaticAnalysisConfig | None = None) -> None:
        self.config = config or StaticAnalysisConfig()

    def validate(self, *, actions: list[StaticAction], entities: list[StaticEntity], graph: InstructionProvenanceGraph) -> list[StaticChain]:
        chains: list[StaticChain] = []
        entities_by_id = {entity.entity_id: entity for entity in entities}
        active = [action for action in actions if action.modality not in SUPPRESSED_MODALITIES and action.grounding_status != "unsupported"]
        suppressed = [action for action in actions if action.modality in SUPPRESSED_MODALITIES]
        chains.extend(self._credential_exfil(active, entities_by_id, graph))
        chains.extend(self._download_execute(active, entities_by_id, graph))
        chains.extend(self._dropper(active, entities_by_id, graph))
        chains.extend(self._persistence(active, entities_by_id, graph))
        chains.extend(self._destructive(active, entities_by_id, graph))
        chains.extend(self._permission(active, entities_by_id, graph))
        if not chains and active:
            chains.append(self._isolated(active, graph, "isolated"))
        if not chains and suppressed:
            chains.append(self._isolated(suppressed, graph, "none", limitations=["suppressed_modalities_present"]))
        return _dedupe(chains)

    def _credential_exfil(self, actions: list[StaticAction], entities: dict[str, StaticEntity], graph: InstructionProvenanceGraph) -> list[StaticChain]:
        reads = [a for a in actions if a.action_type in {"READ", "ACCESS_CREDENTIAL", "COLLECT"}]
        sends = [a for a in actions if a.action_type in {"SEND", "UPLOAD", "INVOKE_API"}]
        chains = []
        for read in reads:
            read_entities = _action_entities(read, entities)
            sensitive = [e for e in read_entities if e.entity_type in {"Credential", "SensitiveResource", "EnvironmentVariable"}]
            if not sensitive:
                continue
            for send in sends:
                send_entities = _action_entities(send, entities)
                sinks = [e for e in send_entities if e.entity_type in {"NetworkEndpoint", "APIEndpoint"}]
                if not sinks:
                    chains.append(self._chain("credential_exfiltration", "partial", [read, send], sensitive[0], None, graph, ["missing_external_sink"]))
                    continue
                continuity = _share_entity(read, send) or any(e.entity_id in _entity_ids(send, entities) for e in sensitive)
                status = "closed" if continuity else "partial"
                limitations = [] if continuity else ["missing_entity_continuity_between_read_and_send"]
                chains.append(self._chain("credential_exfiltration", status, [read, send], sensitive[0], sinks[0], graph, limitations))
        return chains

    def _download_execute(self, actions: list[StaticAction], entities: dict[str, StaticEntity], graph: InstructionProvenanceGraph) -> list[StaticChain]:
        downloads = [a for a in actions if a.action_type == "DOWNLOAD"]
        executes = [a for a in actions if a.action_type in {"EXECUTE", "INSTALL"}]
        chains = []
        for download in downloads:
            source = next((e for e in _action_entities(download, entities) if e.entity_type == "NetworkEndpoint"), None)
            if source is None and any(e.entity_type == "EnvironmentVariable" for e in _action_entities(download, entities)):
                endpoints = [entity for entity in entities.values() if entity.entity_type == "NetworkEndpoint"]
                source = endpoints[0] if len(endpoints) == 1 else None
            local = next((e for e in _action_entities(download, entities) if e.entity_type in {"File", "Script", "Archive", "Executable", "RuntimeAlignableObject"}), None)
            for execute in executes:
                exec_entity = next((e for e in _action_entities(execute, entities) if e.entity_type in {"File", "Script", "Archive", "Executable", "RuntimeAlignableObject"}), None)
                continuity = bool(local and exec_entity and (local.entity_id == exec_entity.entity_id or _basename_related(local, exec_entity)))
                if source and (continuity or local is None):
                    chains.append(self._chain("download_execute", "closed" if continuity else "partial", [download, execute], source, exec_entity or local, graph, [] if continuity else ["download_target_not_resolved_to_executed_artifact"]))
        return chains

    def _dropper(self, actions: list[StaticAction], entities: dict[str, StaticEntity], graph: InstructionProvenanceGraph) -> list[StaticChain]:
        chains = []
        for download in [a for a in actions if a.action_type == "DOWNLOAD"]:
            for extract in [a for a in actions if a.action_type in {"EXTRACT", "DECODE"}]:
                for execute in [a for a in actions if a.action_type == "EXECUTE"]:
                    source = next((e for e in _action_entities(download, entities) if e.entity_type == "NetworkEndpoint"), None)
                    archive = next((e for e in _action_entities(download, entities) if e.entity_type == "Archive"), None)
                    executed = next((e for e in _action_entities(execute, entities) if e.entity_type in {"Script", "Executable", "File"}), None)
                    if source and archive and executed:
                        chains.append(self._chain("dropper_multistage_execution", "closed", [download, extract, execute], source, executed, graph, []))
        return chains

    def _persistence(self, actions: list[StaticAction], entities: dict[str, StaticEntity], graph: InstructionProvenanceGraph) -> list[StaticChain]:
        persists = [a for a in actions if a.action_type in {"PERSIST", "REGISTER_SERVICE"}]
        executes = [a for a in actions if a.action_type in {"EXECUTE", "WRITE"}]
        if persists and executes:
            sink = next((e for a in persists for e in _action_entities(a, entities) if e.entity_type == "PersistenceTarget"), None)
            source = next((e for a in executes for e in _action_entities(a, entities) if e.entity_type in {"Script", "Executable", "File"}), None)
            return [self._chain("persistence", "closed" if sink else "partial", [executes[0], persists[0]], source, sink, graph, [] if sink else ["missing_persistence_target_entity"])]
        return []

    def _destructive(self, actions: list[StaticAction], entities: dict[str, StaticEntity], graph: InstructionProvenanceGraph) -> list[StaticChain]:
        destructive = [a for a in actions if a.action_type in {"WRITE", "MODIFY", "DELETE"}]
        chains = []
        for action in destructive:
            target = next((e for e in _action_entities(action, entities) if e.entity_type in {"SensitiveResource", "File"} and _protected(e)), None)
            if target:
                chains.append(self._chain("destructive_modification", "closed", [action], target, target, graph, []))
        return chains

    def _permission(self, actions: list[StaticAction], entities: dict[str, StaticEntity], graph: InstructionProvenanceGraph) -> list[StaticChain]:
        perms = [a for a in actions if a.action_type in {"REQUEST_PERMISSION", "CHANGE_PERMISSION"}]
        return [self._chain("permission_expansion", "closed", [a], None, next((e for e in _action_entities(a, entities) if e.entity_type == "Permission"), None), graph, []) for a in perms]

    def _isolated(self, actions: list[StaticAction], graph: InstructionProvenanceGraph, status: str, limitations: list[str] | None = None) -> StaticChain:
        return self._chain("isolated_security_actions", status, actions[:3], None, None, graph, limitations or ["no_valid_source_to_sink_template"])

    def _chain(self, chain_type: str, status: str, actions: list[StaticAction], source: StaticEntity | None, sink: StaticEntity | None, graph: InstructionProvenanceGraph, limitations: list[str]) -> StaticChain:
        action_ids = [a.action_id for a in actions]
        edges = [e for e in graph.edges if set(e.action_ids) & set(action_ids)]
        evidence_units = sorted({u for edge in edges for u in edge.evidence_unit_ids})
        modalities = [a.modality for a in actions]
        if any(a.grounding_status in {"partially_grounded", "ambiguous"} for a in actions) and status == "closed":
            status = "uncertain"
            limitations.append("partially_grounded_action")
        if any(a.modality in {"conditional", "optional"} for a in actions) and status == "closed":
            status = "partial"
            limitations.append("conditional_or_optional_gate")
        unresolved = [e.entity_id for e in [source, sink] if e and e.resolution_status in {"ambiguous", "unresolved"}]
        priority, reasons = review_priority(status, chain_type, [e.evidence_level for e in edges], modalities, unresolved, _external(sink, self.config.trusted_domains))
        nodes = ([source.entity_id] if source else []) + action_ids + ([sink.entity_id] if sink else [])
        explanation = f"{status} instruction-derived {chain_type} path over actions {', '.join(action_ids)}."
        return StaticChain(_chain_id(chain_type, nodes, evidence_units), chain_type, status, priority, source.entity_id if source else None, sink.entity_id if sink else None, nodes, [e.edge_id for e in edges], evidence_units, unresolved, [a.condition for a in actions if a.condition], _modality_summary(modalities), explanation, limitations, reasons)


def _action_entities(action: StaticAction, entities: dict[str, StaticEntity]) -> list[StaticEntity]:
    ids = _entity_ids(action, entities)
    return [entities[eid] for eid in ids if eid in entities]


def _entity_ids(action: StaticAction, entities: dict[str, StaticEntity]) -> list[str]:
    mention_to_entity = {mention: entity.entity_id for entity in entities.values() for mention in entity.mentions}
    return [mention_to_entity[m] for m in action.object_mentions + action.source_mentions + action.destination_mentions + action.tool_mentions if m in mention_to_entity]


def _share_entity(a: StaticAction, b: StaticAction) -> bool:
    return bool(set(a.object_mentions + a.source_mentions + a.destination_mentions) & set(b.object_mentions + b.source_mentions + b.destination_mentions))


def _basename_related(a: StaticEntity, b: StaticEntity) -> bool:
    if a.resolution_status == "ambiguous" or b.resolution_status == "ambiguous":
        return False
    abase = a.runtime_alignment_keys.get("basename") or a.runtime_alignment_keys.get("alias")
    bbase = b.runtime_alignment_keys.get("basename") or b.runtime_alignment_keys.get("alias")
    return bool(abase and bbase and abase == bbase)


def _protected(entity: StaticEntity) -> bool:
    text = entity.canonical_value.lower()
    return any(token in text for token in {"id_rsa", ".env", "credential", "secret", "/etc/", "/root/"})


def _external(entity: StaticEntity | None, trusted_domains: list[str]) -> bool:
    if entity is None or entity.entity_type not in {"NetworkEndpoint", "APIEndpoint"}:
        return False
    parsed = urlparse(entity.canonical_value)
    trusted = {domain.lower() for domain in trusted_domains}
    return bool(parsed.hostname and parsed.hostname.lower() not in trusted)


def _modality_summary(modalities: list[str]) -> str:
    if not modalities:
        return "unknown"
    if len(set(modalities)) == 1:
        return modalities[0]
    return ",".join(sorted(set(modalities)))


def _chain_id(chain_type: str, nodes: list[str], units: list[str]) -> str:
    return "SC" + hashlib.sha256(repr((chain_type, nodes, units)).encode("utf-8")).hexdigest()[:10]


def _dedupe(chains: list[StaticChain]) -> list[StaticChain]:
    seen: set[str] = set()
    result: list[StaticChain] = []
    for chain in chains:
        key = f"{chain.chain_type}:{chain.status}:{chain.ordered_nodes}"
        if key in seen:
            continue
        seen.add(key)
        result.append(chain)
    return result
