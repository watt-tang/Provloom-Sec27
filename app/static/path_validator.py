from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import urlparse

from app.static.action_schema import StaticAction
from app.static.entity_schema import StaticEntity
from app.static.instruction_graph import InstructionProvenanceGraph, StaticGraphEdge
from app.static.policy_classifier import PolicyClassifier
from app.static.static_config import StaticAnalysisConfig


SUPPRESSED_MODALITIES = {"prohibited", "example_only", "hypothetical", "quoted_untrusted", "descriptive"}
PACKAGE_INSTALL_RE = re.compile(r"\b(pip|pip3|npm|yarn|pnpm|apt(?:-get)?|cargo|gem|go|brew)\s+(?:install|add)\b", re.I)
AUTH_USE_RE = re.compile(r"\b(authorization|bearer|x-api-key|api[_-]?key|access[_-]?token|client[_-]?secret|oauth|sdk client|login|authenticate|auth)\b", re.I)
PAYLOAD_USE_RE = re.compile(r"\b(body|payload|form|multipart|message|attachment|upload|diagnostic|bundle|exfiltrate)\b", re.I)
LOCAL_EXPOSURE_RE = re.compile(r"\b(log|stdout|stderr|debug|temporary file|temp file|cache|report|print|echo|write|save|store)\b", re.I)
PRIV_ESC_RE = re.compile(r"\b(chmod\s+(?:[0-7]*[42][0-7]{3}|u\+s|g\+s)|setuid|setgid|/etc/sudoers|docker\.sock|root shell|disable sandbox|container escape|usermod|groupmod)\b", re.I)
PIPE_EXEC_RE = re.compile(r"\b(curl|wget)\b[^|\n]*(?:\|\s*(?:sudo\s+)?(?:sh|bash|python|python3))", re.I)
TEMP_OR_HIDDEN_RE = re.compile(r"(^|/)(tmp|temp|\\.[A-Za-z0-9_.-]+|[^/]+)$", re.I)


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
    capability_type: str = "unknown_security_capability"
    policy_status: str = "not_applicable"
    alert_status: str = "none"
    trust_assessment: dict[str, Any] = field(default_factory=dict)
    data_continuity: dict[str, Any] = field(default_factory=dict)
    scope_continuity: dict[str, Any] = field(default_factory=dict)
    resolution_strength_summary: str = "none"
    raw_candidate_chain_count: int = 1
    canonical_chain_count: int = 1
    duplicate_suppressed_count: int = 0
    invalid_path_count: int = 0
    uncertain_path_count: int = 0
    policy_reasons: list[str] = field(default_factory=list)
    duplicate_evidence_ids: list[str] = field(default_factory=list)
    review_reason: str = "not_applicable"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StaticPathValidator:
    def __init__(self, config: StaticAnalysisConfig | None = None) -> None:
        self.config = config or StaticAnalysisConfig()
        self.policy = PolicyClassifier()

    def validate(self, *, actions: list[StaticAction], entities: list[StaticEntity], graph: InstructionProvenanceGraph) -> list[StaticChain]:
        entities_by_id = {entity.entity_id: entity for entity in entities}
        context = _Context(actions, entities_by_id, graph, self.config)
        active = [action for action in actions if action.modality not in SUPPRESSED_MODALITIES and action.grounding_status != "unsupported"]
        suppressed = [action for action in actions if action.modality in SUPPRESSED_MODALITIES]
        chains: list[StaticChain] = []
        chains.extend(self._credential_paths(active, context))
        chains.extend(self._download_execute(active, context))
        chains.extend(self._dropper(active, context))
        chains.extend(self._persistence(active, context))
        chains.extend(self._destructive(active, context))
        chains.extend(self._permission(active, context))
        chains.extend(self._reverse_shell(active, context))
        chains.extend(self._ransomware(active, context))
        chains.extend(self._resource_abuse(active, context))
        chains.extend(self._instruction_policy(active, context))
        if not chains and active:
            chains.append(self._isolated(active, context, "isolated"))
        if not chains and suppressed:
            chains.append(self._isolated(suppressed, context, "none", limitations=["suppressed_modalities_present"]))
        return _canonical_dedupe(chains)

    def _credential_paths(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        reads = [a for a in actions if a.action_type in {"READ", "ACCESS_CREDENTIAL", "COLLECT"}]
        sends = [a for a in actions if a.action_type in {"SEND", "UPLOAD", "INVOKE_API"}]
        writes = [a for a in actions if a.action_type in {"WRITE", "MODIFY"}]
        for read in reads:
            sensitive = context.sensitive_entities(read)
            if not sensitive:
                continue
            source = sensitive[0]
            for write in writes:
                continuity = context.data_continuity(read, write, required_entity_ids={source.entity_id})
                if continuity["closed"] and LOCAL_EXPOSURE_RE.search(_text(write)):
                    chains.append(self._chain("credential_exposure", "closed", [read, write], source, context.primary_non_network_entity(write), context, [], "credential_exposure", continuity))
            for send in sends:
                sink = context.primary_endpoint(send)
                continuity = context.data_continuity(read, send, required_entity_ids={source.entity_id})
                limitations: list[str] = []
                if sink is None:
                    limitations.append("missing_external_sink")
                if not continuity["closed"]:
                    limitations.append("missing_shared_sensitive_data_object")
                if _generic_sink_local_credential(source, read, send):
                    continuity = {"closed": False, "method": "generic_sink_local_credential_without_source_read", "shared_entity_ids": [], "resolution_strength": "none"}
                    limitations.append("source_not_proven_before_sink")
                trust = context.trust_assessment(source, sink, [read, send])
                capability = _credential_capability(read, send, source, sink, trust, continuity)
                status = "closed" if sink and continuity["closed"] and capability in {"credential_authentication", "credential_exfiltration"} else "partial"
                if capability == "credential_exfiltration" and not _payload_use(send):
                    status = "partial"
                    limitations.append("sensitive_value_not_proven_in_payload_or_upload")
                if capability == "credential_authentication" and not trust.get("trusted"):
                    status = "partial"
                    limitations.append("authentication_endpoint_not_trusted_or_declared")
                chains.append(self._chain("credential_exfiltration", status, [read, send], source, sink, context, limitations, capability, continuity, trust))
        return chains

    def _download_execute(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        for install in [a for a in actions if a.action_type == "INSTALL" and _package_install(a)]:
            chains.append(self._chain("download_execute", "closed", [install], context.primary_endpoint(install), context.primary_non_network_entity(install), context, [], "declared_dependency_install", {"closed": True, "method": "package_manager_install", "resolution_strength": "strong"}))
        downloads = [a for a in actions if a.action_type == "DOWNLOAD"]
        executes = [a for a in actions if a.action_type in {"EXECUTE", "INSTALL"} and not _package_install(a)]
        for download in downloads:
            if not _artifact_download(download):
                continue
            source = context.primary_endpoint(download) or context.unique_endpoint_fallback(download)
            local = context.download_target(download)
            if source and PIPE_EXEC_RE.search(_text(download)):
                capability = _download_capability(source, None, context, pipe_exec=True)
                chains.append(self._chain("download_execute", "closed", [download], source, source, context, [], capability, {"closed": True, "method": "pipe_to_shell_without_artifact_identity", "resolution_strength": "medium"}))
            for execute in executes:
                if local and not _executes_artifact(execute, local):
                    continue
                continuity = context.artifact_continuity(download, execute, local)
                if not source:
                    continue
                limitations = [] if continuity["closed"] else ["downloaded_artifact_not_resolved_to_executed_artifact"]
                capability = _download_capability(source, local or context.primary_non_network_entity(execute), context, pipe_exec=False)
                status = "closed" if continuity["closed"] else "partial"
                chains.append(self._chain("download_execute", status, [download, execute], source, context.primary_non_network_entity(execute) or local, context, limitations, capability, continuity))
        return chains

    def _dropper(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        for download in [a for a in actions if a.action_type == "DOWNLOAD"]:
            archive = context.primary_entity(download, {"Archive"})
            source = context.primary_endpoint(download)
            if not archive or not source:
                continue
            for extract in [a for a in actions if a.action_type in {"EXTRACT", "DECODE"}]:
                extract_refs_archive = archive.entity_id in context.entity_ids(extract) or context.same_unit(download, extract)
                if not extract_refs_archive:
                    continue
                for execute in [a for a in actions if a.action_type == "EXECUTE"]:
                    executed = context.primary_entity(execute, {"Script", "Executable", "File"})
                    if not executed:
                        continue
                    status = "closed" if context.scope_continuity(extract, execute)["compatible"] else "uncertain"
                    chains.append(self._chain("dropper_multistage_execution", status, [download, extract, execute], source, executed, context, [] if status == "closed" else ["extracted_artifact_identity_not_fully_resolved"], "untrusted_download_execute" if _external(source, self.config.trusted_domains) else "remote_artifact_execution", {"closed": status == "closed", "method": "archive_extract_execute", "resolution_strength": "strong" if status == "closed" else "medium"}))
        return chains

    def _persistence(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        for action in [a for a in actions if a.action_type in {"PERSIST", "REGISTER_SERVICE"}]:
            sink = context.primary_entity(action, {"PersistenceTarget"}) or context.persistence_entity_in_unit(action)
            strong = bool(sink and _strong_persistence_write(_text(action)))
            status = "closed" if strong else "partial"
            capability = "agent_lifecycle_persistence" if strong and _agent_lifecycle_persistence(_text(action)) else "persistence_write"
            limitations = [] if strong else ["missing_concrete_persistence_write_or_register"]
            if not sink:
                limitations.append("missing_persistence_target_entity")
            chains.append(self._chain("persistence", status, [action], context.primary_non_network_entity(action), sink, context, limitations, capability, {"closed": strong, "method": "explicit_persistence_target" if strong else "persistence_keyword_only", "resolution_strength": "strong" if strong else "none"}))
        return chains

    def _destructive(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        for action in [a for a in actions if a.action_type in {"WRITE", "MODIFY", "DELETE"}]:
            target = next((e for e in context.action_entities(action) if e.entity_type in {"SensitiveResource", "File"} and _protected(e)), None)
            if target and _destructive_operation(_text(action), action.action_type):
                chains.append(self._chain("destructive_modification", "closed", [action], target, target, context, [], "destructive_modification", {"closed": True, "method": "protected_target", "resolution_strength": "strong"}))
        return chains

    def _permission(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        for action in [a for a in actions if a.action_type in {"REQUEST_PERMISSION", "CHANGE_PERMISSION", "MODIFY"}]:
            text = _text(action)
            if not (PRIV_ESC_RE.search(text) or action.action_type in {"REQUEST_PERMISSION", "CHANGE_PERMISSION"}):
                continue
            permission = context.primary_entity(action, {"Permission"})
            if PRIV_ESC_RE.search(text):
                capability = "privilege_escalation"
                status = "closed"
            elif action.action_type == "CHANGE_PERMISSION":
                capability = "permission_expansion"
                status = "partial"
            else:
                capability = "permission_request"
                status = "closed"
            chains.append(self._chain("permission_expansion", status, [action], None, permission, context, [] if status == "closed" else ["permission_boundary_not_comparable"], capability, {"closed": status == "closed", "method": "permission_keyword_with_boundary_check", "resolution_strength": "strong" if capability == "privilege_escalation" else "medium"}))
        return chains

    def _reverse_shell(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        for action in actions:
            text = _text(action)
            if _reverse_shell_pattern(text):
                endpoint = context.primary_endpoint(action)
                status = "closed" if endpoint or re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text) else "partial"
                chains.append(self._chain("reverse_shell", status, [action], endpoint, endpoint, context, [] if status == "closed" else ["missing_reverse_shell_endpoint"], "reverse_shell", {"closed": status == "closed", "method": "endpoint_shell_redirect", "resolution_strength": "strong"}))
        return chains

    def _ransomware(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        for action in actions:
            text = _text(action)
            if _ransomware_pattern(text):
                target = context.primary_non_network_entity(action)
                chains.append(self._chain("ransomware", "closed", [action], target, target, context, [], "ransomware", {"closed": True, "method": "enumerate_encrypt_destructive", "resolution_strength": "strong"}))
        return chains

    def _resource_abuse(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        for action in actions:
            text = _text(action)
            if _resource_abuse_pattern(text):
                chains.append(self._chain("resource_abuse", "closed", [action], None, None, context, [], "resource_abuse", {"closed": True, "method": "explicit_resource_abuse_execution", "resolution_strength": "strong"}))
        return chains

    def _instruction_policy(self, actions: list[StaticAction], context: "_Context") -> list[StaticChain]:
        chains: list[StaticChain] = []
        for action in actions:
            text = _text(action)
            capability = _instruction_policy_capability(text)
            if capability:
                chains.append(self._chain("instruction_policy", "closed", [action], None, None, context, [], capability, {"closed": True, "method": "explicit_instruction_policy_span", "resolution_strength": "strong"}))
        return chains

    def _isolated(self, actions: list[StaticAction], context: "_Context", status: str, limitations: list[str] | None = None) -> StaticChain:
        return self._chain("isolated_security_actions", status, actions[:3], None, None, context, limitations or ["no_valid_source_to_sink_template"], "unknown_security_capability", {"closed": False, "method": "isolated", "resolution_strength": "none"})

    def _chain(
        self,
        chain_type: str,
        status: str,
        actions: list[StaticAction],
        source: StaticEntity | None,
        sink: StaticEntity | None,
        context: "_Context",
        limitations: list[str],
        capability_type: str,
        data_continuity: dict[str, Any],
        trust_assessment: dict[str, Any] | None = None,
    ) -> StaticChain:
        action_ids = [a.action_id for a in actions]
        edges = [e for e in context.graph.edges if set(e.action_ids) & set(action_ids)]
        evidence_units = sorted({u for edge in edges for u in edge.evidence_unit_ids} | {a.evidence.unit_id for a in actions if a.evidence})
        modalities = [a.modality for a in actions]
        limitations = list(dict.fromkeys(limitations))
        unresolved = [e.entity_id for e in [source, sink] if e and e.resolution_status in {"ambiguous", "unresolved"}]
        if _has_uncertain_critical_edge(edges) and status == "closed":
            status = "uncertain"
            limitations.append("critical_edge_not_explicit_or_deterministic_resolved")
        if any(a.grounding_status in {"partially_grounded", "ambiguous"} for a in actions) and status == "closed":
            status = "uncertain"
            limitations.append("partially_grounded_action")
        if any(a.modality in {"conditional", "optional"} for a in actions) and status == "closed":
            status = "partial"
            limitations.append("conditional_or_optional_gate")
        if unresolved and status == "closed":
            status = "uncertain"
            limitations.append("unresolved_critical_entity")
        trust = trust_assessment or {"trusted": False, "trust_status": "unknown", "trust_reason": "not_applicable", "resolution_strength": "none", "evidence_unit_ids": []}
        policy = self.policy.classify(
            path_status=status,
            capability_type=capability_type,
            trust_assessment=trust,
            limitations=limitations,
            has_unresolved=bool(unresolved),
            has_conditions=any(a.condition or a.modality in {"conditional", "optional"} for a in actions),
        )
        nodes = ([source.entity_id] if source else []) + action_ids + ([sink.entity_id] if sink and sink != source else [])
        scope = _scope_summary(actions)
        strength = str(data_continuity.get("resolution_strength", "none"))
        explanation = f"{status} instruction-derived {capability_type} capability over actions {', '.join(action_ids)}; policy={policy.policy_status}, alert={policy.alert_status}."
        return StaticChain(
            _chain_id(capability_type, nodes, evidence_units),
            chain_type,
            status,
            policy.review_priority,
            source.entity_id if source else None,
            sink.entity_id if sink else None,
            nodes,
            [e.edge_id for e in edges],
            evidence_units,
            unresolved,
            [a.condition for a in actions if a.condition],
            _modality_summary(modalities),
            explanation,
            limitations,
            policy.policy_reasons,
            capability_type,
            policy.policy_status,
            policy.alert_status,
            trust,
            data_continuity,
            scope,
            strength,
            1,
            1,
            0,
            0,
            1 if status == "uncertain" else 0,
            policy.policy_reasons,
            [],
            policy.review_reason,
        )


class _Context:
    def __init__(self, actions: list[StaticAction], entities: dict[str, StaticEntity], graph: InstructionProvenanceGraph, config: StaticAnalysisConfig) -> None:
        self.actions = actions
        self.entities = entities
        self.graph = graph
        self.config = config
        self.mention_to_entity = {mention: entity.entity_id for entity in entities.values() for mention in entity.mentions}

    def entity_ids(self, action: StaticAction) -> set[str]:
        mentions = action.object_mentions + action.source_mentions + action.destination_mentions + action.tool_mentions
        ids = {self.mention_to_entity[m] for m in mentions if m in self.mention_to_entity}
        coref = action.metadata.get("coreference_entity_id")
        if isinstance(coref, str):
            ids.add(coref)
        return ids

    def action_entities(self, action: StaticAction) -> list[StaticEntity]:
        return [self.entities[eid] for eid in self.entity_ids(action) if eid in self.entities]

    def primary_entity(self, action: StaticAction, types: set[str]) -> StaticEntity | None:
        return next((e for e in self.action_entities(action) if e.entity_type in types), None)

    def primary_non_network_entity(self, action: StaticAction) -> StaticEntity | None:
        return next((e for e in self.action_entities(action) if e.entity_type not in {"NetworkEndpoint", "APIEndpoint", "Permission"}), None)

    def primary_endpoint(self, action: StaticAction) -> StaticEntity | None:
        return self.primary_entity(action, {"NetworkEndpoint", "APIEndpoint"})

    def persistence_entity_in_unit(self, action: StaticAction) -> StaticEntity | None:
        if not action.evidence:
            return None
        text = action.evidence.exact_text.lower()
        return next((e for e in self.entities.values() if e.entity_type == "PersistenceTarget" and e.canonical_value.lower() in text), None)

    def unique_endpoint_fallback(self, action: StaticAction) -> StaticEntity | None:
        if not any(e.entity_type == "EnvironmentVariable" for e in self.action_entities(action)):
            return None
        endpoints = [e for e in self.entities.values() if e.entity_type in {"NetworkEndpoint", "APIEndpoint"}]
        return endpoints[0] if len(endpoints) == 1 else None

    def download_target(self, action: StaticAction) -> StaticEntity | None:
        destination_entities = [self.entities[self.mention_to_entity[m]] for m in action.destination_mentions if m in self.mention_to_entity]
        return next((e for e in destination_entities if e.entity_type in {"File", "Script", "Archive", "Executable", "RuntimeAlignableObject"}), None)

    def sensitive_entities(self, action: StaticAction) -> list[StaticEntity]:
        entities = []
        for entity in self.action_entities(action):
            if entity.entity_type in {"Credential", "SensitiveResource"}:
                entities.append(entity)
            elif entity.entity_type == "EnvironmentVariable" and _sensitive_text(entity.canonical_value):
                entities.append(entity)
            elif entity.entity_type not in {"EnvironmentVariable"} and _sensitive_text(entity.canonical_value):
                entities.append(entity)
        return sorted(entities, key=_sensitive_entity_rank)

    def data_continuity(self, read: StaticAction, sink: StaticAction, required_entity_ids: set[str]) -> dict[str, Any]:
        read_ids = self.entity_ids(read)
        sink_ids = self.entity_ids(sink)
        shared = sorted(read_ids & sink_ids & required_entity_ids)
        if shared:
            return {"closed": True, "method": "same_sensitive_entity", "shared_entity_ids": shared, "resolution_strength": "strong"}
        if self.same_unit(read, sink) and _pronoun_or_payload_reference(sink):
            return {"closed": True, "method": "same_unit_pronoun_or_payload_reference", "shared_entity_ids": sorted(required_entity_ids), "resolution_strength": "medium"}
        return {"closed": False, "method": "no_shared_data_object", "shared_entity_ids": [], "resolution_strength": "none"}

    def artifact_continuity(self, download: StaticAction, execute: StaticAction, local: StaticEntity | None) -> dict[str, Any]:
        exec_ids = self.entity_ids(execute)
        if local and local.entity_id in exec_ids:
            return {"closed": True, "method": "same_downloaded_artifact_entity", "shared_entity_ids": [local.entity_id], "resolution_strength": "strong"}
        coref = execute.metadata.get("coreference_entity_id")
        if local and coref == local.entity_id and self.scope_continuity(download, execute)["compatible"]:
            return {"closed": True, "method": "unique_coreference_to_downloaded_artifact", "shared_entity_ids": [local.entity_id], "resolution_strength": "medium"}
        return {"closed": False, "method": "no_artifact_identity_continuity", "shared_entity_ids": [], "resolution_strength": "none"}

    def same_unit(self, a: StaticAction, b: StaticAction) -> bool:
        return bool(a.evidence and b.evidence and a.evidence.unit_id == b.evidence.unit_id)

    def scope_continuity(self, a: StaticAction, b: StaticAction) -> dict[str, Any]:
        if self.same_unit(a, b):
            return {"compatible": True, "scope": "same_unit"}
        if a.evidence and b.evidence and a.evidence.artifact_id == b.evidence.artifact_id and a.metadata.get("parent_section") and a.metadata.get("parent_section") == b.metadata.get("parent_section"):
            shared = bool(self.entity_ids(a) & self.entity_ids(b))
            return {"compatible": shared, "scope": "same_section_with_shared_entity" if shared else "same_section_no_shared_entity"}
        return {"compatible": False, "scope": "no_explicit_scope_continuity"}

    def trust_assessment(self, credential: StaticEntity | None, endpoint: StaticEntity | None, actions: list[StaticAction]) -> dict[str, Any]:
        if endpoint is None or endpoint.entity_type not in {"NetworkEndpoint", "APIEndpoint"}:
            return {"trusted": False, "trust_status": "unknown", "trust_reason": "missing_endpoint", "resolution_strength": "none", "confidence": 0.0, "evidence_unit_ids": []}
        parsed = urlparse(endpoint.canonical_value)
        domain = (parsed.hostname or "").lower()
        evidence = sorted({a.evidence.unit_id for a in actions if a.evidence})
        if domain in {d.lower() for d in self.config.trusted_domains}:
            return {"trusted": True, "trust_status": "trusted", "trust_reason": "configured_allowlist", "resolution_strength": "strong", "confidence": 1.0, "evidence_unit_ids": evidence}
        if credential and _credential_domain_match(credential, domain):
            return {"trusted": True, "trust_status": "trusted", "trust_reason": "credential_service_domain_match", "resolution_strength": "strong", "confidence": 0.9, "evidence_unit_ids": evidence}
        if any("oauth" in _text(action).lower() for action in actions) and ("oauth" in domain or "/token" in parsed.path.lower()):
            return {"trusted": True, "trust_status": "trusted", "trust_reason": "oauth_token_exchange", "resolution_strength": "strong", "confidence": 0.85, "evidence_unit_ids": evidence}
        return {"trusted": False, "trust_status": "untrusted", "trust_reason": "untrusted_or_undeclared_endpoint", "resolution_strength": "strong", "confidence": 0.5, "evidence_unit_ids": evidence}


def _credential_capability(read: StaticAction, send: StaticAction, source: StaticEntity, sink: StaticEntity | None, trust: dict[str, Any], continuity: dict[str, Any]) -> str:
    if _authentication_use(send) or _source_only_in_auth_context(send, source):
        return "credential_authentication"
    if not sink or not continuity.get("closed"):
        return "credential_exposure" if LOCAL_EXPOSURE_RE.search(_text(send)) else "credential_exfiltration"
    return "credential_exfiltration" if _payload_use(send) and not trust.get("trusted") else "credential_authentication" if trust.get("trusted") else "credential_exposure"


def _authentication_use(action: StaticAction) -> bool:
    return bool(AUTH_USE_RE.search(_text(action))) and not _payload_use(action)


def _payload_use(action: StaticAction) -> bool:
    flow_role = str(action.metadata.get("flow_role", ""))
    if flow_role in {"payload", "socket_payload", "subprocess_payload", "pipe_payload"}:
        return True
    text = _text(action)
    if re.search(r"\b(authorization|bearer|x-api-key)\b", text, re.I) and not re.search(r"\b(body|payload|message|content|upload|attachment|diagnostic|bundle)\b", text, re.I):
        return False
    return bool(PAYLOAD_USE_RE.search(text) or any(token in text for token in ["-d", "--data", "--data-raw", "--data-binary", "-F", "--form", "json=", "data=", "files=", "body:"]))


def _strong_persistence_write(text: str) -> bool:
    lower = text.lower()
    if _agent_lifecycle_persistence(text):
        return bool(re.search(r"\b(write|modify|add|install|register|create|set up|configure)\b", lower))
    if re.search(r"\b(crontab\s+-|@reboot|/etc/cron|systemctl\b[^\n;]*\benable\b|launchctl\s+(?:load|bootstrap)|schtasks\s+/create)\b", lower):
        return True
    if re.search(r"\b(write|modify|install|register|create|enable)\b", lower) and re.search(r"\b(cron|crontab|systemd|launchd|scheduled task|startup directory|autostart)\b", lower):
        return True
    return False


def _agent_lifecycle_persistence(text: str) -> bool:
    return bool(re.search(r"(\.claude/settings\.json|sessionstart|lifecycle hook|opencode hook|agent session hook)", text, re.I))


def _source_only_in_auth_context(action: StaticAction, source: StaticEntity) -> bool:
    text = _text(action)
    if not AUTH_USE_RE.search(text):
        return False
    source_terms = {source.canonical_value.lower(), *(alias.lower() for alias in source.aliases)}
    source_terms = {term for term in source_terms if term and len(term) > 2}
    matched_lines = [line for line in text.splitlines() if any(term in line.lower() for term in source_terms)]
    if not matched_lines:
        return False
    return all(
        (AUTH_USE_RE.search(line) or re.search(r"\b(headers?|add_header)\b", line, re.I))
        and not (PAYLOAD_USE_RE.search(line) or any(token in line for token in ["-d", "--data", "--data-raw", "--data-binary", "-F", "--form", "json=", "data=", "files=", "body:"]))
        for line in matched_lines
    )


def _download_capability(source: StaticEntity, local: StaticEntity | None, context: _Context, *, pipe_exec: bool) -> str:
    if not _external(source, context.config.trusted_domains):
        return "remote_artifact_execution"
    value = (local.canonical_value if local else source.canonical_value).lower()
    if pipe_exec and local is None:
        return "remote_artifact_execution"
    if pipe_exec or TEMP_OR_HIDDEN_RE.search(value):
        return "untrusted_download_execute"
    return "remote_artifact_execution"


def _artifact_download(action: StaticAction) -> bool:
    text = _text(action)
    if PIPE_EXEC_RE.search(text):
        return True
    if re.search(r"\b(curl|wget)\b", text, re.I) and re.search(r"(\s-o\s|\s-O\b|--output|--output-document)", text, re.I):
        return True
    if re.search(r"\b(download|fetch|retrieve)\b", text, re.I) and re.search(r"\b(script|binary|executable|archive|zip|tar|payload|updater|installer|artifact|file)\b", text, re.I):
        return True
    return False


def _executes_artifact(action: StaticAction, artifact: StaticEntity) -> bool:
    value = artifact.canonical_value
    if not value:
        return False
    text = _text(action)
    escaped = re.escape(value)
    basename = re.escape(value.rsplit("/", 1)[-1])
    runner = r"(?:python3?|node|bash|sh|ruby|perl|pwsh|powershell)"
    if re.search(rf"\b{runner}\s+{escaped}\b", text, re.I) or re.search(rf"\b{runner}\s+[^\n;]*{basename}\b", text, re.I):
        return True
    if re.search(rf"(^|\s)(?:\.\/|/tmp/|/var/tmp/|~?/)[^\s;]*{basename}\b", text, re.I):
        return True
    if re.search(rf"chmod\s+\+x\s+[^\n;]*{basename}.*(?:&&|;)\s*[^\n;]*{basename}", text, re.I):
        return True
    return False


def _package_install(action: StaticAction) -> bool:
    return bool(PACKAGE_INSTALL_RE.search(_text(action)))


def _protected(entity: StaticEntity) -> bool:
    text = entity.canonical_value.lower()
    return any(token in text for token in {"id_rsa", ".env", "credential", "secret", "/etc/", "/root/", "sudoers"})


def _destructive_operation(text: str, action_type: str) -> bool:
    if action_type == "DELETE":
        return True
    lower = text.lower()
    if re.search(r"\b(delete|remove|rm\s+-rf|overwrite|wipe|truncate|encrypt|destroy|corrupt)\b", lower):
        return True
    if re.search(r"\b(modify|replace|change)\b", lower) and re.search(r"\b(/etc/|sudoers|/root/|authorized_keys)\b", lower):
        return True
    return False


def _external(entity: StaticEntity | None, trusted_domains: list[str]) -> bool:
    if entity is None or entity.entity_type not in {"NetworkEndpoint", "APIEndpoint"}:
        return False
    parsed = urlparse(entity.canonical_value)
    trusted = {domain.lower() for domain in trusted_domains}
    return bool(parsed.hostname and parsed.hostname.lower() not in trusted)


def _credential_domain_match(credential: StaticEntity, domain: str) -> bool:
    tokens = set(re.split(r"[^a-z0-9]+", " ".join([credential.canonical_value, *credential.aliases]).lower()))
    tokens -= {"api", "key", "token", "secret", "client", "credential", "credentials", "access", "auth", "password", "env"}
    return any(token and len(token) >= 3 and token in domain for token in tokens)


def _sensitive_text(value: str) -> bool:
    return bool(re.search(r"(api[_-]?key|token|secret|credential|id_rsa|\.env|password)", value, re.I))


def _sensitive_entity_rank(entity: StaticEntity) -> tuple[int, str]:
    generic = entity.canonical_value.lower() in {"token", "key", "secret", "credential", "credentials", "password"}
    type_rank = {"EnvironmentVariable": 0, "SensitiveResource": 1, "Credential": 2}.get(entity.entity_type, 3)
    return (4 if generic else type_rank, entity.canonical_value)


def _generic_sink_local_credential(source: StaticEntity, read: StaticAction, send: StaticAction) -> bool:
    if source.entity_type != "Credential" or source.canonical_value.lower() not in {"token", "key", "secret", "credential", "credentials", "password"}:
        return False
    if not read.evidence or not send.evidence or read.evidence.unit_id != send.evidence.unit_id:
        return False
    text = read.evidence.exact_text.lower()
    return read.action_type == "ACCESS_CREDENTIAL" and not any(token in text for token in {"read", "load", "open", "getenv", "os.environ", "cat ", ".env", "id_rsa"})


def _pronoun_or_payload_reference(action: StaticAction) -> bool:
    return bool(re.search(r"\b(it|same|credential|credentials|token|secret|key|payload|body|file|diagnostic)\b", _text(action), re.I))


def _has_uncertain_critical_edge(edges: list[StaticGraphEdge]) -> bool:
    for edge in edges:
        strength = edge.metadata.get("resolution_strength")
        if edge.evidence_level in {"uncertain", "inferred"} or strength == "weak":
            return True
    return False


def _scope_summary(actions: list[StaticAction]) -> dict[str, Any]:
    units = [a.evidence.unit_id for a in actions if a.evidence]
    artifacts = [a.evidence.artifact_id for a in actions if a.evidence]
    sections = [a.metadata.get("parent_section", "") for a in actions]
    if len(set(units)) == 1 and units:
        scope = "same_unit"
    elif len(set(artifacts)) == 1 and len(set(sections)) == 1 and sections and sections[0]:
        scope = "same_section"
    elif len(set(artifacts)) > 1:
        scope = "cross_artifact_requires_explicit_entity_continuity"
    else:
        scope = "mixed"
    return {"scope": scope, "unit_ids": units, "artifact_ids": artifacts, "sections": sections}


def _modality_summary(modalities: list[str]) -> str:
    if not modalities:
        return "unknown"
    if len(set(modalities)) == 1:
        return modalities[0]
    return ",".join(sorted(set(modalities)))


def _text(action: StaticAction) -> str:
    return action.evidence.exact_text if action.evidence else ""


def _chain_id(chain_type: str, nodes: list[str], units: list[str]) -> str:
    return "SC" + hashlib.sha256(repr((chain_type, nodes, units)).encode("utf-8")).hexdigest()[:10]


def _canonical_key(chain: StaticChain) -> tuple[Any, ...]:
    return (
        chain.capability_type,
        chain.source_entity,
        tuple(node for node in chain.ordered_nodes if node.startswith("A")),
        chain.sink_entity,
        chain.modality_summary,
        tuple(chain.conditions),
    )


def _canonical_dedupe(chains: list[StaticChain]) -> list[StaticChain]:
    raw_input_count = len(chains)
    grouped: dict[tuple[Any, ...], list[StaticChain]] = defaultdict(list)
    for chain in chains:
        grouped[_canonical_key(chain)].append(chain)
    primary: list[StaticChain] = []
    for group in grouped.values():
        group.sort(key=_chain_rank)
        chosen = group[0]
        duplicates = group[1:]
        chosen.duplicate_suppressed_count = len(duplicates)
        chosen.duplicate_evidence_ids = sorted({unit for chain in duplicates for unit in chain.evidence_unit_ids})
        chosen.raw_candidate_chain_count = len(group)
        primary.append(chosen)
    by_capability: dict[str, list[StaticChain]] = defaultdict(list)
    for chain in primary:
        by_capability[chain.capability_type].append(chain)
    result: list[StaticChain] = []
    for group in by_capability.values():
        group.sort(key=_chain_rank)
        visible = group[:3]
        suppressed = group[3:]
        if suppressed:
            extra = sum(1 + chain.duplicate_suppressed_count for chain in suppressed)
            visible[-1].duplicate_suppressed_count += extra
            visible[-1].duplicate_evidence_ids.extend(sorted({unit for chain in suppressed for unit in chain.evidence_unit_ids}))
        result.extend(visible)
    total_duplicates = max(0, raw_input_count - len(result))
    total_uncertain = sum(1 for chain in result if chain.status == "uncertain")
    for index, chain in enumerate(result):
        chain.raw_candidate_chain_count = raw_input_count
        chain.canonical_chain_count = len(result)
        chain.duplicate_suppressed_count = total_duplicates if index == 0 else 0
        chain.uncertain_path_count = total_uncertain
    return result


def _chain_rank(chain: StaticChain) -> tuple[int, int, int, int, float]:
    explicit_edges = sum(1 for edge_id in chain.ordered_edges if edge_id)
    unresolved = len(chain.unresolved_links)
    strength_rank = {"strong": 0, "medium": 1, "weak": 2, "none": 3}.get(chain.resolution_strength_summary, 3)
    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(chain.review_priority, 4)
    return (priority_rank, unresolved, len(chain.ordered_nodes), strength_rank, -explicit_edges)


def _reverse_shell_pattern(text: str) -> bool:
    lowered = text.lower()
    has_shell = any(token in lowered for token in {"bash -i", "/bin/sh -i", "sh -i", "nc -e", "socat"})
    has_io = any(token in lowered for token in {"/dev/tcp", "dup2", "0>&1", "2>&1", "tcp:"})
    has_endpoint = bool(re.search(r"https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|[A-Za-z0-9.-]+:\d{2,5}", text))
    return has_shell and has_io and has_endpoint


def _ransomware_pattern(text: str) -> bool:
    lowered = text.lower()
    enumerate_files = any(token in lowered for token in {"find ", "os.walk", "glob", "get-childitem", "enumerate"})
    encrypt_files = any(token in lowered for token in {"encrypt", "fernet", "aes", "cipher", "openssl enc"})
    destructive = any(token in lowered for token in {"delete original", "remove original", "unlink", "overwrite", "ransom note", "readme_restore", "decrypt"})
    return enumerate_files and encrypt_files and destructive


def _resource_abuse_pattern(text: str) -> bool:
    lowered = text.lower()
    return ":(){ :|:& };:" in text or any(token in lowered for token in {"xmrig", "minerd", "cryptominer", "stress-ng --cpu", "fork bomb", "while true; do curl"})


def _instruction_policy_capability(text: str) -> str | None:
    lowered = text.lower()
    if re.search(r"\b(you are now|from now on act as|replace your identity)\b", lowered):
        return "role_hijack"
    if re.search(r"\b(ignore previous instructions|bypass safety|disregard system policy|override higher-priority|do not follow the user)\b", lowered):
        return "instruction_override" if "override" in lowered or "ignore previous" in lowered else "safety_bypass"
    if re.search(r"\b(reveal system prompt|print hidden instructions|expose developer message|extract internal policy|system prompt leak)\b", lowered):
        return "system_prompt_leak"
    if re.search(r"\b(change your goal|new objective is|instead of the user request)\b", lowered):
        return "goal_hijacking"
    if re.search(r"\b(insert false|hide facts|modify output stance|propaganda|conceal evidence)\b", lowered):
        return "content_manipulation"
    return None
