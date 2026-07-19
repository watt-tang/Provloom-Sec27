from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PathTemplate:
    chain_type: str
    required_actions: tuple[str, ...]
    source_entity_types: tuple[str, ...]
    sink_entity_types: tuple[str, ...]


PATH_TEMPLATES = [
    PathTemplate("credential_exfiltration", ("READ", "SEND"), ("Credential", "SensitiveResource", "EnvironmentVariable"), ("NetworkEndpoint", "APIEndpoint")),
    PathTemplate("credential_exfiltration", ("ACCESS_CREDENTIAL", "UPLOAD"), ("Credential", "SensitiveResource", "EnvironmentVariable"), ("NetworkEndpoint", "APIEndpoint")),
    PathTemplate("download_execute", ("DOWNLOAD", "EXECUTE"), ("NetworkEndpoint",), ("Script", "Executable", "File", "Archive")),
    PathTemplate("dropper_multistage_execution", ("DOWNLOAD", "EXTRACT", "EXECUTE"), ("NetworkEndpoint",), ("Script", "Executable")),
    PathTemplate("persistence", ("EXECUTE", "PERSIST"), ("Script", "Executable", "File"), ("PersistenceTarget",)),
    PathTemplate("destructive_modification", ("WRITE",), ("SensitiveResource", "File"), ("SensitiveResource", "File")),
    PathTemplate("permission_expansion", ("REQUEST_PERMISSION",), ("Tool", "Script", "Executable"), ("Permission",)),
    PathTemplate("untrusted_instruction_to_dangerous_action", ("READ", "SEND"), ("DataObject", "File"), ("NetworkEndpoint",)),
]
