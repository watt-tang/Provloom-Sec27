from __future__ import annotations

VALID_CONTEXTS = {"installation", "setup", "execution", "maintenance", "update", "documentation"}
ALLOWED_MODALITIES = {"required", "recommended"}
CONDITIONAL_MODALITIES = {"conditional", "optional"}
SUPPRESSED_MODALITIES = {"prohibited", "example_only", "descriptive"}

TRUST_BOUNDARY_ENTITY_TYPES = {"URL", "domain", "external_resource", "repository"}
CONTROL_TRANSFER_OPS = {"execute", "invoke", "install", "register_service", "register_cron", "persist", "modify_environment", "update", "replace"}
IMPACT_OPS = {"register_service", "register_cron", "persist", "modify_environment", "modify_configuration", "update", "replace", "grant_permission", "send", "connect_account"}

PATH_TYPES = {
    "remote_fetch_execute",
    "supply_chain_persistence",
    "global_environment_modification",
    "credential_or_account_risk",
    "bulk_update_authority",
    "instruction_candidate_exfiltration",
}
