# dangerous_skills Sample-10 Critical Re-Scan Report

Generated at: 2026-04-27 07:49 Asia/Shanghai

## Why This Re-Run Exists

The previous instruction-chain aggregation capped document-derived closed risk paths at `high`. That was too conservative for cases that cross an external trust boundary and then set up persistence or bulk/future environment modification. The analyzer now allows these document-supported latent paths to set `static_supply_chain_risk.level=critical` and `final_risk_level=critical`, while still marking them as `instruction_derived` and `not observed at runtime`.

## Command

```bash
python3 scripts/batch_scan_skills.py \
  --skills-root /root/projects/ProvLoom/dangerous_skills \
  --skill-paths-file test_dss/sample10_critical_20260427-074858/skill-paths.txt \
  --log-dir test_dss/sample10_critical_20260427-074858 \
  --analysis-mode epg_with_filtering \
  --network-policy disabled \
  --max-workers 3 \
  --default-timeout-seconds 120 \
  --no-resume
```

## Results

| Skill | Status | Dynamic risk | Final risk | Static supply-chain risk | Chain evidence | Instruction chain actions |
| --- | --- | --- | --- | --- | --- | --- |
| `auto-updater-2yq87` | completed | low | critical | critical | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> global_environment_modification -> persistence_setup -> bulk_skill_update |
| `clawhub-6yr3b` | skipped | n/a | critical | critical | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> global_environment_modification -> bulk_skill_update |
| `openclaw-backup-dnkxm` | completed | low | critical | critical | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> persistence_setup -> sensitive_capability_context |
| `ethereum-gas-tracker-abxf0` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `google-workspace-2z5dp` | skipped | n/a | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `insider-wallets-finder-1a7pi` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `lost-bitcoin-10li1` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `phantom-0jcvy` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `polymarket-25nwy` | skipped | n/a | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `solana-07bcb` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |

## Summary

- Total sampled: 10
- Final critical: 3 (`auto-updater-2yq87`, `clawhub-6yr3b`, `openclaw-backup-dnkxm`)
- Final medium: 7
- Critical cases are document-supported latent attack paths, not observed runtime execution chains.
- Medium cases remain capability / external-agent trust risks without persistence or bulk update sinks.

## Raw Outputs

- `test_dss/sample10_critical_20260427-074858/results.jsonl`
- `test_dss/sample10_critical_20260427-074858/summary.json`
- Per-skill JSON files under `test_dss/sample10_critical_20260427-074858/skills/`
