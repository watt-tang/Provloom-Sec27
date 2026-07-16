# dangerous_skills Sample-10 Scan Report

Generated at: 2026-04-27 07:42 Asia/Shanghai

## Command

```bash
python3 scripts/batch_scan_skills.py \
  --skills-root /root/projects/ProvLoom/dangerous_skills \
  --skill-paths-file test_dss/sample10_20260427-074214/skill-paths.txt \
  --log-dir test_dss/sample10_20260427-074214 \
  --analysis-mode epg_with_filtering \
  --network-policy disabled \
  --max-workers 3 \
  --default-timeout-seconds 120 \
  --no-resume
```

## Sampled Skills

The sample intentionally mixes different families:

- auto-updater: `auto-updater-2yq87`
- clawhub: `clawhub-6yr3b`
- ethereum gas tracker: `ethereum-gas-tracker-abxf0`
- google workspace: `google-workspace-2z5dp`
- insider wallets: `insider-wallets-finder-1a7pi`
- lost bitcoin: `lost-bitcoin-10li1`
- phantom: `phantom-0jcvy`
- polymarket: `polymarket-25nwy`
- solana: `solana-07bcb`
- openclaw backup: `openclaw-backup-dnkxm`

## Results

| Skill | Status | Dynamic risk | Final risk | Static supply-chain risk | Chain evidence | Instruction chain actions |
| --- | --- | --- | --- | --- | --- | --- |
| `auto-updater-2yq87` | completed | low | high | high | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> global_environment_modification -> persistence_setup -> bulk_skill_update |
| `clawhub-6yr3b` | skipped | n/a | high | high | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> global_environment_modification -> bulk_skill_update |
| `openclaw-backup-dnkxm` | completed | low | high | high | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> persistence_setup -> sensitive_capability_context |
| `ethereum-gas-tracker-abxf0` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `google-workspace-2z5dp` | skipped | n/a | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `insider-wallets-finder-1a7pi` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `lost-bitcoin-10li1` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `phantom-0jcvy` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `polymarket-25nwy` | skipped | n/a | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |
| `solana-07bcb` | completed | low | medium | medium | instruction_derived | external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> sensitive_capability_context |

## Summary

- Total sampled: 10
- Completed: 7
- Skipped bounded: 3 (`auth_or_external_account_required`)
- Instruction-derived chain recovered: 10 / 10
- Final high: 3 (`auto-updater-2yq87`, `clawhub-6yr3b`, `openclaw-backup-dnkxm`)
- Final medium: 7

The high cases have a document-supported closed risk path such as external agent or remote acquisition plus persistence or bulk skill/environment modification. The medium cases are capability / external-agent trust risks involving sensitive wallet, blockchain, OAuth, workspace, or trading contexts, but they are not reported as observed runtime exfiltration chains.

## Raw Outputs

- `test_dss/sample10_20260427-074214/results.jsonl`
- `test_dss/sample10_20260427-074214/summary.json`
- Per-skill JSON files under `test_dss/sample10_20260427-074214/skills/`
