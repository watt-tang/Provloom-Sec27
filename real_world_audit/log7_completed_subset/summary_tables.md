# log7 Completed-Subset Sampled Audit Tables

These tables are a mix of `code-generated` and `placeholder` outputs. No population-level accuracy claims are made.

## Completed-Subset Sampled Audit Summary

| Field | Value | Status |
| --- | ---: | --- |
| Scheduled skills | 617 | code-generated |
| Completed executions | 465 | code-generated |
| Skipped executions | 152 | code-generated |
| Sampled completed cases | 29 | code-generated |
| Manual review completed | 0 | sampled-manual-review-pending |

## Sampling by Stratum

| Stratum | Selected | Status |
| --- | ---: | --- |
| `chain_backed_critical` | 5 | code-generated |
| `partial_evidence_medium` | 5 | code-generated |
| `note_like_fp_cluster` | 8 | code-generated |
| `upload_or_mirror_outward` | 3 | code-generated |
| `llm_decision_heavy` | 4 | code-generated |
| `representative_low_risk` | 4 | code-generated |

## Predicted vs Manually Reviewed Label Comparison

| Bucket | Count | Status |
| --- | ---: | --- |
| Predicted review-worthy (`critical`/`high`/`medium`) | 25 | code-generated |
| Manually confirmed malicious | 0 | sampled-manual-review-pending |
| Manually confirmed benign | 0 | sampled-manual-review-pending |
| Pending manual labels | 29 | sampled-manual-review-pending |

## FP Cluster Breakdown in Completed Subset

| Cluster | Risk Level | Primary Chain Nonempty | Count | Status |
| --- | --- | --- | ---: | --- |
| `chain_backed` | `critical` | `True` | 1 | code-generated |
| `helper_listing` | `medium` | `False` | 8 | code-generated |
| `llm_decision_heavy` | `critical` | `True` | 155 | code-generated |
| `llm_decision_heavy` | `high` | `True` | 2 | code-generated |
| `llm_decision_heavy` | `low` | `False` | 8 | code-generated |
| `llm_decision_heavy` | `medium` | `False` | 260 | code-generated |
| `note_like_local_output` | `critical` | `True` | 10 | code-generated |
| `note_like_local_output` | `medium` | `False` | 16 | code-generated |
| `upload_or_mirror_outward` | `critical` | `True` | 1 | code-generated |
| `upload_or_mirror_outward` | `medium` | `False` | 4 | code-generated |

## Note-Like Benign-FP Focus

| skill_id | risk_level | primary_chain_nonempty | suspected_fp_type | Status |
| --- | --- | --- | --- | --- |
| `mnt_e_dangerous_skills_ahok-skill` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_audit-skills_skills_audit-skills` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_finance-report-analyzer` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_memobank_skills_cold-start` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_memobank_skills_mb-init` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_memobank_skills_mb-review` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_node-aws-security-audit` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_research-report-fetcher` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_skill-security-audit` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_skills_skills_report` | `critical` | `True` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_agentaudit-skill` | `medium` | `False` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_audit-skills` | `medium` | `False` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_cass_memory_system` | `medium` | `False` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_chinese-novelist-skill` | `medium` | `False` | `helper_listing_or_archive` | code-generated |
| `mnt_e_dangerous_skills_choom_nextjs-app_skills_core_memory-management` | `medium` | `False` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_devhelper_skills_chrome-bookmark-reader` | `medium` | `False` | `helper_listing_or_archive` | code-generated |
| `mnt_e_dangerous_skills_elite-longterm-memory` | `medium` | `False` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_eternal-memory-skill` | `medium` | `False` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_github-trending-daily-report_github-trending-daily-report` | `medium` | `False` | `note_report_inventory_or_mirror` | code-generated |
| `mnt_e_dangerous_skills_kata-skills_skills_kata-list-phase-assumptions` | `medium` | `False` | `helper_listing_or_archive` | code-generated |