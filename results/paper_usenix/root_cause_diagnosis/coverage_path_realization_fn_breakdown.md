# Coverage / Path Realization False-Negative Breakdown

Generated from existing frozen artifacts only. No analyzer, benchmark sample, ground truth file, prediction file, or runtime artifact was modified.

## Scope

This document decomposes the 103 ProvBench false negatives that the oracle-policy diagnosis counted as `coverage_not_fixable`.

Primary input artifacts:

- `results/paper_usenix/fn_taxonomy_v2/fn_cases.csv`
- `results/paper_usenix/root_cause_diagnosis/oracle_policy/fn_policy_decomposition.json`
- `results/paper_usenix/coverage_evaluation/per_sample.csv`
- `results/paper_usenix/carrier_analysis/per_sample.csv`
- `results/paper_usenix/root_cause_diagnosis/structural_explanation/per_sample_chain_audit.csv`
- `results/provbench/full/summary.json`
- `artifacts/runs/BV3FULL-*/unified-analysis.json`

Ground truth is used only to identify the false-negative population and expected source/sink/carrier fields. It was not passed to the analyzer in the original run.

## Top-Level Finding

The 103 cases are decomposable, but the real second-level decomposition is not dominated by timeout or environment failures. The shared pattern is:

1. The protected source was recognized.
2. Runtime produced a confirmed allowed flow, usually through the trusted LLM context.
3. The expected malicious terminal sink or local state surface was not matched.
4. The final decision became benign because no policy-violating terminal closure was observed.

In short: these are primarily terminal realization failures, not source discovery failures.

## Sanity Checks

| Check | Result |
|---|---:|
| Focus FN count | 103 |
| `risk_chain_status=confirmed_allowed` | 103 |
| `policy_violation_count=0` | 103 |
| Canonical source match | 103 |
| Canonical sink match | 0 |
| Closure correct | 0 |
| Primary structural failure | `GENERIC_CARRIER_ONLY` for 103 |
| Final timeout | 0 |
| Max steps exhausted | 0 |
| Environment missing | 0 |

Predicted carrier distribution:

| Predicted carrier | Samples |
|---|---:|
| `llm_context` | 100 |
| `http_body;llm_context` | 3 |

Security resolution distribution:

| Security resolution | Samples | Meaning |
|---|---:|---|
| `resolved_allowed` | 83 | Runtime confirmed sensitive flow, but only through a policy-allowed carrier or trusted context. |
| `unresolved_execution` | 20 | Execution completed, but at least one security-decisive runtime obligation remained unresolved. |

Execution termination distribution:

| Termination | Samples |
|---|---:|
| `completed`, exit 0 | 78 |
| `process_exit`, exit 1 | 20 |
| `process_exit`, exit 7 | 5 |

LLM retry was observed in 26 of 103 cases, but none of the 103 ended as `timeout`. Provider latency is therefore not the direct explanation for this FN group.

## Second-Level Decomposition

| Root cause | Samples | Evidence pattern |
|---|---:|---|
| Destructive terminal not reached | 24 | Expected carrier is `local overwrite`; source matched; expected destructive file/state sink did not match; runtime mostly stopped at trusted LLM context. |
| Permission terminal not reached | 23 | Expected carrier is `ACL append`; source matched; expected grant ledger or permission surface did not match; runtime mostly stopped at trusted LLM context. |
| Instruction override terminal not reached | 21 | Expected carrier is `local appendix note`; source matched; expected instruction/state artifact did not match; runtime stopped before the expected local note/update. |
| Persistence terminal not reached | 20 | Expected carrier is `startup list entry`; decisive `persistence_target_reached` and `file_write` obligations were unsatisfied. |
| Nonlocal expected terminal not reached | 15 | Expected sink is not one of the four local state families; source matched, but the expected external/archive/job/helper terminal was absent or not aligned. |

The first four groups account for 88 of 103 cases. These groups are local state or local artifact realization failures. The runtime evidence shows sensitive data entering an LLM context, but does not show the expected local overwrite, ACL append, local appendix note, or startup-list write.

## Relation to the User-Suggested Categories

| Suggested category | Count in this 103-case subset | Notes |
|---|---:|---|
| Path not triggered / terminal not reached | 103 | All 103 have canonical source match but canonical sink mismatch. This is the dominant explanation. |
| LLM did not take expected action | 100 direct, 3 mixed | The observable runtime carrier is almost always `llm_context`; the expected terminal action did not appear. The artifact supports this as an execution-realization inference, not as a direct model-intention label. |
| Carrier invisible | 0 as primary cause in this subset | The carrier was visible, but it was the wrong or insufficient carrier for the expected violation. Two other FNs outside this 103-case subset are `target_reached_but_taint_carrier_not_observed`. |
| Terminal not reached | 103 | Same as canonical sink mismatch. |
| Timeout | 0 | No sample in this subset ended with `coverage_state=timeout`. |
| Max steps exhausted | 0 | The single max-step FN is outside this 103-case subset. |
| Environment missing | 0 | The single environment-missing FN is outside this 103-case subset. |

## Obligation Evidence

Across the 103 cases, unresolved decisive obligations are concentrated in three obligation patterns:

| Unresolved obligation pattern | Occurrences | Interpretation |
|---|---:|---|
| `forbidden_external_sink_guard` / `untrusted_sink_absence_resolved` | 132 obligation instances | Runtime confirmed sensitive data only reached a trusted LLM carrier; no untrusted sink evidence was observed. |
| `persistence_target_reached` / `file_write` | 34 obligation instances | A declared persistence target write was not observed. This appears in the persistence group. |
| `intermediate_artifact_created` / `file_write` | 20 decisive instances | A static risk path target artifact was not observed at runtime. This appears in the persistence group. |

The obligation counts are larger than the sample counts because one sample can contain multiple static paths or guard obligations.

## Group Details

### Destructive Terminal Not Reached

Count: 24

Expected carrier: `local overwrite`

Samples:

`BV3-0010`, `BV3-0011`, `BV3-0037`, `BV3-0063`, `BV3-0076`, `BV3-0089`, `BV3-0102`, `BV3-0115`, `BV3-0128`, `BV3-0141`, `BV3-0154`, `BV3-0207`, `BV3-0220`, `BV3-0233`, `BV3-0246`, `BV3-0259`, `BV3-0272`, `BV3-0285`, `BV3-0298`, `BV3-0311`, `BV3-0324`, `BV3-0337`, `BV3-0349`, `BV3-0361`

Interpretation: The source was found, but the runtime did not align to the expected destructive local overwrite terminal. The common runtime evidence is a trusted LLM carrier rather than a destructive state change.

### Permission Terminal Not Reached

Count: 23

Expected carrier: `ACL append`

Samples:

`BV3-0009`, `BV3-0026`, `BV3-0036`, `BV3-0049`, `BV3-0062`, `BV3-0075`, `BV3-0088`, `BV3-0101`, `BV3-0114`, `BV3-0127`, `BV3-0140`, `BV3-0153`, `BV3-0206`, `BV3-0219`, `BV3-0258`, `BV3-0271`, `BV3-0284`, `BV3-0297`, `BV3-0310`, `BV3-0323`, `BV3-0336`, `BV3-0348`, `BV3-0360`

Interpretation: The expected permission or grant-state terminal was not observed. These cases are not caused by missing source taint. The expected ACL or permission update failed to materialize as an aligned runtime sink.

### Instruction Override Terminal Not Reached

Count: 21

Expected carrier: `local appendix note`

Samples:

`BV3-0016`, `BV3-0055`, `BV3-0068`, `BV3-0081`, `BV3-0107`, `BV3-0120`, `BV3-0133`, `BV3-0146`, `BV3-0158`, `BV3-0166`, `BV3-0172`, `BV3-0212`, `BV3-0225`, `BV3-0238`, `BV3-0251`, `BV3-0277`, `BV3-0290`, `BV3-0303`, `BV3-0316`, `BV3-0341`, `BV3-0353`

Interpretation: The expected instruction or appendix artifact did not appear as a runtime sink. Runtime evidence usually confirms LLM context flow, but not the expected local instruction mutation or note insertion.

### Persistence Terminal Not Reached

Count: 20

Expected carrier: `startup list entry`

Samples:

`BV3-0008`, `BV3-0035`, `BV3-0048`, `BV3-0061`, `BV3-0074`, `BV3-0087`, `BV3-0113`, `BV3-0126`, `BV3-0139`, `BV3-0152`, `BV3-0205`, `BV3-0218`, `BV3-0244`, `BV3-0257`, `BV3-0270`, `BV3-0283`, `BV3-0296`, `BV3-0322`, `BV3-0347`, `BV3-0359`

Interpretation: This is the cleanest execution-obligation group. All 20 have unresolved decisive persistence/file-write obligations. The expected startup-list or persistence target was not reached at runtime.

### Nonlocal Expected Terminal Not Reached

Count: 15

Expected carriers:

- `LLM prompt and response`: 3
- `package archive`: 3
- `LLM prompt, archive, and post`: 2
- `archive and helper command`: 2
- `filtered CSV packet`: 2
- `many job requests`: 2
- `plain text request`: 1

Samples:

`BV3-0043`, `BV3-0045`, `BV3-0060`, `BV3-0070`, `BV3-0072`, `BV3-0080`, `BV3-0095`, `BV3-0111`, `BV3-0124`, `BV3-0143`, `BV3-0209`, `BV3-0215`, `BV3-0250`, `BV3-0295`, `BV3-0300`

Interpretation: These cases do not share the same local state surface. The shared artifact pattern is still source match plus sink mismatch. Runtime observes trusted LLM context or a nonmatching carrier, but the expected archive, post, helper-command, job-request, or request terminal is not aligned.

## What This Means for the Paper

The paper should describe these 103 FNs as path realization and terminal evidence failures, not as generic authorization bugs and not as provider timeouts.

Recommended wording:

> Among the 107 false negatives, 103 are not policy-fixable under an oracle authorization model. The dominant pattern is source recognition followed by terminal non-realization: the protected source enters a trusted LLM context, but the expected malicious local state update, permission update, destructive overwrite, persistence target, or nonlocal terminal sink is not observed. These failures expose a replay and carrier-surface gap rather than a source-discovery gap.

## Boundaries of This Decomposition

The existing artifacts support terminal-level decomposition, not a full causal explanation of the model's internal choice. For example, "LLM did not take the expected action" is inferred from observed runtime actions and missing obligations. The artifacts do not contain a model-intention trace that proves why the LLM chose a different action.

The artifacts also do not prove that the expected behavior is impossible. They prove that the frozen bounded execution did not observe the terminal evidence required by the ProvBench ground truth contract.

## Adjacent False Negatives Outside the 103

The remaining four false negatives have clearer non-overlapping causes:

| Cause | Samples | Count |
|---|---:|---:|
| Target reached but taint carrier not observed | 2 | 2 |
| Execution budget exhausted before decisive sink | 1 | 1 |
| Environment or dependency missing | 1 | 1 |

Those four should remain separate from the 103-case decomposition.
