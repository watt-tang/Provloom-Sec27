# Root-Cause Diagnosis Summary

Scope: evaluation-only diagnosis over the fixed formal Benchmark v3 common-success population, N=776.

## Direct Answers

1. The previously reported 61.6% complete-chain recall is closure-level correctness: it reflects source-to-sink/security closure recovery, not full structural relay reconstruction.
2. It is not structural chain reconstruction. The decisive runtime chains are carrier-level witnesses, while GT complete chains include named staging/payload/state artifacts.
3. Relay literal F1: 0.000000.
4. Relay canonical F1: 0.000000.
5. Relay semantic F1: 0.000042.
6. Exact literal structural chain F1: 0.000000.
7. Exact canonical structural chain F1: 0.000000.
8. Exact semantic structural chain F1: 0.000000.
9. Relay mismatch taxonomy: {'GENERIC_CARRIER_ONLY': 1181, 'WRONG_OBJECT': 284, 'RELATION_PRESENT_OBJECT_MISSING': 8}.
10. Exact-chain failure decomposition: {'GENERIC_CARRIER_ONLY': 595, 'WRONG_OBJECT': 173, 'RELATION_PRESENT_OBJECT_MISSING': 8}.
11. Canonical Source/Sink/Edge F1: source=0.472447, sink=0.341113, edge=0.493896.
12. Semantic Source/Sink/Edge F1: source=0.472447, sink=0.341113, edge=0.000000.
13. Generic carriers were not counted as specific relay identities.
14. The accurate scientific claim is: source-to-sink closure with carrier-level witness, plus partial artifact evidence in the runtime graph; not reliable ordered structural provenance reconstruction.
15. 107 FN decomposition: {'coverage_not_fixable': 103, 'provenance_not_fixable': 3, 'execution_not_fixable': 1}.
16. 39 trusted/allowed FP decomposition: {'pure_policy_fp': 39}.
17. Current Full metrics: TP=291 TN=339 FP=39 FN=107 Precision=0.881818 Recall=0.731156 F1=0.799451 FPR=0.103175.
18. Oracle-policy diagnostic metrics: TP=291 TN=378 FP=0 FN=107 Precision=1.000000 Recall=0.731156 F1=0.844702 FPR=0.000000.
19. Oracle policy restores 0.000000 recall and eliminates 39 FP. This is a diagnostic upper bound, not a system result.
20. The primary bottleneck is both relay representation and policy adjudication, but for different metrics: structural explanation is limited by carrier-level/partially connected provenance; trusted-allowed false positives are pure policy adjudication errors when the recovered flow is otherwise correct.
21. Evaluation bug found: previous URL matching could collapse endpoints by splitting on the first colon; see evaluation_bug_report.md.

## Decision

D. relay + policy both need work if the paper wants to claim explanation-level structural provenance and reduce trusted-allowed errors. If the claim is narrowed to source-to-sink closure with carrier-level witnesses, analyzer changes are not required for that narrower claim.

## Integrity Audit

- GT was loaded only by this offline evaluator after frozen predictions were read.
- Oracle policy only changes evaluation-time final adjudication over existing evidence; it does not create sources, sinks, edges, closures, coverage, or runtime events.
- Normalization rules are global and deterministic; their SHA256 is recorded in the metrics.
- Generic carriers are explicitly forbidden from matching named GT relays.
- Literal metrics are preserved separately from canonical and semantic metrics.
- N is fixed at 776; no samples are silently excluded.
- Oracle metrics are labeled NOT A SYSTEM RESULT / DIAGNOSTIC UPPER BOUND ONLY.
