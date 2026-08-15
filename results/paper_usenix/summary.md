# ProvLoom USENIX Paper Evaluation Artifacts

Generated at: 2026-08-10T05:15:37.296973+00:00

Scope: fixed formal ProvBench 776-case corpus.

## Explanation Metrics
- confirmed_violation_chain: P=0.863, R=0.618, F1=0.720 (tp=246, pred=285, gold=398)
- complete_chain: P=1.000, R=0.616, F1=0.762 (tp=245, pred=245, gold=398)
- source: P=0.500, R=0.506, F1=0.503 (tp=393, pred=786, gold=776)
- sink: P=0.718, R=0.367, F1=0.486 (tp=285, pred=397, gold=776)
- relay_or_intermediate: P=0.000, R=0.000, F1=0.000 (tp=0, pred=1187, gold=1473)
- edge_operation: P=0.892, R=0.426, F1=0.577 (tp=708, pred=794, gold=1661)
- exact_chain_match: P=0.000, R=0.000, F1=0.000 (tp=0, pred=393, gold=398)
- minimal_witness: P=0.222, R=0.436, F1=0.294 (tp=338, pred=1524, gold=776)

## Failure Taxonomy
- FP: {'trust_or_authorization_resolution_error': 39}
- FN: {'policy_or_authorization_mismatch_after_partial_path': 80, 'branch_or_execution_path_incomplete': 20, 'other_false_negative': 3, 'target_reached_no_carrier_flow': 2, 'bounded_execution_not_completed': 1, 'environment_missing': 1}
- FN v2: {'authorization_or_trust_model_downgraded_expected_violation': 103, 'target_reached_but_taint_carrier_not_observed': 2, 'execution_budget_exhausted_before_decisive_sink': 1, 'environment_or_dependency_missing': 1}
- Trusted-allowed FP: {'confirmed_chain_policy_allowlist_mismatch': 39}

## Explanation Audit
- Three-level counts: {'non_violation_or_false_closure': 378, 'L2_endpoint_correct': 246, 'missed_closure': 152}
- Interpretation: runtime witnesses are carrier-level (`taint -> http_body/llm_context -> endpoint`), while GT complete chains include named staging/payload artifacts.

## Static vs Full
- Main transition reasons: {'runtime_execution_or_path_incomplete_suppressed_static_risk': 101, 'runtime_policy_or_no_flow_corrected_static_false_positive': 62, 'runtime_false_closure_or_trust_resolution_added_false_positive': 29, 'runtime_observed_allowed_or_no_flow_overrode_static_risk': 6}

## Co-occurrence Baselines
- any_network: F1=0.678, Precision=0.513, Recall=1.000, FPR=1.000
- source_and_network: F1=0.708, Precision=0.584, Recall=0.899, FPR=0.675
- any_taint_chain: F1=0.707, Precision=0.587, Recall=0.889, FPR=0.659

## Efficiency
- Total latency seconds: median=80.695, p95=391.165
- LLM requests/sample: median=9.0, p95=14.0
- Tokens/sample: median=24545.5, p95=53644.25
