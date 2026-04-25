from scripts.run_benchmark import (
    BenchmarkCase,
    compute_complete_chain_rate,
    compute_edge_level_f1,
    compute_endpoint_accuracy,
    compute_explanation_error_modes,
    compute_partial_chain_usefulness,
)


def test_staged_chain_missing_relay_gets_partial_credit() -> None:
    case = BenchmarkCase(
        case_id="v2_staged_audit_group_file",
        skill_path="unused",
        is_malicious=True,
        expected_behaviors=["sensitive_file_read", "file_write", "network_access"],
        expected_source_nodes=[{"node_type": "file", "label": "/etc/group"}],
        expected_sink_nodes=[{"node_type": "network_endpoint", "label": "https://httpbin.org/post"}],
        expected_primary_chain=[
            {"node_type": "file", "label": "/etc/group"},
            {"node_type": "file", "label": "runtime_output/audit-group-stage.txt"},
            {"node_type": "network_endpoint", "label": "https://httpbin.org/post"},
        ],
        expected_root_cause="unsafe_dataflow_design",
        dynamic_runnable=True,
        family="malicious",
    )
    predicted_chain = [
        {"node_type": "file", "label": "/etc/group"},
        {"node_type": "tool_call", "label": "Send Stage"},
        {"node_type": "network_endpoint", "label": "https://httpbin.org/post"},
    ]

    assert compute_endpoint_accuracy(case, predicted_chain) == 1.0
    assert compute_edge_level_f1(case, predicted_chain) == 0.875
    assert compute_complete_chain_rate(case, predicted_chain) == 0.75
    assert compute_partial_chain_usefulness(case, predicted_chain) == 1.0
    assert compute_explanation_error_modes(case, {"primary_chain": predicted_chain}) == [
        "partial_chain_missing_relay",
        "staged_relay_collapsed_to_direct_transfer",
    ]


def test_source_relay_alias_reduces_endpoint_and_partial_scores() -> None:
    case = BenchmarkCase(
        case_id="v2_unauthorized_audit_alpha",
        skill_path="unused",
        is_malicious=True,
        expected_behaviors=["file_write", "network_access"],
        expected_source_nodes=[{"node_type": "file", "label": "runtime_output/audit-alpha.txt"}],
        expected_sink_nodes=[{"node_type": "network_endpoint", "label": "https://httpbin.org/post"}],
        expected_primary_chain=[
            {"node_type": "file", "label": "runtime_output/audit-alpha.txt"},
            {"node_type": "file", "label": "runtime_output/audit-alpha.txt"},
            {"node_type": "network_endpoint", "label": "https://httpbin.org/post"},
        ],
        expected_root_cause="overprivileged_tool_use",
        dynamic_runnable=True,
        family="malicious",
    )
    predicted_chain = [
        {"node_type": "file", "label": "runtime_output/audit-alpha.txt"},
        {"node_type": "tool_call", "label": "Send Export"},
        {"node_type": "network_endpoint", "label": "https://httpbin.org/post"},
    ]

    assert compute_endpoint_accuracy(case, predicted_chain) == 0.9
    assert compute_partial_chain_usefulness(case, predicted_chain) == 0.9
    assert compute_explanation_error_modes(case, {"primary_chain": predicted_chain}) == [
        "source_relay_endpoint_ambiguity",
    ]
