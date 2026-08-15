#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


def close(actual: float, expected: float, tol: float = 0.0005) -> bool:
    return abs(float(actual) - expected) <= tol


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def main() -> int:
    errors: list[str] = []

    full = json.loads(Path("results/provbench/full/metrics.json").read_text())
    overall = full["overall"]
    require(overall["count"] == 776, "Full count must be 776", errors)
    require(overall["confusion_matrix"] == {"tp": 291, "tn": 339, "fp": 39, "fn": 107}, "Full confusion matrix mismatch", errors)
    require(close(overall["precision"], 0.881818), "Full precision mismatch", errors)
    require(close(overall["recall"], 0.731156), "Full recall mismatch", errors)
    require(close(overall["f1"], 0.799451), "Full F1 mismatch", errors)
    require(close(overall["benign_lookalike_fpr"], 0.0), "Benign-lookalike FPR mismatch", errors)

    paper = json.loads(Path("results/paper_usenix/metrics.json").read_text())
    bench = paper["benchmark"]
    require(bench["n"] == 776, "ProvBench n mismatch", errors)
    require(bench["expected_policy_outcome"] == {
        "benign_lookalike": 179,
        "confirmed_violation": 398,
        "review_coverage": 79,
        "trusted_allowed": 120,
    }, "ProvBench outcome counts mismatch", errors)
    require(bench["complete_counterfactual_pairs"] == 142, "Counterfactual pair count mismatch", errors)
    require(bench["multi_file"]["True"] == 199, "Multi-file count mismatch", errors)
    require(bench["llm_mediated"]["True"] == 316, "LLM-mediated count mismatch", errors)
    require(bench["network_or_external"]["True"] == 579, "Network/external count mismatch", errors)

    chain = paper["chain_metrics"]
    require(close(chain["confirmed_violation_chain"]["precision"], 0.863), "Violation closure precision mismatch", errors)
    require(close(chain["confirmed_violation_chain"]["recall"], 0.618), "Violation closure recall mismatch", errors)
    require(close(chain["confirmed_violation_chain"]["f1"], 0.720), "Violation closure F1 mismatch", errors)
    require(close(chain["complete_chain"]["precision"], 1.0), "Evidence closure precision mismatch", errors)
    require(close(chain["complete_chain"]["recall"], 0.616), "Evidence closure recall mismatch", errors)
    require(close(chain["complete_chain"]["f1"], 0.762), "Evidence closure F1 mismatch", errors)
    require(chain["complete_chain"]["tp"] == 245, "Evidence closure count mismatch", errors)

    expected_ablation = {
        "Full": (0.881818, 0.731156, 0.799451, 0.103175, 0.0, 0.325),
        "Static-only": (0.846809, 1.0, 0.917051, 0.190476, 0.173184, 0.241667),
        "Event-only": (0.788644, 0.628141, 0.699301, 0.177249, 0.03352, 0.508333),
        "No alignment": (0.858086, 0.653266, 0.741797, 0.113757, 0.022346, 0.325),
        "No policy": (0.583204, 0.942211, 0.720461, 0.708995, 0.793296, 0.833333),
    }
    ablation = {row["variant"]: row for row in json.loads(Path("results/ablation/metrics.json").read_text())}
    for name, expected in expected_ablation.items():
        row = ablation[name]
        for key, value in zip(["precision", "recall", "f1", "fpr", "benign_lookalike_fpr", "trusted_allowed_fpr"], expected):
            require(close(row[key], value), f"{name} {key} mismatch", errors)

    comparison = json.loads(Path("results/baselines/common_success_comparison/comparison.json").read_text())
    systems = {row["system"]: row for row in comparison["systems"]}
    expected_baselines = {
        "AI-Infra-Guard": (101, 373, 5, 297, 0.95283, 0.253769, 0.400794),
        "Cisco LLM Scanner": (312, 340, 38, 86, 0.891429, 0.78392, 0.834225),
        "SkillScan": (144, 360, 18, 254, 0.888889, 0.361809, 0.514286),
    }
    for name, expected in expected_baselines.items():
        row = systems[name]
        cm = row["confusion_matrix"]
        require((cm["tp"], cm["tn"], cm["fp"], cm["fn"]) == expected[:4], f"{name} confusion matrix mismatch", errors)
        for key, value in zip(["precision", "recall", "f1"], expected[4:]):
            require(close(row[key], value), f"{name} {key} mismatch", errors)

    if errors:
        print("Result validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print("Result validation passed")
    print("Full: P=0.882 R=0.731 F1=0.799")
    print("Static: P=0.847 R=1.000 F1=0.917")
    print("Baselines and ablations match the paper")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
