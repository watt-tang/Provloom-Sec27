# ProvBench Evaluation Metrics

- Evaluation only: `True`
- Prediction file: `results/provbench/full/summary.json`
- Prediction SHA256: `3ad577121ae9d296dcf70e7a97a2f5cd18b0821cbb508adc391b90ca94974923`
- Ground truth dir: `provbench/ground_truth`
- Ground truth loaded by analyzer: `False`
- Evaluated count: `776`
- Missing prediction count: `0`
- Failed sample count: `0`

## Overall

- count: `776`
- confusion_matrix: `{'tp': 291, 'tn': 339, 'fp': 39, 'fn': 107}`
- accuracy: `0.811856`
- precision: `0.881818`
- recall: `0.731156`
- f1: `0.799451`
- specificity: `0.896825`
- fpr: `0.103175`
- benign_lookalike_fpr: `0.0`
- trusted_allowed_fpr: `0.325`
- review_rate: `0.136598`
- error_capture_rate: `0.189873`
- confirmed_violation_chain_recall: `0.61809`
- complete_chain_recall: `0.615578`
- false_closure_rate: `0.103175`
- decision_counts: `{'benign': 446, 'malicious': 330}`
- review_count: `106`
- evaluated_count: `776`
- completed_evaluated_count: `776`
- missing_prediction_count: `0`
- failed_sample_count: `0`
- missing_prediction_ids: `[]`
- failed_sample_ids: `[]`

## per_outcome

| Group | Count | Accuracy | Precision | Recall | F1 | FPR | Review | Chain Recall | False Closure |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| benign_lookalike | 179 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.072626 | 0.0 | 0.0 |
| confirmed_violation | 398 | 0.731156 | 1.0 | 0.731156 | 0.844702 | 0.0 | 0.150754 | 0.61809 | 0.0 |
| review_coverage | 79 | 1.0 | 0.0 | 0.0 | 0.0 | 0.0 | 0.189873 | 0.0 | 0.0 |
| trusted_allowed | 120 | 0.675 | 0.0 | 0.0 | 0.0 | 0.325 | 0.15 | 0.0 | 0.325 |

## per_risk_family

| Group | Count | Accuracy | Precision | Recall | F1 | FPR | Review | Chain Recall | False Closure |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Credential access and exfiltration | 67 | 0.895522 | 0.85 | 0.971429 | 0.906667 | 0.1875 | 0.059701 | 0.914286 | 0.1875 |
| Destructive modification / ransomware | 50 | 0.5 | 0.0 | 0.0 | 0.0 | 0.0 | 0.04 | 0.0 | 0.0 |
| Instruction override and hidden behavior | 49 | 0.571429 | 1.0 | 0.16 | 0.275862 | 0.0 | 0.102041 | 0.0 | 0.0 |
| LLM-mediated disclosure | 56 | 0.875 | 0.870968 | 0.9 | 0.885246 | 0.153846 | 0.142857 | 0.833333 | 0.153846 |
| Multi-stage compositional behavior | 148 | 0.952703 | 0.935897 | 0.973333 | 0.954248 | 0.068493 | 0.216216 | 0.813333 | 0.068493 |
| Permission or privilege expansion | 49 | 0.530612 | 1.0 | 0.041667 | 0.08 | 0.0 | 0.061224 | 0.0 | 0.0 |
| Persistence | 49 | 0.591837 | 1.0 | 0.2 | 0.333333 | 0.0 | 0.387755 | 0.0 | 0.0 |
| Private data collection and upload | 57 | 0.877193 | 0.848485 | 0.933333 | 0.888889 | 0.185185 | 0.105263 | 0.833333 | 0.185185 |
| Resource abuse | 39 | 0.820513 | 0.809524 | 0.85 | 0.829268 | 0.210526 | 0.102564 | 0.75 | 0.210526 |
| Reverse shell / remote control | 49 | 0.918367 | 0.92 | 0.92 | 0.92 | 0.083333 | 0.122449 | 0.76 | 0.083333 |
| Supply-chain or dependency abuse | 47 | 0.829787 | 0.814815 | 0.88 | 0.846154 | 0.227273 | 0.085106 | 0.8 | 0.227273 |
| Unauthorized external actions | 49 | 0.877551 | 0.806452 | 1.0 | 0.892857 | 0.25 | 0.102041 | 0.84 | 0.25 |
| Untrusted download and execute | 67 | 0.940299 | 0.941176 | 0.941176 | 0.941176 | 0.060606 | 0.119403 | 0.823529 | 0.060606 |

## per_split

| Group | Count | Accuracy | Precision | Recall | F1 | FPR | Review | Chain Recall | False Closure |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| blind-heldout | 462 | 0.796537 | 0.878947 | 0.701681 | 0.780374 | 0.102679 | 0.121212 | 0.584034 | 0.102679 |
| challenge-heldout | 195 | 0.794872 | 0.857143 | 0.72 | 0.782609 | 0.126316 | 0.169231 | 0.56 | 0.126316 |
| development | 119 | 0.89916 | 0.928571 | 0.866667 | 0.896552 | 0.067797 | 0.142857 | 0.85 | 0.067797 |
