# Ground Truth Schema

本目录中的每个 `<case_id>.json` 都与 `datasets/skills/{benign,malicious}/<case_id>/` 一一对应。

## Schema

```json
{
  "case_id": "malicious_sensitive_exfil_direct",
  "is_malicious": true,
  "expected_behaviors": [
    "sensitive_file_read",
    "network_access",
    "read_then_exfiltration"
  ],
  "expected_source_nodes": [
    {
      "node_type": "file",
      "label": "/etc/hosts"
    }
  ],
  "expected_sink_nodes": [
    {
      "node_type": "network_endpoint",
      "label": "https://httpbin.org/post"
    }
  ],
  "expected_primary_chain": [
    {
      "node_type": "file",
      "label": "/etc/hosts"
    },
    {
      "node_type": "network_endpoint",
      "label": "https://httpbin.org/post"
    }
  ],
  "expected_root_cause": "unsafe_dataflow_design",
  "dynamic_runnable": true,
  "notes": "Shortest direct source-to-sink exfiltration case."
}
```

## Field Meanings

- `case_id`: 稳定样本 ID，必须与技能目录名一致。
- `is_malicious`: 样本是否为恶意。
- `expected_behaviors`: GT 中期望命中的行为标签；当前 benchmark 用它计算 `detection_rate`。
- `expected_source_nodes`: GT 主攻击链的源端点列表。
- `expected_sink_nodes`: GT 主攻击链的汇端点列表。
- `expected_primary_chain`: GT 主链的关键节点序列，用于 `edge_level_f1` 和 `complete_chain_rate`。
- `expected_root_cause`: 细粒度根因标签。当前优先支持：
  - `unsafe_dataflow_design`
  - `unsafe_command_construction`
  - `llm_decision_induced_action`
  - `overprivileged_tool_use`
  - `unknown`
- `dynamic_runnable`: 是否应纳入 `rule_only` / `rule_plus_epg` 动态基线。
- `notes`: 可选说明，用于案例分析或标注说明。

## Labeling Rules

- `benign` 样本也必须提供完整 ground truth。
- 没有主攻击链的样本，`expected_source_nodes`、`expected_sink_nodes`、`expected_primary_chain` 可以为空数组。
- `root_cause_accuracy` 仅对 malicious 样本聚合统计。
- `dynamic_runnable=false` 的样本会在动态基线中被结构化标记为 skipped，而不会被当作失败样本。

## Metric Semantics

- `endpoint_accuracy`: 预测链的 source / sink 是否命中 GT 端点。
- `edge_level_f1`: 预测链边集合与 GT 主链边集合的 F1。
- `complete_chain_rate`: 预测链是否完整覆盖 GT 主链。
- `partial_chain_usefulness`: 是否至少恢复了 GT 的 source-to-sink 主方向。
- `root_cause_accuracy`: 恶意样本上预测细粒度 root cause 与 GT 是否一致。
