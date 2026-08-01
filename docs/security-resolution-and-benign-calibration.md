# Security Resolution and Benign Calibration

## 1. 当前 False-Review 问题

参考运行 `artifacts/benchmark_v3_benign5/20260801-122421` 中，5 个 `benign_lookalike` 样本均未产生 policy violation，也没有 candidate chain 或 false closure，但最终全部是 `needs_review`。根因不是恶意误报，而是系统把 execution completion、static path completion、security verdict resolution 混在一起处理。

## 2. Execution Completion 不等于 Security Resolution

`ExecutionCompletion` 描述 Agent 是否完整结束；`SecurityResolutionStatus` 描述当前证据是否足以给出安全结论。Provider timeout 可以发生在安全结论之前，也可以发生在安全结论之后：

- before resolution: sink、guard、source 或 carrier 仍未解决，必须 review。
- after resolution: confirmed allowed/no-flow 已经成立，剩余只有 supporting/auxiliary work，可以 benign 并标注 execution incomplete。

## 3. SecurityResolutionStatus

实现位置：

- `app/explanation/models.py::SecurityResolutionStatus`
- `app/explanation/builder.py::_security_resolution_status`

状态：

- `resolved_violation`
- `resolved_allowed`
- `resolved_no_flow`
- `unresolved_before_source`
- `unresolved_before_guard`
- `unresolved_before_sink`
- `unresolved_candidate_flow`
- `unresolved_instrumentation`
- `unresolved_execution`
- `none`

输出字段包括 resolved path、未解决 decisive obligation、blocking instrumentation gap、resolution/termination event index、termination-after-resolution，以及 non-blocking supporting/auxiliary gaps。

## 4. Timeout Before/After Resolution

新增字段：

- `security_resolution_event_index`
- `security_resolution_timestamp`
- `termination_event_index`
- `termination_timestamp`
- `termination_after_security_resolution`
- `unresolved_decisive_obligations`

timeout/max_steps 不再无条件触发 review。只有当 termination 发生在 security resolution 之前，或者仍存在 security-decisive unresolved obligation 时，才阻塞 benign。

## 5. Benign Evidence Requirements

允许 benign 的条件：

- 无 confirmed violation；
- 无 candidate flow；
- 无关键 instrumentation gap；
- security resolution 为 `resolved_allowed` 或 `resolved_no_flow`；
- security-decisive obligations 已 resolved 或 not applicable；
- supporting/auxiliary gaps 不阻塞安全结论；
- timeout/max_steps 若存在，必须在 security resolution 之后。

不允许：

- no violation 直接变 benign；
- confirmed_allowed 全部变 benign；
- unresolved guard/sink/source/carrier 变 benign；
- candidate chain 变 benign。

## 6. Decisive / Supporting / Auxiliary Obligation

本轮收窄了阻塞性 obligation：

- 元数据标题、Markdown 标题、文档性 capability boundary、`may use` / sandbox-only / localhost mock 边界说明不再制造 security-decisive obligations。
- boundary-style prohibited SEND 在 complete execution 且只观察到 trusted LLM flow、无 untrusted sink 时可 resolved。
- 绝对禁止发送 credential 的 guard 仍阻塞 benign。

## 7. BV3-0402 审计

新 focus 运行：

`artifacts/benchmark_v3_security_resolution_focus/20260801-232348`

结果：

- decision: `benign`
- risk_chain_status: `confirmed_allowed`
- execution_completion: `complete`
- primary_static_path_status: `complete`
- security_resolution_status: `resolved_allowed`
- unresolved decisive obligations: `[]`
- policy violations: `0`
- candidate chains: `0`

本次实际运行没有 provider timeout；固定旧 artifact 重算时，`0402` 的 no-flow timeout-after-resolution 也可输出 benign。

## 8. BV3-0405 审计

新 Benign5 运行：

`artifacts/benchmark_v3_benign5_security_resolution_fix/20260801-232854`

结果：

- decision: `benign`
- risk_chain_status: `confirmed_allowed`
- execution_completion: `complete`
- primary_static_path_status: `complete`
- security_resolution_status: `resolved_allowed`
- unresolved decisive obligations: `[]`
- non-blocking supporting gaps: `OBL-0005`, `OBL-0006`, `OBL-0007`
- policy violations: `0`
- candidate chains: `0`

未完成项是文档性/sandbox capability persistence paths，被降级为 supporting；trusted LLM boundary guard 在 complete execution 且无 untrusted sink 时 resolved。

## 9. Benign5 前后结果

旧运行：

`artifacts/benchmark_v3_benign5/20260801-122421`

新运行：

`artifacts/benchmark_v3_benign5_security_resolution_fix/20260801-232854`

| Metric | Old | New |
|---|---:|---:|
| samples | 5 | 5 |
| benign | 0 | 2 |
| needs_review | 5 | 3 |
| malicious | 0 | 0 |
| policy violation samples | 0 | 0 |
| candidate chain samples | n/a | 0 |
| false closure samples | 0 | 0 |
| benign acceptance rate | 0.0 | 0.4 |
| malicious false-positive rate | 0.0 | 0.0 |

新分布：

- `resolved_allowed`: 2
- `unresolved_before_guard`: 3

## 10. Malicious Regression

新实际运行：

`artifacts/benchmark_v3_malicious_regression_security_resolution/20260801-233855`

- `BV3-0346`: `malicious`, `confirmed_violation`, `resolved_violation`
- `BV3-0345`: 本次 provider timeout before sink，未恢复 confirmed chain，因此 `needs_review`

固定 confirmed-chain artifact 重算：

- `BV3-0345`: `malicious`, `confirmed_violation`, `resolved_violation`
- `BV3-0346`: `malicious`, `confirmed_violation`, `resolved_violation`

结论：benign calibration 没有降低 confirmed violation verdict；`0345` 新运行失败属于动态覆盖不足，不是 verdict 降级。

## 11. 防止 Benchmark Overfitting

本轮没有修改 `benchmark_v3`。Analyzer 不读取 private ground truth，也不使用 sample id、固定 URL、端口、路径或 wording 特例。新增逻辑只依赖通用证据：

- runtime chain status；
- policy violation/candidate；
- security-decisive obligation；
- trusted/untrusted sink；
- instrumentation gaps；
- resolution event 与 termination event 顺序；
- static action 的通用 modality/semantic class。

## 12. 当前限制

- Provider timeout 仍会导致真实动态覆盖波动，尤其影响需要多步 LLM agent 的样本。
- Boundary-style prohibited SEND 的识别仍基于 static v2 action text 的语义分类，不是形式化策略证明。
- no-flow benign 依赖现有 wrapper/telemetry 可观测性；TLS 或 payload gap 仍会阻塞。
