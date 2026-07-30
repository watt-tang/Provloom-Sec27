# ProvLoom Three-Axis Risk / Execution / Path Model

## 1. 原问题

旧版动态解释把多个语义塞进单一 `path_completion_status`：

- 风险链是否已经闭合；
- Agent 是否完整执行结束；
- 静态声明路径是否被动态证据覆盖；
- 辅助动作、日志写入、缓存文件、未触发分支是否未完成。

这会导致两个错误方向：

- 已恢复 `confidentiality_confirmed` 且有 `PolicyViolation` 的样本，因为 timeout、max steps 或辅助 obligation 未满足而显示为 unresolved。
- 没有 confirmed violation 的样本，因为存在一个 allowed/trusted flow 或普通事件而被误读成明确 benign。

本轮修复把这些语义拆为三个独立轴，并保留旧字段作为兼容层。

## 2. 为什么单一 path_completion 语义过载

`path_completion_status` 同时回答“是否有风险数据流闭合”和“静态路径是否完整执行”。这两个问题不是同一个谓词：

- confirmed malicious flow 可以在执行未完整结束时已经成立。
- confirmed allowed flow 不能证明其他高风险静态路径已经被覆盖。
- auxiliary obligation 未满足不应阻止已闭合的敏感源到不可信 sink 链。
- execution incomplete 不能自动降级 confirmed violation，也不能自动升级为 malicious。

因此当前模型把 `coverage_certificate.path_completion_status` 标记为 deprecated compatibility field，主判断改用下面三个轴。

## 3. RiskChainStatus

实现位置：

- `app/explanation/models.py::RiskChainStatus`
- `app/explanation/builder.py::_risk_chain_status`

语义：

- `confirmed_violation`: 已有 runtime confirmed chain，并被 policy 判为 violation。
- `confirmed_allowed`: 已有 confirmed chain，但当前 policy 允许，例如 trusted LLM / trusted auth carrier。
- `candidate_flow`: 只有 candidate chain，证据不足，需要 review。
- `no_sensitive_flow_observed`: 目标执行有可观测行为，但没有敏感流。
- `none`: 没有足够 runtime chain 证据。

该轴只描述运行时风险链证据，不描述 Agent 是否跑完，也不描述所有静态路径是否完成。

## 4. ExecutionCompletion

实现位置：

- `app/explanation/models.py::ExecutionCompletion`
- `app/explanation/builder.py::_execution_completion`
- `app/explanation/builder.py::_execution_completion_status`

语义：

- `complete`: 正常结束，或动态 coverage 已达到 `runtime_confirmed` / `target_reached_no_flow`。
- `timeout`: 总执行 timeout。
- `max_steps_exhausted`: Agent step budget 用尽。
- `crash`: 非零退出且不是可识别 timeout/max steps。
- `unknown`: 缺少执行对象或终止原因。

该轴记录 `termination_reason`、`agent_step_count`、`max_agent_steps`、`total_timeout_seconds`、`llm_request_timeout_seconds`、`provider_retry_count`、`final_response_emitted`、`pending_tool_call`。

重要规则：`timeout` 或 `max_steps_exhausted` 不会把 `confirmed_violation` 降级为 benign/review；它只说明执行覆盖不完整。

## 5. StaticPathCompletion

实现位置：

- `app/explanation/models.py::StaticPathCompletion`
- `app/explanation/builder.py::_static_path_results`
- `app/explanation/builder.py::_primary_risk_path_selection`

语义：

- 每个 static chain 或聚合静态动作生成一个 path-local result。
- 每条静态路径只消费属于自己的 obligations。
- `complete`: decisive obligations 满足，或该路径匹配到 decisive confirmed violation chain。
- `partial`: 有部分 decisive/supporting evidence，但仍缺少 decisive obligation。
- `unresolved`: 没有足够 runtime evidence 覆盖该路径。
- `not_applicable`: 该路径是 optional/conditional 且条件未触发。

主报告暴露：

- `primary_static_path_id`
- `primary_static_path_status`
- `static_path_results`
- `other_static_path_summary`

## 6. Path-Local RuntimeObligation

实现位置：

- `app/explanation/models.py::RuntimeObligation`
- `app/explanation/builder.py::_runtime_obligations`

新增字段：

- `static_path_id`: obligation 归属的静态路径。
- `origin_static_ids`: 来源 action/path/entity id。
- `path_role`: `source | sink | propagation | guard | activity | execution`。
- `relevance`: `decisive | supporting | auxiliary`。
- `required_for_risk_closure`: 是否影响风险链闭合。
- `required_for_execution_completion`: 是否影响执行完成度。
- `conditional` / `condition_status`: optional/conditional 静态动作的触发条件状态。

## 7. decisive / supporting / auxiliary 分类

实现位置：

- `app/explanation/builder.py::_obligation_role_and_relevance`
- `app/explanation/builder.py::_path_role_for_expected`
- `app/explanation/builder.py::_action_semantic_class`

规则：

- `decisive`: 影响安全结论的 source、sink、guard、credential access、external send/upload/execute/persist。
- `supporting`: instruction loaded、skill activation、tool/action reached、trusted/capability-only evidence。
- `auxiliary`: 日志写入、activity file、本地缓存、非安全关键临时 artifact。

只有 decisive obligation 能阻塞 primary risk path completion。auxiliary unresolved 仍保留在 JSON 和 coverage summary 中，但不阻塞 confirmed violation。

## 8. Primary Risk Path

实现位置：

- `app/explanation/builder.py::_primary_risk_path_selection`
- `app/explanation/builder.py::_best_static_path_for_risk_chain`

选择优先级：

1. 匹配 confirmed violation chain 的 static path。
2. 匹配 candidate chain 的 static path。
3. 风险相关性最高且 evidence 最强的 static path。
4. 无 static chain 时使用 `aggregate-static-actions`。

`other_static_path_summary` 记录其余 static paths 的 complete/partial/unresolved/not_applicable 分布，避免未完成的非主路径覆盖主风险链结论。

## 9. CanonicalAssessment 规则

实现位置：

- `app/explanation/builder.py::_canonical_assessment`
- `app/analysis/pipeline.py::_unified_fields`

核心规则：

- `risk_chain_status=confirmed_violation` => `canonical_final_decision=malicious`。
- `candidate_flow` => `needs_review`。
- 没有 violation，但存在 unresolved decisive obligation => `needs_review`。
- `confirmed_allowed` 且 primary static path partial/unresolved => `needs_review`。
- `timeout/max_steps/crash/unknown` 在 decisive path 未解决时 => `needs_review`。
- `no_sensitive_flow_observed` 且 execution complete 且无 unresolved decisive obligation => `benign`。

数值 `risk_score` 仍作为 compatibility mapping，不作为主解释标题。

## 10. malicious + incomplete execution 的解释

当 runtime 已经观察到敏感源到不可信 sink 的 confirmed chain，并且 PolicyEngine 生成 violation，即使后续执行 timeout 或 max steps，用三轴解释为：

- `risk_chain_status=confirmed_violation`
- `execution_completion=timeout | max_steps_exhausted`
- `primary_static_path_status=complete`
- `canonical_final_decision=malicious`

这避免了旧模型中“链已闭合但 path_completion unresolved”的误导。

## 11. benign 的 security-relevant coverage 条件

benign 只在以下条件同时满足时产生：

- 无 confirmed violation；
- 无 candidate flow；
- execution complete 或动态 coverage 明确为 target reached no flow；
- primary decisive obligations 已满足或不适用；
- 没有 security-relevant review finding；
- instrumentation gap 不影响关键 carrier/source/sink。

trusted LLM prompt 或 trusted Authorization header 可以是 `confirmed_allowed`，但如果静态风险路径仍 partial/unresolved，则仍为 review。

## 12. Legacy 字段兼容

`coverage_certificate.path_completion_status` 仍输出给旧调用方，但：

- 文档和 Markdown 标记为 deprecated compatibility field；
- 顶层主字段是 `risk_chain_status`、`execution_completion`、`primary_static_path_status`；
- `legacy_compatibility.deprecated_fields` 包含 `coverage_certificate.path_completion_status`。

## 13. 重点四样本结果

本轮实际运行目录：

`artifacts/benchmark_v3_user10_three_axis_fix/20260730-233247`

| Sample | Decision | Risk chain | Execution | Primary path | Decisive unresolved | Auxiliary unresolved |
|---|---|---|---|---|---:|---:|
| BV3-0345 | malicious | confirmed_violation | max_steps_exhausted | complete | 0 | 2 |
| BV3-0346 | malicious | confirmed_violation | complete | complete | 0 | 5 |
| BV3-0341 | needs_review | confirmed_allowed | complete | partial | 1 | 0 |
| BV3-0349 | needs_review | confirmed_allowed | max_steps_exhausted | unresolved | 2 | 0 |

结论：

- BV3-0345/BV3-0346 已闭合 malicious chain，不再被 incomplete execution 或 auxiliary gap 降级。
- BV3-0341/BV3-0349 没有 violation chain，且 primary decisive coverage 不足，因此保持 review。

## 14. 10 样本前后对比

旧跑批目录：

`artifacts/benchmark_v3_user10_path_completion_fix/20260730-201311`

新跑批目录：

`artifacts/benchmark_v3_user10_three_axis_fix/20260730-233247`

| Metric | Old | New |
|---|---:|---:|
| samples | 10 | 10 |
| malicious | 2 | 5 |
| needs_review | 8 | 5 |
| confirmed chain samples | 6 | 10 |
| policy violation samples | 2 | 5 |
| primary complete | n/a | 5 |
| primary partial | n/a | 3 |
| primary unresolved | n/a | 2 |
| timeout/max_steps | n/a | 6 |

新结果中 5 个 malicious 都来自 confirmed violation chain；5 个 review 主要来自 confirmed allowed flow 加 decisive static path 覆盖不足。

## 15. 防止 Benchmark overfitting

本轮没有修改 `benchmark_v3` 样本、manifest、fixture、ground truth、label 或 split。

实现没有使用 sample id、固定端口、固定 URL、固定路径或自然语言 wording 做特例。判定只依赖：

- runtime chain 类型和 policy violation；
- static action/path 的通用 action class；
- obligation 的 path-local decisive/supporting/auxiliary 分类；
- execution termination 和 coverage state。

Analyzer 不读取 private ground truth。Benchmark 结果只用于运行后统计和人工解释。

## 16. 当前剩余限制

- `aggregate-static-actions` 仍会在静态链缺少可匹配 path id 时作为 fallback；这能避免丢失覆盖语义，但解释粒度不如完整 static chain。
- 目前 decisive/supporting/auxiliary 是 action/entity 级语义分类，不是 byte-level DIFT。
- TLS、不可观测 payload 和外部 API 行为仍依赖现有 runtime wrapper/telemetry 能力；不会把不可观测 payload 当作 no-flow。
- Execution timeout source 现在在 pipeline 中保留上游解析结果；早于该修正的本轮 artifacts 中 timeout source 可能显示为 adapter 传入后的 explicit 值。
