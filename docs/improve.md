# ProvLoom 改进说明：Instruction-level Provenance Chain Recovery

本文档总结本次“新增一条链（instruction-level/document-supported chain）”的实现、对原有模型的影响、验证结果与产物路径，便于后续整合到论文。

## 1. 改进目标与边界

### 1.1 目标
- 在不改变现有动态沙箱主流程的前提下，为 ProvLoom 增加轻量级静态指令链恢复能力。
- 解决“runtime 未触发/触发不完整时，恶意意图主要藏在 SKILL.md/README 安装维护指令中”的漏检问题。

### 1.2 保持不变的部分
- 动态 telemetry 驱动的 primary_chain 主流程保持不变。
- 不默认下载外部 URL，不执行外部安装命令，不递归拉取远程依赖。
- 不把普通安装说明（如 `pip install` / `npm install`）默认判为高危。

## 2. 对原有模型的具体修改

## 2.1 新增模块（核心）
- 新增文件：[app/analyzer/instruction_chain.py](/root/projects/ProvLoom/app/analyzer/instruction_chain.py)

该模块实现了：
- 文档扫描范围限制（仅本地 skill bundle 文本）：
  - `SKILL.md`
  - `README.md`
  - `README-*.md`
  - `package.json`
  - `scripts/*.sh`, `scripts/*.py`
- 资源预算控制：
  - 单文件上限 `256KB`
  - 总预算上限 `1MB`
- 规则识别（regex + 轻量解析）：
  - 外部 agent 安装
  - 远程脚本/二进制获取
  - 固定密码压缩包
  - 持久化/自动触发
  - 全局环境修改
  - 批量 skill 更新
  - 敏感能力上下文（wallet/OAuth/token 等，作为 boost）
- 闭环判定（closed risk path）：
  - `external trust boundary crossing`
  - `execution/control transfer`
  - `security-impact sink`

## 2.2 分析主流程接入点
- 在 [app/analyzer/rules.py](/root/projects/ProvLoom/app/analyzer/rules.py) 的 `analyze_trace`（动态）和 `analyze_static_skill`（静态）末尾统一调用：
  - `apply_instruction_chain_decision(...)`

即：先做原有动态/静态分析，再叠加 instruction-level 聚合，不破坏主流程。

## 2.3 API / Schema 向后兼容扩展
- 扩展响应模型：[app/backend/schemas.py](/root/projects/ProvLoom/app/backend/schemas.py)
- 透传字段到 API 输出：[app/backend/api.py](/root/projects/ProvLoom/app/backend/api.py)

新增字段（不删除旧字段）：
- `dynamic_chain_observed`
- `instruction_chain_recovered`
- `chain_evidence_type` (`observed_runtime|instruction_derived|hybrid|none`)
- `instruction_chain`
- `instruction_indicators`
- `static_supply_chain_risk`
- `instruction_document_scan`
- `final_risk_level`
- `final_label_reason`

## 2.4 批量/基准输出链路同步
- [scripts/batch_scan_skills.py](/root/projects/ProvLoom/scripts/batch_scan_skills.py) 增加对应字段写入。
- [scripts/run_benchmark.py](/root/projects/ProvLoom/scripts/run_benchmark.py) 增加对应字段导出与评估结构透传。

## 2.5 回归测试新增与修正
- 新增测试：[test/test_instruction_chain.py](/root/projects/ProvLoom/test/test_instruction_chain.py)
  - 覆盖 auto-updater / clawhub / ethereum-gas-tracker 类风险恢复
  - 覆盖误报抑制（普通安装、仅 cron、仅全局安装）
- 根据当前样本目录修正了一个测试路径与断言（`cllawhub` 样本命名与实际指标类别一致）。

## 3. 风险聚合策略（与原模型关系）

关键逻辑在 `instruction_chain.py::_aggregate_final_risk_level`：

1. 若动态结果已达 `high/critical`，保持动态高风险结论，不被新增路径降级。  
2. 若动态风险低/证据不完整，但 instruction 闭环成立，可提升最终风险。  
3. 若仅有外部安装或普通依赖安装、无 sink 闭环，不直接拉到 high/critical。  

结论：**新增路径不会把原本已是 critical/high 的样本综合后降级。**

## 4. 术语与表述规范（报告层）

针对 instruction 恢复路径，统一使用：
- `instruction-derived chain`
- `document-supported chain`
- `latent attack path`
- `not observed at runtime`
- `requires user execution/setup`

避免把文档推断链写成“已在运行时发生”。

## 5. 已完成验证与结果

### 5.1 单元测试
- 指令链测试：
  - `python3 -m unittest discover -s test -p 'test_instruction_chain.py' -v`
  - 结果：`6/6 OK`
- 现有双轴决策 smoke：
  - `python3 -m unittest discover -s test -p 'test_dual_axis_decision.py' -v`
  - 结果：`6/6 OK`

### 5.2 关键回归（auto-updater）
- 直接回归 `dangerous_skills/auto-updater-2yq87`：
  - `instruction_chain_recovered=True`
  - `chain_evidence_type=instruction_derived`
  - `static_supply_chain_risk.level=critical`
  - `final_risk_level=critical`
  - 链动作包含：`external_agent_install -> remote_script_or_binary_acquisition -> fixed_password_archive -> global_environment_modification -> persistence_setup -> bulk_skill_update`

### 5.3 benchmark v2 smoke（static_only）
- 执行：
  - `python3 scripts/run_benchmark.py --analysis-mode static_only --datasets-root benchmark_v2/datasets`
- 摘要（本次运行）：
  - `case_count=139`
  - `completed_case_count=139`
  - `failed_case_count=0`
  - `detection_rate=1.0`
  - `false_positive_rate=0.0`

## 6. 修改后结果文件位置


### 6.2 benchmark 输出
- 汇总：
  - [benchmark-summary-static_only.json](/root/projects/ProvLoom/artifacts/benchmark/benchmark-summary-static_only.json)
  - [benchmark-summary-static_only.csv](/root/projects/ProvLoom/artifacts/benchmark/benchmark-summary-static_only.csv)
- 历史兼容烟测文件：
  - [static_only_compat_smoke_summary.json](/root/projects/ProvLoom/benchmark_v2/generated/static_only_compat_smoke_summary.json)

### 6.3 人工复核表（real_world2）
- [human_review_sheet.csv](/root/projects/ProvLoom/real_world2/human_review_sheet.csv)

## 7. 论文可直接引用的贡献点

1. 在不改动动态主流程的情况下，新增 instruction-level provenance chain recovery。  
2. 通过“闭环条件”降低误报，不把普通安装说明直接判高危。  
3. 在 dynamic 证据弱时补齐 document-supported latent attack path，提高对供应链/持久化/环境控制风险的识别能力。  
4. 保持向后兼容：原字段不删，新增字段可空，原 critical/high 不被降级。  

