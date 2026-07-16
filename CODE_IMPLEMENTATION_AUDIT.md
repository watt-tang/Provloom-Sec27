# ProvLoom 只读式实现审计

审计时间：2026-07-14  
审计范围：`/root/projects/ProvLoom` 当前工作区代码、脚本、数据与本地论文 PDF  
审计约束：未修改任何源代码；未访问外部网络；未执行真实恶意样本、远程脚本或安装程序。  

---

## 审计方法

- 仅依据本地代码、脚本、CSV/JSON/PDF 与 Git 状态做结论，不根据 README、论文措辞或函数名补全实现。
- 每个关键结论尽量附：
  - 文件路径
  - 函数/类
  - 行号
  - 调用链
- 找不到实现时明确写“未在代码中找到”。

状态标签说明：

- `Fully implemented`：代码中有可执行实现，且被主流程调用。
- `Partially implemented`：有实现，但覆盖有限、简化明显或只覆盖一部分场景。
- `Heuristic/rule-based`：主要依赖规则、阈值、正则、关键词、顺序拼接等。
- `LLM-dependent`：主能力依赖外部 LLM 或 LLM 决策。
- `Manually produced`：主要来自人工 CSV/人工审阅，而非代码自动推出。
- `Evaluation-only`：只在 benchmark/图表/论文产物中使用。
- `Described but not implemented`：论文声称或暗示存在，但代码中未找到对应实现。

---

## 一、项目总体结构

### 1.1 从主入口到最终结果的真实调用链

动态主流程调用链：

`app/main.py:14-26`  
→ `app/backend/api.py:22-30` 路由 `/analyze-skill`  
→ `app/backend/api.py:89-98` 调 `DockerRunner.run(...)`  
→ `app/runner/docker_runner.py:48-295` 复制 skill、准备 adapters/trigger、启动 Docker、收集 trace/runtime events  
→ `app/analyzer/rules.py:64-234` `analyze_trace(...)`  
→ `app/telemetry/normalizer.py:37-53` 归一化事件  
→ `app/graph/builder.py:285-292` 构建 EPG  
→ `app/analyzer/attack_chain.py:37-113` 恢复 primary chain  
→ `app/analyzer/decision_engine.py` / `app/analyzer/risk_scoring.py:73-164` / `app/analyzer/dual_axis_decision.py:17-123` 做风险与证据归因  
→ `app/analyzer/instruction_chain.py:133-167` 合并 instruction-chain 结果  
→ `app/telemetry/collector.py:90-100` `build_execution_report(...)`  
→ `app/backend/api.py:103-170` 组装最终响应

静态主流程调用链：

`app/main.py:14-26`  
→ `app/backend/api.py:65-79`  
→ `app/runtime/skill_parser.py:61-92` `load_skill_definition(...)`  
→ `app/analyzer/rules.py:237-410` `analyze_static_skill(...)`  
→ `app/analyzer/instruction_chain.py:133-167` 合并 instruction-chain  
→ `app/backend/api.py:241-280` 生成静态响应

benchmark 调用链：

`scripts/run_benchmark.py:44-92`  
→ `discover_cases(...)` (`scripts/run_benchmark.py:95-124`)  
→ `run_and_evaluate_case(...)` (`scripts/run_benchmark.py:147-185`)  
→ 动态模式进入 `DockerRunner.run(...)` + `analyze_trace(...)`  
→ 静态模式进入 `load_skill_definition(...)` + `analyze_static_skill(...)`  
→ `evaluate_case(...)` (`scripts/run_benchmark.py:288-348`)  
→ 聚合写入 `artifacts/benchmark/benchmark-summary.json`

### 1.2 分阶段结构表

| 阶段 | 入口文件/函数 | 输入 | 输出 | 配置/依赖 | 是否参与实验 | 状态 |
|---|---|---|---|---|---|---|
| Skill bundle 定位 | `app/runtime/skill_parser.py:36-58` `resolve_skill_target` | `skill_path` | skill 根目录、`SKILL.md` 相对路径 | 本地文件系统 | 是 | Fully implemented |
| artifact loading | `app/runtime/skill_parser.py:61-92` | `SKILL.md` | `SkillDefinition` | frontmatter、fenced JSON | 是 | Partially implemented |
| static instruction analysis | `app/analyzer/instruction_chain.py:86-130` | skill 本地文档集合 | `instruction_indicators`, `instruction_chain`, `static_supply_chain_risk` | 正则规则 | 是 | Heuristic/rule-based |
| sandboxed execution | `app/runner/docker_runner.py:48-295` | skill、payload、LLM config | `SandboxExecution` | Docker、strace | 是 | Fully implemented |
| telemetry collection | `app/runner/docker_runner.py:222-242`, `app/telemetry/collector.py:11-100` | trace、runtime events | file/network/process/tool/llm/data_flow 事件 | strace + runtime wrapper + adapter 注入 | 是 | Partially implemented |
| execution provenance graph | `app/graph/builder.py:21-35, 285-292` | normalized events + telemetry report | `ExecutionProvenanceGraph` | 规则连边 | 是 | Partially implemented |
| dynamic chain recovery | `app/analyzer/attack_chain.py:37-113` | EPG + detected behaviors | `primary_chain` | BFS + ranking/filtering | 是 | Heuristic/rule-based |
| evidence attribution | `app/analyzer/rules.py:156-233`, `app/analyzer/instruction_chain.py:161-167` | dynamic + instruction 结果 | `final_decision`, `chain_evidence_type`, `final_risk_level` | 规则表 | 是 | Heuristic/rule-based |
| severity/root cause | `app/analyzer/risk_scoring.py:73-164`, `app/analyzer/dual_axis_decision.py:17-123`, `app/analyzer/rules.py:687-745` | source/sink/behaviors/chain | risk score、severity、root cause | 规则阈值 | 是 | Heuristic/rule-based |
| benchmark evaluation | `scripts/run_benchmark.py` | benchmark cases | 指标 JSON/CSV | 本地数据集 | 是 | Fully implemented |
| real-world audit | `scripts/generate_human_complete670.py:414-476`, `scripts/generate_realworld_scanner_tables.py` | 本地 JSON/CSV/人工表 | `docs/human_complete670.csv` 等 | 本地绝对路径 + 人工标签 | 是 | Manually produced |

### 1.3 关键配置与外部依赖

- API 入口：`app/main.py:14-26`
- Docker 运行器：`app/runner/docker_runner.py:32-46`
- Dockerfile 构建：`app/runner/docker_runner.py:302-336`
- LLM 默认配置：`app/backend/schemas.py:7-10, 51-80`
- OpenAI-compatible 调用：`app/runtime/llm_client.py:16-75`
- 论文 PDF：`paper-acsac26-paper467.pdf`

---

## 二、Static Instruction Chain 的真实实现

### 总结判断

`Static Instruction Chain` 在当前代码中不是语义解析器、不是 artifact graph 推理器、也不是基于 LLM 的自然语言结构化抽取器；它是一个**扫描少量本地文本文件、用硬编码正则识别若干风险类别、再按固定顺序拼接链条**的模块。  

核心证据：

- 规则定义：`app/analyzer/instruction_chain.py:21-81`
- 文档加载范围与大小限制：`app/analyzer/instruction_chain.py:170-215`
- 风险判定：`app/analyzer/instruction_chain.py:218-302`
- 链条构造：`app/analyzer/instruction_chain.py:305-339`
- dynamic/instruction 合并：`app/analyzer/instruction_chain.py:133-167, 342-400`

另一个重要事实：`app/analyzer/instruction_chain.py` 当前是**未提交文件**。`git status --short` 显示 `?? app/analyzer/instruction_chain.py`，因此它不属于当前 Git 已提交历史的一部分。该点会影响可复现性和论文-代码一致性判断。

### 2.1 输入解析

实际读取文件：

- `SKILL.md`
- `README.md`
- `README-*.md`
- `package.json`
- `scripts/*.sh`
- `scripts/*.py`

证据：`app/analyzer/instruction_chain.py:170-183`

明确未在该模块中找到的读取对象：

- JavaScript 文件：未在代码中找到
- 其他配置文件（如 YAML/TOML/INI/lockfile）：未在代码中找到
- 任意递归目录深搜的 helper code：未在代码中找到

限制：

- 单文件最大读取：`MAX_FILE_BYTES = 256 * 1024`，`app/analyzer/instruction_chain.py:9`
- 总预算：`MAX_TOTAL_BYTES = 1024 * 1024`，`app/analyzer/instruction_chain.py:10`
- 超预算即停止：`app/analyzer/instruction_chain.py:202-214`

解析粒度：

- 只对文本做正则扫描：`app/analyzer/instruction_chain.py:92-112`
- 不解析 markdown AST、链接图、命令 AST、段落关系、代码注释语义
- `skill_parser` 只在 runtime 静态 action 模式下解析 fenced ` ```skill-actions ` JSON，不属于 instruction-chain 语义抽取器：`app/runtime/skill_parser.py:133-160`

结论：`Heuristic/rule-based`

### 2.2 动作提取

自然语言到 action 的真实过程：

1. `_load_candidate_documents(...)` 读入少量文件  
2. 对每个文档文本运行 `INDICATOR_RULES` 正则  
3. 每次命中生成一个 indicator dict  
4. indicator 仅包含若干手工字段，再由 `_score_instruction_risk(...)` 聚合类别组合  
5. 若满足闭合条件，则 `_build_instruction_chain(...)` 以固定顺序拼接成链

证据：

- 命中逻辑：`app/analyzer/instruction_chain.py:92-112`
- indicator 结构：`app/analyzer/instruction_chain.py:100-110`
- target 提取：`app/analyzer/instruction_chain.py:409-423`

实际 action/indicator 数据结构字段：

- `category`
- `action`
- `target`
- `evidence_source`
- `evidence_type`
- `observed_at_runtime`
- `confidence`
- `raw_snippet`

证据：`app/analyzer/instruction_chain.py:100-110`

明确未在代码中找到的结构化字段：

- `actor`
- `operation`
- `object`
- `source`
- `destination`
- `condition`
- `privilege`
- 精确 `evidence span` 起止偏移
- 跨句 coreference / 实体归一化

实现方法：

- 正则/关键词：`app/analyzer/instruction_chain.py:21-81`
- 不是 AST
- 不是 embedding
- 不是分类器
- 不是外部 LLM

如果使用 LLM：

- instruction-chain 模块中：未在代码中找到
- 模型名、Prompt、temperature、seed、retry、cache、多次采样、一致性检查：均未在 instruction-chain 模块中找到

结论：`Heuristic/rule-based`

### 2.3 语义处理能力核查

针对审稿意见中的语义难点，本次审计在 `app/analyzer/instruction_chain.py` 中**未在代码中找到**以下处理：

- 否定句，例如 “do not execute this script”
- 安全警告
- README 教学示例
- 防御性文本
- 注释掉的命令
- 条件语句
- 可选安装步骤
- 用户确认步骤
- 段落间关系
- 同义表达归一化
- 混淆/对抗性文本鲁棒性
- Skill 内容对分析器的 prompt injection 防御

原因：

- 整个模块只有文档枚举、正则匹配、类别组合、固定顺序串联，没有 NLP 判别分支：`app/analyzer/instruction_chain.py:86-130, 170-339`

结论：这些能力在论文中被需要，但在代码中**未实现或至少未在代码中找到**。状态为 `Described but not implemented`。

### 2.4 “local artifact graph” 的真实实现

论文声称 instruction component 分析 local artifacts / local artifact graph（PDF `paper-acsac26-paper467.pdf` 抽取文本第 54-60、98-102、179-183、227-236、642-668 行）。

代码中真实情况：

- 未找到一个显式的 `artifact graph` 数据结构类
- 未找到节点对象、边对象、图搜索、跨文件依赖边
- 未找到 trust-boundary、control-transfer、impact-sink 的图上路径验证

真实存在的是：

- 文档集合 `documents`
- indicator 列表 `instruction_indicators`
- 闭合时按固定顺序产生的 edge-like dict 列表 `instruction_chain`

证据：

- 文档扫描：`app/analyzer/instruction_chain.py:86-130`
- 固定顺序链：`app/analyzer/instruction_chain.py:305-339`

所以“local artifact graph”在代码里更接近：

```text
documents --regex--> indicators --category combination--> risk level
                                          \
                                           -> fixed-order pseudo-chain
```

而不是：

```text
artifact graph with typed nodes/edges + path search + entity linking
```

结论：论文中的 “local artifact graph” 在当前代码中属于 `Described but not implemented`。

### 2.5 Closed Instruction Chain 的真实判定

接近伪代码的真实逻辑：

```text
categories = matched indicator categories
actions = matched indicator actions

has_trust_boundary =
    external_agent OR remote_acquisition OR fixed_password_archive

has_execution_transfer =
    external_agent_install OR remote_script_or_binary_acquisition
    OR global_environment_modification

if has_trust_boundary and has_execution_transfer and (has_persistence or has_bulk):
    level = critical
    closed_risk_path = True
elif has_external_agent and has_execution_transfer and has_env:
    level = high
    closed_risk_path = True
elif has_external_agent and has_sensitive and (has_remote or has_fixed_password):
    level = medium
    closed_risk_path = True
elif has_trust_boundary and has_execution_transfer:
    level = medium
    closed_risk_path = False
...
```

证据：`app/analyzer/instruction_chain.py:218-302`

链条构造方式：

- 仅当 `closed_risk_path=True` 时，按固定 action 顺序取每种 action 的第一个 indicator
- 上一节点初始值固定为 `"skill_bundle_documentation"`
- 后续边的 `source` 是前一条边的 `target`

证据：`app/analyzer/instruction_chain.py:305-339`

因此，代码**没有真正验证**：

- 路径连接关系：未在代码中找到
- 同一实体/同一资源：未在代码中找到
- 同一安装/维护流程：未在代码中找到
- 跨文件因果关系：未在代码中找到
- 指令顺序是否来自文档真实顺序：未在代码中找到

它验证的是：**几个类别/动作关键词命中后，满足布尔组合条件**。  

结论：`Closed Instruction Chain` 在代码中是 `Heuristic/rule-based`，不是真正的 graph/path validation。

---

## 三、Dynamic Analysis 的真实实现

### 3.1 Sandbox

隔离机制：

- Docker 容器：`app/runner/docker_runner.py:147-189`
- `--cap-drop ALL`：`app/runner/docker_runner.py:152-153`
- `--security-opt no-new-privileges`：`app/runner/docker_runner.py:154-155`
- `--pids-limit 64`：`app/runner/docker_runner.py:156-157`
- 内存/CPU 限制：`app/runner/docker_runner.py:158-161`
- 可选 `--network none`：`app/runner/docker_runner.py:169-170`

动态执行命令：

- 容器内通过 `strace -ff -tt -s 256 -o /artifacts/trace.log -e trace=file,process,network python -m app.runtime.container_runtime ...` 运行：`app/runner/docker_runner.py:338-355`

每次运行环境：

- 使用 `TemporaryDirectory`
- 将 skill 复制到临时目录
- 新建独立 artifacts 目录
- 结束后 `docker rm -f`

证据：`app/runner/docker_runner.py:75-82, 144-145, 292-294, 357-363`

外部网络是否真的阻断：

- 运行态只有 `network_policy == "disabled"` 才加 `--network none`：`app/runner/docker_runner.py:169-170`
- 默认 `network_policy` 在 API schema 中是 `"default"`：`app/backend/schemas.py:97-109`
- Docker image build 仍使用 `docker build --network host`：`app/runner/docker_runner.py:316-333`

所以答案是：

- 运行态：可以配置阻断，但默认不阻断
- 构建态：明确使用宿主网络

synthetic sensitive files：

- `CredentialStateAdapter` 会在 `.provloom/adapters/credential_state/` 下创建：
  - `fake.env`
  - `fake_token.json`
  - `fake_account_profile.json`
  - `fake_scopes.txt`

证据：`app/runtime/adapter_layer.py:236-286`

真实凭据/宿主泄漏风险：

- 运行容器挂载 skill 目录和 artifacts 目录：`app/runner/docker_runner.py:162-165`
- LLM 配置初始写入 artifacts，其中 `api_key` 后续才被脱敏：`app/runner/docker_runner.py:84-99, 218-219, 365-375`
- 默认 API key 直接硬编码在源码：`app/backend/schemas.py:7-10, 44-57`

结论：

- sandbox 本身是 `Fully implemented`
- 网络隔离与真实世界“完全离线审计”不等价
- synthetic artifact 机制会把“动态证据”与“适配器注入证据”混在一起，状态 `Partially implemented`

### 3.2 Telemetry

实际采集的事件类型：

- file read / write：来自 `strace` 解析结果，`app/runner/docker_runner.py:222-233`
- process creation：来自 `strace` 解析结果，`app/runner/docker_runner.py:228-232`
- network connection：来自 `strace` 解析结果，`app/runner/docker_runner.py:226-233`
- tool call：来自 runtime wrapper JSONL，`app/telemetry/collector.py:11-35`
- LLM decision：来自 runtime wrapper JSONL，`app/telemetry/collector.py:38-57`
- data_flow：不是 OS-level 采样，而是后处理 hint，`app/telemetry/collector.py:60-87`

event schema 与 parent relation：

- 统一事件结构 `NormalizedEvent`：`app/telemetry/normalizer.py:20-35`
- LLM parent 通过上一 request 或上一事件补：`app/telemetry/normalizer.py:76-109`
- tool parent 通过同 step 的 LLM request 或同 tool start 补：`app/telemetry/normalizer.py:112-156`
- file/process/network 事件 parent 默认挂到“最后一个 tool 或最后一个 llm”：`app/telemetry/normalizer.py:282-314`

是否记录数据内容：

- file/network/process OS 事件不记录字节内容，只记录 path/address/command 等元信息：`app/telemetry/normalizer.py:159-241`
- tool/LLM 事件会带有限 preview 或 metadata：`app/runtime/container_runtime.py:65-73, 388-400`

是否仅根据工具包装器推断：

- tool/LLM 是 runtime wrapper 直接写 JSONL
- file/process/network 是 `strace`
- data_flow 不是 OS taint，而是后处理推断

结论：`Telemetry` 为 `Partially implemented`

### 3.3 Execution Provenance Graph

节点类型：

- `llm_step`
- `tool_call`
- `process`
- `file`
- `network_endpoint`
- `data`
- generic event

证据：`app/graph/builder.py:37-145`

边类型：

- `reads`
- `writes`
- `connects`
- `causes`
- `flows_to`

证据：`app/graph/builder.py:147-183, 185-232`

边构造真实来源：

- tool config → file/network：`app/graph/builder.py:147-183`
- parent_event_id → `causes`：`app/graph/builder.py:185-190`
- process pid 与 file/network 同 pid 对齐：`app/graph/builder.py:192-218`
- data_flow hints → `flows_to`：`app/graph/builder.py:220-232`

data-flow edge 是否是真实污点传播？

不是。核心证据：

- `build_data_flow_hints(...)` 只在“有敏感读 + 有网络事件”时，取**第一个敏感读**和**第一个网络事件**生成一条 `DataFlowEvent`：`app/telemetry/collector.py:60-87`
- 注释文字也写明：`"Potential source-to-sink flow. Use for future sensitive dataflow analysis."`，`app/telemetry/collector.py:84`

这意味着：

- “某个进程读了敏感文件后又联网”时，代码会**直接给出 source→sink hint**
- 不验证发送的数据内容
- 不验证 read 与 send 的字节依赖
- 不验证中间处理是否真使用了该数据

结论：EPG 是 `Partially implemented`，其中 data-flow 部分属于 `Heuristic/rule-based`，不是 taint tracking。

### 3.4 路径搜索与 Filtering

candidate path 生成：

- 先按行为门槛决定是否搜索：`app/analyzer/attack_chain.py:45-52`
- source 候选为 file 节点：`app/analyzer/attack_chain.py:144-163`
- sink 候选分 resolved / unresolved / relay 三组：`app/analyzer/attack_chain.py:165-195`
- 用 BFS 搜路：`app/analyzer/attack_chain.py:125-141`

ranking：

- 先比较 path 长度、噪声数、source priority、sink priority、字典序：`app/analyzer/attack_chain.py:219-242`
- source priority：敏感/工具相邻/生成文件/公共文件：`app/analyzer/attack_chain.py:197-216`
- sink priority：URL > domain > IP > unresolved；relay 最低：`app/analyzer/attack_chain.py:245-263`

filtering：

- `filter_noise=True` 时压缩路径，去掉中间 noisy file/data 节点：`app/analyzer/attack_chain.py:90-92, 265-282`
- noisy file 通过前缀/白名单识别：`app/analyzer/attack_chain.py:9-34, 332-337`

Filtering 会不会改变结果？

- 会影响 recovered `primary_chain` 的具体节点与 relay 展示：`app/analyzer/attack_chain.py:90-92, 265-282`
- 也会影响 benchmark 的 endpoint/F1/complete chain 指标，因为这些指标直接用 `primary_chain`：`scripts/run_benchmark.py:298-305, 351-417`
- 代码中没有单独的 “只改显示、不改判定” 保证

结论：`Dynamic chain recovery` 为 `Heuristic/rule-based`

---

## 四、Evidence Attribution 和 Severity

### 4.1 dynamic 与 instruction 如何合并

dynamic + instruction 合并发生在 `apply_instruction_chain_decision(...)`：

- 写入：
  - `dynamic_chain_observed`
  - `instruction_chain_recovered`
  - `instruction_chain`
  - `instruction_indicators`
  - `static_supply_chain_risk`
  - `instruction_document_scan`
- 再计算：
  - `chain_evidence_type`
  - `final_risk_level`
  - `final_label_reason`

证据：`app/analyzer/instruction_chain.py:133-167`

`chain_evidence_type` 逻辑：

- dynamic + instruction → `hybrid`
- dynamic only → `observed_runtime`
- instruction only → `instruction_derived`
- neither → `none`

证据：`app/analyzer/instruction_chain.py:393-400`

注意：

- 代码**不要求** hybrid 的两条链描述同一行为、同一 source/sink、同一根因
- 只要 `dynamic_chain_observed` 和 `instruction_chain_recovered` 同时为真，就标 `hybrid`

结论：hybrid 只是布尔并置，不是语义一致性验证。

### 4.2 severity / malicious / escalation 的真实关系

风险分数与 final decision：

- `raw_score >= 60` → `MALICIOUS`
- `raw_score >= 30` → `NEEDS_REVIEW`
- else → `BENIGN`

证据：`app/analyzer/risk_scoring.py:157-164`

评分因子示例：

- `high_sensitivity_source_to_external_sink` +80：`app/analyzer/risk_scoring.py:77-91`
- `generated_artifact_external_transfer` +55：`app/analyzer/risk_scoring.py:92-100`
- `overprivileged_outward_tool_action` +45：`app/analyzer/risk_scoring.py:101-109`
- `unsafe_command_construction` +70：`app/analyzer/risk_scoring.py:110-118`
- `llm_directed_external_account_registration` +80：`app/analyzer/risk_scoring.py:119-130`
- `llm_induced_risky_action` +25：`app/analyzer/risk_scoring.py:131-139`
- `unknown_source_external_sink` +25：`app/analyzer/risk_scoring.py:140-156`

双轴标签：

- `severity_label`: `benign_like` / `weakly_suspicious` / `substantial_risk` / `severe_risk`
- `evidence_strength`: `speculative` / `partial` / `chain_backed` / `strongly_evidenced`

证据：`app/analyzer/dual_axis_decision.py:6-14, 17-123`

high/critical queue 概念：

- 代码里没有一个统一“escalation queue”对象
- 实际上更接近：
  - `final_decision`：malicious / needs_review / benign
  - `final_risk_level`：low/medium/high/critical
  - `severity_label`
  - `evidence_strength`
- 真实世界图表中的 high/critical 是后续统计口径，不是单独检测标签：`scripts/make_realworld_threshold_figure.py:11-25`

### 4.3 术语映射表

| 概念 | 代码字段/变量 | 判定条件 | 是否等价于 malicious |
|---|---|---|---|
| detected | `detected_behaviors` | 动态/静态规则命中 | 否 |
| closed chain | `dynamic_chain_observed` 或 `instruction_chain_recovered` | dynamic 有 `primary_chain`；instruction 满足布尔闭合条件 | 否 |
| hybrid | `chain_evidence_type == "hybrid"` | dynamic_chain_observed AND instruction_chain_recovered | 否 |
| escalated | 无单一字段；常见统计口径是 `final_risk_level in {high,critical}` | 后处理统计 | 否 |
| high/critical | `final_risk_level` | 动态风险分值分段或 instruction 风险抬升 | 否 |
| malicious detector output | `final_decision == "malicious"` | `risk_score >= 60` | 是代码内部恶意判定，不等价于人工 malicious 标签 |
| human malicious label | `existing_human_decision == "malicious"` in `docs/human_complete670.csv` | 人工标签 | 不是模型输出 |

---

## 五、21、9、7、26 的代码来源

### 5.1 670 / 21 / 79 / 570

来源文件：

- `docs/human_complete670.csv`
- 生成脚本：`scripts/generate_human_complete670.py:414-476`

生成逻辑：

- 470 高风险样本：`scripts/generate_human_complete670.py:281-336, 436-446`
- 200 safe-like 样本：`scripts/generate_human_complete670.py:339-411, 448-458`
- 脚本强制断言：
  - 470：`scripts/generate_human_complete670.py:460-461`
  - 200：`scripts/generate_human_complete670.py:462-463`
  - 总数 670：`scripts/generate_human_complete670.py:464-465`

复算结果（直接统计 `docs/human_complete670.csv`）：

- 670 rows
- `existing_human_decision`：
  - malicious = 21
  - ambiguous = 79
  - benign = 570

这组数字可从 CSV 重新计算，但**标签本身是人工产物**，不是模型自动生成。状态：`Manually produced`

### 5.2 9 个恶意样本恢复 closed chain

来源：

- `docs/human_complete670.csv`
- 由 `provloom_evidence_type` 与人工 malicious 标签共同决定

在该 CSV 中：

- malicious 总数 = 21
- 其中 `provloom_evidence_type == instruction_derived` 的 malicious = 9
- `provloom_evidence_type == no_closed_chain` 的 malicious = 12

复算结果见本次审计静态统计。

注意：

- 这 9 个在 CSV 里是 **instruction_derived**
- 不是 9 个 `observed_runtime`
- 因此“9 个恢复 closed chain”更准确地说是：在该 CSV 编码里，9 个 malicious 被 ProvLoom 归为非 `no_closed_chain`

### 5.3 26 / 7 / 7 / 12

两个来源要分开：

1. 可复算来源：`docs/human_complete670.csv`
   - 过滤条件：`provloom_final_risk_level in {high, critical}`
   - 结果：
     - 总数 26
     - malicious 7
     - ambiguous 7
     - benign 12

2. 图表脚本硬编码来源：`scripts/make_realworld_threshold_figure.py:11-25`
   - `HIGH_CRITICAL` 里直接写死：
     - `ProvLoom`: `mal=7, ambig=7, benign=12, total=26`

因此：

- 26/7/7/12 能从 CSV 复算
- 但图表脚本并不是现场计算，而是硬编码这些数

状态：

- CSV 统计：`Manually produced` + 可复算
- 图表脚本：`Evaluation-only`

### 5.4 9 和 7 为什么不同

- `9`：21 个人工 malicious 里，ProvLoom 给出 closed-chain 型证据的数量（在 CSV 中体现为 9 个 `instruction_derived`）
- `7`：所有 ProvLoom `high/critical` 样本中，被人工标为 malicious 的数量

它们统计口径不同，所以**不构成逻辑矛盾**。  

### 5.5 是否存在脚本/论文/产物不一致

存在几个需要明确区分的层次：

- 论文摘要中的 670/21/79/570/9 与 `docs/human_complete670.csv` 一致
- 26/7/7/12 能从同一 CSV 复算，但图表脚本是硬编码，不是现场聚合
- `real_world2/human_review_sheet.csv` 只有 26 行，不是 670 主表；若误把它当主审计表会得到完全不同统计

---

## 六、Benchmark 构建与潜在偏置

### 6.1 104 malicious / 43 benign 如何生成

case generator：

- `scripts/generate_benchmark_v2.py`

模板化生成证据：

- `CaseSpec` 模板：`scripts/generate_benchmark_v2.py:60-165`
- 直接 exfiltration 模板：`scripts/generate_benchmark_v2.py:171-220`
- staged relay 模板：`scripts/generate_benchmark_v2.py:222-307`
- LLM-induced 模板：`scripts/generate_benchmark_v2.py:470-510`
- mixed multi-hop 模板：`scripts/generate_benchmark_v2.py:513-545`
- benign lookalike 模板：如 `hard_benign_fetch_note_case(...)`、`hard_benign_helper_case(...)`、`clean_local_relay_benign_case(...)`，`scripts/generate_benchmark_v2.py:628-848`

manifest：

- `benchmark_v2/generated/benchmark_v2_manifest.json`
- `case_count = 147`
- 恶意 104、良性 43，可从 manifest 直接复算

结论：benchmark 明显是**模板化生成**。状态：`Evaluation-only`

### 6.2 benchmark 与 detector 是否共享规则/常量

共享/相近点：

- benchmark 生成器大量使用固定敏感文件：
  - `/etc/passwd`
  - `/etc/hostname`
  - `/etc/group`
  - `/etc/os-release`
  - 见 `scripts/generate_benchmark_v2.py:22-27`
- detector 的敏感路径规则也主要围绕 `/etc/`, `/root/`, `/proc/`, `/sys/`, `/var/run/`：
  - `app/analyzer/rules.py:22-32, 413-416`
  - `app/telemetry/collector.py:66-71`
  - `app/analyzer/attack_chain.py:322-329`
- benchmark 恶意样本大量用固定 outward URL：
  - `EXTERNAL_POST_URL = https://httpbin.org/post`
  - `EXTERNAL_FETCH_URL = https://httpbin.org/get`
  - `APPROVED_POST_URL = https://httpbin.org/post?approved=1`
  - `scripts/generate_benchmark_v2.py:18-20`
- detector 并不直接读 case_id/manifest 判标签，但它确实依赖这些显式 URL/path/tool pattern 来恢复 source/sink

未发现的严重情况：

- detector 根据 case name 或目录名直接判断标签：未在代码中找到
- runtime 读取 benchmark manifest 做判定：未在代码中找到

但存在的偏置风险：

- benchmark 使用固定少量敏感文件名
- 使用固定少量 URL
- 恶意/良性由同一作者模板化构造
- benign lookalikes 是“针对可疑表面模式”刻意制作的 hard controls
- 没有开发集/测试集分离、没有 held-out set、没有 blind annotation 流程代码

证据：

- 模板化构造：`scripts/generate_benchmark_v2.py:171-848`
- manifest 评估状态：`benchmark_v2/generated/benchmark_v2_manifest.json`
- benchmark 发现与评估：`scripts/run_benchmark.py:95-185`

### 6.3 是否能看出 benchmark 与 detector 同步修改

Git 历史显示：

- `89d1b9b Improve benchmark scoring and audit tooling`
- `fafac05 Add batch scan workflow and risk analysis updates`
- `f4d1ded Add benchmark pipeline and decision analysis`
- `c4e6a49 Add provenance-based runtime analysis pipeline`

这些 commit 同时涉及：

- `scripts/generate_benchmark_v2.py`
- `scripts/run_benchmark.py`
- `app/analyzer/rules.py`

这不能单独证明“看了测试结果后调规则”，但能证明 benchmark 与 detector 在同一开发过程中耦合演化。  

结论：审稿人关于 benchmark 偏置/耦合设计的担心是 `Partially accurate`。

---

## 七、24 个被跳过案例

### 7.1 全部 24 个案例

从 `benchmark_v2/generated/benchmark_v2_manifest.json` 复算：

- 12 个 `static_evaluable`
- 12 个 `partially_stubbed`

具体 ID：

- `v2_llm_note_passwd`
- `v2_llm_note_hostname`
- `v2_llm_note_group`
- `v2_llm_note_os_release`
- `v2_llm_report_passwd`
- `v2_llm_report_hostname`
- `v2_llm_report_group`
- `v2_llm_report_os_release`
- `v2_llm_audit_passwd`
- `v2_llm_audit_hostname`
- `v2_llm_audit_group`
- `v2_llm_audit_os_release`
- `v2_mixed_audit_passwd`
- `v2_mixed_audit_hostname`
- `v2_mixed_audit_group`
- `v2_mixed_audit_os_release`
- `v2_mixed_mirror_passwd`
- `v2_mixed_mirror_hostname`
- `v2_mixed_mirror_group`
- `v2_mixed_mirror_os_release`
- `v2_mixed_export_passwd`
- `v2_mixed_export_hostname`
- `v2_mixed_export_group`
- `v2_mixed_export_os_release`

### 7.2 按原因分类

| 类别 | 数量 | 代码证据 | 说明 |
|---|---|---|---|
| LLM-mediated / design-level | 12 | `scripts/generate_benchmark_v2.py:470-510` | `evaluation_status="static_evaluable"`，明确说为了保留 design-level coverage 而不伪造 runtime traces |
| partially stubbed / dynamic replay noisy | 12 | `scripts/generate_benchmark_v2.py:513-545` | `evaluation_status="partially_stubbed"`，notes 明确写 dynamic replay noisy |

评估脚本跳过逻辑：

- `analysis_mode != "static_only"` 且 `not case.dynamic_runnable` 时，直接 `_skipped_case_result(...)`：`scripts/run_benchmark.py:147-157`

因此这 24 个不是“系统完全不能分析”，而是：

- 动态 benchmark 框架不执行
- static_only 仍会分析它们

### 7.3 detection rate 是否排除了它们

是。

`artifacts/benchmark/benchmark-summary.json` 显示：

- `rule_plus_epg`:
  - `case_count = 147`
  - `completed_case_count = 123`
  - `skipped_case_count = 24`
  - `malicious_case_count = 80`
  - `benign_case_count = 43`
  - `detection_rate = 1.0`

因此论文中的动态指标是对 **123 completed dynamic cases** 计算的，而不是全部 147。

### 7.4 80/80 与 80/104

- runnable malicious recall = `80/80 = 1.0`
- 全体 malicious 覆盖 = `80/104 ≈ 0.7692`

如果把 24 个非动态恶意样本按 false negative 计，则 ProvLoom 的全体 malicious recall 不是 1.0，而是约 76.9%。

---

## 八、Baseline 比较是否公平

### 8.1 ProvLoom 的比较集合

ProvLoom 动态模式：

- 实际完成 123 cases
- 跳过 24 cases

证据：`artifacts/benchmark/benchmark-summary.json`

### 8.2 SkillScan 的比较集合

仓库中明确可见的 benchmark baseline 只有 SkillScan 对比文件：

- `skillscan_benchmark_cmp/skillscan_benchmark_results.jsonl`
- `skillscan_benchmark_cmp_summary.md`

从结果复算：

- `any_hit_pred`，全部 147：
  - TP 96, FP 22, FN 8, TN 21
- `any_hit_pred`，共同 123：
  - TP 72, FP 22, FN 8, TN 21
- `risk_level_pred`，全部 147：
  - TP 0, FP 0, FN 104, TN 43
- `risk_level_pred`，共同 123：
  - TP 0, FP 0, FN 80, TN 43

### 8.3 Cisco / SkillFortify / ClawVet

在仓库中：

- 找到了真实世界 670 样本聚合脚本对它们的统计：`scripts/generate_realworld_scanner_tables.py`
- 也找到了 `generate_human_complete670.py` 中对它们 CSV 的合并：`scripts/generate_human_complete670.py:184-190, 273-320, 355-395`
- **但未在代码中找到** Cisco/ClawVet/SkillFortify 在 147-case benchmark 上的等价执行与对比脚本

因此：

- “所有 baseline 在 benchmark 上如何统一运行”的完整证据在仓库中不全
- 审稿人关于 baseline 集合不一致的担心是 `Accurate`

### 8.4 公平性结论

A. 所有系统在共同 123 个可运行案例上比较  

- ProvLoom `rule_plus_epg`: TP 80, FP 0, FN 0, TN 43
- SkillScan `any_hit_pred`: TP 72, FP 22, FN 8, TN 21
- 其他 baseline：未在代码中找到同口径 benchmark 结果

B. 所有系统在完整 147 个案例上比较  

- ProvLoom `rule_plus_epg`: TP 80, FP 0, FN 24, TN 43
- SkillScan `any_hit_pred`: TP 96, FP 22, FN 8, TN 21
- 其他 baseline：未在代码中找到同口径 benchmark 结果

关键结论：

- 论文里把 ProvLoom 动态指标写成 123 completed dynamic cases 是诚实的
- 但若拿它与在 147 全集上运行的静态 baseline 直接比较，就存在集合不一致问题

---

## 九、真实世界审计流程

论文 claim（本地 PDF 文本）：

- `paper-acsac26-paper467.pdf` 抽取文本第 68-76、119-129、146-148 行声称：
  - 88,769 public skills
  - 670 manual analysis
  - 21 malicious / 79 ambiguous / 570 benign
  - 9/21 closed chains

代码/数据能确认的真实流程：

`88,769 public skills`  
→ 论文文本说先用 Cisco prescreen（PDF 抽取文本第 1161-1166 行）  
→ 本地脚本 `scripts/generate_human_complete670.py` 只合并：
  - 470 high-risk corpus
  - 200 safe-like corpus
  - review seed from `real_world2/human_review_sheet.csv`
→ 输出 `docs/human_complete670.csv`

可从代码确认：

- ProvLoom 并不是在代码里“直接跑 88,769 个样本后输出 670 标签”
- 代码里真正可见的是：
  - 一个 470 + 200 的汇总表生成器：`scripts/generate_human_complete670.py:414-476`
  - 一个 26 行人工 review sheet：`real_world2/human_review_sheet.csv`
  - 一个 670 行总表：`docs/human_complete670.csv`

不能从代码确认的事项：

- ProvLoom 是否跑过全部 88,769：未在代码中找到
- 人工审阅是否 blind review：未在代码中找到
- 多名标注者与 disagreement resolution：未在代码中找到
- inter-rater agreement：未在代码中找到
- responsible disclosure 证据：未在代码中找到

代码能证明的角色定位：

- Cisco Scanner 明显承担了 prescreen / candidate reduction 角色（见论文文本与汇总脚本）
- ProvLoom 更像：
  - `triage system`
  - `explanation system`
  - `post-hoc analysis tool`

而不是单独从 88,769 中发现 21 恶意的完整 detector pipeline。

---

## 十、12 个未恢复闭合链的恶意样本

从 `docs/human_complete670.csv` 复算：

- human malicious = 21
- `provloom_evidence_type = no_closed_chain` 的 malicious = 12

### 10.1 12 个未恢复 closed chain 的恶意样本

| Sample | 攻击类型（依据人工 GT） | Dynamic 是否运行 | Static 是否产生结果 | 缺失链环节 | 失败原因 | 是否可修复 |
|---|---|---|---|---|---|---|
| bad-humanizer | hidden prompt injection / unauthorized file write | 是 | 是 | instruction chain 未闭合 | static extraction 漏检；规则不覆盖隐藏指令/注入语义 | 可能 |
| pdf | remote script execution | 是 | 是 | trust-boundary/control-transfer 未闭合 | regex coverage 不足 | 可能 |
| rlm | supply chain install | 是 | 是 | instruction chain 未闭合 | 规则未把样本文本映射到闭合组合 | 可能 |
| polymarket | supply chain install | 否（skipped_bounded） | 是 | 动态未跑；静态未闭合 | 运行边界 + static 漏检 | 部分 |
| pomodoro | supply chain install | 是 | 是 | instruction chain 未闭合 | 规则不充分 | 可能 |
| postey | supply chain install | 是 | 是 | instruction chain 未闭合 | 规则不充分 | 可能 |
| visualize-with-libraries | overpermissioned / malicious fixture | 是 | 是 | 闭合链定义与样本恶意性不匹配 | 样本恶意但不一定形成作者定义的闭合链 | 可能有限 |
| soulsys | remote install + fixed password archive | 是 | 是 | trust-boundary/impact 组合未闭合 | regex/组合条件遗漏 | 可能 |
| helper-tool | explicit compromise | 是 | 是 | instruction chain 未闭合 | 规则体系与此类显式恶意不对齐 | 可能 |
| yahoo-finance | supply chain attack | 是 | 是 | instruction chain 未闭合 | 规则不充分 | 可能 |
| youtube-summarize | supply chain attack | 是 | 是 | instruction chain 未闭合 | 规则不充分 | 可能 |
| youtube-thumbnail-grabber | supply chain attack | 是 | 是 | instruction chain 未闭合 | 规则不充分 | 可能 |

总体判断：

- 这 12 个里，大部分人工 GT 都是 instruction-derived 供应链/安装类恶意
- 但 ProvLoom 的 instruction 规则只有很窄的几类正则和闭合布尔组合
- 因此“没有恢复闭合链”更像**规则覆盖不足**，不是复杂图算法失败

### 10.2 12 个 high/critical 但人工 benign 的样本

从 `docs/human_complete670.csv` 复算，`provloom_final_risk_level in {high,critical}` 且 `existing_human_decision=benign` 的 12 个样本包括：

- `claude-jobs`
- `github-trending-daily-report`
- `glance`
- `leadgenius-api`
- `openclaw-backup`
- `openclaw-checkpoint`
- `openclaw-leaderboard`
- `openclaw-self-healing`
- `prompt-guard`
- `rabbit-r1-livekit`
- `safe-exec`
- `secureclaw`

误报来源大致分三类：

1. instruction-derived 供应链/更新/persistence 规则过强  
   - 例如 `github-trending-daily-report`, `openclaw-backup`, `secureclaw`
2. generated artifact / outward POST 被高分惩罚，但人工认为是合法业务提交  
   - 例如 `openclaw-leaderboard`, `leadgenius-api`
3. adapter/observed runtime / hybrid 证据把合法高权限工具误推到高风险  
   - 例如 `prompt-guard`, `claude-jobs`

---

## 十一、Reproducibility 审计

### 11.1 已找到的可复现要素

- Dockerfile 存在并被主流程使用：`app/runner/docker_runner.py:302-336`
- benchmark 主脚本存在：`scripts/run_benchmark.py`
- benchmark 生成器存在：`scripts/generate_benchmark_v2.py`
- 人工 670 汇总脚本存在：`scripts/generate_human_complete670.py`

### 11.2 明显削弱可复现性的因素

1. 默认 LLM key 硬编码  
   - `app/backend/schemas.py:7-10, 44-57`

2. LLM 运行依赖外部 API  
   - `app/runtime/llm_client.py:31-75`

3. instruction_chain.py 当前未提交  
   - `git status --short` 显示 `?? app/analyzer/instruction_chain.py`

4. 大量本地绝对路径依赖  
   - `/mnt/e/dangerous_skills`
   - `/mnt/e/log8/skills`
   - `/mnt/e/log10_stasticduibi/...`
   - `/mnt/e/sample`
   - 见 `scripts/generate_human_complete670.py:13-24`

5. 真实世界 670 标签依赖人工 CSV，而非端到端自动生成  
   - `docs/human_complete670.csv`

6. Prompt 文件未独立外置  
   - runtime LLM prompt 写死在 `app/runtime/container_runtime.py:484-512`

7. 无 seed / 无 retry / 无 cache  
   - `app/runtime/llm_client.py:16-75`

### 11.3 哪些实验在不联网、不跑恶意代码前提下可复现

可基本复现：

- benchmark 生成逻辑
- benchmark 汇总与评分逻辑
- 670 CSV 的后处理聚合逻辑
- 图表脚本输出

不能完整复现或高度依赖本地环境：

- 需要真实 LLM API 的路径
- 真实世界 88,769 → 670 的原始筛选全过程
- 依赖 `/mnt/e/...` 私有本地数据快照的实验
- responsible disclosure

结论：`Reproducibility` 为 `Partially implemented`

---

## 十二、论文 Claim 与代码实现对照表

| 论文 Claim | 对应代码 | 实现状态 | 证据 | 风险/差距 |
|---|---|---|---|---|
| dynamic execution | `app/runner/docker_runner.py` | Fully implemented | `48-295` | 默认网络不禁用 |
| sandbox isolation | `app/runner/docker_runner.py` | Partially implemented | `147-170` | build 用 host network；运行态默认可联网 |
| telemetry | `docker_runner.py`, `collector.py`, `normalizer.py` | Partially implemented | `222-242`; `11-100`; `37-53` | data_flow 不是 taint |
| EPG construction | `app/graph/builder.py` | Partially implemented | `21-35`, `37-232`, `285-292` | 图是事件拼接，不是强因果 provenance |
| source-to-sink chain recovery | `app/analyzer/attack_chain.py` | Heuristic/rule-based | `37-113`, `125-282` | BFS + ranking，依赖启发式 |
| instruction-derived chain | `app/analyzer/instruction_chain.py` | Heuristic/rule-based | `21-81`, `86-130`, `218-339` | 无 NLP/graph/path validation；且文件未提交 |
| hybrid evidence | `instruction_chain.py` | Partially implemented | `393-400` | 只要两边为真即 hybrid，不检查是否同一行为 |
| root-cause attribution | `rules.py`, `root_cause_v2.py` | Heuristic/rule-based | `687-745` | 规则映射，不是 learned attribution |
| severity | `risk_scoring.py`, `dual_axis_decision.py` | Heuristic/rule-based | `73-164`; `17-123` | 阈值和规则表驱动 |
| filtering | `attack_chain.py` | Heuristic/rule-based | `90-92`, `265-282` | 会影响 recovered chain 与评测指标 |
| Benchmark | `generate_benchmark_v2.py`, `run_benchmark.py` | Fully implemented | `60-165`, `171-848`; `44-92` | 模板化、偏置风险明显 |
| benign lookalikes | `generate_benchmark_v2.py` | Evaluation-only | `628-848` | 作者刻意构造 hard controls |
| 88,769-skill audit | 论文 PDF + 局部脚本 | Described but not fully implemented in repo | PDF lines `68-76`, `119-129`; scripts only cover 670 aggregation | 端到端流水线未完整落地到仓库 |
| 670 manual labels | `docs/human_complete670.csv`, `generate_human_complete670.py` | Manually produced | CSV + `414-476` | 标签来自人工，不是自动检测真值 |
| 21 malicious | `docs/human_complete670.csv` | Manually produced | CSV 复算 | 人工标签 |
| 9 closed chains | `docs/human_complete670.csv` | Manually produced + script-derivable | CSV 复算 | 9 指 instruction-derived，不是 9 个 runtime chain |
| responsible disclosure | 未在代码中找到 | Cannot verify from code | PDF lines `73-75`, `147-148` only | 更可能是论文材料/作者流程，不是代码证据 |

---

## 十三、对审稿意见的代码级判断

| 审稿意见 | 判断 | 理由 |
|---|---|---|
| Skill security explanation 与 malicious detection 关系不清 | Accurate | 代码里 `detected_behaviors`、`final_decision`、`final_risk_level`、`chain_evidence_type` 是不同概念，论文若不区分容易误读 |
| 论文只说做什么，没说怎么做 | Accurate | 尤其 instruction-chain 在代码里是正则+布尔组合，但论文表述容易让人以为有更强语义实现 |
| static instruction-chain extraction 像黑盒 | Accurate | 代码存在，但方法非常窄，而且当前文件未提交；若论文不展开实现，读者会把它当黑盒 |
| 不清楚是 hard-coded rules / heuristic parsing / external LLM | Accurate | 代码显示是 hard-coded regex + heuristic composition，不是 LLM |
| 不清楚 trust-boundary / control transfer / sink 如何从自然语言中提取 | Accurate | 代码没有通用提取器，只有类别命中与组合规则 |
| 不清楚如何处理 negation/warning/example/defensive text | Accurate | 未在代码中找到 |
| 24/147 没进入动态重放，动态覆盖边界更小 | Accurate | `scripts/run_benchmark.py:155-157` 与 summary 均证实 |
| Benchmark 与系统规则共同设计，可能泄漏/偏置 | Partially accurate | 没找到直接读 case_id 判标签，但模板化、共享模式、固定 path/URL 使偏置风险真实存在 |
| Baseline 与 ProvLoom 使用不同样本集合 | Accurate | ProvLoom 动态指标在 123；SkillScan 可在 147；其余 baseline 147-case 脚本缺失 |
| 21/9/7/26 数字易混淆 | Accurate | 9 与 7 统计口径不同，26/7/7/12 图脚本硬编码更易误读 |
| ProvLoom 更适合 triage/explanation system | Accurate | 代码更像 evidence-based triage + explanation，而非 definitive detector |
| 论文没充分分析 12 个未恢复闭合链恶意样本 | Accurate | 代码和 CSV 都显示这 12 个主要暴露静态规则覆盖不足 |

特别问题：

1. “ProvLoom performs perfectly on this dataset”是否准确？  
   - 不准确。对 123 runnable malicious 是 80/80，但对 104 全体 malicious 只有 80/104。

2. “ProvLoom identified 9 out of 21 malicious skills”是否准确？  
   - 若指“恢复 closed-chain 型证据”，基本准确。若指“发现了 9 个恶意样本”，不准确，因为 21 是人工 malicious 标签。

3. 9 和 7 是否真的矛盾？  
   - 不矛盾。9 是 malicious 中 closed-chain 数；7 是 high/critical 样本中人工 malicious 数。

4. static instruction-chain extraction 是否真的是黑盒？  
   - 从代码看不是“没有实现”，但确实是一个论文中讲得不够透明的黑盒式规则模块。

5. dynamic component 是否有足够实现细节？  
   - 比 static 部分清楚得多，但 data-flow/causal semantics 仍明显弱于论文直觉。

6. Benchmark 是否存在明显设计偏置或数据泄漏？  
   - 存在明显偏置风险；未找到最严重的直接 label leakage。

7. Baseline comparison 是否使用了不同样本集合？  
   - 是。

8. ProvLoom 更接近 detector，还是 triage/explanation system？  
   - 更接近 triage/explanation system。

9. 代码中能否证明 responsible disclosure？  
   - 不能。更像论文外流程材料。

---

## 十四、最终结论

### A. 当前系统真实完成度（10 分制）

| 部分 | 分数 | 理由 |
|---|---|---|
| Dynamic analysis | 7/10 | Docker + strace + runtime wrapper 是真实可执行系统，但网络/adapter/data-flow 语义有限 |
| Static instruction extraction | 3/10 | 有实现，但本质是窄规则扫描；很多论文需要的语义能力未实现 |
| Provenance graph | 6/10 | 有统一图结构与链恢复，但很多边是启发式拼接 |
| Chain reconstruction | 6/10 | 动态链恢复可运行，但 heavily heuristic；instruction 链不是严格 path search |
| Attribution | 5/10 | 风险、evidence、hybrid、root cause 都能产出，但主要是规则表 |
| Benchmark validity | 4/10 | 工程上完整；科学上模板化、耦合、无 held-out、集合不一致问题明显 |
| Real-world audit | 4/10 | 有 670 汇总产物，但主流程高度依赖人工 CSV 与本地私有路径 |
| Reproducibility | 3/10 | 本地绝对路径、未提交文件、外部 API、硬编码 key 都明显削弱复现性 |

### B. 当前论文最可能被拒的三个代码层原因

1. `instruction-derived chain` 与论文叙述不匹配  
   - 代码只是 regex + 类别组合 + 固定顺序伪链，远弱于论文给人的语义图推理印象。

2. benchmark 与对比实验的科学性不足  
   - 24/147 动态跳过、123 vs 147 集合不一致、模板化样本与 detector 规则共演化。

3. real-world audit 证据链更多是人工汇总，不是可复现的端到端系统输出  
   - 670/21/79/570/9 虽可复算，但核心标签与筛选流程不由公开代码独立生成。

### C. 投稿 USENIX Security 前必须完成的工作

P0：不完成就不应该投稿

- 重写 static instruction-chain，实现真正的结构化抽取与路径验证  
  - 涉及：`app/analyzer/instruction_chain.py`，可能新增 parser/graph/entity linking 模块
- 统一 benchmark 对比集合，重算所有 baseline  
  - 涉及：`scripts/run_benchmark.py`、新增 Cisco/ClawVet/SkillFortify benchmark adapters
- 清理可复现性问题  
  - 涉及：`app/backend/schemas.py`、本地绝对路径脚本、未提交文件

P1：显著影响录用概率

- 对 12 个未恢复闭合链的恶意样本做系统失败分析并修复关键漏检
- 把 dynamic data-flow 从 first-read/first-network hint 升级为更可信的 dependency logic
- 明确论文定位为 triage/explanation，而非 definitive malicious detector

P2：锦上添花

- 加入 blind annotation / 多标注者一致性材料
- 自动从 CSV 生成所有论文图表和表格，去掉硬编码统计
- 把 instruction-chain 与 runtime-chain 的语义对齐做成真正 hybrid reasoning

### D. 是否值得继续

建议：`Pivot positioning`

理由：

- 现有动态框架、EPG、benchmark 脚手架并非没有价值；
- 但当前 static instruction 部分与“恶意技能检测器”定位之间差距过大；
- 如果保留系统并改写论文定位为：
  - bounded dynamic triage
  - evidence attribution
  - closed-chain explanation
  - instruction-level latent risk heuristics
  
  则系统仍有保留价值。  

如果坚持当前论文定位与主张，则需要接近 `Major redesign` 级别的补强。

---

## 最短结论

基于代码而不是论文表述，当前 ProvLoom 更像一个**有真实动态执行框架的 triage/explanation system**：动态部分是可运行的，instruction 部分主要是正则规则，real-world 审计数字高度依赖人工 CSV，benchmark 与 baseline 比较存在集合不一致和模板偏置风险。  

最关键的不一致点是：论文让人以为有较强的 instruction-chain 语义恢复与 local artifact graph 推理，但代码里没有找到相应强实现。
