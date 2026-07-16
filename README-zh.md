# ProvLoom：Skill Runtime Security Sandbox

ProvLoom 是一个面向 `SKILL.md` 驱动 Skill 的执行式安全沙箱与攻击链分析系统。它不是只读文本的静态工具，而是通过真实运行 Skill 来恢复攻击链与安全解释。

## Overview

Skill 可以理解为一种由 `SKILL.md` 描述的自动化或 agent 任务。一个 Skill 往往不仅包含提示词或说明文本，还会结合本地文件、辅助脚本、工具调用、网络访问，以及在某些场景下的 LLM 决策。因此，Skill 的安全分析天然困难，主要体现在：

- 风险通常是多步形成的，而不是单个行为触发的。
- LLM 与工具调用会引入额外的因果链条，无法仅从静态文本直接恢复。
- 一个检测器即使能发现可疑行为，也未必能解释风险是如何形成的。

ProvLoom 的目标不是只做“检测”，而是做“可解释的运行时分析”。系统会在 Docker sandbox 中真实执行 Skill，采集运行期 telemetry，构建 execution provenance graph，恢复 semantic attack chain，并给出 root cause attribution，例如 unsafe dataflow design、unsafe command construction 或 LLM-induced unsafe action。

## Key Features

- 在隔离 Docker 容器中真实执行 Skill。
- 采集文件、进程、网络、工具调用和 LLM 相关的运行时 telemetry。
- 基于规范化 telemetry 构建 execution provenance graph。
- 恢复 source -> optional relay -> sink 形式的 semantic attack chain。
- 对风险进行 root-cause attribution，而不仅是行为打标。
- 输出适合 benchmark 与论文 artifact 评估的结构化结果。

## System Architecture

ProvLoom 的核心执行链路如下：

```text
SKILL.md / Skill bundle
        ↓
Docker sandbox 中的 ProvLoom runtime
        ↓
Runtime telemetry collection
        ↓
Normalized events + execution provenance graph
        ↓
Primary chain recovery
        ↓
Analyst-facing explanation + root cause
```

系统最终输出的不是单纯分数，而是一个可审计的解释对象：事件流、图结构、primary chain 和 root-cause summary 可以分别检查。

## Execution Model

这一点非常关键：ProvLoom 不是静态分析器。

- 动态模式下，系统会在 Docker sandbox 中真实执行 Skill。
- 运行时使用的是仓库内自实现的 ProvLoom runtime，也就是 `app/runtime/container_runtime.py`，用来执行 `SKILL.md` 驱动的 Skill 并记录运行期事件。
- `rule_only`、`rule_plus_epg`、`epg_with_filtering` 等动态基线都会触发真实执行。
- `static_only` 不会运行 Skill，只会分析声明结构和 action 定义。
- 标记为 `dynamic_runnable=false` 的 benchmark case 会在动态模式下被跳过。这类 case 主要对应依赖外部 LLM 行为、或更适合作为设计层问题来分析的场景。

因此，评估时必须区分：

- 哪些结果来自真实执行
- 哪些结果来自静态分析
- 哪些 case 在动态模式下按设计被跳过

## Benchmark & Evaluation

仓库提供了一个 50 case 的 benchmark：

- 25 个 malicious case
- 25 个 benign case

恶意 case 家族包括：

- direct sensitive exfiltration
- staged / relay-based exfiltration
- unauthorized external transfer
- unsafe command construction
- LLM-induced unsafe action

良性 case 家族包括：

- public read / public fetch
- benign public upload / relay-shaped flow
- local transform / helper workflow
- note-like 或 report-like 的本地输出场景

这个 benchmark 故意同时覆盖 execution-level 与 LLM-level 风险，因此动态覆盖不是完全一致的：

- `static_only` 覆盖全部 benchmark case。
- 动态模式会跳过 `dynamic_runnable=false` 的 case。
- 评估里的 `1.0` 应理解为在当前 artifact evidence model 下的 task-defined success，而不是现实世界 Skill 安全问题已经完全解决。

## Example Output

一个典型的 analyst-facing attack chain 输出可能如下：

```text
source: /workspace/skill/secrets/customer_list.csv
relay:  tool call "Send Export"
sink:   https://httpbin.org/post
root cause: overprivileged tool use
```

ProvLoom 追求的是恢复“语义上足够”的因果路径，即解释风险为何形成，而不是逐条重放运行期中的所有底层事件。

## Quick Start

### 1. 克隆仓库

```bash
git clone https://github.com/watt-tang/clawguard_sandbox.git ProvLoom
cd ProvLoom
```

### 2. 检查依赖

当前 MVP 的 API 层只使用 Python 标准库，因此不要求额外安装 Python 包。但你需要具备：

- Python 3
- Docker

第一次运行时，系统会自动构建 sandbox Docker image。

### 3. 运行 benchmark

```bash
python3 scripts/run_benchmark.py --datasets-root ./datasets
```

### 4. 查看结果

聚合 benchmark 输出位于：

```text
artifacts/benchmark/
```

各 case 的输出位于：

```text
artifacts/benchmark/cases/<analysis_mode>/<case_id>/
```

每次真实执行的 runtime artifact 位于：

```text
artifacts/runs/<execution_id>/
```

### 5. 可选：启动 API 服务

```bash
python3 -m app.main --host 0.0.0.0 --port 8000
```

API 入口位于 `app/backend/api.py`。

## Project Structure

关键目录如下：

- `app/runtime/`：ProvLoom runtime、`SKILL.md` 解析与执行逻辑。
- `app/runner/`：Docker sandbox 生命周期管理与 trace 处理。
- `app/analyzer/`：规则分析、风险评分、链恢复和归因逻辑。
- `app/telemetry/`：telemetry 规范化与执行报告生成。
- `scripts/`：benchmark 生成与执行入口。
- `artifacts/`：运行时 artifact、benchmark 汇总与 case 级输出。
- `datasets/`：benchmark Skill 与 ground truth。
- `docs/`：artifact 说明、benchmark 设计文档、case study 笔记等。
- `Latex/`：论文与 artifact 写作相关源码。

## Limitations

ProvLoom 是一个研究系统，不是完整防御产品。当前边界包括：

- 它不是 prevention / enforcement system。
- telemetry 并不完整，不能提供 kernel-complete provenance。
- 一部分 LLM 相关 case 不做 dynamic execution。
- 动态 trace 中会包含 loader、环境初始化等运行噪声。
- semantic chain 正确，不等于逐条重放了全部底层运行事件。

这些边界都是显式设计的一部分，解读 benchmark 结果时必须保留它们。

## Research Contribution

从系统研究与论文 artifact 角度，这个仓库的贡献主要在于：

- 将 `SKILL.md` 驱动 Skill 的安全问题形式化为 semantic attack-chain recovery。
- 提供一个将 runtime telemetry 与 provenance reasoning 结合起来的 execution-based analysis pipeline。
- 强调 explainability over detection：不仅判断是否风险存在，还解释风险如何形成。
- 提供可 benchmark、可 case-level 审计的研究 artifact，而不是只输出聚合指标。

## Intended Audience

本仓库主要面向：

- 研究 agent / workflow runtime 安全分析的安全研究人员
- 论文 artifact 评审与审稿人
- 希望扩展 runtime、telemetry 或 analyzer 的开发者

如果你需要的是一个静态策略检查器，这个仓库并不适合。ProvLoom 的核心定位是基于真实执行证据的安全分析。
