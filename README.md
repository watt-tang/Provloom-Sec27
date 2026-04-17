# Skill Runtime Security Sandbox

一个完整的、headless 的 Skill 动态安全沙箱系统，用于检测以 `SKILL.md` 为核心载体的 Skill 在真实执行过程中的安全风险。

系统不是普通脚本执行器，也不是只看文本的静态分析器，而是一个以 `SKILL.md` 为入口、在隔离环境中真实加载并执行 Skill 的 `Skill Runtime Security Sandbox`。

## 核心定位

系统输入对象默认是：

- 单个 `SKILL.md` 文件
- 包含 `SKILL.md` 的 Skill 目录
- Skill 目录中的附带脚本、配置、资源文件

典型输入形态：

```text
skill_bundle/
├── SKILL.md
├── tools/
│   └── helper.py
├── config.json
└── assets/
```

执行流程是：

1. 加载 `SKILL.md`
2. 在隔离 runtime 中执行 Skill
3. 触发工具调用、文件访问、网络请求、进程行为
4. 采集行为
5. 规则分析与评分
6. 返回结构化安全报告
7. 销毁沙箱

## TinyClaw 集成方案

系统使用 TinyClaw 作为运行基础。

当前方案是：

- 每个 sandbox 基于独立 Docker 容器运行
- sandbox 镜像在构建时按照 TinyClaw README 的方式安装 TinyClaw：
  - `curl -fsSL https://tinyclaw.net/install.sh | sh`
- 容器内 TinyClaw 二进制会安装到 `/usr/local/bin/tinyclaw`
- Runtime 启动时会记录 TinyClaw 是否可用，以及其路径

说明：

- 当前公开仓库只有 TinyClaw README 和安装方式，没有开源完整 runtime 内核代码可供直接链接调用
- 因此本项目实现的是一个 `TinyClaw-compatible Skill Runtime`
- 它以 TinyClaw 为运行基础，并围绕 `SKILL.md` 执行模型构建受控执行器

## 系统结构

```text
.
├── app
│   ├── analyzer
│   │   ├── __init__.py
│   │   └── rules.py
│   ├── backend
│   │   ├── __init__.py
│   │   ├── api.py
│   │   ├── log_writer.py
│   │   ├── schemas.py
│   │   └── task_store.py
│   ├── runner
│   │   ├── __init__.py
│   │   ├── docker_runner.py
│   │   ├── models.py
│   │   └── trace_parser.py
│   ├── runtime
│   │   ├── __init__.py
│   │   ├── container_runtime.py
│   │   └── skill_parser.py
│   ├── telemetry
│   │   ├── __init__.py
│   │   └── collector.py
│   ├── reporting
│   │   ├── __init__.py
│   │   └── risk_mapper.py
│   ├── __init__.py
│   └── main.py
├── docker
│   └── sandbox
│       └── Dockerfile
├── examples
│   └── skills
│       ├── deepseek_skill_demo
│       │   ├── SKILL.md
│       │   └── tools
│       │       └── helper.py
│       └── skill_bundle_demo
│           ├── SKILL.md
│           └── tools
│               └── helper.py
├── Log                         # 运行期生成，默认不纳入 Git
├── scripts
│   ├── backfill_log_risks.py
│   ├── rename_log_files.py
│   ├── render_log_resources.py
│   ├── render_log_risks.py
│   └── run_deepseek_suite.py
├── tinyclaw
│   └── README.md
├── test
│   └── SKILL.md
└── README.md
```

## 六层模块说明

### 1. backend

负责：

- REST API
- 请求校验
- task 状态查询
- 响应格式化

核心文件：

- [app/backend/api.py](/root/projects/clawguard-skill-sandbox/app/backend/api.py:1)
- [app/backend/schemas.py](/root/projects/clawguard-skill-sandbox/app/backend/schemas.py:1)
- [app/backend/task_store.py](/root/projects/clawguard-skill-sandbox/app/backend/task_store.py:1)

### 2. runner

负责：

- sandbox 生命周期管理
- Docker 镜像构建
- 容器启动与销毁
- 超时终止与强制清理
- 每任务独立容器，不复用容器

核心文件：

- [app/runner/docker_runner.py](/root/projects/clawguard-skill-sandbox/app/runner/docker_runner.py:1)
- [app/runner/models.py](/root/projects/clawguard-skill-sandbox/app/runner/models.py:1)
- [app/runner/trace_parser.py](/root/projects/clawguard-skill-sandbox/app/runner/trace_parser.py:1)

### 3. runtime

负责：

- 发现 `SKILL.md`
- 解析 Skill frontmatter
- 解析 `skill-actions` fenced JSON
- 在容器中真实执行 Skill 行为
- 支持本地受控执行模式
- 支持真实 LLM API 驱动执行模式
- 发出可观测的工具调用链 telemetry

核心文件：

- [app/runtime/skill_parser.py](/root/projects/clawguard-skill-sandbox/app/runtime/skill_parser.py:1)
- [app/runtime/container_runtime.py](/root/projects/clawguard-skill-sandbox/app/runtime/container_runtime.py:1)
- [app/runtime/llm_client.py](/root/projects/clawguard-skill-sandbox/app/runtime/llm_client.py:1)

### 4. telemetry

负责：

- 收集 runtime 工具调用事件
- 组织 file/network/process/tool-call 结果
- 预留 source -> sink 数据流提示结构

核心文件：

- [app/telemetry/collector.py](/root/projects/clawguard-skill-sandbox/app/telemetry/collector.py:1)

### 5. analyzer

负责：

- 规则分析
- 风险评分
- 证据时间线生成
- 组合行为识别

核心文件：

- [app/analyzer/rules.py](/root/projects/clawguard-skill-sandbox/app/analyzer/rules.py:1)

### 6. reporting

负责：

- 风险标签中文化
- 日志中的可读风险摘要
- 风险等级和主风险项映射

核心文件：

- [app/reporting/risk_mapper.py](/root/projects/clawguard-skill-sandbox/app/reporting/risk_mapper.py:1)

## 支持的输入对象

### 1. 单个 `SKILL.md`

```json
{
  "skill_path": "./test/SKILL.md"
}
```

### 2. Skill 目录

```json
{
  "skill_path": "./examples/skills/skill_bundle_demo"
}
```

### 3. Skill 目录 + 输入载荷

```json
{
  "skill_path": "./examples/skills/skill_bundle_demo",
  "input_payload": {
    "message": "sandbox-demo"
  },
  "timeout_seconds": 60,
  "network_policy": "default"
}
```

## Skill Runtime 约定

Skill 本身不是天然可执行程序，所以这里实现了受控的 Skill Runtime。

当前 Runtime 约定：

- 解析 `SKILL.md`
- 从 `skill-actions` fenced JSON 读取动作定义
- 如果 `SKILL.md` 没有声明 `skill-actions`，也可以在启用 `llm_config.enabled=true` 时作为真实 Skill 交给 LLM Runtime 执行
- 支持两种执行方式：
  - 顺序受控执行
  - LLM 决策执行
- 将动作结果写入 context
- 后续动作可引用前面动作输出

支持的动作类型：

- `read_file`
- `write_file`
- `run_command`
- `http_request`

### 真实 LLM API 模式

现在系统已经支持真实 LLM API 驱动的 Skill Runtime。

默认优先支持：

- `DeepSeek API`

实现方式：

- Runtime 使用 OpenAI-compatible Chat Completions 协议
- 可以直接连接 DeepSeek
- LLM 根据 `SKILL.md`、输入载荷和可用工具列表，逐步决定下一步调用哪个工具
- 每次模型请求与响应都会写入 telemetry

当前支持的 LLM Runtime 模式：

- `tinyclaw-embedded`
  - 不依赖外部模型
  - 按 `skill-actions` 顺序执行
- `deepseek-agent`
  - 通过真实 DeepSeek API 驱动
  - 由模型决定工具调用顺序
- `llm-enabled generic skill`
  - 即使 `SKILL.md` 只有说明文本、没有显式 action
  - 只要请求里启用了 `llm_config.enabled=true`
  - Runtime 仍会把该 Skill 当成真实技能说明来执行，并给模型暴露内建工具：
    - `read_file`
    - `write_file`
    - `run_command`
    - `http_request`

### DeepSeek 接入参数

调用 `/analyze-skill` 时，可传入：

```json
{
  "llm_config": {
    "enabled": true,
    "provider": "deepseek",
    "base_url": "https://api.deepseek.com",
    "api_key": "sk-xxxx",
    "model": "deepseek-chat",
    "temperature": 0.0,
    "max_steps": 8
  }
}
```

说明：

- `provider`
  - 当前建议填 `deepseek`
- `base_url`
  - DeepSeek 默认是 `https://api.deepseek.com`
- `api_key`
  - 你的 DeepSeek API Key
- `model`
  - 常用可填 `deepseek-chat`
- `max_steps`
  - 最多允许模型做多少轮工具决策

模板引用示例：

```text
{{ input_payload.message }}
{{ actions.read_sensitive_hosts.stdout }}
{{ skill.name }}
```

## 示例 Skill

示例 Skill 位于：

- [examples/skills/skill_bundle_demo/SKILL.md](/root/projects/clawguard-skill-sandbox/examples/skills/skill_bundle_demo/SKILL.md:1)
- [examples/skills/skill_bundle_demo/tools/helper.py](/root/projects/clawguard-skill-sandbox/examples/skills/skill_bundle_demo/tools/helper.py:1)

这个 Skill 会：

- 读取 `/etc/hosts`
- 写入 `runtime_output/skill-note.txt`
- 执行附带脚本 `tools/helper.py`
- 发送 HTTP 请求到 `https://httpbin.org/post`

因此它非常适合触发：

- `sensitive_file_read`
- `file_write`
- `process_spawn`
- `shell_execution`
- `network_access`
- `read_then_exfiltration`

### DeepSeek 驱动示例 Skill

额外提供了一个真实 LLM Runtime 示例：

- [examples/skills/deepseek_skill_demo/SKILL.md](/root/projects/clawguard-skill-sandbox/examples/skills/deepseek_skill_demo/SKILL.md:1)
- [examples/skills/deepseek_skill_demo/tools/helper.py](/root/projects/clawguard-skill-sandbox/examples/skills/deepseek_skill_demo/tools/helper.py:1)

这个 Skill 的 `runtime` 设置为：

```yaml
runtime: deepseek-agent
```

它会让模型自行决定：

- 先读文件
- 再跑脚本
- 再写文件
- 最后发请求

## 行为采集能力

### 文件访问

通过 `strace -e trace=file` 采集：

- 读取了哪些文件
- 写入了哪些文件
- 创建 / 删除 / rename 行为

### 网络行为

通过 `strace -e trace=network` 采集：

- DNS 连接
- TCP 连接
- 目标 IP / 端口

### 进程执行

通过 `strace -e trace=process` 采集：

- `execve`
- `fork`
- `vfork`
- shell 启动
- 子进程行为

### stdout / stderr

容器内执行输出分别落盘：

- `/artifacts/stdout.log`
- `/artifacts/stderr.log`

### 工具调用链

Runtime 通过 `/artifacts/runtime-events.jsonl` 写入：

- tool call start
- tool call finish
- tool type
- tool status

### LLM 调用事件

如果启用了 `llm_config`，还会记录：

- LLM request
- LLM response
- step 编号
- provider / model
- response preview

## Log 落盘机制

每次通过 API 提交的分析任务，都会自动把结果写入项目根目录下的 `Log/`：

- `Log/<skill_or_case>__<execution_id前12位>.json`

例如：

- `Log/skill_bundle_demo__1f9ad42ca02a.json`
- `Log/deepseek_demo__e89060d26aeb.json`

日志内容包含：

- 原始请求参数
- 当前任务状态
- 完整分析结果
- 失败错误信息

如果你直接跑测试脚本：

```bash
python3 scripts/run_deepseek_suite.py --api-key YOUR_DEEPSEEK_API_KEY
```

脚本也会把每个测试用例的结果分别写入 `Log/`。

### 数据流预留结构

Telemetry 会根据：

- 敏感文件读取
- 网络连接

生成基础的 source -> sink 提示结构，用于后续更细粒度的数据流分析。

## 规则引擎

当前 analyzer 已实现以下规则：

- `file_write`
- `network_access`
- `process_spawn`
- `shell_execution`
- `sensitive_file_read`
- `read_then_exfiltration`
- `execution_timeout`

输出包括：

- `risk_score`
- `detected_behaviors`
- `evidence_timeline`

## 接口设计

### `GET /health`

返回：

```json
{
  "status": "ok"
}
```

### `POST /analyze-skill`

请求体：

```json
{
  "skill_path": "./examples/skills/skill_bundle_demo",
  "input_payload": {
    "message": "sandbox-demo"
  },
  "timeout_seconds": 60,
  "network_policy": "default"
}
```

字段说明：

- `skill_path`
  - Skill 文件路径或 Skill 目录路径
  - 支持单个 `SKILL.md` 或包含 `SKILL.md` 的目录
- `input_payload`
  - 传入 Skill Runtime 的输入对象
- `timeout_seconds`
  - 执行超时
- `network_policy`
  - 当前支持：
    - `default`
    - `disabled`
- `llm_config`
  - 可选
  - 用于开启真实 LLM API 模式
  - 当前优先支持 DeepSeek

返回至少包含：

- `execution_id`
- `risk_score`
- `detected_behaviors`
- `evidence_timeline`
- `file_events`
- `network_events`
- `process_events`
- `tool_calls`
- `llm_events`
- `data_flows`
- `resource_usage`

### `GET /task/{id}`

根据任务 id 查询任务执行状态与结果。

## Sandbox 创建与自动销毁逻辑

Runner 的实现位于 [app/runner/docker_runner.py](/root/projects/clawguard-skill-sandbox/app/runner/docker_runner.py:1)。

关键策略：

- 每次分析请求都创建唯一容器名
- 使用 `docker run --rm`
- 不复用容器
- 单次任务独立挂载：
  - `/workspace/skill`
  - `/artifacts`
- 如果执行超时：
  - 先由 `timeout` 终止容器内命令
  - 若主进程超出硬超时，runner 会调用 `docker rm -f`

因此满足：

- 每任务独立 sandbox
- 任务结束自动销毁
- 支持超时终止和强制清理
- 不复用容器

## 本地启动步骤

### 1. 环境要求

- Linux / WSL2
- Python 3.10+
- Docker Engine
- 可访问 TinyClaw 下载地址

### 2. 启动 Docker

```bash
docker --version
docker info
```

### 3. 启动服务

```bash
cd /root/projects/clawguard-skill-sandbox
python3 -m app.main --host 0.0.0.0 --port 8000
```

### 4. 健康检查

```bash
curl --noproxy '*' http://127.0.0.1:8000/health
```

## curl 测试示例

### 分析 Skill 目录

```bash
curl --noproxy '*' -X POST http://127.0.0.1:8000/analyze-skill \
  -H 'Content-Type: application/json' \
  -d '{
    "skill_path": "./examples/skills/skill_bundle_demo",
    "input_payload": {
      "message": "sandbox-demo"
    },
    "timeout_seconds": 60,
    "network_policy": "default"
  }'
```

### 使用 DeepSeek API 分析 LLM Skill

```bash
curl --noproxy '*' -X POST http://127.0.0.1:8000/analyze-skill \
  -H 'Content-Type: application/json' \
  -d '{
    "skill_path": "./examples/skills/deepseek_skill_demo",
    "input_payload": {
      "message": "hello-deepseek"
    },
    "timeout_seconds": 60,
    "network_policy": "default",
    "llm_config": {
      "enabled": true,
      "provider": "deepseek",
      "base_url": "https://api.deepseek.com",
      "api_key": "YOUR_DEEPSEEK_API_KEY",
      "model": "deepseek-chat",
      "temperature": 0.0,
      "max_steps": 8
    }
  }'
```

### 使用 DeepSeek API 分析没有 `skill-actions` 的真实 SKILL.md

这正是 `test/SKILL.md` 这种输入的默认模式。

```bash
curl --noproxy '*' -X POST http://127.0.0.1:8000/analyze-skill \
  -H 'Content-Type: application/json' \
  -d '{
    "skill_path": "./test",
    "input_payload": {
      "task": "根据 SKILL.md 的说明尝试执行一次最小真实工作流。如果依赖缺失，请验证并写出失败结论。",
      "query": "上海周末咖啡店推荐"
    },
    "timeout_seconds": 90,
    "network_policy": "default",
    "llm_config": {
      "enabled": true,
      "provider": "deepseek",
      "base_url": "https://api.deepseek.com",
      "api_key": "YOUR_DEEPSEEK_API_KEY",
      "model": "deepseek-chat",
      "temperature": 0.0,
      "max_steps": 8
    }
  }'
```

### 一键跑示例 Skill 和 `test/` Skill

```bash
cd /root/projects/clawguard-skill-sandbox
python3 scripts/run_deepseek_suite.py --api-key YOUR_DEEPSEEK_API_KEY
```

这个脚本会：

- 运行 `examples/skills/deepseek_skill_demo`
- 运行 `test/SKILL.md`
- 把每次结果写入 `Log/`
- 在终端输出一个精简汇总 JSON

### 查询任务

```bash
curl --noproxy '*' http://127.0.0.1:8000/task/<execution_id>
```

### 查看每次 Docker 运行的资源占用

每次新的分析任务都会返回并写入：

- `resource_usage.memory_limit_bytes`
- `resource_usage.memory_peak_bytes`
- `resource_usage.writable_layer_bytes`
- `resource_usage.skill_bundle_bytes`
- `resource_usage.artifacts_bytes`
- `resource_usage.estimated_total_disk_bytes`

批量查看日志里的资源统计：

```bash
python3 scripts/render_log_resources.py Log
```

## 示例 JSON 输出

下面是一个典型返回结构示例：

```json
{
  "execution_id": "9f9d53df1ed74f72a4b6a99ef0b2a7a0",
  "status": "completed",
  "skill_path": "/abs/path/examples/skills/skill_bundle_demo",
  "skill_file": "SKILL.md",
  "sandbox_image": "skill-runtime-sandbox:latest",
  "runtime_name": "tinyclaw-embedded",
  "network_policy": "default",
  "exit_code": 0,
  "timed_out": false,
  "stdout": "helper processed: sandbox-demo\n",
  "stderr": "",
  "trace_summary": {
    "file_event_count": 9,
    "network_event_count": 3,
    "process_event_count": 2,
    "tool_call_count": 8,
    "llm_event_count": 10,
    "stdout_line_count": 1,
    "stderr_line_count": 0
  },
  "risk_score": 100,
  "detected_behaviors": [
    "file_write",
    "network_access",
    "process_spawn",
    "read_then_exfiltration",
    "sensitive_file_read",
    "shell_execution"
  ],
  "evidence_timeline": [
    {
      "timestamp": "2026-04-17T12:00:00Z",
      "category": "tool_call",
      "action": "start",
      "detail": "start Read Hosts File (read_file)",
      "metadata": {
        "tool_id": "read_sensitive_hosts",
        "tool_name": "Read Hosts File",
        "tool_type": "read_file",
        "status": null
      }
    }
  ],
  "file_events": [],
  "network_events": [],
  "process_events": [],
  "tool_calls": [],
  "llm_events": [],
  "data_flows": []
}
```

## 当前实现状态

已经落地的能力：

- 以 `SKILL.md` / Skill 目录为核心输入
- TinyClaw 作为运行基础
- 支持真实 LLM API 的 Skill Runtime
- 支持 DeepSeek API 接入
- 独立 sandbox 生命周期管理
- 自动销毁
- 真实行为采集
- 工具调用链 telemetry
- 规则分析与评分
- `POST /analyze-skill`
- `GET /task/{id}`
- `GET /health`

## 限制与后续扩展

当前是完整可运行工程，但仍然是第一版 Runtime Sandbox，后续可继续增强：

- 支持 service 型 Skill
- 支持 manifest 型 Skill
- 更丰富的 `SKILL.md` 语法
- 更细粒度的数据流分析
- eBPF 级别 telemetry
- 持久化任务存储
- 多任务异步队列
- 更细粒度网络策略

## 结论

这个工程已经不是“只执行脚本”的简化器，而是一个真正围绕 `SKILL.md` / Skill 目录构建的 Skill 动态安全沙箱系统：

- 输入对象正确
- 有 Skill Runtime / Executor
- 有 sandbox 生命周期管理
- 有真实运行时行为采集
- 有规则分析引擎
- 有任务接口和结果查询
- 有 TinyClaw 运行基础
