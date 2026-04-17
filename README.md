# Skill Dynamic Sandbox MVP

一个最小可行版的 headless 后端系统：通过 Docker 隔离执行不受信任的 Skill，使用 `strace` 采集运行时行为，并输出结构化 JSON 安全报告。

## 先回答两个关键问题

### 1. 执行 Skill 的时候需要提供 API 吗？

不需要。

这个 MVP 里的 `POST /analyze-skill` 是沙箱系统自己的分析 API，不是被分析 Skill 必须实现的 API。

也就是说：

- 你调用本系统的 API：`POST /analyze-skill`
- 你把一个本地 Skill 目录路径和启动命令传给它
- 系统会把这个 Skill 丢进 Docker 里执行
- 系统自己采集运行时行为并生成报告

被分析的 Skill 本身只要是一个“可执行目录”就行，不需要额外暴露 HTTP API，不需要实现回调接口，也不需要接入 SDK。

### 2. 这个系统里 Skill 的载体是什么？

当前 MVP 中，Skill 的载体就是“一个本地目录 + 一个入口命令”。

最小约定如下：

- `skill_path`：指向一个本地目录
- `command`：在这个目录里执行的命令

例如：

```json
{
  "skill_path": "./examples/skills/network_file_probe",
  "command": ["python", "skill.py"],
  "timeout_seconds": 20
}
```

这表示：

- Skill 载体目录是 `./examples/skills/network_file_probe`
- 入口程序是该目录下的 `skill.py`
- 在 Docker 容器中执行 `python skill.py`

所以这个 MVP 里的 Skill 不是某种特殊的协议对象，也不是数据库记录，更不是必须有 `manifest.json` 的插件格式。它本质上就是一个待执行的代码目录。

### 当前支持的 Skill 形态

理论上只要容器里能执行，都可以作为 Skill：

- Python 脚本目录
- Shell 脚本目录
- Node.js 项目目录
- 二进制程序目录

但这个 MVP 的默认沙箱镜像当前只内置了：

- `python`
- `sh`
- `strace`
- `curl`

所以现阶段最稳妥的是：

- Python Skill
- Shell Skill

如果你想跑 Node.js Skill，可以后续扩展沙箱镜像，在 [docker/sandbox/Dockerfile](/root/projects/clawguard-skill-sandbox/docker/sandbox/Dockerfile:1) 里安装 Node.js。

## 功能范围

- `POST /analyze-skill`
- Docker 隔离执行 Skill
- 采集文件访问、网络连接、进程执行、stdout、stderr
- 输出 `risk_score`、`detected_behaviors`、`evidence_timeline`

## 项目结构

```text
.
├── app
│   ├── analyzer
│   │   └── rules.py
│   ├── backend
│   │   ├── api.py
│   │   └── schemas.py
│   ├── runner
│   │   ├── docker_runner.py
│   │   ├── models.py
│   │   └── trace_parser.py
│   └── main.py
├── docker
│   └── sandbox
│       └── Dockerfile
├── examples
│   └── skills
│       └── network_file_probe
│           └── skill.py
└── requirements.txt
```

## 系统工作方式

一次分析请求的完整流程如下：

1. 客户端调用 `POST /analyze-skill`
2. backend 接收请求并校验 `skill_path`、`command`、`timeout_seconds`
3. runner 将 Skill 目录复制到临时目录
4. runner 调用 `docker run` 启动隔离容器
5. 容器内执行 `strace -ff -tt -e trace=file,process,network <command>`
6. runner 收集：
   - `stdout`
   - `stderr`
   - 文件访问行为
   - 网络连接行为
   - 进程执行行为
7. analyzer 根据规则引擎打标签和评分
8. backend 返回结构化 JSON 报告

## Skill 目录约定

这个项目当前没有强制的 Skill 标准格式，但推荐遵循下面这个最小目录规范：

```text
my-skill/
├── skill.py
└── skill.sh
```

或者：

```text
my-skill/
├── package.json
├── index.js
└── scripts/
```

沙箱系统并不会自动识别入口文件，而是由调用方显式传入 `command`。

例如：

- Python Skill：`["python", "skill.py"]`
- Shell Skill：`["sh", "skill.sh"]`
- Node Skill：`["node", "index.js"]`

## 设计说明

### backend

标准库 WSGI 服务提供 HTTP 接口，接收分析请求并返回结构化 JSON。

### runner

`DockerRunner` 负责：

1. 构建沙箱镜像
2. 把目标 Skill 目录复制到临时目录
3. 通过 `docker run` 在容器内执行命令
4. 用 `strace -ff -tt -e trace=file,process,network` 采集系统调用
5. 回收 `stdout`、`stderr`、trace 日志和执行元数据

### analyzer

最小规则引擎根据采集结果打标签和评分：

- 有网络活动：加分
- 有 shell 或子进程：加分
- 有写文件：加分
- 访问敏感路径：加分
- 超时：加分

## 项目启动文档

### 环境要求

- Linux 或 WSL2
- Python 3.10+
- Docker Engine

### 1. 确认 Python 可用

```bash
python3 --version
```

### 2. 确认 Docker 可用

```bash
docker --version
docker info
```

如果 `docker info` 失败，先确保 Docker daemon 已启动。

### 3. 启动分析服务

```bash
cd /root/projects/clawguard-skill-sandbox
python3 -m app.main --host 0.0.0.0 --port 8000
```

启动成功后会看到：

```text
Serving Skill Dynamic Sandbox MVP on http://0.0.0.0:8000
```

### 4. 健康检查

```bash
curl --noproxy '*' http://127.0.0.1:8000/health
```

期望返回：

```json
{
  "status": "ok"
}
```

### 5. 分析一个示例 Skill

```bash
curl --noproxy '*' -X POST http://127.0.0.1:8000/analyze-skill \
  -H 'Content-Type: application/json' \
  -d '{
    "skill_path": "./examples/skills/network_file_probe",
    "command": ["python", "skill.py"],
    "timeout_seconds": 20
  }'
```

## 接口说明

### `POST /analyze-skill`

请求体：

```json
{
  "skill_path": "./examples/skills/network_file_probe",
  "command": ["python", "skill.py"],
  "timeout_seconds": 20
}
```

字段说明：

- `skill_path`
  - 本地 Skill 目录路径
  - 必填
- `command`
  - 容器内执行命令
  - 必填
  - 例如 `["python", "skill.py"]`
- `timeout_seconds`
  - 执行超时时间
  - 可选，默认 `20`

返回字段说明：

- `exit_code`
  - Skill 执行退出码
- `timed_out`
  - 是否超时
- `stdout`
  - 标准输出
- `stderr`
  - 标准错误
- `trace_summary`
  - 行为摘要计数
- `risk_score`
  - 风险分数，范围 `0-100`
- `detected_behaviors`
  - 检测出的行为标签
- `evidence_timeline`
  - 时间排序证据列表

## 示例 Skill 说明

[examples/skills/network_file_probe/skill.py](/root/projects/clawguard-skill-sandbox/examples/skills/network_file_probe/skill.py:1) 这个示例 Skill 会：

- 在当前目录创建 `output.txt`
- 读取 `/etc/hosts`
- 请求 `https://example.com`
- 启动一次 `sh -c`

因此报告里通常会出现：

- 文件创建
- 敏感路径读取
- DNS/HTTPS 连接
- shell 启动

## 如何新增你自己的 Skill

假设你要新增一个 Python Skill：

```text
examples/skills/my_skill/
└── skill.py
```

`skill.py`：

```python
from pathlib import Path

Path("hello.txt").write_text("hello sandbox\n", encoding="utf-8")
print("done")
```

然后调用：

```bash
curl --noproxy '*' -X POST http://127.0.0.1:8000/analyze-skill \
  -H 'Content-Type: application/json' \
  -d '{
    "skill_path": "./examples/skills/my_skill",
    "command": ["python", "skill.py"],
    "timeout_seconds": 20
  }'
```

## 常见问题

### 1. Skill 一定要实现 HTTP API 吗？

不用。

这个系统分析的是“代码执行行为”，不是“服务对外接口行为”。只要 Skill 能被命令行启动即可。

### 2. Skill 一定要叫 `skill.py` 吗？

不用。

名字完全可以自定义，只要你在 `command` 里写对入口命令即可。

### 3. 这个系统会自动识别 Skill 入口吗？

不会。

当前 MVP 采用最简单方式：由调用方显式传入 `command`。

### 4. 为什么不是上传 zip、执行 manifest、或注册 Skill 元数据？

因为这是 MVP。

当前版本优先保证：

- 能跑
- 能隔离
- 能采集
- 能输出安全报告

后续如果要产品化，可以增加：

- Skill manifest
- Skill 包上传
- 版本管理
- 远程对象存储
- 批量分析
- 权限与鉴权

### 5. 为什么有的文件访问看起来像系统初始化？

因为底层是基于 `strace` 做动态采集，运行时会带出一些解释器和系统层行为。

当前 analyzer 已经过滤了一部分噪音，但这仍然是一个“最小可运行”的动态分析系统，不是完整商用级沙箱。

## 本地启动

这一节保留一个最简版速查：

```bash
docker --version
docker info
python3 -m app.main --host 0.0.0.0 --port 8000
curl --noproxy '*' -X POST http://127.0.0.1:8000/analyze-skill \
  -H 'Content-Type: application/json' \
  -d '{
    "skill_path": "./examples/skills/network_file_probe",
    "command": ["python", "skill.py"],
    "timeout_seconds": 20
  }'
```

## 示例返回

```json
{
  "skill_path": "/abs/path/examples/skills/network_file_probe",
  "sandbox_image": "skill-sandbox-mvp:latest",
  "command": ["python", "skill.py"],
  "exit_code": 0,
  "timed_out": false,
  "stdout": "Read /etc/hosts bytes: 172\nFetched bytes: 120\n{\"child_stdout\": \"child-process-ran\"}\n",
  "stderr": "",
  "trace_summary": {
    "file_event_count": 9,
    "network_event_count": 3,
    "process_event_count": 4,
    "stdout_line_count": 3,
    "stderr_line_count": 0
  },
  "risk_score": 100,
  "detected_behaviors": [
    "child_process_execution",
    "file_write_activity",
    "network_activity",
    "sensitive_file_access",
    "shell_spawn"
  ],
  "evidence_timeline": [
    {
      "timestamp": "12:00:00.000001",
      "category": "file",
      "action": "read",
      "detail": "read /etc/hosts",
      "metadata": {
        "path": "/etc/hosts",
        "pid": "17"
      }
    }
  ]
}
```

## 说明

- 这是 MVP，实现目标是先跑通端到端链路，不做复杂调度、多租户、鉴权。
- 当前行为采集基于 `strace` 文本解析，便于演示与扩展；后续可替换为 eBPF、seccomp 审计或更细粒度事件模型。
- 当前环境默认允许容器出网，这样才能观测网络行为；后续可以再增加可配置网络策略。
- 当前 Skill 载体是“目录 + 命令”，不是插件注册中心格式，也不是必须提供 API 的服务型 Skill。
