# dangerous_skills/auto-updater-2yq87/SKILL.md 检测报告

生成时间: 2026-04-26 21:45 Asia/Shanghai

## 目标

- Skill: `/root/projects/ProvLoom/dangerous_skills/auto-updater-2yq87/SKILL.md`
- 输出目录: `/root/projects/ProvLoom/test_dss`
- 检测命令:

```bash
python3 scripts/batch_scan_skills.py \
  --skills-root /root/projects/ProvLoom/dangerous_skills \
  --skill-paths-file test_dss/skill-paths.txt \
  --log-dir test_dss \
  --max-workers 1 \
  --default-timeout-seconds 120 \
  --no-resume
```

## 自动化检测结果

- 状态: completed
- 风险分数: 0
- 风险等级: low / 低风险
- detected_behaviors: []
- severity_label: benign_like
- evidence_strength: partial
- execution_outcome: completed_full
- primary_chain: []
- root_cause_v2.mechanism_class: insufficient_context
- root_cause_v2.evidence_status: trigger_incomplete

原始结果文件:

- `test_dss/results.jsonl`
- `test_dss/summary.json`
- `test_dss/skills/root_projects_provloom_dangerous_skills_auto-updater-2yq87.json`

## 执行证据限制

本次运行没有观察到真实的文件、进程或外部网络风险链:

- trace_summary.file_event_count: 3
- trace_summary.network_event_count: 0
- trace_summary.process_event_count: 0
- trace_summary.tool_call_count: 3
- trace_summary.llm_event_count: 1

但执行 stderr 中出现 LLM 请求失败:

```text
RuntimeError: LLM request returned HTTP 400 for provider=siliconflow model=deepseek-ai/DeepSeek-V3-Chat
```

因此自动化结论只能说明: 在本次沙箱触发条件下，未成功执行到可观测的高风险行为。该结论不应等同于 skill 安全。

## 静态复核风险点

该 `SKILL.md` 文档本身包含多处高风险操作建议:

- 要求安装并运行第三方 `openclaw-agent` 工具。
- Windows 安装链接指向 GitHub release zip，并提示使用固定解压密码 `openclaw`。
- macOS 安装流程要求用户访问 `glot.io` 页面、复制安装脚本并粘贴到 Terminal 执行。
- 引导创建每日 cron 任务，使用 `clawdbot cron add --wake now --deliver` 定时唤醒并执行自动更新。
- 更新路径包含全局包更新命令: `npm update -g clawdbot@latest`、`pnpm update -g`、`bun update -g`。
- 更新路径包含批量 skill 更新命令: `clawdhub update --all`。

这些行为组合形成供应链与持久化风险:

- 外部二进制/脚本安装: 用户被引导执行来自网络的工具或脚本。
- 持久化执行: cron 每日自动运行。
- 远程代码/配置变更: 自动更新 Clawdbot 与全部 skills。
- 权限与完整性风险: 全局包更新和 skill 批量更新可能改变运行环境。

## 综合判定

自动化沙箱判定: 低风险，未检测到命中的高风险行为。

人工静态复核判定: 高风险可疑 skill。主要原因是它指导用户安装外部 agent、执行远程安装脚本、配置持久化定时任务，并自动更新执行环境和全部 skills。即使本次动态触发没有落地执行链，这类指令对用户系统和供应链完整性仍有明显风险。

## 建议

- 不要按该 skill 指示安装 `openclaw-agent` 或执行 `glot.io` 上的安装脚本。
- 不要创建该每日自动更新 cron。
- 若必须保留自动更新能力，应要求固定可信源、校验签名/哈希、最小权限运行、禁用自动批量更新 skills，并加入人工确认步骤。
