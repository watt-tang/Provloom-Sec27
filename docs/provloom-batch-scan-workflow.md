# ProvLoom 批量扫描工作流说明

这份文档说明当前项目里“危险技能批量扫描”的整体逻辑，覆盖扫描入口、日志产物、结果查询、CSV 导出，以及日志目录被轮换后如何恢复到正确结果路径。

## 1. 目标与范围

当前这套流程的目标，是对一批指定的技能目录做统一批量扫描，并把每个技能的风险分析结果落盘，便于后续：

- 实时看扫描进度
- 回看单个技能的结果
- 统计风险等级
- 导出 `critical` 技能或攻击路径到 `docs/*.csv`

本项目这次使用的是“按路径清单扫描”模式，而不是“自动遍历整个根目录后再筛选”。扫描目标来自：

- [artifacts/dangerous-skill-paths.txt](/root/projects/ProvLoom/artifacts/dangerous-skill-paths.txt)

该文件是一行一个技能目录路径，当前主要指向 `/mnt/e/dangerous_skills/...` 下的技能。

## 2. 核心入口

### 2.1 主扫描脚本

主入口是：

- [scripts/batch_scan_skills.py](/root/projects/ProvLoom/scripts/batch_scan_skills.py)

它负责：

- 解析扫描参数
- 规范化 Windows/WSL 路径
- 读取技能路径列表或发现技能目录
- 检查技能是否可运行
- 并发执行扫描
- 实时写入进度和结果
- 在结束时生成汇总文件

### 2.2 本项目封装好的 skill

为了避免每次手拼长命令，项目里又封装了一层可复用 skill：

- [SKILL.md](/root/projects/ProvLoom/.agents/skills/provloom-batch-scan/SKILL.md)
- [rerun_scan.py](/root/projects/ProvLoom/.agents/skills/provloom-batch-scan/scripts/rerun_scan.py)
- [show_progress.py](/root/projects/ProvLoom/.agents/skills/provloom-batch-scan/scripts/show_progress.py)
- [show_results.py](/root/projects/ProvLoom/.agents/skills/provloom-batch-scan/scripts/show_results.py)

这层封装做了三件事：

- 统一使用 `artifacts/dangerous-skill-paths.txt`
- 默认把新一轮扫描写到 `/mnt/e/log3`
- 在 `/mnt/e/log3` 已存在内容时，先把旧目录轮换成备份目录

## 3. 标准扫描逻辑

### 3.1 输入

标准输入包括：

- `--skills-root /mnt/e/dangerous_skills`
- `--skill-paths-file artifacts/dangerous-skill-paths.txt`
- `--log-dir /mnt/e/log3`
- `--max-workers 10`
- `--analysis-mode epg_with_filtering`
- `--network-policy default`
- `--timeout-seconds 600`
- `--no-resume`

LLM API key 现在默认支持从环境变量读取：

- `PROVLOOM_SCAN_API_KEY`

这是通过 [scripts/batch_scan_skills.py](/root/projects/ProvLoom/scripts/batch_scan_skills.py) 中 `--api-key` 的默认值改成环境变量实现的。

### 3.2 发现与过滤

主脚本启动后，先进入 `discovering` 阶段。

如果传了 `--skill-paths-file`：

- 不做全目录递归发现
- 直接按路径清单扫描

如果没传 `--skill-paths-file`：

- 会在 `skills_root` 下查找所有包含 `SKILL.md` 的目录

### 3.3 可运行性检查

每个技能在真正执行前会做一次轻量检查：

- 运行时类型是否受支持
- action 类型是否受支持
- 是否需要 LLM
- 如果需要 LLM，当前是否提供了 API key
- `run_command` 依赖的命令在容器中是否可用

如果不满足条件，会被标成 `skipped`，并记录 `skip_reason`。

### 3.4 并发执行

真正的扫描阶段由 `ThreadPoolExecutor` 驱动，并发数来自 `--max-workers`。

本次标准流程使用：

- `10` 并发

每个技能会进入如下流程：

1. 解析技能定义
2. 根据运行时和 action 判断是否启用 LLM
3. 调用 `DockerRunner` 执行技能
4. 调用 `analyze_trace()` 分析运行轨迹
5. 通过 `map_risk_profile()` 映射风险等级
6. 将结果写入单技能 JSON 和总结果流

## 4. 日志与结果产物

每一轮扫描目录下，主要会有这些文件：

- `progress.json`
- `manifest.json`
- `results.jsonl`
- `summary.json`
- `discovered-skill-paths.txt`
- `skills/*.json`

### 4.1 `progress.json`

作用：

- 实时状态面板
- 适合轮询
- 适合前台观察

里面通常会包含：

- `status`
- `phase`
- `totals.discovered`
- `totals.processed`
- `totals.completed`
- `totals.skipped`
- `totals.failed`
- `active_skills`
- `config`

### 4.2 `manifest.json`

作用：

- 固化本轮任务输入
- 记录当时到底扫了哪些路径

适合回答：

- 这一轮到底扫了多少个技能
- 实际输入清单是什么
- 是否按 CSV 或按路径文件筛选

### 4.3 `results.jsonl`

作用：

- 每行一个技能结果
- 最适合边扫边读
- 最适合做二次统计和 CSV 导出

这是后续导出 `critical` 技能 CSV 的主数据源。

### 4.4 `summary.json`

作用：

- 扫描完成后的总汇总
- 附带完整 `results` 数组

它更适合“整轮扫描已经结束”的场景；如果扫描还没结束，优先看 `results.jsonl`。

### 4.5 `skills/*.json`

作用：

- 单个技能一份 JSON
- 适合追某个具体技能

文件名是技能目录路径经过 `slugify_path()` 处理后的结果。

## 5. 风险字段的含义

单条结果里最常用的字段是：

- `name`
- `skill_id`
- `skill_root`
- `status`
- `risk_score`
- `risk_level`
- `risk_level_name`
- `detected_behaviors`
- `primary_chain`
- `root_cause`

其中：

- `risk_level` 是英文枚举值，如 `low`、`medium`、`critical`
- `risk_level_name` 是中文展示值，如 `低风险`、`中风险`
- `primary_chain` 是攻击/危险路径的主链路

如果后续要导出“危险路径”CSV，通常就是把 `primary_chain` 压平成一行文字。

## 6. 结果查询方式

### 6.1 用 skill 脚本查进度

查看一行进度：

```bash
python3 .agents/skills/provloom-batch-scan/scripts/show_progress.py --log-dir <日志目录>
```

查看 JSON：

```bash
python3 .agents/skills/provloom-batch-scan/scripts/show_progress.py --log-dir <日志目录> --json
```

### 6.2 用 skill 脚本看最近结果

```bash
python3 .agents/skills/provloom-batch-scan/scripts/show_results.py --log-dir <日志目录> --tail 20
```

只看统计：

```bash
python3 .agents/skills/provloom-batch-scan/scripts/show_results.py --log-dir <日志目录> --summary
```

### 6.3 直接读 `results.jsonl`

适合二次加工，比如导 CSV：

```bash
python3 - <<'PY'
import json
from pathlib import Path
p = Path('/mnt/e/log3/results.jsonl')
rows = [json.loads(line) for line in p.read_text(encoding='utf-8').splitlines() if line.strip()]
print(len(rows))
PY
```

## 7. 日志目录轮换与“路径恢复”逻辑

这部分是本次工作里最需要特别说明的地方。

### 7.1 为什么会出现多个 `log3` 目录

封装脚本 [rerun_scan.py](/root/projects/ProvLoom/.agents/skills/provloom-batch-scan/scripts/rerun_scan.py) 的设计是：

- 新一轮扫描固定写 `/mnt/e/log3`
- 如果 `/mnt/e/log3` 已有内容，先把它移动到：
  `/mnt/e/log3.rerun-backup-<时间戳>`

这样做的好处是不会把两轮结果混在同一个目录里。

### 7.2 本次实际发生过什么

当前 `/mnt/e` 下相关目录是：

- `/mnt/e/log3`
- `/mnt/e/log3.rerun-backup-20260420-140028`
- `/mnt/e/log3.rerun-backup-20260420-142830`

它们对应关系如下：

1. `/mnt/e/log3.rerun-backup-20260420-140028`
   这是较早一轮“不带 LLM key”的扫描结果。
   结果特征是：
   `processed=617`、`completed=0`、`skipped=617`、`llm_api_enabled=false`

2. `/mnt/e/log3.rerun-backup-20260420-142830`
   这是本次真正的“带 LLM key 的完整结果”。
   结果特征是：
   `processed=617`、`completed=617`、`skipped=0`、`llm_api_enabled=true`

3. `/mnt/e/log3`
   当前这个目录已经不是完整结果目录，至少当前没有 `progress.json`。
   这意味着如果直接盯 `/mnt/e/log3`，有可能会误以为结果丢失。

### 7.3 如何恢复到正确结果路径

当 `/mnt/e/log3` 不再是有效结果目录时，不要只看目录名，要按“内容特征”定位正确目录。

推荐步骤：

1. 列出所有 `log3` 相关目录
2. 检查每个目录下是否存在 `progress.json` 与 `results.jsonl`
3. 读取 `progress.json`
4. 根据 `processed/completed/skipped/llm_api_enabled/finished_at` 判断哪一轮才是目标结果

这次我们最后认定的正确目录是：

- `/mnt/e/log3.rerun-backup-20260420-142830`

因为它满足：

- `status=completed`
- `processed=617`
- `completed=617`
- `skipped=0`
- `llm_api_enabled=true`

### 7.4 实操建议

以后如果再次发生“`/mnt/e/log3` 看起来空了”的情况，不要先恢复目录名，先确认哪一个备份目录才是你要的那轮结果。

推荐优先看：

- `progress.json`
- `results.jsonl`

而不是只看目录最新修改时间。

## 8. 当前这轮扫描的结论

基于：

- `/mnt/e/log3.rerun-backup-20260420-142830/results.jsonl`

本次带 LLM 的完整扫描结果是：

- 总数 `617`
- `completed=617`
- `skipped=0`
- `failed=0`
- 风险分布：
  `616` 个 `medium / 中风险`
  `1` 个 `low / 低风险`
  `0` 个 `critical`

这也是为什么本次导出的 `critical` CSV 只有表头，没有数据行：

- [critical-skills-log3-20260420.csv](/root/projects/ProvLoom/docs/critical-skills-log3-20260420.csv)
- [critical-primary-chain-skills-log3-20260420.csv](/root/projects/ProvLoom/docs/critical-primary-chain-skills-log3-20260420.csv)

## 9. CSV 导出的当前逻辑

目前 CSV 导出不是自动流水线的一部分，而是基于 `results.jsonl` 做二次筛选。

如果要导出 `critical` 技能：

- 过滤条件通常是 `risk_level == "critical"`

如果要导出危险路径：

- 从 `primary_chain` 中整理攻击链路
- 压平成 CSV 一列，例如 `攻击路径`

本次没有 `critical`，所以对应 CSV 为空表。

## 10. 推荐的后续整理方向

当前这套流程已经够用，但还有两个值得补强的点：

1. 让 `show_progress.py` 和 `show_results.py` 支持“自动选择最新有效结果目录”，而不是默认只看 `/mnt/e/log3`
2. 把“导出 CSV”也封成脚本，避免每次手写筛选逻辑

这样后面就能把“扫描、查询、导出”收敛成同一套稳定工具链。

