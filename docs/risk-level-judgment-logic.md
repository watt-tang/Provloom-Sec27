# ProvLoom 当前 `critical / medium / low` 判定逻辑说明

这份文档整理的是仓库里“当前生效”的风险等级判定链路，重点回答三个问题：

- `critical`、`medium`、`low` 到底是怎么来的
- 哪些证据会把分数拉高，哪些模式会把分数压低
- 为什么你现在的扫描结果里经常只看到 `low / medium / critical`，很少看到 `high`

本文基于当前代码实现整理，不是基于历史口径或论文表述反推。核心代码位置包括：

- [app/analyzer/rules.py](/root/projects/ProvLoom/app/analyzer/rules.py:55)
- [app/analyzer/decision_engine.py](/root/projects/ProvLoom/app/analyzer/decision_engine.py:18)
- [app/analyzer/source_classifier.py](/root/projects/ProvLoom/app/analyzer/source_classifier.py:38)
- [app/analyzer/sink_classifier.py](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:9)
- [app/analyzer/risk_scoring.py](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:12)
- [app/analyzer/benign_patterns.py](/root/projects/ProvLoom/app/analyzer/benign_patterns.py:8)
- [app/reporting/risk_mapper.py](/root/projects/ProvLoom/app/reporting/risk_mapper.py:51)
- [scripts/batch_scan_skills.py](/root/projects/ProvLoom/scripts/batch_scan_skills.py:585)

## 1. 先说结论

当前 ProvLoom 的最终风险等级不是“看到某个行为就直接判成 `critical`/`medium`/`low`”，而是一个四阶段流程：

1. 从执行轨迹中提取基础行为标签，例如 `network_access`、`shell_execution`、`sensitive_file_read`
2. 从主链、工具调用、文件事件、网络事件里推断 `source` 和 `sink` 的语义
3. 根据规则做“加分”和“减分”，得到最终 `risk_score`
4. 再把 `risk_score` 映射成 `risk_level`

也就是说：

- `risk_level` 的直接输入是 `risk_score`
- `risk_score` 的直接输入是 `triggered_factors` 和 `suppression_factors`
- `detected_behaviors` 只是证据入口，不等于最终等级

## 2. 最终等级映射表

最终等级映射定义在 [app/reporting/risk_mapper.py](/root/projects/ProvLoom/app/reporting/risk_mapper.py:51)：

- `0-19` -> `low / 低风险`
- `20-49` -> `medium / 中风险`
- `50-79` -> `high / 高风险`
- `80-100` -> `critical / 严重风险`

对应代码：

- [app/reporting/risk_mapper.py:51](/root/projects/ProvLoom/app/reporting/risk_mapper.py:51)
- [app/reporting/risk_mapper.py:114](/root/projects/ProvLoom/app/reporting/risk_mapper.py:114)

这里有一个很关键的点：

- 系统实际定义了四档，不是三档
- 你现在主要关注的是 `critical / medium / low`
- 但代码里确实存在 `high`

所以如果只问“`critical / medium / low` 的判定逻辑”，严格来说应该理解成：

- 这三档是最终分数落在哪个区间
- 不是三个单独的 if/else 分支

## 3. 一条结果是怎么走到 `risk_level` 的

### 3.1 第一层：基础行为命中

动态分析入口在 [app/analyzer/rules.py](/root/projects/ProvLoom/app/analyzer/rules.py:55)。

系统先从运行轨迹里提取基础行为：

- 看到有效网络事件 -> `network_access`
- 看到 shell 进程 `/bin/sh`、`/bin/bash` 等 -> `shell_execution`
- 看到进程执行 -> `process_spawn`
- 看到文件写入/创建/删除重命名 -> `file_write`
- 看到敏感路径读证据 -> `sensitive_file_read`
- 先读敏感源再联网 -> `read_then_exfiltration`
- 超时 -> `execution_timeout`

对应代码：

- [app/analyzer/rules.py:62](/root/projects/ProvLoom/app/analyzer/rules.py:62)
- [app/analyzer/rules.py:64](/root/projects/ProvLoom/app/analyzer/rules.py:64)
- [app/analyzer/rules.py:67](/root/projects/ProvLoom/app/analyzer/rules.py:67)
- [app/analyzer/rules.py:73](/root/projects/ProvLoom/app/analyzer/rules.py:73)
- [app/analyzer/rules.py:77](/root/projects/ProvLoom/app/analyzer/rules.py:77)
- [app/analyzer/rules.py:80](/root/projects/ProvLoom/app/analyzer/rules.py:80)
- [app/analyzer/rules.py:83](/root/projects/ProvLoom/app/analyzer/rules.py:83)

注意：

- 这一步只是在收集“观察到的行为”
- 还没有产生最终 `risk_level`

### 3.2 第二层：构造主链和上下文

如果分析模式是 `rule_plus_epg`、`epg_without_filtering` 或 `epg_with_filtering`，系统会继续构建 EPG，并尝试提取 `primary_chain`：

- [app/analyzer/rules.py:115](/root/projects/ProvLoom/app/analyzer/rules.py:115)
- [app/analyzer/rules.py:381](/root/projects/ProvLoom/app/analyzer/rules.py:381)

`primary_chain` 很重要，因为后面的 source/sink 推断和高风险判断会优先依赖它。

### 3.3 第三层：判 source 是高/中/低敏感

source 分类在 [app/analyzer/source_classifier.py](/root/projects/ProvLoom/app/analyzer/source_classifier.py:38)。

当前逻辑可以概括成：

- `public/...` 视为 `LOW`
- 敏感路径前缀 `/etc/`、`/root/`、`/proc/`、`/sys/`、`/var/run/` 视为 `HIGH`
- 本地生成产物，例如 `runtime_output/...` 或非绝对路径本地文件，通常视为 `MEDIUM`
- 无法判断时是 `UNKNOWN`

对应代码：

- 敏感路径前缀定义：[app/analyzer/source_classifier.py:13](/root/projects/ProvLoom/app/analyzer/source_classifier.py:13)
- 噪声敏感路径白名单，例如 `/etc/ld.so.cache` 不算高敏感：[app/analyzer/source_classifier.py:14](/root/projects/ProvLoom/app/analyzer/source_classifier.py:14)
- `public/` -> `LOW`：[app/analyzer/source_classifier.py:123](/root/projects/ProvLoom/app/analyzer/source_classifier.py:123)
- 敏感路径 -> `HIGH`：[app/analyzer/source_classifier.py:135](/root/projects/ProvLoom/app/analyzer/source_classifier.py:135)
- 本地产物 -> `MEDIUM`：[app/analyzer/source_classifier.py:152](/root/projects/ProvLoom/app/analyzer/source_classifier.py:152)
- 无法识别 -> `UNKNOWN`：[app/analyzer/source_classifier.py:163](/root/projects/ProvLoom/app/analyzer/source_classifier.py:163)

另外，source 不是只看当前路径名，还会沿 action 依赖往前追 lineage：

- `read_file` 直接继承读入路径
- `http_request GET` 的结果视为公共输入，按 `LOW`
- `write_file` 会继承上游依赖；如果没有上游公共 lineage，则默认保留 `MEDIUM`
- `run_command` 会解析命令里的路径，也会追到这些路径对应的 writer action

对应代码：

- action 递归追踪：[app/analyzer/source_classifier.py:175](/root/projects/ProvLoom/app/analyzer/source_classifier.py:175)
- `http_request GET` 视为公共内容：[app/analyzer/source_classifier.py:195](/root/projects/ProvLoom/app/analyzer/source_classifier.py:195)
- `write_file` 默认中敏感生成物：[app/analyzer/source_classifier.py:216](/root/projects/ProvLoom/app/analyzer/source_classifier.py:216)
- lineage 合并时按 `HIGH > MEDIUM > LOW > UNKNOWN` 取最高：[app/analyzer/source_classifier.py:263](/root/projects/ProvLoom/app/analyzer/source_classifier.py:263)

### 3.4 第四层：判 sink 的语义

sink 分类在 [app/analyzer/sink_classifier.py](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:9)。

系统优先级是：

1. 先看 `primary_chain` 末端的 `network_endpoint`
2. 没有就看 `http_request` 工具动作
3. 再没有就退化到最后一个网络事件

对应代码：

- 主链 sink 优先：[app/analyzer/sink_classifier.py:12](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:12)
- 退化到 `http_request`：[app/analyzer/sink_classifier.py:41](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:41)
- 再退化到原始网络事件：[app/analyzer/sink_classifier.py:55](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:55)

sink 语义当前分成这些类：

- `TOOL_INTERNAL_ENDPOINT`
- `LLM_MEDIATED_UNKNOWN_SINK`
- `UNKNOWN_NETWORK_SINK`
- `CALLBACK_OR_WEBHOOK`
- `PUBLIC_FETCH_ONLY`
- `PUBLIC_UPLOAD_OR_POST`

判定规则如下：

- 内网或 localhost -> `TOOL_INTERNAL_ENDPOINT`
- 经 LLM relay 外发，但下游真实目标不明 -> `LLM_MEDIATED_UNKNOWN_SINK`
- 只看到了受控保留地址/解析不清 -> `UNKNOWN_NETWORK_SINK`
- URL 包含 `webhook/callback/hook` -> `CALLBACK_OR_WEBHOOK`
- HTTP `GET` -> `PUBLIC_FETCH_ONLY`
- HTTP `POST/PUT/PATCH` -> `PUBLIC_UPLOAD_OR_POST`
- 其余信息不足 -> `UNKNOWN_NETWORK_SINK`

对应代码：

- [app/analyzer/sink_classifier.py:115](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:115)
- [app/analyzer/sink_classifier.py:118](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:118)
- [app/analyzer/sink_classifier.py:121](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:121)
- [app/analyzer/sink_classifier.py:124](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:124)
- [app/analyzer/sink_classifier.py:127](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:127)
- [app/analyzer/sink_classifier.py:130](/root/projects/ProvLoom/app/analyzer/sink_classifier.py:130)

### 3.5 第五层：判命令风险

命令风险判定在 [app/analyzer/decision_engine.py](/root/projects/ProvLoom/app/analyzer/decision_engine.py:89)。

以下情况会被视为 `risky_command = True`：

- 命令模板直接插入 `input_payload`
- shell 命令里出现 `|`、`;`、`$(`、反引号、`&&`
- 命令显式引用敏感路径，如 `/etc/passwd`、`/etc/shadow`、`/etc/hosts`、`/root/`

对应代码：

- [app/analyzer/decision_engine.py:104](/root/projects/ProvLoom/app/analyzer/decision_engine.py:104)
- [app/analyzer/decision_engine.py:106](/root/projects/ProvLoom/app/analyzer/decision_engine.py:106)
- [app/analyzer/decision_engine.py:108](/root/projects/ProvLoom/app/analyzer/decision_engine.py:108)

## 4. 真正决定分数的加分项

真正的分数计算在 [app/analyzer/risk_scoring.py](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:37)。

当前生效的加分项如下。

### 4.1 `+80` 高敏感源到外部 sink

命中条件：

- `source.sensitivity == HIGH`
- sink 是外部方向
- 而且这个外部 sink 有证据支撑

“有证据支撑”的定义不是一定要把真实域名完全还原出来，只要满足以下任意一项即可：

- 有声明端点
- 有工具级 `http_request`
- 有网络证据来源
- 有 `primary_chain`
- 或命中过 `network_access`

对应代码：

- 外部 sink 证据判断：[app/analyzer/risk_scoring.py:12](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:12)
- `HIGH` source + external sink -> `+80`：[app/analyzer/risk_scoring.py:28](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:28)
- 加分项定义：[app/analyzer/risk_scoring.py:41](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:41)

这条是当前最典型的 `critical` 入口。

### 4.2 `+55` 本地生成物向外传输

命中条件：

- `source.sensitivity == MEDIUM`
- sink 语义是以下之一：
  - `PUBLIC_UPLOAD_OR_POST`
  - `CALLBACK_OR_WEBHOOK`
  - `LLM_MEDIATED_UNKNOWN_SINK`
  - `UNKNOWN_NETWORK_SINK`
- 且 source 不是 public lineage

对应代码：

- [app/analyzer/risk_scoring.py:56](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:56)

这条本身通常会落在 `high`，但如果再叠加 `LLM` 风险，可能升到 `critical`。

### 4.3 `+45` 过度授权的 outward tool action

命中条件在 [app/analyzer/decision_engine.py](/root/projects/ProvLoom/app/analyzer/decision_engine.py:41) 先计算：

- source 是 `MEDIUM`
- source 是本地生成物
- 不是 public lineage
- sink 是 external
- 且是工具级 `http_request`

命中后在 [app/analyzer/risk_scoring.py](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:74) 加 `45` 分。

### 4.4 `+70` 危险命令构造

只要 `risky_command == True`，就在 [app/analyzer/risk_scoring.py](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:83) 加 `70` 分。

这条本身一般会落在 `high`；如果再叠加 LLM，则很容易进 `critical`。

### 4.5 `+25` LLM 诱导风险动作

命中条件：

- 存在 LLM 参与
- 且出现 outward network 或 risky command

对应代码：

- [app/analyzer/risk_scoring.py:92](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:92)

这条是当前很多 `medium` 的直接来源。只要只有这一条，就会得到 `25` 分，也就是 `medium`。

### 4.6 `+25` 未知源到外部 sink

命中条件：

- `source.sensitivity == UNKNOWN`
- 有 outward network
- sink 语义是：
  - `CALLBACK_OR_WEBHOOK`
  - `LLM_MEDIATED_UNKNOWN_SINK`
  - `UNKNOWN_NETWORK_SINK`

对应代码：

- [app/analyzer/risk_scoring.py:101](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:101)

这条也通常直接落在 `medium`。

## 5. 会把分数压低的扣分项

扣分逻辑在 [app/analyzer/benign_patterns.py](/root/projects/ProvLoom/app/analyzer/benign_patterns.py:8)。

### 5.1 `-45` `public_fetch_to_public_upload`

条件：

- 没有 risky command
- 不是高敏感 source
- 不是 overprivileged outward action
- source 来自 public lineage
- source 是 `LOW`
- sink 是 `PUBLIC_UPLOAD_OR_POST`

对应代码：

- [app/analyzer/benign_patterns.py:80](/root/projects/ProvLoom/app/analyzer/benign_patterns.py:80)

### 5.2 `-30` `public_fetch_to_transform_or_note`

条件：

- source 来自 public lineage
- source 是 `LOW`
- sink 是 `PUBLIC_FETCH_ONLY` 或 `UNKNOWN_NETWORK_SINK`

对应代码：

- [app/analyzer/benign_patterns.py:89](/root/projects/ProvLoom/app/analyzer/benign_patterns.py:89)

### 5.3 `-40` `mirror_style_public_relay`

条件：

- 主链里存在 relay
- source 来自 public lineage
- source 是 `LOW`
- sink 是 `PUBLIC_UPLOAD_OR_POST`

对应代码：

- [app/analyzer/benign_patterns.py:98](/root/projects/ProvLoom/app/analyzer/benign_patterns.py:98)

### 5.4 `-40` `legal_helper_command`

条件：

- 没有 risky command
- 没有 outward network
- source 不是高敏感
- 且命令看起来像合法 helper，例如包含 `tools/helper.py`、`wc`、`sha`、`tar`

对应代码：

- [app/analyzer/benign_patterns.py:109](/root/projects/ProvLoom/app/analyzer/benign_patterns.py:109)

### 5.5 `-25` `benign_llm_safe_tool_usage`

条件：

- 有 LLM
- 没有 risky command
- source 是 `LOW` 或 `UNKNOWN`
- sink 是 `PUBLIC_FETCH_ONLY`、`TOOL_INTERNAL_ENDPOINT` 或 `UNKNOWN_NETWORK_SINK`

对应代码：

- [app/analyzer/benign_patterns.py:118](/root/projects/ProvLoom/app/analyzer/benign_patterns.py:118)

## 6. 最终分数怎么算

总公式在 [app/analyzer/decision_engine.py](/root/projects/ProvLoom/app/analyzer/decision_engine.py:64)：

`final_score = clamp(raw_score + suppression_sum, 0, 100)`

也就是：

- 先把所有加分项求和，得到 `raw_score`
- 再叠加所有 suppression 的负分
- 最后裁剪到 `0-100`

对应代码：

- `raw_score` 计算：[app/analyzer/risk_scoring.py:118](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:118)
- suppression 叠加：[app/analyzer/decision_engine.py:65](/root/projects/ProvLoom/app/analyzer/decision_engine.py:65)
- `0-100` 裁剪：[app/analyzer/decision_engine.py:66](/root/projects/ProvLoom/app/analyzer/decision_engine.py:66)

另外，系统内部还有一个独立于 `risk_level` 的三态判定：

- `>= 60` -> `malicious`
- `30-59` -> `needs_review`
- `< 30` -> `benign`

对应代码：

- [app/analyzer/decision_engine.py:67](/root/projects/ProvLoom/app/analyzer/decision_engine.py:67)
- [app/analyzer/risk_scoring.py:119](/root/projects/ProvLoom/app/analyzer/risk_scoring.py:119)

注意这和 `risk_level` 不是同一套标签：

- `risk_level` 是 `low / medium / high / critical`
- `final_decision` 是 `benign / needs_review / malicious`

## 7. `critical / medium / low` 分别怎么落下来

### 7.1 `critical`

`critical` 的充要条件只有一个：

- 最终 `risk_score >= 80`

最常见路径是：

- 高敏感 source 到外部 sink -> `+80`
- 如果同时有 LLM 参与 -> 再 `+25`
- 最终分数被裁到 `100`

也就是说，当前很多 `critical` 实际上来自：

- 敏感本地文件
- 有外部方向
- 有一定链路或网络证据支撑

不是简单的“看到 shell”或“看到联网”。

典型组合：

- `80` -> `critical`
- `80 + 25 = 100` -> `critical`
- `55 + 25 = 80` -> `critical`
- `70 + 25 = 95` -> `critical`

### 7.2 `medium`

`medium` 的条件是：

- 最终 `risk_score` 落在 `20-49`

当前最典型的来源有两个：

- 只有 `llm_induced_risky_action` -> `25`
- 只有 `unknown_source_external_sink` -> `25`

也就是说，大量 `medium` 不是“中等程度的数据外泄已确认”，而更像：

- 有 LLM 参与且存在 outward action
- 或存在外联，但 source 还没解释清楚

这也是为什么真实 skill 批量扫描里 `medium` 往往非常多。

另外，一些被 suppression 压过的结果也可能落在 `20-49`，例如：

- `45 - 25 = 20`
- `70 - 40 = 30`

### 7.3 `low`

`low` 的条件是：

- 最终 `risk_score` 落在 `0-19`

常见情况：

- 没命中任何加分项，直接 `0`
- 命中了小风险项，但被 benign suppression 拉回去了

例如：

- `25 - 25 = 0`

所以 `low` 不是“完全没任何行为”，而是“最终综合判断分数很低”。

## 8. 一个最容易混淆的点

`BEHAVIOR_LABELS` 里的 `severity` 不是最终 `risk_level`。

在 [app/reporting/risk_mapper.py](/root/projects/ProvLoom/app/reporting/risk_mapper.py:6) 里：

- `network_access` 被标成 `high`
- `shell_execution` 被标成 `critical`
- `sensitive_file_read` 被标成 `critical`

但这些字段的作用主要是：

- 生成 `primary_risk`
- 生成人类可读的 `risk_summary`

对应代码：

- 行为标签定义：[app/reporting/risk_mapper.py:6](/root/projects/ProvLoom/app/reporting/risk_mapper.py:6)
- 选主要风险标签：[app/reporting/risk_mapper.py:103](/root/projects/ProvLoom/app/reporting/risk_mapper.py:103)
- 生成摘要：[app/reporting/risk_mapper.py:121](/root/projects/ProvLoom/app/reporting/risk_mapper.py:121)

真正决定 `risk_level` 的，是 `risk_score` 区间，而不是这些 `severity` 文本。

举例：

- 一个样本即便命中了 `network_access`
- 在展示摘要里它可能带 `high` 行为标签
- 但如果最终分数只有 `25`
- 它的 `risk_level` 仍然只是 `medium`

## 9. 为什么你现在经常只看到 `low / medium / critical`

从当前规则组合来看，这是一个很自然的结果。

因为很多样本会落在这些典型分数：

- `0`
- `25`
- `80`
- `100`

而当前真实扫描里最常见的实际触发模式往往是：

- 普通联网或 LLM outward action -> `25`
- 高敏感 source 到外部方向 -> `80`
- 高敏感 source 到外部方向再叠加 LLM -> `100`

这就会让结果大量集中在：

- `low`
- `medium`
- `critical`

反而 `high` 需要命中像下面这些“中高风险但未到 80”的组合才常见：

- 仅 `generated_artifact_external_transfer` -> `55`
- 仅 `unsafe_command_construction` -> `70`
- `overprivileged_outward_tool_action + llm` -> `70`

如果当前语料里这些模式不多，或者它们又被其他因子推高/压低，就会造成你肉眼上几乎看不到 `high`。

## 10. 批量扫描结果里这些字段是怎么写出来的

批量扫描时，`analyze_trace()` 先产出分析结果，然后 `build_result_payload()` 调用 `map_risk_profile()` 填充：

- `risk_level`
- `risk_level_name`
- `risk_summary`

对应代码：

- [scripts/batch_scan_skills.py:585](/root/projects/ProvLoom/scripts/batch_scan_skills.py:585)
- [scripts/batch_scan_skills.py:628](/root/projects/ProvLoom/scripts/batch_scan_skills.py:628)
- [scripts/batch_scan_skills.py:639](/root/projects/ProvLoom/scripts/batch_scan_skills.py:639)

所以你在 `results.jsonl`、`summary.json`、导出的 CSV 里看到的等级，最终都来自这一套映射。

## 11. 用一句话概括当前判定逻辑

当前 ProvLoom 的 `critical / medium / low` 不是“按单个行为标签硬判”，而是：

- 先从执行证据恢复 source、sink、command risk、LLM involvement
- 再按规则加分减分得到 `risk_score`
- 最后用分数区间映射成 `risk_level`

如果只看这三档的实操口径，可以记成：

- `critical`：高敏感 source 已和外部方向形成足够强的证据链，或多项高危因子叠加后达到 `80+`
- `medium`：存在 outward/LLM 风险信号，但证据还停留在弱解释层，通常是 `25` 左右
- `low`：没有形成足够风险分，或者被 benign pattern 明显压低
