# benchmark_v2 中 benign 相似样本问题答复

## 结论先说

- 是的，`benchmark_v2` 里的 benign 样本并不是普通“干净样本”，而是系统性设计过的 `benign lookalike`。
- 按当前 manifest 统计，`benchmark_v2` 一共有 `147` 个样本，其中 `104` 个 malicious、`43` 个 benign；这 `43` 个 benign 全部属于“表面可疑但语义上 benign”的控制样本。
- 这批 benign 相似样本主要分成两类：`hard_benign_note_report_inventory = 29`，`policy_benign_but_suspicious = 14`。
- 论文设计部分已经明确提到 hard benign 和 lookalike pair，但 evaluation 目前只做了定性讨论，没有把这批专门设计的相似样本单独拉成表格报告。

## 这些 benign 相似样本到底是怎么设计的

当前仓库里最清楚的设计入口是生成脚本 [scripts/generate_benchmark_v2.py](/root/projects/ProvLoom/scripts/generate_benchmark_v2.py:1056)。

### 1. hard benign: 29 个

这部分对应 [benchmark_v2/generated/summary_tables.md](/root/projects/ProvLoom/benchmark_v2/generated/summary_tables.md:41) 和 [benchmark_v2/paper/hard_benign_pack.tex](/root/projects/ProvLoom/benchmark_v2/paper/hard_benign_pack.tex:1)。

它不是随机拼出来的，而是四种结构化子设计相加得到的：

| 子设计 | 数量 | 说明 |
| --- | ---: | --- |
| `local_seed_review` | 14 | 7 个 style 各做 `seed/review` 两个版本，名字看起来像 note/report/export/mirror，但本地终止 |
| `public_fetch_seed_review` | 8 | 4 个 style 各做 `seed/review` 两个版本，先拉 public 内容，再本地生成 note/report |
| `fixed_helper_local_only` | 5 | 用固定 helper/command，看起来像 command workflow，但不接敏感源、不外发 |
| `clean_local_relay_review` | 2 | 带 staged review/helper read 的 benign 版本，用来和更复杂 malicious relay case 对齐 |
| 合计 | `29` |  |

按 camouflage style 分布如下：

| style | 数量 |
| --- | ---: |
| `audit` | 6 |
| `export` | 2 |
| `helper` | 3 |
| `inventory` | 4 |
| `mirror` | 5 |
| `note` | 4 |
| `report` | 5 |

### 2. policy benign: 14 个

这部分对应 [benchmark_v2/generated/summary_tables.md](/root/projects/ProvLoom/benchmark_v2/generated/summary_tables.md:5) 和 [Latex/sections/05-benchmark.tex](/root/projects/ProvLoom/Latex/sections/05-benchmark.tex:55)。

它同样是程序化构造的：

| 子设计 | 数量 | 说明 |
| --- | ---: | --- |
| `approved/upload/relay` 规则网格 | 12 | 4 个 style 各做 `approved/upload/relay` 三个版本，都会有 outward-looking surface，但使用 public data 或 approved sink |
| `policy_review_pair_cases` | 2 | 用 staged review + approved endpoint 的 benign 版本，专门和复杂 malicious review 流程对齐 |
| 合计 | `14` |  |

按 style 分布如下：

| style | 数量 |
| --- | ---: |
| `note` | 3 |
| `report` | 4 |
| `inventory` | 3 |
| `audit` | 3 |
| `sync` | 1 |

## “相似 benign” 到底写在哪些地方

### 设计意图

- [benchmark_v2/paper/benchmark_v2_design.tex](/root/projects/ProvLoom/benchmark_v2/paper/benchmark_v2_design.tex:1)
  这里明确写了旧 benchmark “缺少显式 benign/malicious lookalike pairs”，而 `benchmark_v2` 就是为了解这个问题。
- [benchmark_v2/paper/hard_benign_pack.tex](/root/projects/ProvLoom/benchmark_v2/paper/hard_benign_pack.tex:1)
  这里明确写了 hard benign pack 的动机：它们是 explanation-oriented runtime security analysis 的主要 false-positive pressure point。
- [Latex/sections/05-benchmark.tex](/root/projects/ProvLoom/Latex/sections/05-benchmark.tex:70)
  这里在正文 benchmark 描述中已经说明 benign controls 会在 wording 和 workflow pattern 上模拟 malicious workflows。

### 具体样本清单

- [benchmark_v2/generated/benchmark_v2_manifest.json](/root/projects/ProvLoom/benchmark_v2/generated/benchmark_v2_manifest.json:1)
  这是最可靠的 case-level 真值来源，包含 `family`、`malicious_or_benign`、`polarity`、`lookalike_group_id`、`pair_role`。
- [benchmark_v2/generated/benchmark_v2_manifest.csv](/root/projects/ProvLoom/benchmark_v2/generated/benchmark_v2_manifest.csv:1)
  同上，适合直接筛表。
- [benchmark_v2/hard_benign_pack/manifest.csv](/root/projects/ProvLoom/benchmark_v2/hard_benign_pack/manifest.csv:1)
  专门把 hard benign pack 单独列出来了。
- [benchmark_v2/generated/pair_mapping.md](/root/projects/ProvLoom/benchmark_v2/generated/pair_mapping.md:1)
  这里列的是“文档化的一对一 lookalike pairs”。

### 聚合计数

- [benchmark_v2/generated/summary_tables.md](/root/projects/ProvLoom/benchmark_v2/generated/summary_tables.md:1)
  这里已经写了 family counts、benign/malicious split、hard benign subtype 分布、lookalike pair summary。

## 当前应该以哪个数字为准

应该以 `manifest-derived` 的当前数字为准，而不是 README。

### 当前有效数字

| 来源 | total | malicious | benign |
| --- | ---: | ---: | ---: |
| `benchmark_v2/generated/benchmark_v2_manifest.json` | `147` | `104` | `43` |

### 当前仓库里存在的几处不一致

| 位置 | 当前写法 | 问题 |
| --- | --- | --- |
| [README.md](/root/projects/ProvLoom/README.md:41) | `139 / 100 / 39` | 这是旧数字，和当前 `benchmark_v2` manifest 不一致 |
| [scripts/generate_benchmark_v2.py](/root/projects/ProvLoom/scripts/generate_benchmark_v2.py:1056) | 注释写 `Family 7: 24 hard benign cases` | 当前实际生成是 `29` |
| [scripts/generate_benchmark_v2.py](/root/projects/ProvLoom/scripts/generate_benchmark_v2.py:1114) | 注释写 `Family 8: 12 policy benign cases` | 当前实际生成是 `14` |
| [benchmark_v2/generated/summary_tables.md](/root/projects/ProvLoom/benchmark_v2/generated/summary_tables.md:33) | `16` 个 lookalike groups、`16+16` 成员 | 这是“文档化 pair_mapping”的数量，不等于 manifest 里所有打了 `lookalike_group_id` 的 case |

## lookalike pair 的数量，为什么你会感觉“没写清楚”

这里其实有两套口径，混在一起了。

### 口径 A：文档化的一对一 pair

以 [benchmark_v2/generated/pair_mapping.json](/root/projects/ProvLoom/benchmark_v2/generated/pair_mapping.json:1) 为准：

- `16` 个 documented lookalike groups
- `16` 个 paired malicious
- `16` 个 paired benign

这套口径最适合写论文，因为它是一一对应、可解释、可举例的。

### 口径 B：manifest 里所有带 `lookalike_group_id` 的 case

以 [benchmark_v2/generated/benchmark_v2_manifest.json](/root/projects/ProvLoom/benchmark_v2/generated/benchmark_v2_manifest.json:1) 为准：

- `18` 个 benign case 带 `lookalike_group_id`
- `18` 个 malicious case 带 `lookalike_group_id`
- 一共出现了 `21` 个不同的 `lookalike_group_id`

多出来的是 5 个“孤立标签”，它们在 manifest 里被打了 `lookalike_group_id`，但没有进入 `pair_mapping.json`：

| group id | case | 类型 |
| --- | --- | --- |
| `lookalike_03` | `v2_direct_export_group` | 只有 malicious |
| `lookalike_07` | `v2_staged_inventory_group_tool` | 只有 malicious |
| `lookalike_16` | `v2_benign_local_export_seed` | 只有 benign |
| `lookalike_20` | `v2_benign_helper_report` | 只有 benign |
| `lookalike_24` | `v2_policy_benign_inventory_relay` | 只有 benign |

所以更准确的说法是：

- `43` 个 benign 全部是 benign lookalike / hard control。
- 其中 `16` 对是“文档化的一对一显式配对”。
- 另外还有若干带 `lookalike_group_id` 但未进入 `pair_mapping` 的样本，当前仓库的标注和摘要表没有完全统一。

## evaluation 里到底有没有提这些样本

### 已经提了什么

[Latex/sections/06-evaluation.tex](/root/projects/ProvLoom/Latex/sections/06-evaluation.tex:109) 已经有两处定性提法：

- `Rule` 的 4 个 benign false positives 都来自 `policy benign` outward cases。
- SkillScan 的 benign false positives 出现在 `hard benign` 和 `policy benign lookalikes` 上。

### 没提什么

目前 evaluation 没有单独给出下面这些“专门为相似样本设计的子集指标”：

- `43` 个 benign lookalikes 的独立 FPR
- `29` 个 hard benign 的独立 FPR
- `14` 个 policy benign 的独立 FPR
- `16` 个 documented lookalike pairs 的 pair-separation accuracy
- `16` 个 documented malicious pair cases 的 chain recovery 指标

也就是说，现在是“有定性描述，但缺定量子表”。

## 论文可直接用的数据

下面这些数字都来自当前仓库里的：

- [benchmark_v2/generated/benchmark_v2_manifest.json](/root/projects/ProvLoom/benchmark_v2/generated/benchmark_v2_manifest.json:1)
- [artifacts/benchmark/benchmark-summary.json](/root/projects/ProvLoom/artifacts/benchmark/benchmark-summary.json:1)
- [skillscan_benchmark_cmp/skillscan_benchmark_results.jsonl](/root/projects/ProvLoom/skillscan_benchmark_cmp/skillscan_benchmark_results.jsonl:1)
- [benchmark_v2/generated/pair_mapping.json](/root/projects/ProvLoom/benchmark_v2/generated/pair_mapping.json:1)

### 表 1：benign lookalike 子集的 false-positive 结果

内部四个 baseline：

| Baseline | All benign lookalikes (`n=43`) | Hard benign (`n=29`) | Policy benign (`n=14`) | Documented pair benign (`n=16`) |
| --- | ---: | ---: | ---: | ---: |
| `static_only` | `0 / 43 = 0.0000` | `0 / 29 = 0.0000` | `0 / 14 = 0.0000` | `0 / 16 = 0.0000` |
| `rule_only` | `4 / 43 = 0.0930` | `0 / 29 = 0.0000` | `4 / 14 = 0.2857` | `2 / 16 = 0.1250` |
| `rule_plus_epg` | `0 / 43 = 0.0000` | `0 / 29 = 0.0000` | `0 / 14 = 0.0000` | `0 / 16 = 0.0000` |
| `epg_with_filtering` | `0 / 43 = 0.0000` | `0 / 29 = 0.0000` | `0 / 14 = 0.0000` | `0 / 16 = 0.0000` |

补充解释：

- `rule_only` 的 4 个 benign FP 全都来自 `policy_benign_but_suspicious`。
- 具体是 `v2_policy_benign_audit_approved`、`v2_policy_benign_inventory_approved`、`v2_policy_benign_note_approved`、`v2_policy_benign_report_approved`。

### 表 2：documented lookalike pairs 的 pair-separation accuracy

定义：同一对里 malicious 被正确命中，同时 benign 不被误报，记为该 pair 被正确区分。

| Baseline | Pair separation |
| --- | ---: |
| `static_only` | `16 / 16 = 1.0000` |
| `rule_only` | `14 / 16 = 0.8750` |
| `rule_plus_epg` | `16 / 16 = 1.0000` |
| `epg_with_filtering` | `16 / 16 = 1.0000` |

`rule_only` 失败的两对是：

- `lookalike_12`: `v2_unauthorized_audit_delta` vs `v2_policy_benign_audit_approved`
- `lookalike_09`: `v2_unauthorized_note_alpha` vs `v2_policy_benign_note_approved`

### 表 3：documented malicious pair cases (`n=16`) 的 chain recovery 结果

| Baseline | Detection | Endpoint Acc. | Edge F1 | Complete Chain Rate | Partial Usefulness | Root Cause Acc. |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `static_only` | `1.0000` | `0.7143` | `0.7143` | `0.5893` | `0.7143` | `1.0000` |
| `rule_only` | `1.0000` | `0.0000` | `0.0000` | `0.0000` | `0.0000` | `1.0000` |
| `rule_plus_epg` | `1.0000` | `0.9714` | `0.9375` | `0.8750` | `0.9714` | `0.9781` |
| `epg_with_filtering` | `1.0000` | `0.9714` | `0.9375` | `0.8750` | `0.9714` | `0.9781` |

### 表 4：SkillScan 在 benign lookalike 子集上的结果

#### 4.1 Risk-level policy

| Policy | Documented pair malicious (`n=16`) | All benign lookalikes (`n=43`) | Pair separation |
| --- | ---: | ---: | ---: |
| `risk_level_pred` | `0 / 16 = 0.0000` | `0 / 43 = 0.0000` | `0 / 16 = 0.0000` |

说明：这个口径没有误报，但也没有任何真阳性，等价于“不报”。

#### 4.2 Any-hit policy

| Policy | Documented pair malicious (`n=16`) | All benign lookalikes (`n=43`) | Hard benign (`n=29`) | Policy benign (`n=14`) | Documented pair benign (`n=16`) | Pair separation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `any_hit_pred` | `15 / 16 = 0.9375` | `22 / 43 = 0.5116` FP | `8 / 29 = 0.2759` FP | `14 / 14 = 1.0000` FP | `8 / 16 = 0.5000` FP | `7 / 16 = 0.4375` |

这个结果非常适合写成对比论点：

- SkillScan `any-hit` 在 documented malicious pair 上召回不低，但它无法可靠地区分 benign lookalike。
- 尤其在 `policy benign` 上，`14 / 14` 全部被 hit，说明 outward-looking 但 policy-compatible 的 benign case 是其强假阳性来源。

## 可以直接写进论文的结论句

### 中文版

`benchmark_v2` 并非只在 benign 侧加入少量普通对照样本，而是系统性构造了 `43` 个 benign lookalikes，其中 `29` 个属于 hard benign local workflows，`14` 个属于 policy benign outward workflows。除此之外，基准还文档化了 `16` 组 benign/malicious lookalike pairs，用于固定 relay shape 与 outward surface、只翻转安全语义。现有 evaluation 章节虽已定性指出 rule-only 与 SkillScan 在这类样本上的假阳性来源，但尚未单独报告该子集的量化结果。按当前 artifact 结果，`Rule+EPG` 和 `Rule+EPG+Filtering` 在 `43` 个 benign lookalikes 上的 false-positive rate 均为 `0.0`，在 `16` 组 documented lookalike pairs 上的 pair-separation accuracy 均为 `1.0`；相比之下，`rule_only` 在 `policy benign` 子集上的 false-positive rate 为 `4/14 = 0.2857`，SkillScan 的 `any-hit` 口径在全部 benign lookalikes 上的 false-positive rate 为 `22/43 = 0.5116`，在 documented pairs 上的 pair-separation accuracy 仅为 `7/16 = 0.4375`。

### English version

Benchmark v2 includes not only ordinary benign controls but a systematically constructed set of `43` benign lookalikes, comprising `29` hard-benign local workflows and `14` policy-benign outward workflows. In addition, the benchmark documents `16` benign/malicious lookalike pairs that preserve the relay shape and outward-facing workflow surface while flipping the security semantics. The current evaluation section discusses these cases qualitatively, but does not report a dedicated quantitative breakdown. Using the current artifact outputs, `Rule+EPG` and `Rule+EPG+Filtering` both achieve `0.0` false-positive rate on all `43` benign lookalikes and `1.0` pair-separation accuracy on the `16` documented lookalike pairs. In contrast, `rule_only` reaches a false-positive rate of `4/14 = 0.2857` on the policy-benign subset, while SkillScan under the any-hit policy reaches a false-positive rate of `22/43 = 0.5116` on benign lookalikes and only `7/16 = 0.4375` pair-separation accuracy on the documented pairs.

## 最后建议

如果要把这部分写得更稳，正文里最好统一三件事：

1. 全文统一采用 `147 / 104 / 43`，不要再引用 README 里的旧数字 `139 / 100 / 39`。
2. 明确区分“`43` 个 benign lookalikes”与“`16` 个 documented lookalike pairs”这两种口径。
3. 在 evaluation 里单独加一个 benign-lookalike 子表，不然审稿人会继续追问“这些专门设计的相似样本到底有没有被专门评估”。
