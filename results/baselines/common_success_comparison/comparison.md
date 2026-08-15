# Common-Success Baseline Comparison

- Generated at: `2026-08-09T16:52:15.251392+00:00`
- Common-success count: `776` / 800
- Excluded samples: `24`
- Included systems: ProvLoom, AI-Infra-Guard, Cisco LLM Scanner, SkillScan
- Excluded system: Sentry current artifact is `INVALID_CONFIGURATION`; not used as formal Sentry Full baseline.

| System | N | TP | TN | FP | FN | Acc | Precision | Recall | F1 | FPR | BL-FPR | Trusted-FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ProvLoom | 776 | 291 | 339 | 39 | 107 | 0.811856 | 0.881818 | 0.731156 | 0.799451 | 0.103175 | 0.000000 | 0.325000 |
| AI-Infra-Guard | 776 | 101 | 373 | 5 | 297 | 0.610825 | 0.952830 | 0.253769 | 0.400794 | 0.013228 | 0.011173 | 0.025000 |
| Cisco LLM Scanner | 776 | 312 | 340 | 38 | 86 | 0.840206 | 0.891429 | 0.783920 | 0.834225 | 0.100529 | 0.089385 | 0.183333 |
| SkillScan | 776 | 144 | 360 | 18 | 254 | 0.649485 | 0.888889 | 0.361809 | 0.514286 | 0.047619 | 0.022346 | 0.075000 |

## Valid Set Audit
| System | Valid | Invalid |
|---|---:|---:|
| ProvLoom | 797 | 3 |
| AI-Infra-Guard | 799 | 1 |
| Cisco LLM Scanner | 795 | 5 |
| SkillScan | 785 | 15 |
