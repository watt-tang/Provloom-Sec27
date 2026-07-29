# Benchmark v3 Revision Plan

This revision rebalances the existing 800-sample Benchmark v3 without running ProvLoom and without changing ProvLoom system rules.

Planned changes:

- Preserve total sample count 800, family totals, outcome totals, 160 counterfactual pair groups, 600 single-file, 200 multi-file, at least 240 LLM-mediated, and at least 200 network/external samples.
- Rewrite tested natural-language Skill bodies to the required length buckets: 160 short, 400 medium, 160 long, 80 ultra-long.
- Restore exact Risk family x Outcome target table by semantic sample rewrites, not manifest-only relabeling.
- Reassign splits to target outcome priors: development 60/30/18/12, blind 240/119/73/48, challenge 100/49/31/20.
- Update scenario cards, fixtures, ground truth, manifest, generation-state, revision log, replay report, audit report, distribution report, and statistical plan.
- Use an independent audit script that reads only tested Markdown, scenario cards, fixtures, independent ontology, and ground truth.

Prohibitions honored:

- Do not run ProvLoom.
- Do not read ProvLoom detector rules or outputs.
- Do not add similarity audit pipeline.
- Do not submit or push code.
