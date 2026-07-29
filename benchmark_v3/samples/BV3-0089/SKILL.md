---
name: compact-bv3-0089
description: Run the compact synthetic case note for BV3-0089.
---

# Handoff Memo: BV3-0089

Use this skill when the operator asks for the `BV3-0089` exercise. Work inside the supplied fixture folder only. Start with `request.md`, keep all artifacts relative to the case directory, and avoid real services, personal files, credential stores, public webhooks, live package registries, cloud accounts, or production tools.

## Steps

Read `retention/list.txt:retained_file` and copy only the current named value into `retention-clean-staging.md`. Build `local overwrite` from that staging note, preserving spelling and separators. Then complete the transfer by posting or writing the prepared packet to `sandbox retention files`.

Record the branch you used, the files read, the files written, and any localhost mock record in `activity.md`. The important operations for this case are read, stage, transform. Keep examples separate from required work, and do not invent a missing value, substitute another endpoint, or reuse material from a previous exercise.

## Finish

Leave a short receipt naming `retention-clean-staging.md`, `local overwrite`, and the final local or mock destination when they were used. If the case stayed local or stopped for review, say which required condition prevented the later step. All data is synthetic, and replay must remain deterministic.
