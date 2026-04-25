# ACSAC benchmark_v2 Changelog

This changelog records the repository-side additions made to strengthen the ACSAC submission package.

## Benchmark credibility

- Added `benchmark_v2/` with a unified schema, compatibility notes, manifest, and family-based inventory.
- Expanded the benchmark structure around risk mechanisms instead of leaving the suite as a flat case list.
- Added explicit lookalike pair mappings for benign/malicious semantic discrimination.

## False-positive analysis rigor

- Added a dedicated hard-benign pack for note/report/inventory/helper/mirror workflows.
- Added a minimal decision-layer patch so local-only generated artifacts and GET-only fetch-to-note cases stop being scored as outward transfers.
- Added regression tests for local note, helper listing, and public fetch audit-note behavior.

## Benchmark-to-real-world bridge

- Added a `log7` completed-subset sampled audit generator and exported a prefilled annotation sheet.
- Added code-generated cluster tables and placeholder prediction-vs-manual tables with explicit pending status.

## Explanation-oriented evaluation strength

- Preserved source/relay/sink-oriented case structure in benchmark_v2.
- Added paper-ready text that explains why benchmark_v2 expansion is not case inflation and why sampled audit strengthens external credibility without overstating accuracy.
