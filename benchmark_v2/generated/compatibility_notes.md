# benchmark_v2 Compatibility Notes

- `scripts/run_benchmark.py --datasets-root benchmark_v2/datasets` can consume the generated dataset without evaluator changes.
- Compatibility is preserved by keeping the existing v1 ground-truth fields: `is_malicious`, `expected_behaviors`, `expected_source_nodes`, `expected_sink_nodes`, `expected_primary_chain`, `expected_root_cause`, and `dynamic_runnable`.
- benchmark_v2-specific fields are additive and ignored by the current evaluator if it does not consume them.
- `evaluation_status` refines `dynamic_runnable` into `dynamic_runnable`, `static_evaluable`, and `partially_stubbed` for paper-ready reporting and manual audit workflows.