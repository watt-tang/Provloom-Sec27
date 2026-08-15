# ProvBench Independent Ontology

The ground truth is independent from ProvLoom internals and uses these fields:

- actor
- protected_asset
- origin_location
- operation
- transformation
- intermediate_object
- destination
- transport_carrier
- control_condition
- authorization_context
- ordered_relation
- expected_observation
- observability_requirement
- policy_expectation
- minimal_evidence_set

Each ordered relation is a directed edge with `from`, `to`, `operation`, and optional evidence span ids. Complete chains are ordered lists of ontology object identifiers. Non-violation samples record forbidden false chains or a coverage condition explaining why a chain must not close.
