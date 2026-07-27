# Full Regression Report

Date: 2026-07-27

## Test Discovery

`find test -maxdepth 2 -type f | sort` found 17 Python test files plus `test/SKILL.md` and `__pycache__` entries.

The previously used pattern `test_static_v2*.py` matches zero files and is not counted as passing. The real Static v2 test file is `test/test_static_analysis_v2.py`.

`grep -R "StaticV2|static_v2|PathValidator|PolicyClassifier|Dataflow|held.out|chain.compatible" -n test` returned no matches, but `test/test_static_analysis_v2.py` contains the actual Static v2 suite.

## Results

- `python3 -m unittest discover -s test -p 'test_dynamic*.py'`: 49 tests, passed
- `python3 -m unittest discover -s test -p 'test_static_analysis_v2.py'`: 53 tests, passed
- `python3 -m unittest discover -s test -p 'test_trace_parser*.py'`: 1 test, passed
- `python3 -m unittest discover -s test -p 'test_adapter_layer.py'`: 5 tests, passed
- `python3 -m unittest discover -s test -p 'test_trigger_synthesis.py'`: 5 tests, passed
- `python3 -m unittest discover -s test -p 'test_*.py'`: 157 tests, passed
- `python3 -m compileall app test scripts`: passed

Skipped tests: 0 reported by unittest.

Failures/errors: 0.

External requirements:

- Unit test suite did not require Docker, network, model API, or root.
- Official-image carrier and alignment probes required Docker and a local mock HTTP/LLM service.

Lint tools:

- `ruff`: unavailable in PATH
- `mypy`: unavailable in PATH
- `pylint`: unavailable in PATH

## Coverage Notes

Covered by tests/probes:

- marker registration and source matching
- file propagation
- process/context downgrade
- network payload carriers
- LLM context carrier
- trusted Authorization flow
- untrusted JSON body exfiltration
- static-runtime alignment input path
- endpoint contradiction
- canonical assessment bridge
- privacy scan for probe artifacts

Remaining gaps:

- no eBPF/FUSE integration tests
- no TLS MITM/decrypted HTTPS payload tests
- no byte-level in-process DIFT tests
- artifact identity for download-then-exec remains weak
- alignment still emits many runtime-only noisy library/file nodes

