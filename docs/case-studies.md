# Case Studies

## Case 1: Direct Sensitive Exfiltration

- Case ID: `malicious_sensitive_exfil_direct`
- GT: `/etc/hosts` -> `https://httpbin.org/post`
- `rule_only`: should detect file/network behaviors but may not recover a chain
- `rule_plus_epg`: should recover a direct source-to-sink primary chain
- Difference: EPG adds explicit chain evidence instead of isolated behavior labels

## Case 2: Unauthorized External Transfer

- Case ID: `malicious_unauthorized_network_transfer`
- GT: `runtime_output/export.txt` -> `https://httpbin.org/post`
- `rule_only`: likely reports `network_access`
- `rule_plus_epg`: should connect the locally generated file to the external sink
- Difference: EPG makes the local-data source visible

## Case 3: Indirect Buffer Exfiltration

- Case ID: `malicious_indirect_exfil_buffer`
- GT: `/etc/hosts` -> `runtime_output/buffer.txt` -> `https://httpbin.org/post`
- `rule_only`: reports suspicious behaviors
- `rule_plus_epg`: may recover only a partial chain depending on buffer visibility
- Difference: this case stresses multi-step reconstruction

## Case 4: Unsafe Command Construction

- Case ID: `malicious_command_exec_misuse`
- GT: no source-to-sink chain, but root cause is `unsafe_command_construction`
- `rule_only`: should surface process behavior
- `rule_plus_epg`: preserves the same detection but keeps root-cause output aligned
- Difference: root-cause attribution matters more than chain recovery here

## Failure Case: LLM-Induced Unsafe Tool Invocation

- Case ID: `malicious_llm_unsafe_tool`
- GT: LLM-induced sensitive exfiltration design
- Limitation: dynamic baselines skip this case because it requires external LLM credentials
- Why this matters: it documents a current reproducibility boundary instead of silently dropping the case

## Benchmark Context

- The expanded suite contains 15 exfiltration-oriented malicious cases across direct sensitive exfiltration, indirect or staged relay chains, and unauthorized external transfer.
- Dynamic baselines skip 7 total cases because `dynamic_runnable=false`: 4 malicious LLM-induced unsafe-action variants, 1 prompt-injection-flavored malicious case, and 2 benign LLM-routed safe cases.
