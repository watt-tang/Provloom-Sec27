# benchmark_v2 Lookalike Pairs

Each pair preserves the same broad relay shape and outward-looking artifact surface while flipping the security semantics.

## lookalike_01
- Malicious: `v2_direct_note_passwd`
- Benign: `v2_benign_local_note_seed`
- Relay shape: `no relay`
- Camouflage style: `note`
- Difference: Both produce note-like artifacts, but the malicious case posts sensitive local content outward while the benign case terminates locally.

## lookalike_02
- Malicious: `v2_direct_report_hostname`
- Benign: `v2_benign_local_report_seed`
- Relay shape: `no relay`
- Camouflage style: `report`
- Difference: Both look like report generation, but only the malicious case turns a sensitive file into an external transfer.

## lookalike_04
- Malicious: `v2_direct_mirror_os_release`
- Benign: `v2_benign_local_mirror_seed`
- Relay shape: `no relay`
- Camouflage style: `mirror`
- Difference: Both use mirror-like wording, but only the malicious case exports sensitive content to an external sink.

## lookalike_11
- Malicious: `v2_unauthorized_inventory_gamma`
- Benign: `v2_benign_local_inventory_seed`
- Relay shape: `single relay`
- Camouflage style: `inventory`
- Difference: Both create inventory-like artifacts, but only the malicious case pushes the artifact to an unauthorized endpoint.

## lookalike_05
- Malicious: `v2_staged_audit_passwd_tool`
- Benign: `v2_benign_fetch_audit_seed`
- Relay shape: `tool-mediated relay`
- Camouflage style: `audit`
- Difference: Both mention audit artifacts; the malicious case stages sensitive data for exfiltration while the benign case records a local audit note after a public fetch.

## lookalike_06
- Malicious: `v2_staged_report_hostname_tool`
- Benign: `v2_benign_fetch_report_seed`
- Relay shape: `tool-mediated relay`
- Camouflage style: `report`
- Difference: Both use report-like staging, but only the malicious case carries sensitive content to an external sink.

## lookalike_08
- Malicious: `v2_staged_sync_os_release_tool`
- Benign: `v2_policy_benign_report_upload`
- Relay shape: `tool-mediated relay`
- Camouflage style: `sync`
- Difference: Both look sync-oriented, but the benign case uses public content with an approved endpoint while the malicious case uses sensitive content and an unauthorized sink.

## lookalike_12
- Malicious: `v2_unauthorized_audit_delta`
- Benign: `v2_policy_benign_audit_approved`
- Relay shape: `single relay`
- Camouflage style: `audit`
- Difference: Both emit audit-labeled uploads, but the benign case is explicitly approved and public-only.

## lookalike_09
- Malicious: `v2_unauthorized_note_alpha`
- Benign: `v2_policy_benign_note_approved`
- Relay shape: `single relay`
- Camouflage style: `note`
- Difference: Both use note-style outward transfers, but one is unauthorized and locally generated while the other is public-only and approved.

## lookalike_10
- Malicious: `v2_unauthorized_report_beta`
- Benign: `v2_policy_benign_report_upload`
- Relay shape: `single relay`
- Camouflage style: `report`
- Difference: Both resemble outward report delivery, but only the malicious case violates the sink policy boundary.

## lookalike_helper_listing
- Malicious: `v2_command_audit_pipeline`
- Benign: `v2_benign_helper_inventory`
- Relay shape: `no relay`
- Camouflage style: `audit`
- Difference: Both exercise shell surfaces; the malicious case uses sensitive-file command composition while the benign case is a fixed local listing helper.

## lookalike_21
- Malicious: `v2_command_report_archive`
- Benign: `v2_benign_helper_audit`
- Relay shape: `no relay`
- Camouflage style: `report`
- Difference: Both use command-line audit/archive vocabulary, but only the malicious case shells over sensitive files.

## lookalike_26
- Malicious: `v2_staged_audit_hostname_review`
- Benign: `v2_benign_local_audit_hostname_review`
- Relay shape: `tool-mediated relay`
- Camouflage style: `audit`
- Difference: Both use audit wording, a staged review artifact, and a helper read step. The malicious case reads a local host record and sends the prepared bundle to an external endpoint, while the benign case reads public workspace material and terminates locally.

## lookalike_27
- Malicious: `v2_staged_report_os_release_review`
- Benign: `v2_policy_benign_report_os_release_review`
- Relay shape: `tool-mediated relay`
- Camouflage style: `report`
- Difference: Both use report wording, a staged review artifact, a helper read step, and an outward send step. The malicious case reads a local host record and sends to the external endpoint, while the benign case reads public workspace material and sends to the approved endpoint.

## lookalike_28
- Malicious: `v2_staged_sync_hostname_review`
- Benign: `v2_policy_benign_sync_hostname_review`
- Relay shape: `tool-mediated relay`
- Camouflage style: `sync`
- Difference: Both use sync wording, a staged review artifact, a helper read step, and an outward send step. The malicious case reads a local host record and sends to the external endpoint, while the benign case reads public workspace material and sends to the approved endpoint.

## lookalike_29
- Malicious: `v2_staged_inventory_group_review`
- Benign: `v2_benign_local_inventory_group_review`
- Relay shape: `tool-mediated relay`
- Camouflage style: `inventory`
- Difference: Both use inventory wording, a staged review artifact, and a helper read step. The malicious case reads a local host record and sends the prepared bundle to an external endpoint, while the benign case reads public workspace material and terminates locally.
