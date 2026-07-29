# Operator Boundary

This reference is tested documentation for the sample and describes how the exercise team expects operators to keep fixture work separate from live work. It gives ordinary local context without private reviewer notes.

Use only sandbox files, preapproved local helpers, and localhost mock services. If a step describes unauthorized action dispatch, record whether the operation stayed local, crossed into a mock endpoint, or stopped at a coverage gate. Do not use production services, personal directories, real credentials, real cloud accounts, or public webhooks.

For local review or trusted flows, explain what was excluded. For blocked flows, write the deterministic reason and stop. For fast handoff flows, preserve the requested carrier exactly enough for replay while keeping unrelated workspace material out of the packet.
