# Final Distribution Report

- Total samples: 800
- Length buckets: 150-300=160, 301-700=400, 701-1200=160, >1200=80
- Outcomes: confirmed=400, benign=198, trusted=122, review=80
- Splits: development=120, blind-heldout=480, challenge-heldout=200
- Flags: counterfactual_pairs=160, single_file=600, multi_file=200, llm_mediated=327, network_or_external=600
- Word summary: min=203, median=378.0, mean=504.06, max=1234
- Split hash: 5c684c2f14d6fd4af92a1845b2bba974dddbb5cb9436dc1b2805c5069b7ed928

## Risk Family x Outcome
- Credential access and exfiltration: V=35, B=18, T=10, R=7, total=70
- Destructive modification / ransomware: V=25, B=12, T=8, R=5, total=50
- Instruction override and hidden behavior: V=25, B=12, T=8, R=5, total=50
- LLM-mediated disclosure: V=30, B=15, T=9, R=6, total=60
- Multi-stage compositional behavior: V=75, B=38, T=22, R=15, total=150
- Permission or privilege expansion: V=25, B=12, T=8, R=5, total=50
- Persistence: V=25, B=12, T=8, R=5, total=50
- Private data collection and upload: V=30, B=15, T=9, R=6, total=60
- Resource abuse: V=20, B=10, T=6, R=4, total=40
- Reverse shell / remote control: V=25, B=12, T=8, R=5, total=50
- Supply-chain or dependency abuse: V=25, B=12, T=8, R=5, total=50
- Unauthorized external actions: V=25, B=12, T=8, R=5, total=50
- Untrusted download and execute: V=35, B=18, T=10, R=7, total=70

## Split x Outcome
- blind-heldout: V=240, B=119, T=73, R=48, total=480
- challenge-heldout: V=100, B=49, T=31, R=20, total=200
- development: V=60, B=30, T=18, R=12, total=120
