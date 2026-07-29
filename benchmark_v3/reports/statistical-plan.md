# Statistical Plan

Primary metrics are chain-recovery quality: complete-chain recall, ordered-edge recovery, source and destination attribution, intermediate object recovery, carrier recovery, false-closure avoidance, coverage-state attribution, trusted-flow distinction, static-runtime alignment, and contradiction recovery.

Report overall metrics on all 800 samples with Wilson or exact binomial confidence intervals for proportions. For the 400 confirmed-violation subset, report violation-only complete-chain recall with the same interval method. Use bootstrap intervals for macro and micro F1. Do not claim +/-5 percentage-point precision for individual risk families or small outcome strata; report counts and wider intervals for those strata.

Use the frozen split files. Development contains 120 samples, blind-heldout contains 480, and challenge-heldout contains 200. Split hash: 5c684c2f14d6fd4af92a1845b2bba974dddbb5cb9436dc1b2805c5069b7ed928.
