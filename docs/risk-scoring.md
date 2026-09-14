# Security score

SPECTER reports a deterministic 0–100 security score as a prioritization aid, not proof of security.

For each unique finding:

```text
deduction =
  severityWeight
  × confidenceMultiplier
  × categoryMultiplier
  × noveltyMultiplier
  × phaseMultiplier
  × scannerMultiplier
  × validationMultiplier
```

Severity weights:

| Severity | Weight |
| --- | ---: |
| critical | 28 |
| high | 16 |
| medium | 8 |
| low | 3 |
| info | 0 |

Confidence multipliers:

| Confidence | Multiplier |
| --- | ---: |
| confirmed | 1.18 |
| high | 1.00 |
| medium | 0.72 |
| low | 0.40 |

A finding new relative to the supplied baseline receives the existing 1.12 novelty multiplier.

Active findings receive a 1.12 scanner multiplier. Preview phase uses 1.05 and production phase uses 1.12. A safely confirmed active condition uses 1.12 validation weight; a potential condition uses 0.88. `inconclusive`, `resolved` and `suppressed` findings deduct zero.

The existing category factor is still applied. A single finding is capped at 35 points. Deduction accumulation uses the existing diminishing factor so a long tail of low-confidence issues does not become equivalent to several high-confidence critical conditions.

The final score is rounded to one decimal place and clamped to the inclusive range 0–100. It can never become negative.

Model-generated text does not influence severity, confidence or score.
