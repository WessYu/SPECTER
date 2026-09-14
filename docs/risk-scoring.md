# Security score

SPECTER reports a 0–100 security score as a prioritization aid, not as proof that an application is secure.

Each unique, non-suppressed finding starts with a severity weight: critical 28, high 16, medium 8, low 3 and info 0. The weight is multiplied by confidence (high 1.0, medium 0.72, low 0.4) and by a documented category factor. A finding that is new relative to a supplied baseline receives a 1.12 multiplier. A single finding can deduct at most 35 points.

Findings are fingerprint-deduplicated. The total uses a diminishing factor as findings accumulate so a long tail of low-confidence warnings does not create false equivalence with multiple critical vulnerabilities. The result is rounded to one decimal place and clamped to 0–100.

The score is intentionally deterministic. Model-generated text does not influence severity or score.
