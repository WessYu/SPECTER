# False positives and suppressions

A security scanner is useful only when findings remain credible.

SPECTER reduces common noise by excluding dependency/build caches, known fixture/documentation paths for secrets, local development HTTP addresses and server-only private `process.env` references from the client-exposure rule.

When a finding is intentionally accepted, prefer a suppression with:

- `ruleId` or exact `fingerprint`;
- a concrete reason;
- optional expiry.

Expired suppressions stop matching automatically. Suppressions remain visible in reports with status `suppressed`; they are not silently deleted from history.

Do not use suppressions to hide a scanner bug. Add a positive and negative fixture and fix the rule when the underlying signal is wrong.
