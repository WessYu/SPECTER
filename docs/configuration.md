# Configuration

SPECTER loads `specter.config.ts` first, then `specter.config.json` when present.

The `.ts` form is deliberately a **data-only syntax**: object/array/string/number/boolean/null literals, comments and `export default` are accepted. Imports, function calls, property access, template interpolation and arbitrary expressions are rejected. This prevents configuration loading from becoming code execution during CI scans.

Top-level keys:

- `failOn`: CI severity threshold;
- `maxScoreDrop`: allowed score regression;
- `ignore`: rule IDs suppressed with a generated configuration reason;
- `suppressions`: auditable rule/fingerprint suppressions with reason and optional expiration;
- `scan`: source/build/dependencies/remote/runtime switches;
- `limits`: file, request, page, redirect, response and concurrency limits.

Unknown keys fail closed with a configuration error.

Prefer targeted `suppressions` over broad `ignore` entries because targeted suppressions preserve rationale and expiry.
