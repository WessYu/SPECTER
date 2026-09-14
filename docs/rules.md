# Rules

SPECTER favors deterministic evidence over a large volume of shallow alerts.

Every finding includes a stable `ruleId`, severity, confidence, category, source, fingerprint and remediation. Active findings additionally identify scanner, phase, route/method/parameter when applicable, safe evidence and safe reproduction.

## Active rule namespace

Active rules never reuse passive/static IDs.

| Rule | Meaning |
| --- | --- |
| `SPECTER-ACTIVE-REFLECTION-001` | inert input marker reflected by a live response |
| `SPECTER-ACTIVE-DOM-001` | controllable input correlated with client-side DOM sources/sinks |
| `SPECTER-ACTIVE-REDIRECT-001` | external reserved redirect destination accepted |
| `SPECTER-ACTIVE-COOKIE-001` | sensitive cookie missing defensive scope/attributes |
| `SPECTER-ACTIVE-SESSION-001` | test session identifier not rotated after login |
| `SPECTER-ACTIVE-SESSION-002` | previous test session remains valid after logout |
| `SPECTER-ACTIVE-CSRF-001` | CSRF defense could not be safely confirmed |
| `SPECTER-ACTIVE-AUTH-001` | private-like route behaves equivalently when anonymous |
| `SPECTER-ACTIVE-METHOD-001` | unexpected state-changing methods advertised |
| `SPECTER-ACTIVE-CORS-001` | untrusted Origin accepted with credentials |
| `SPECTER-ACTIVE-CORS-002` | arbitrary Origin reflection |
| `SPECTER-ACTIVE-CACHE-001` | authenticated response may be cacheable |
| `SPECTER-ACTIVE-MIME-001` | live MIME type conflicts with JSON-shaped content |
| `SPECTER-ACTIVE-LEAK-001` | stack/database/path/framework diagnostics exposed |
| `SPECTER-ACTIVE-HOST-001` | forwarded-host input influences output |
| `SPECTER-ACTIVE-HOST-002` | Host input influences output |
| `SPECTER-ACTIVE-HEADERS-001` | security-header behavior differs across routes |
| `SPECTER-ACTIVE-TLS-001` | certificate trust/validity failure |
| `SPECTER-ACTIVE-HTTPS-001` | HTTP does not consistently redirect to HTTPS |

`confirmed` means a safe condition was reproduced. `potential` means evidence is strong but not exploit confirmation. `inconclusive` is used when proving more would require unsafe mutation or assumptions; it does not block CI by default.

Existing source, secret, build, dependency and passive remote rules remain unchanged and keep their existing IDs and fingerprints.
