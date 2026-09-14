# Rules

SPECTER favors a smaller deterministic rule set over large volumes of shallow findings.

Current source rules cover dynamic code execution (`eval`, `new Function`), unsafe raw HTML, `document.write`, sensitive token storage in `localStorage`, non-local plaintext HTTP and suspicious private environment references in client-facing code.

Secret rules detect credential-like values such as Stripe/GitHub/AWS-style keys, private keys, database URLs, JWT-like values and high-entropy secret assignments. Evidence is redacted before report output.

Remote rules inspect security headers, CSP, cookies, CORS and TLS state. Missing controls are scored contextually rather than automatically labeled critical.

Build rules inspect generated text artifacts for exposed secrets, source maps, copied env files, private/internal URLs and debug information.

Dependency findings come from the selected advisory provider and preserve whether the affected package is direct or transitive.

Every finding includes a stable `ruleId`, severity, confidence, category, source, fingerprint and remediation. Fingerprints drive regression comparison.
