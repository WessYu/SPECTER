# Active security

Active Security is SPECTER's authorized, bounded runtime validation layer.

It answers a different question from passive scanning: not only "what looks unsafe?", but "can this suspected condition be reproduced safely on the running application?"

It is still defensive validation, not automated exploitation.

## Authorization

Active testing is opt-in.

- `localhost`, `127.0.0.1` and loopback are accepted for local testing.
- Preview hostnames may be explicitly listed in `active.previewHosts`.
- Other remote hostnames require ownership verification.

```bash
specter authorize https://example.com
```

SPECTER generates:

```text
/.well-known/specter-verification.txt

specter-verification=<random-token>
```

After publishing it:

```bash
specter verify https://example.com
specter pentest https://example.com
```

Authorization is exact-hostname scoped and expires. Redirects never authorize a second hostname. Stored verification state keeps a cryptographic hash instead of the plaintext token.

## Profiles and budget

Default profile: `safe`.

`safe` minimizes requests. `standard` expands coverage while remaining non-destructive. There is no aggressive profile.

Default budget:

```ts
active: {
  enabled: false,
  profile: "safe",
  maxRequests: 150,
  maxRequestsPerSecond: 3,
  concurrency: 2,
  requestTimeoutMs: 5000,
  maxEndpoints: 40,
  maxParametersPerEndpoint: 10,
  allowStateChangingMethods: false,
  previewHosts: [],
}
```

The request counter is consumed before issuing each request. Budget exhaustion stops additional validation rather than exceeding the configured limit.

## What active validation does

SPECTER can safely validate:

- inert parameter reflection and output context;
- client-side source/sink correlation;
- open redirects without following the external destination;
- session cookie attributes;
- session rotation and logout invalidation with a supplied test account;
- observable CSRF defenses;
- anonymous versus authenticated guard consistency;
- OPTIONS/Allow method exposure;
- controlled CORS behavior;
- caching of authenticated test responses;
- MIME/content-type behavior;
- forwarded Host/Host reflection;
- security-header consistency across observed routes;
- TLS and HTTP→HTTPS consistency;
- diagnostic leakage in observed API responses.

API error checks use small structural inputs and observed endpoints. SPECTER does not send SQL commands, shell syntax or exploit payloads.

## Endpoint discovery

Only application-observed sources are used: links, forms, referenced JavaScript, published sitemap/OpenAPI material and routes already observed by SPECTER.

There is no directory brute force or administrative-path wordlist.

## Test accounts

Set both:

```text
SPECTER_TEST_USERNAME
SPECTER_TEST_PASSWORD
```

Only observed login/logout flows are used. Values are not persisted or printed.

## Confidence and status

Active findings use:

- `confirmed`: unsafe condition reproduced with safe evidence;
- `potential`: evidence suggests risk but is not enough for safe confirmation;
- `inconclusive`: SPECTER deliberately stopped rather than mutate data or overclaim.

Confirmation never means exploitation.

## Privacy and evidence

Central redaction applies before evidence is reported or persisted. SPECTER does not intentionally retain full Authorization headers, full cookies, passwords, API keys, secrets or session identifiers.

Safe reproduction uses SPECTER rule filters, for example:

```bash
specter pentest https://example.com --rule SPECTER-ACTIVE-CORS-001
```

It does not generate secret-bearing curl commands.

## API and dashboard

The API supports persistent active targets, verification, queued scans, scan status/history, active findings and cancellation. Jobs are tenant-scoped and audited.

The project dashboard separates Static, Passive and Active security. The Active Security page shows authorization state, request budget, endpoints, confirmed findings, score and regression delta.

## Limitations

- SPECTER intentionally prefers `inconclusive` over risky mutation.
- It does not exercise arbitrary POST/PUT/PATCH/DELETE operations.
- Authenticated checks depend on an observed compatible login/logout flow.
- The API queue is bounded but in-process, not a durable distributed worker.
- Safe automated validation cannot replace manual business-logic testing.
