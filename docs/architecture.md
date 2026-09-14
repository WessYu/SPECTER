# Architecture

SPECTER is a TypeScript monorepo built with pnpm workspaces and Turborepo.

## Security pipeline

```text
SOURCE
  ↓
STATIC SECURITY + SECRETS + DEPENDENCIES
  ↓
BUILD
  ↓
PREVIEW / LOCAL
  ↓
AUTHORIZED ACTIVE SECURITY
  ↓
PRODUCTION
  ↓
PASSIVE + AUTHORIZED ACTIVE VALIDATION
  ↓
MONITOR
  ↓
REGRESSION / SCORE / CI GATE
```

All scanners emit the same versioned finding model:

```text
scanner -> Finding -> Redaction -> Risk Engine -> ScanResult
                                      │
                                      ├─ JSON / SARIF / CLI
                                      ├─ Regression / CI gate
                                      └─ API / PostgreSQL / Dashboard
```

`packages/types` owns public domain shapes. `packages/core` owns finding construction, stable fingerprints, redaction, suppressions, regression and gates. `packages/risk-engine` owns deterministic scoring.

## Passive versus active

`packages/scanner-web` observes HTTP(S), TLS, headers, cookies, routes and optional browser runtime behavior.

`packages/scanner-active` is separate. It only runs after an authorization decision and performs bounded, non-destructive validation with inert canaries and reserved invalid hostnames. It reuses `scanner-web`'s DNS pinning and safe-request layer instead of implementing another network stack.

Remote active authorization is exact-hostname scoped. Redirects never transfer authorization.

## Active execution

An active scan has:

- an authorization state;
- a `safe` or `standard` profile;
- a hard request budget;
- per-second rate limiting;
- a concurrency ceiling;
- request deadlines;
- endpoint and parameter ceilings;
- an `AbortSignal`.

The current scanner performs requests sequentially, which is stricter than the configured concurrency ceiling. The ceiling remains part of the public configuration so controlled parallel scheduling can be introduced without changing the safety contract.

## API jobs

The Fastify API persists `ActiveTarget`, `ActiveScan` and `ActiveAuditLog` records. Starting an active scan returns a queued job immediately. An in-process queue caps concurrently executing active jobs and each running job owns an `AbortController`.

Job states are:

`queued -> running -> completed | failed | cancelled`.

Completed active results are also persisted through the normal `Scan` / `Finding` model, so history, fingerprints, scoring, regression and the dashboard do not use a second reporting system.

The in-process queue is intentionally not presented as a durable distributed worker. If the API process terminates while a job is running, external orchestration should reconcile stale jobs before treating them as completed.

## Tenant boundary

Every active target, job, finding query and cancellation resolves through `organization -> project` ownership. Test-account credentials are read only from process secrets/environment and are never persisted in active job records, findings or audit logs.

The Next.js dashboard is a server-rendered client of the authenticated API. It displays persisted scan state rather than fabricated metrics.
