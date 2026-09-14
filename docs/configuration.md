# Configuration

SPECTER loads `specter.config.ts` first and then `specter.config.json`.

The TypeScript form is data-only. Imports, function calls, property access, template interpolation and arbitrary expressions are rejected. Unknown keys fail closed.

```ts
export default {
  failOn: "high",
  maxScoreDrop: 5,
  ignore: [],
  suppressions: [],
  scan: {
    source: true,
    build: true,
    dependencies: true,
    remote: true,
    runtime: false,
  },
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
  },
  limits: {
    maxFileBytes: 1000000,
    requestTimeoutMs: 10000,
    scanTimeoutMs: 60000,
    maxRedirects: 5,
    maxPages: 20,
    maxResponseBytes: 5000000,
    concurrency: 4,
  },
};
```

## Active configuration

`active.enabled` defaults to false. The explicit commands `pentest` and `scan --active` are themselves opt-in and therefore enable the active engine for that invocation.

`profile` accepts only `safe` or `standard`. There is intentionally no aggressive profile.

`maxRequests` is a hard ceiling. A request consumes budget before it is issued, so a scan cannot exceed the configured value.

`maxRequestsPerSecond` limits issuance rate. `concurrency` is a ceiling; the current engine is sequential and therefore remains below it.

`requestTimeoutMs`, `maxEndpoints` and `maxParametersPerEndpoint` bound scan work.

`allowStateChangingMethods` defaults to false. SPECTER does not invoke arbitrary state-changing application operations. Login/logout requests are only used with an explicit test account and are limited to the observed authentication flow.

`previewHosts` is an explicit authorization mechanism for preview environments. Every hostname must be listed separately. Do not use wildcard-like values.

Invalid active configuration returns CLI exit code 2.
