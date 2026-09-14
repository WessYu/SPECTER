# Architecture

SPECTER is a TypeScript monorepo with pnpm workspaces and Turborepo.

Data flow:

```text
SOURCE ─┐
BUILD  ─┼─> Findings -> Redaction -> Risk Engine -> ScanResult
REMOTE ─┤                                    │
RUNTIME ┘                                    ├-> JSON / SARIF / CLI
                                             ├-> Regression / CI gate
                                             └-> API / PostgreSQL / Dashboard
```

`packages/types` owns versioned public domain shapes. `packages/core` owns fingerprints, finding construction, redaction, suppressions, regression and gates. Scanners depend inward on those packages instead of on the dashboard/API.

The API enforces `organization -> project` ownership on project-scoped reads and mutations. Persistence re-applies database suppressions when scans are ingested and marks findings resolved only within the relevant scan-source class.

The dashboard is a server-rendered Next.js console backed by the authenticated API. Regression calculations remain in core/backend code rather than being recreated in the UI.
