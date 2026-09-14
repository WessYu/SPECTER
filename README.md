# SPECTER

**Application security from source to production.**

SPECTER is a defensive application-security platform for JavaScript/TypeScript projects. It scans source code, generated build artifacts and published HTTP(S) applications, then compares scans so teams can see **what became less secure, where it changed, and when the regression appeared**.

The core design goal is security regression detection rather than maximizing raw finding counts.

## What is implemented

- local JS/TS source scanning with deterministic rule IDs and stable fingerprints;
- secret detection with centralized evidence redaction;
- dependency inventory for npm, pnpm and Yarn plus a provider interface and OSV provider;
- generated-build inspection without automatically executing untrusted build scripts;
- passive remote scanning for TLS, security headers, cookies, CSP and CORS;
- SSRF-hardened HTTP requests with DNS resolution checks, IP blocking, redirect revalidation, response limits and timeouts;
- optional defensive Playwright runtime observation;
- observed route and third-party-domain discovery without directory brute forcing;
- 0–100 risk scoring with documented weights and diminishing aggregation;
- JSON and SARIF 2.1.0 reports;
- scan comparison, baselines and CI security gates;
- GitHub Action source integration;
- PostgreSQL/Prisma persistence, GitHub OAuth sessions, hashed CI API keys and tenant-scoped API access;
- a Next.js security console for projects, scans, findings, history, regression diffs, attack surface and domain trust;
- deterministic vulnerable/safe fixtures and an offline smoke-validation workflow.

SPECTER does **not** prove that an application is secure and is not an exploitation framework. See [Security model](docs/security-model.md).

## Quick start

Requirements:

- Node.js 20.11 or later;
- pnpm 10.x.

```bash
pnpm install
pnpm build
pnpm test
pnpm smoke
```

After building, scan a local project:

```bash
pnpm specter scan examples/vulnerable-next --offline --no-build
```

Or scan a published application passively:

```bash
pnpm specter scan https://example.com
```

Machine-readable reports:

```bash
pnpm specter scan . --json
pnpm specter scan . --sarif
```

The CLI always writes a report under `.specter/` unless `--output` is provided.

## Security regression gate

```bash
pnpm specter scan . --baseline previous.json --ci --fail-on high --max-score-drop 5
```

Exit codes:

| Code | Meaning |
| ---: | --- |
| `0` | scan/gate succeeded |
| `1` | security gate failed |
| `2` | command/configuration error |
| `3` | scan/runtime failure |

## Configuration

Run:

```bash
pnpm specter init
pnpm specter config
```

Example `specter.config.ts`:

```ts
export default {
  failOn: "high",
  maxScoreDrop: 5,
  ignore: [],
  suppressions: [
    {
      ruleId: "SPECTER-SOURCE-006",
      reason: "Development-only callback documented in ADR-17",
      expiresAt: "2026-12-31T23:59:59.000Z",
    },
  ],
  scan: {
    source: true,
    build: true,
    dependencies: true,
    remote: true,
    runtime: false,
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

The config loader intentionally accepts only literal data. It does not execute arbitrary TypeScript/JavaScript from configuration files.

## Repository structure

```text
apps/
  api/                 Fastify + Prisma API
  dashboard/           Next.js security console
packages/
  cli/                 CLI orchestration
  config/              strict configuration parser
  core/                findings, fingerprints, redaction, regression, gates
  reporter/            JSON + SARIF
  risk-engine/         documented 0–100 score
  scanner-static/      source rules
  scanner-secrets/     credential detection
  scanner-dependencies dependency inventory/advisories
  scanner-build/       generated artifact inspection
  scanner-web/         remote/runtime/surface scanning
  types/               versioned public domain types
integrations/
  github-action/
examples/
  vulnerable-next/
  secure-next/
  vulnerable-react/
  secure-react/
docs/
```

## API and dashboard

The API uses PostgreSQL and versioned Prisma migrations. Authentication supports GitHub OAuth-backed browser sessions and organization-scoped API keys. API keys are stored as hashes; the full key is returned only at creation.

See [Getting started](docs/getting-started.md), [Architecture](docs/architecture.md), and [Configuration](docs/configuration.md) for local setup.

## Validation

The repository includes:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm smoke
```

`pnpm smoke` is intentionally network-independent. It verifies safe/vulnerable source fixtures, secret redaction, dependency-provider behavior, config parsing, SARIF output, SSRF blocking and the local CLI path.

## Documentation

- [Getting started](docs/getting-started.md)
- [CLI](docs/cli.md)
- [Configuration](docs/configuration.md)
- [Rules](docs/rules.md)
- [Risk scoring](docs/risk-scoring.md)
- [Security model](docs/security-model.md)
- [Privacy](docs/privacy.md)
- [Architecture](docs/architecture.md)
- [CI](docs/ci.md)
- [Remote scanning](docs/remote-scanning.md)
- [False positives](docs/false-positives.md)
- [Contributing](docs/contributing.md)

## Limitations

- dependency vulnerability lookup requires network access unless a caller supplies another provider;
- Playwright runtime scanning requires the optional Playwright package and Chromium browser;
- passive remote observations do not prove exploitability or absence of vulnerabilities;
- browser runtime DNS pinning is less strict than the low-level HTTP scanner because Chromium controls its own resolver; keep runtime scanning opt-in and use it only for authorized targets;
- the GitHub Action must be built into `integrations/github-action/dist/index.js` before tagging a distributable action release.

## License

MIT.
