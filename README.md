<div align="center">

# SPECTER

### Application security from source to production.

**Detect security regressions before they ship.**

Defensive AppSec for JavaScript and TypeScript projects: source, secrets, dependencies,
builds, deployed applications, baselines and CI gates.

[![CI](https://github.com/WessYu/SPECTER/actions/workflows/ci.yml/badge.svg)](https://github.com/WessYu/SPECTER/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-111827.svg)](LICENSE)

</div>

```text
             .-─────────-.
          .-'             '-.
        .'       ╭───╮       '.
       /        ╱     ╲        \
      /        │  ◢ ◣  │        \
     │         │   ▾   │         │
     │         ╲  ───  ╱         │
      \         '───'         /
       '.       ╱│   │╲       .'
         '-._  ╱ │   │ ╲  _.-'
             '╲  │   │  ╱'
               ╲│   │╱
                ╲   ╱
                 ╲ ╱
                  ╵

┏━┓┏━┓┏━╸┏━╸╺┳╸┏━╸┏━┓
┗━┓┣━┛┣╸ ┃   ┃ ┣╸ ┣┳┛
┗━┛╹  ┗━╸┗━╸ ╹ ┗━╸╹┗╸
```

## Security changes. Not noise.

Most scanners answer one question: **what looks wrong right now?**

SPECTER is built around another one:

> **What became less secure since the last known-good state?**

It produces stable findings, compares scans, tracks score changes and can stop a CI run when a
new regression crosses policy.

```text
SOURCE  ──▶  BUILD  ──▶  PREVIEW  ──▶  PRODUCTION  ──▶  MONITOR
  │           │            │               │               │
  └─ code     └─ output     └─ runtime      └─ HTTP/TLS      └─ baseline
     secrets     artifacts     behavior        headers          diff
     deps                                      cookies          gate
                                               CSP/CORS
```

## The demo

The repository ships with deliberately vulnerable and safe fixtures so the difference is visible
without inventing sample output.

### Vulnerable fixture

```bash
pnpm specter scan examples/vulnerable-next --ci --fail-on high
```

Observed result with the current fixture:

```text
Security Score
0/100

HIGH         3

Security gate failed:
- SPECTER-SOURCE-001  Dynamic code execution with eval
- SPECTER-SOURCE-007  Private variable exposed to client-facing code
- SPECTER-SECRET-001  Potential exposed secret

❌ CI BLOCKED
```

### Safe fixture

```bash
pnpm specter scan examples/secure-next --ci --fail-on medium
```

```text
Security Score
100/100

CRITICAL     0
HIGH         0
MEDIUM       0
LOW          0
INFO         0

0 findings require review.

✅ CI PASSED
```

Dependency advisory counts come from the configured provider and can change as upstream databases
are updated. The repository smoke suite uses deterministic fixtures for repeatable validation.

## Quick start

Requirements:

- Node.js 20.11 or newer;
- pnpm 10.x.

```bash
git clone https://github.com/WessYu/SPECTER.git
cd SPECTER

pnpm install
pnpm build
pnpm smoke
```

Then inspect the CLI:

```bash
pnpm specter help
```

Scan a local project:

```bash
pnpm specter scan .
```

Run a deterministic offline scan:

```bash
pnpm specter scan examples/vulnerable-next --offline --no-build
```

Passively inspect a published application:

```bash
pnpm specter scan https://example.com
```

Machine-readable output:

```bash
pnpm specter scan . --json
pnpm specter scan . --sarif
```

SPECTER writes its report under `.specter/` unless `--output` is provided.

## What SPECTER covers

| Surface            | What it does                                                                                          |
| ------------------ | ----------------------------------------------------------------------------------------------------- |
| **Source**         | Detects risky JS/TS patterns with stable rule IDs and fingerprints                                    |
| **Secrets**        | Finds credential-like material and redacts evidence before reporting                                  |
| **Dependencies**   | Inventories npm, pnpm and Yarn dependencies with pluggable advisory providers                         |
| **Build output**   | Inspects generated artifacts without automatically executing untrusted build scripts                  |
| **Remote**         | Passively checks TLS, security headers, cookies, CSP and CORS                                         |
| **Attack surface** | Records observed routes and third-party domains without directory brute forcing                       |
| **Runtime**        | Supports opt-in defensive Playwright observation                                                      |
| **Regression**     | Compares scans, baselines, severities and score drops                                                 |
| **Reporting**      | Emits versioned JSON and SARIF 2.1.0                                                                  |
| **Platform**       | Persists projects, scans and findings through PostgreSQL/Prisma and exposes them in a Next.js console |

## CI is a security gate

A scan can be used as policy, not just as a report.

```bash
pnpm specter scan . \
  --baseline previous.json \
  --ci \
  --fail-on high \
  --max-score-drop 5
```

SPECTER can fail the gate when:

- a new finding reaches or exceeds the configured severity;
- an existing finding increases in severity across the threshold;
- the security score drops beyond policy.

| Exit code | Meaning                        |
| --------: | ------------------------------ |
|       `0` | scan and gate succeeded        |
|       `1` | security gate failed           |
|       `2` | command or configuration error |
|       `3` | scan or runtime failure        |

The repository also contains a bundled GitHub Action under
`integrations/github-action/dist/index.js`.

## One finding model

SPECTER keeps the same finding model across local scans, CI, JSON, SARIF, API persistence and the
dashboard.

A finding carries enough context to answer:

```text
What happened?
Where did it happen?
How severe is it?
How confident are we?
What changed?
Is it new?
Was it suppressed?
How do we fix it?
```

That shared model is what makes regression comparison useful instead of reducing security to a
collection of unrelated scanner outputs.

## CLI

```text
specter scan [path|url]        scan source, build or a published app
specter compare <old> <new>    compare two SPECTER reports
specter doctor                 check the local environment
specter init                   create specter.config.ts
specter config                 print the resolved configuration
specter version                print the CLI version
specter help                   show the command screen
```

Common flags:

```text
--json
--sarif
--ci
--baseline <report>
--output <path>
```

## Configuration

Create and inspect configuration with:

```bash
pnpm specter init
pnpm specter config
```

Example:

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

The config loader accepts literal data only. It does not execute arbitrary JavaScript or TypeScript
from configuration files.

## Dashboard and API

SPECTER is more than the CLI.

The API uses Fastify, PostgreSQL and versioned Prisma migrations. Browser authentication is backed
by GitHub OAuth sessions, CI access uses organization-scoped API keys, and stored API keys are
hashed.

The Next.js console exposes:

- projects and scans;
- findings and finding history;
- regression diffs;
- attack surface;
- observed domains and trust state;
- project-level security history.

The dashboard reads the authenticated API. It does not rely on fake project or finding data.

## Repository map

```text
apps/
  api/                    Fastify + Prisma API
  dashboard/              Next.js security console

packages/
  cli/                    CLI orchestration
  config/                 strict configuration parser
  core/                   findings, fingerprints, redaction, regression, gates
  reporter/               JSON + SARIF
  risk-engine/            0–100 security score
  scanner-static/         source rules
  scanner-secrets/        credential detection
  scanner-dependencies/   inventory + advisory providers
  scanner-build/          generated artifact inspection
  scanner-web/            remote, runtime and surface scanning
  types/                  versioned public domain types

integrations/
  github-action/

examples/
  vulnerable-next/
  secure-next/
  vulnerable-react/
  secure-react/

docs/
```

## Defensive by design

SPECTER is built for defensive application-security work on systems you own or are authorized to
test.

It does not implement exploitation, brute forcing, credential attacks, authentication bypass,
WAF evasion, persistence, lateral movement, exfiltration or automated RCE/CVE exploitation.

Remote scanning is intentionally low impact. HTTP requests are protected by DNS resolution checks,
private/reserved IP blocking, redirect revalidation, response limits and timeouts.

SPECTER does **not** prove that an application is secure. It reports evidence and regressions within
the scanners that were actually run.

Read the full [security model](docs/security-model.md) before using remote or runtime scanning.

## Validation

The repository is continuously checked with:

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm smoke
```

The smoke suite is network-independent and validates safe/vulnerable source fixtures, evidence
redaction, dependency-provider behavior, config parsing, SARIF generation, SSRF blocking and the
local CLI path.

CI also covers Node.js 20.11.1, Node.js 22, Windows with Node.js 24, the bundled GitHub Action and a
real PostgreSQL API integration job.

## Documentation

- [Getting started](docs/getting-started.md)
- [CLI reference](docs/cli.md)
- [Configuration](docs/configuration.md)
- [Rules](docs/rules.md)
- [Risk scoring](docs/risk-scoring.md)
- [Security model](docs/security-model.md)
- [Privacy](docs/privacy.md)
- [Architecture](docs/architecture.md)
- [CI and deploy gates](docs/ci.md)
- [Remote scanning](docs/remote-scanning.md)
- [False positives](docs/false-positives.md)
- [Contributing](docs/contributing.md)

## Known boundaries

- online dependency advisories require network access unless another provider is supplied;
- Playwright runtime scanning requires the optional Playwright package and a Chromium browser;
- passive remote observations do not prove exploitability or the absence of vulnerabilities;
- browser runtime DNS pinning is less strict than the low-level HTTP scanner because Chromium
  controls its own resolver;
- the bundled GitHub Action must be kept in sync with its source before distributable tags are cut.

## License

MIT.
