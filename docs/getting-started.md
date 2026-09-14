# Getting started

## Local engine and CLI

Install Node.js 20.11+ and pnpm 10.x, then:

```bash
pnpm install
pnpm build
pnpm test
pnpm smoke
```

Run a deterministic local demonstration:

```bash
pnpm specter scan examples/vulnerable-next --offline --no-build
pnpm specter scan examples/secure-next --offline --no-build
```

`--offline` skips external advisory lookup, making local source/secret validation reproducible without network access.

## API

Create a PostgreSQL database and configure `apps/api/.env` from `apps/api/.env.example`.

```bash
pnpm --filter @specter/api prisma:generate
pnpm --filter @specter/api prisma:deploy
pnpm --filter @specter/api dev
```

Use versioned migrations in production. `prisma db push` is not the production migration mechanism for this project.

## Dashboard

Configure `apps/dashboard/.env.local` from `apps/dashboard/.env.example`, then:

```bash
pnpm --filter @specter/dashboard dev
```

The dashboard reads the authenticated API; it does not use fake project, scan or finding data.
