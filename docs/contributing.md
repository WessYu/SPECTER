# Contributing

Before changing code:

```bash
git status
git branch --show-current
git log --oneline -10
```

Preserve existing work. Do not use destructive reset/clean commands against user changes.

A change is complete only when its code, integration, tests and documentation agree. Run:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm smoke
```

New security rules need unsafe and safe examples, stable rule IDs, severity/confidence rationale, remediation and false-positive guidance. Never add findings only to inflate rule count.

Remote behavior must remain defensive and non-destructive.
