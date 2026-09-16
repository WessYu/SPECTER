# CI and deploy gates

Use a previous JSON report as a baseline:

```bash
specter scan . --ci --baseline .specter/baseline.json --fail-on high --max-score-drop 5
```

The gate can fail on:

- a newly introduced finding at or above the threshold;
- a severity increase crossing the threshold;
- a score drop larger than policy permits.

Suppressed and `inconclusive` findings do not fail the gate by default.

## Active gate

Run active validation against a local or verified preview before deploy:

```bash
specter pentest http://127.0.0.1:3000 \
  --ci \
  --baseline .specter/previous-active.json \
  --fail-on high \
  --max-score-drop 5
```

For a remote production hostname, establish authorization before the CI job:

```bash
specter authorize https://app.example.com
specter verify https://app.example.com
specter pentest https://app.example.com --ci
```

The local CLI authorization store is intentionally not a credential vault. CI runners should provision the verification state in the workspace deliberately or use a verified API-side target.

Authenticated test checks use `SPECTER_TEST_USERNAME` and `SPECTER_TEST_PASSWORD` from the runner's secret store. Never commit these values.

The repository validates:

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm test:active
pnpm build
pnpm smoke
pnpm smoke:active
```

CI covers Node 20.11.1 and 22 on Linux, Node 24 on Windows, the bundled GitHub Action and PostgreSQL integration migrations/tests.

Recommended workflow permissions remain read-only by default. Grant `security-events: write` only to jobs that intentionally upload SARIF.
