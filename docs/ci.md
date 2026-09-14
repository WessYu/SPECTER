# CI and deploy gates

Use a previous JSON report as a baseline:

```bash
specter scan . --ci --baseline .specter/baseline.json --fail-on high --max-score-drop 5
```

The gate can fail on:

- a newly introduced finding at/above the threshold;
- a severity increase crossing the threshold;
- a score drop larger than policy permits.

Suppressed findings do not fail the gate.

The repository also contains a GitHub Action implementation under `integrations/github-action`. A release of that action must include its built `dist/index.js`; do not tag an action release from source-only state.

Recommended workflow permissions are read-only by default. Grant `security-events: write` only in workflows that intentionally upload SARIF to GitHub Code Scanning.
