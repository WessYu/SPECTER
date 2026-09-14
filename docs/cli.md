# CLI

Binary: `specter` from `@specter-security/cli`.

## Commands

```text
specter scan [path|url]
specter compare <previous.json> <current.json>
specter doctor
specter init
specter config
specter version
```

### Scan options

```text
--json
--sarif
--ci
--fail-on <critical|high|medium|low|none>
--max-score-drop <0..100>
--baseline <report.json>
--output <path>
--runtime
--no-runtime
--offline
--no-build
--no-dependencies
```

Local scans run source and secret scanners first. Dependency advisory lookup is recoverable: a provider outage is recorded as a partial error rather than fabricated as a clean dependency result. Build scanning inspects existing generated output and does not automatically run unknown project scripts.

Remote scans use low-impact GET-based observation. Runtime scanning is optional because it starts Chromium.

Exit codes are stable: `0` success, `1` gate failure, `2` configuration/usage error, `3` scan failure.
