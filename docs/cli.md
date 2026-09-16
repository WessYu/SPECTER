# CLI

Binary: `specter` from `@specter-security/cli`.

## Commands

```text
specter scan [path|url]
specter pentest <path|url>
specter authorize <url>
specter verify <url>
specter compare <previous.json> <current.json>
specter doctor
specter init
specter config
specter version
specter help
```

### Standard scan options

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
--active
--active-profile <safe|standard>
--rule <SPECTER-ACTIVE-...>
```

`specter scan <url> --active` runs the existing passive scan and then an authorized active assessment. Both sets of findings are merged before scoring and CI-gate evaluation.

## Active security

```bash
specter pentest http://localhost:3000
specter pentest https://preview.example.com --active-profile safe
specter scan https://example.com --active
```

Localhost and loopback are authorized automatically for active testing. Explicit preview hostnames come from `active.previewHosts`. Other remote hostnames require verification:

```bash
specter authorize https://example.com
# publish /.well-known/specter-verification.txt
specter verify https://example.com
specter pentest https://example.com
```

Authorization is exact-hostname scoped. A redirect to another hostname is not authorized.

`specter pentest <path>` requires a local `specter.active.json` manifest. SPECTER starts that preview without a shell, injects a loopback `PORT`, waits for the configured health path, runs the active scan and terminates the child process.

Example:

```json
{
  "command": "node",
  "args": ["server.mjs"],
  "healthPath": "/"
}
```

Pressing Ctrl+C aborts the active request pipeline and stops the local preview cleanly.

## Test accounts

Session rotation, logout invalidation and authenticated/private-cache checks run only when an explicit test account is available:

```text
SPECTER_TEST_USERNAME
SPECTER_TEST_PASSWORD
```

The values are never printed in reports and are not persisted.

## Exit codes

| Code | Meaning                            |
| ---: | ---------------------------------- |
|    0 | scan succeeded                     |
|    1 | CI security gate failed            |
|    2 | usage or configuration error       |
|    3 | scan/runtime/authorization failure |
|  130 | active assessment cancelled        |

A standalone `pentest` displays PASS/BLOCKED from the configured gate policy. It returns code 1 for policy failure when `--ci` is supplied, matching the existing scan behavior.
