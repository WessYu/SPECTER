# @wess2001/specter

Public CLI and programmatic facade for **SPECTER**, the defensive application-security engine.

## Install

```bash
npm install -D @wess2001/specter
```

## CLI

```bash
npx specter scan .
npx specter scan https://example.com
npx specter pentest http://localhost:3000
```

Active testing remains authorization-gated and is intended only for systems you own or are explicitly authorized to test.

## Programmatic API

```js
import {
  executeLocalScan,
  executeRemoteScan,
  executeActiveScan,
} from "@wess2001/specter";

const local = await executeLocalScan(".", { offline: true });
console.log(local.score.value);
```

The published package bundles SPECTER's internal workspace graph so consumers do not need to install private `@specter/*` packages.

Runtime browser observation uses Playwright when available. Install Playwright separately only if you enable that optional capability.

## Source

The implementation and security model live in the SPECTER repository:
https://github.com/WessYu/SPECTER

MIT.
