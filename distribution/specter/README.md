# @wess2001/specter

Public distribution package for [SPECTER](https://github.com/WessYu/SPECTER).

```bash
npm install -D @wess2001/specter
npx specter scan .
```

Programmatic API:

```js
import { executeLocalScan, executeRemoteScan } from "@wess2001/specter";

const report = await executeLocalScan(".", { offline: true });
console.log(report.score.value);
```

The package bundles SPECTER's internal workspace graph into one distributable package. Playwright remains optional and is only needed for runtime browser observation.
