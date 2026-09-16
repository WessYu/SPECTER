import { mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { build } from "esbuild";

const root = process.cwd();
const outdir = resolve(root, "packages/public/dist");
await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

const common = {
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  sourcemap: false,
  minify: false,
  packages: "bundle",
  tsconfig: resolve(root, "tsconfig.base.json"),
  external: ["playwright"],
  logLevel: "info",
};

await build({
  ...common,
  entryPoints: [resolve(root, "packages/cli/src/index.ts")],
  outfile: resolve(outdir, "index.js"),
});

await build({
  ...common,
  entryPoints: [resolve(root, "packages/cli/src/bin.ts")],
  outfile: resolve(outdir, "bin.js"),
  banner: { js: "#!/usr/bin/env node" },
});
