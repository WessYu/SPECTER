import { execFileSync } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";

const root = process.cwd();
const outdir = resolve(root, "distribution/specter/dist");
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

function runEsbuild(entry, outfile, { banner = false } = {}) {
  const args = [
    "--filter",
    "@specter-security/github-action",
    "exec",
    "esbuild",
    entry,
    "--bundle",
    "--platform=node",
    "--format=esm",
    "--target=node20",
    "--packages=bundle",
    "--external:playwright",
    `--tsconfig=${resolve(root, "tsconfig.base.json")}`,
    `--outfile=${outfile}`,
  ];
  if (banner) args.push("--banner:js=#!/usr/bin/env node");
  execFileSync(pnpm, args, { cwd: root, stdio: "inherit" });
}

runEsbuild(resolve(root, "packages/cli/src/index.ts"), resolve(outdir, "index.js"));
runEsbuild(resolve(root, "packages/cli/src/bin.ts"), resolve(outdir, "bin.js"), {
  banner: true,
});
