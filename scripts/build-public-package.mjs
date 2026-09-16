import { mkdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageRoot = path.join(repositoryRoot, "packages", "public");
const outdir = path.join(packageRoot, "dist");

await rm(outdir, { recursive: true, force: true });
await mkdir(outdir, { recursive: true });

await build({
  entryPoints: {
    index: path.join(packageRoot, "src", "index.ts"),
    bin: path.join(packageRoot, "src", "bin.ts"),
  },
  outdir,
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node20",
  sourcemap: false,
  minify: false,
  legalComments: "none",
  external: ["playwright"],
});
