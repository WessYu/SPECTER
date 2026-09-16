import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const pnpm = process.platform === "win32" ? "pnpm.cmd" : "pnpm";
const packageDir = join(root, "distribution", "specter");
const temp = await mkdtemp(join(tmpdir(), "specter-public-"));

try {
  execFileSync(pnpm, ["public:build"], { cwd: root, stdio: "inherit" });

  const packed = JSON.parse(
    execFileSync(npm, ["pack", "--json"], {
      cwd: packageDir,
      encoding: "utf8",
    }),
  );
  assert.equal(packed.length, 1);
  const tarball = join(packageDir, packed[0].filename);

  await writeFile(
    join(temp, "package.json"),
    JSON.stringify({ name: "specter-public-smoke", private: true, type: "module" }),
  );
  execFileSync(npm, ["install", "--ignore-scripts", tarball], {
    cwd: temp,
    stdio: "inherit",
  });

  const apiPath = join(temp, "node_modules", "@wess2001", "specter", "dist", "index.js");
  const binPath = join(temp, "node_modules", "@wess2001", "specter", "dist", "bin.js");
  const api = await import(pathToFileURL(apiPath).href);
  assert.equal(typeof api.executeLocalScan, "function");
  assert.equal(typeof api.executeRemoteScan, "function");

  const report = await api.executeLocalScan(join(root, "examples", "secure-next"), {
    offline: true,
    build: false,
    dependencies: false,
  });
  assert.equal(report.schemaVersion, "1");
  assert.equal(report.status, "completed");
  assert.ok(Number.isFinite(report.score.value));
  assert.ok(Array.isArray(report.findings));

  const help = execFileSync(process.execPath, [binPath, "help"], {
    cwd: temp,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
  assert.match(help, /SPECTER/);
  assert.match(help, /specter scan/);

  const manifest = JSON.parse(await readFile(join(packageDir, "package.json"), "utf8"));
  assert.equal(manifest.name, "@wess2001/specter");
  console.log("Public SPECTER package smoke passed.");

  await rm(tarball, { force: true });
} finally {
  await rm(temp, { recursive: true, force: true });
}
