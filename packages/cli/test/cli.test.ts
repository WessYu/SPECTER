import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/index.js";

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });
async function project(source = `export const ok = true;`): Promise<string> { const root = await mkdtemp(path.join(os.tmpdir(), "specter-cli-")); dirs.push(root); await writeFile(path.join(root, "package.json"), `{ "name": "fixture", "version": "1.0.0" }`); await writeFile(path.join(root, "app.ts"), source); return root; }

describe("CLI", () => {
  it("returns documented configuration errors", async () => { const root = await project(); const result = await runCli({ cwd: root, args: ["scan", "--fail-on", "impossible"] }); expect(result.exitCode).toBe(2); });
  it("runs a deterministic offline local scan and writes JSON", async () => { const root = await project(`eval(input);`); const result = await runCli({ cwd: root, args: ["scan", ".", "--offline", "--no-build", "--json"] }); expect(result.exitCode).toBe(0); expect(JSON.parse(result.stdout ?? "{}").schemaVersion).toBe("1"); });
  it("rejects executable config syntax", async () => { const root = await project(); await writeFile(path.join(root, "specter.config.ts"), `export default { failOn: process.env.FAIL_ON };`); const result = await runCli({ cwd: root, args: ["config"] }); expect(result.exitCode).toBe(2); });
});
