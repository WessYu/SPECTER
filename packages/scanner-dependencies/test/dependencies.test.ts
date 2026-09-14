import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { inspectDependencies, scanDependencies, StaticAdvisoryProvider } from "../src/index.js";

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });
async function fixture(): Promise<string> { const root = await mkdtemp(path.join(os.tmpdir(), "specter-dep-")); dirs.push(root); await writeFile(path.join(root, "package.json"), JSON.stringify({ dependencies: { lodash: "4.17.20" } })); await writeFile(path.join(root, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {}, "node_modules/lodash": { version: "4.17.20" } } })); return root; }

describe("dependency scanner", () => {
  it("marks direct npm dependencies correctly", async () => { const inventory = await inspectDependencies(await fixture()); expect(inventory.dependencies[0]).toMatchObject({ name: "lodash", version: "4.17.20", direct: true }); });
  it("produces deterministic findings through provider interface", async () => {
    const root = await fixture();
    const provider = new StaticAdvisoryProvider([{ id: "TEST-ADV-1", package: "lodash", affectedVersion: "4.17.20", severity: "high", summary: "Fixture advisory", patchedVersion: "4.17.21" }]);
    const result = await scanDependencies(root, provider);
    expect(result.findings[0]).toMatchObject({ advisory: "TEST-ADV-1", package: "lodash", directDependency: true, severity: "high" });
  });
});
