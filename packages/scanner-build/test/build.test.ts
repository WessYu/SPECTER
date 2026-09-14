import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanBuild } from "../src/index.js";

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });

describe("build scanner", () => {
  it("detects source maps and redacted secrets without executing build scripts", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "specter-build-")); dirs.push(root); await mkdir(path.join(root, "dist"));
    await writeFile(path.join(root, "package.json"), JSON.stringify({ dependencies: { react: "19.1.1" } }));
    await writeFile(path.join(root, "dist", "app.js"), `const key="postgresql://db.invalid/specter_fixture";`);
    await writeFile(path.join(root, "dist", "app.js.map"), `{}`);
    const result = await scanBuild(root, { outputDirectories: ["dist"] });
    expect(result.findings.map((item) => item.ruleId)).toEqual(expect.arrayContaining(["SPECTER-BUILD-001", "SPECTER-BUILD-002"]));
    expect(JSON.stringify(result.findings)).not.toContain("postgresql://db.invalid/specter_fixture");
  });
});
