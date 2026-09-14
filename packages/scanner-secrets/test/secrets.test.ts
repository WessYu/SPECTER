import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSecrets } from "../src/index.js";

const dirs: string[] = [];
afterEach(async () => {
  await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("secret scanner", () => {
  it("redacts detected credentials", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "specter-secret-"));
    dirs.push(root);
    await writeFile(path.join(root, "app.ts"), `const secret = "spt_test_Q7m9Z2x8N4v6K1r5T3w0";`);
    const result = await scanSecrets(root);
    expect(result.findings).toHaveLength(1);
    expect(JSON.stringify(result.findings[0]?.evidence)).not.toContain(
      "spt_test_Q7m9Z2x8N4v6K1r5T3w0",
    );
  });
  it("skips documentation examples by default", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "specter-secret-"));
    dirs.push(root);
    await mkdir(path.join(root, "docs"));
    await writeFile(
      path.join(root, "docs", "example.txt"),
      `const secret = "spt_test_Q7m9Z2x8N4v6K1r5T3w0";`,
    );
    expect((await scanSecrets(root)).findings).toHaveLength(0);
  });
});
