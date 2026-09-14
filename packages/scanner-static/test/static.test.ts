import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSource } from "../src/index.js";

const dirs: string[] = [];
afterEach(async () => { await Promise.all(dirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true }))); });
async function fixture(source: string): Promise<string> { const dir = await mkdtemp(path.join(os.tmpdir(), "specter-static-")); dirs.push(dir); await writeFile(path.join(dir, "app.tsx"), source); return dir; }

describe("static scanner", () => {
  it("finds dangerous runtime patterns", async () => {
    const root = await fixture(`"use client"; const x = process.env.SECRET_KEY; eval(input); localStorage.setItem("token", x ?? "");`);
    const result = await scanSource(root);
    expect(result.findings.map((item) => item.ruleId)).toEqual(expect.arrayContaining(["SPECTER-SOURCE-001", "SPECTER-SOURCE-005", "SPECTER-SOURCE-007"]));
  });
  it("does not call server-only process.env usage a client exposure", async () => {
    const root = await fixture(`export const value = process.env.DATABASE_URL;`);
    expect((await scanSource(root)).findings.some((item) => item.ruleId === "SPECTER-SOURCE-007")).toBe(false);
  });
});
