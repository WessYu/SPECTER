import { access, writeFile } from "node:fs/promises";
import path from "node:path";
import { defaultConfig } from "@specter/config";
import { inspectDependencies } from "@specter/scanner-dependencies";
import { scanSecrets } from "@specter/scanner-secrets";
import { scanSource } from "@specter/scanner-static";
import type { Finding } from "@specter/types";
import { renderLocalScan } from "./terminal.js";

export interface CommandResult {
  readonly exitCode: number;
  readonly stdout?: string;
  readonly stderr?: string;
}

async function fileExists(file: string): Promise<boolean> { try { await access(file); return true; } catch { return false; } }

export async function runLocalScan(target: string): Promise<CommandResult> {
  const absolute = path.resolve(target);
  if (!(await fileExists(path.join(absolute, "package.json")))) return { exitCode: 2, stderr: `No package.json found in ${absolute}\n` };
  const [staticResult, secretResult, dependencyResult] = await Promise.all([
    scanSource(absolute, { maxFileBytes: defaultConfig.limits.maxFileBytes }),
    scanSecrets(absolute, { maxFileBytes: defaultConfig.limits.maxFileBytes }),
    inspectDependencies(absolute),
  ]);
  const findings: Finding[] = [...staticResult.findings, ...secretResult.findings];
  const unique = new Map(findings.map((finding) => [finding.fingerprint, finding]));
  return {
    exitCode: 0,
    stdout: renderLocalScan({ target: absolute, filesScanned: staticResult.filesScanned, findings: [...unique.values()], dependencyCount: dependencyResult.dependencies.length }),
  };
}

export async function initConfig(root: string): Promise<CommandResult> {
  const file = path.join(path.resolve(root), "specter.config.ts");
  if (await fileExists(file)) return { exitCode: 2, stderr: "specter.config.ts already exists.\n" };
  const content = `export default {\n  failOn: "high",\n  maxScoreDrop: 5,\n  ignore: [],\n  scan: {\n    source: true,\n    build: true,\n    dependencies: true,\n    remote: true,\n    runtime: false,\n  },\n};\n`;
  await writeFile(file, content, "utf8");
  return { exitCode: 0, stdout: `Created ${file}\n` };
}

export async function doctor(root: string): Promise<CommandResult> {
  const checks = [
    ["Node.js >= 20", Number(process.version.slice(1).split(".")[0]) >= 20],
    ["package.json", await fileExists(path.join(path.resolve(root), "package.json"))],
  ] as const;
  const failed = checks.filter(([, passed]) => !passed);
  const stdout = ["SPECTER DOCTOR", "", ...checks.map(([name, passed]) => `${passed ? "PASS" : "FAIL"}  ${name}`), ""].join("\n");
  return { exitCode: failed.length ? 2 : 0, stdout };
}
