import { access, writeFile } from "node:fs/promises";
import path from "node:path";

export interface CommandResult {
  readonly exitCode: number;
  readonly stdout?: string;
  readonly stderr?: string;
}

async function fileExists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

export async function initConfig(root: string): Promise<CommandResult> {
  const file = path.join(path.resolve(root), "specter.config.ts");
  if (await fileExists(file))
    return {
      exitCode: 2,
      stderr: "specter.config.ts already exists.\n",
    };
  const content = `export default {
  failOn: "high",
  maxScoreDrop: 5,
  ignore: [],
  suppressions: [],
  scan: {
    source: true,
    build: true,
    dependencies: true,
    remote: true,
    runtime: false,
  },
  active: {
    enabled: false,
    profile: "safe",
    maxRequests: 150,
    maxRequestsPerSecond: 3,
    concurrency: 2,
    requestTimeoutMs: 5000,
    maxEndpoints: 40,
    maxParametersPerEndpoint: 10,
    allowStateChangingMethods: false,
    previewHosts: [],
  },
};
`;
  await writeFile(file, content, "utf8");
  return {
    exitCode: 0,
    stdout: `Created ${file}\n`,
  };
}

export async function doctor(root: string): Promise<CommandResult> {
  const checks = [
    ["Node.js >= 20", Number(process.version.slice(1).split(".")[0]) >= 20],
    ["package.json", await fileExists(path.join(path.resolve(root), "package.json"))],
    ["Active scanner AbortController", typeof AbortController === "function"],
    [
      "Active scanner OpenSSL",
      typeof process.versions.openssl === "string" && process.versions.openssl.length > 0,
    ],
    ["Active scanner URL support", typeof URL === "function"],
  ] as const;
  const failed = checks.filter(([, passed]) => !passed);
  const stdout = [
    "SPECTER DOCTOR",
    "",
    ...checks.map(([name, passed]) => `${passed ? "PASS" : "FAIL"}  ${name}`),
    "",
  ].join("\n");
  return {
    exitCode: failed.length ? 2 : 0,
    stdout,
  };
}
