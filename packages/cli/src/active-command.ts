import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  defaultAuthorizationStore,
  generateDomainAuthorization,
  runActiveScan,
  verifyDomainAuthorization,
} from "@specter/scanner-active";
import { evaluateSecurityGate } from "@specter/core";
import { serializeJsonReport, serializeSarif } from "@specter/reporter";
import type { ActiveProfile, ScanResult, Severity } from "@specter/types";
import { loadConfig } from "./config-loader.js";
import type { CommandResult } from "./commands.js";
import { readScanReport } from "./scan-command.js";
import { startLocalPreview } from "./local-preview.js";

interface ParsedActiveArgs {
  readonly target: string;
  readonly format: "terminal" | "json" | "sarif";
  readonly ci: boolean;
  readonly failOn?: Severity | "none";
  readonly maxScoreDrop?: number;
  readonly baselinePath?: string;
  readonly output?: string;
  readonly profile?: ActiveProfile;
  readonly rules: ReadonlySet<string>;
}

function valueAfter(args: readonly string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value.`);
  return value;
}

function parseActiveArgs(args: readonly string[]): ParsedActiveArgs {
  let target: string | undefined;
  let format: ParsedActiveArgs["format"] = "terminal";
  let ci = false;
  let failOn: ParsedActiveArgs["failOn"];
  let maxScoreDrop: number | undefined;
  let baselinePath: string | undefined;
  let output: string | undefined;
  let profile: ActiveProfile | undefined;
  const rules = new Set<string>();

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      if (format === "sarif") throw new Error("--json and --sarif are mutually exclusive.");
      format = "json";
      continue;
    }
    if (arg === "--sarif") {
      if (format === "json") throw new Error("--json and --sarif are mutually exclusive.");
      format = "sarif";
      continue;
    }
    if (arg === "--ci") {
      ci = true;
      continue;
    }
    if (arg === "--active-profile") {
      const value = valueAfter(args, index, arg);
      if (value !== "safe" && value !== "standard")
        throw new Error("--active-profile must be safe or standard.");
      profile = value;
      index += 1;
      continue;
    }
    if (arg === "--rule") {
      rules.add(valueAfter(args, index, arg));
      index += 1;
      continue;
    }
    if (arg === "--fail-on") {
      const value = valueAfter(args, index, arg);
      if (!["critical", "high", "medium", "low", "none"].includes(value))
        throw new Error("--fail-on must be critical, high, medium, low or none.");
      failOn = value as Severity | "none";
      index += 1;
      continue;
    }
    if (arg === "--max-score-drop") {
      const value = Number(valueAfter(args, index, arg));
      if (!Number.isFinite(value) || value < 0 || value > 100)
        throw new Error("--max-score-drop must be between 0 and 100.");
      maxScoreDrop = value;
      index += 1;
      continue;
    }
    if (arg === "--baseline") {
      baselinePath = valueAfter(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--output") {
      output = valueAfter(args, index, arg);
      index += 1;
      continue;
    }
    if (arg?.startsWith("-")) throw new Error(`Unknown pentest option: ${arg}`);
    if (target) throw new Error("Only one pentest target may be supplied.");
    target = arg;
  }

  if (!target) throw new Error("Usage: specter pentest <path|url> [options]");

  return {
    target,
    format,
    ci,
    rules,
    ...(failOn !== undefined ? { failOn } : {}),
    ...(maxScoreDrop !== undefined ? { maxScoreDrop } : {}),
    ...(baselinePath ? { baselinePath } : {}),
    ...(output ? { output } : {}),
    ...(profile ? { profile } : {}),
  };
}

function activeSuppressions(config: Awaited<ReturnType<typeof loadConfig>>["config"]) {
  return [
    ...config.ignore.map((ruleId) => ({
      ruleId,
      reason: "Ignored by SPECTER configuration",
    })),
    ...config.suppressions,
  ];
}

function renderActiveReport(scan: ScanResult, blocked: boolean): string {
  const counts = scan.summary;
  const authorization = scan.authorization?.status ?? "unverified";
  const lines = [
    "SPECTER ACTIVE SECURITY",
    "AUTHORIZED ACTIVE TEST",
    "",
    "Target",
    scan.target.value,
    "",
    "Authorization",
    authorization.toUpperCase(),
    "",
    "Profile",
    (scan.profile ?? "safe").toUpperCase(),
    "",
    "Endpoints",
    String(scan.endpointCount ?? 0),
    "",
    "Requests",
    `${scan.budget?.used ?? 0} / ${scan.budget?.max ?? 0}`,
    "",
    "Elapsed time",
    `${scan.durationMs} ms`,
    "",
    "Security Score",
    `${scan.score.value} / 100`,
    "",
    `CRITICAL  ${counts.critical}`,
    `HIGH      ${counts.high}`,
    `MEDIUM    ${counts.medium}`,
    `LOW       ${counts.low}`,
    `INFO      ${counts.info}`,
    "",
    `Confirmed ${scan.confirmedCount ?? 0}`,
    `Potential ${scan.potentialCount ?? 0}`,
    "",
    "Regression",
    scan.regressionDelta === undefined
      ? "NO BASELINE"
      : `${scan.regressionDelta >= 0 ? "+" : ""}${scan.regressionDelta} points`,
    "",
    blocked ? "BLOCKED" : "PASS",
  ];
  if (scan.errors.length > 0) {
    lines.push(
      "",
      "Partial / inconclusive checks",
      ...scan.errors.map((error) => `- ${error.code}: ${error.message}`),
    );
  }
  return `${lines.join("\n")}\n`;
}

async function persistActiveReport(
  scan: ScanResult,
  format: ParsedActiveArgs["format"],
  requested: string | undefined,
  cwd: string,
): Promise<string> {
  const extension = format === "sarif" ? ".sarif" : ".json";
  const file = requested
    ? /\.(?:json|sarif)$/i.test(path.resolve(cwd, requested))
      ? path.resolve(cwd, requested)
      : path.join(path.resolve(cwd, requested), `specter-active${extension}`)
    : path.join(cwd, ".specter", `active-report${extension}`);
  await mkdir(path.dirname(file), { recursive: true });
  const content = format === "sarif" ? serializeSarif(scan) : serializeJsonReport(scan);
  await writeFile(file, content, "utf8");
  return file;
}

export async function runPentestCommand(
  args: readonly string[],
  cwd: string,
  signal?: AbortSignal,
): Promise<CommandResult> {
  let parsed: ParsedActiveArgs;
  try {
    parsed = parseActiveArgs(args);
  } catch (error: unknown) {
    return {
      exitCode: 2,
      stderr: `${error instanceof Error ? error.message : "Invalid active scan configuration"}\n`,
    };
  }

  let loaded: Awaited<ReturnType<typeof loadConfig>>;
  let baseline: ScanResult | undefined;
  try {
    loaded = await loadConfig(cwd);
    if (parsed.baselinePath)
      baseline = await readScanReport(path.resolve(cwd, parsed.baselinePath));
  } catch (error: unknown) {
    return {
      exitCode: 2,
      stderr: `${error instanceof Error ? error.message : "Unable to prepare active scan"}\n`,
    };
  }

  let preview: Awaited<ReturnType<typeof startLocalPreview>> | undefined;
  try {
    const target = /^https?:\/\//i.test(parsed.target)
      ? parsed.target
      : (preview = await startLocalPreview(path.resolve(cwd, parsed.target), signal)).url;

    const config = {
      ...loaded.config.active,
      enabled: true,
      profile: parsed.profile ?? loaded.config.active.profile,
    };
    const scan = await runActiveScan(target, {
      config,
      storePath: defaultAuthorizationStore(cwd),
      ...(baseline ? { baseline } : {}),
      ...(signal === undefined ? {} : { signal }),
      ...(parsed.rules.size > 0 ? { rules: parsed.rules } : {}),
      ...(process.env.SPECTER_TEST_USERNAME
        ? { testUsername: process.env.SPECTER_TEST_USERNAME }
        : {}),
      ...(process.env.SPECTER_TEST_PASSWORD
        ? { testPassword: process.env.SPECTER_TEST_PASSWORD }
        : {}),
      suppressions: activeSuppressions(loaded.config),
    });

    const gate = evaluateSecurityGate(scan, baseline, {
      failOn: parsed.failOn ?? loaded.config.failOn,
      maxScoreDrop: parsed.maxScoreDrop ?? loaded.config.maxScoreDrop,
    });

    const saved = await persistActiveReport(scan, parsed.format, parsed.output, cwd);
    const rendered =
      parsed.format === "json"
        ? serializeJsonReport(scan)
        : parsed.format === "sarif"
          ? serializeSarif(scan)
          : `${renderActiveReport(scan, !gate.passed)}\nReport saved:\n${saved}\n`;

    if (parsed.ci && !gate.passed) {
      return {
        exitCode: 1,
        stdout: rendered,
        stderr: `Security gate failed:\n${gate.failures
          .map((failure) => `- ${failure.message}`)
          .join("\n")}\n`,
      };
    }
    return { exitCode: 0, stdout: rendered };
  } catch (error: unknown) {
    if ((error as Error).name === "AbortError")
      return {
        exitCode: 130,
        stderr: "Active security test cancelled.\n",
      };
    return {
      exitCode: 3,
      stderr: `Active security test failed: ${error instanceof Error ? error.message : "Unknown error"}\n`,
    };
  } finally {
    await preview?.stop();
  }
}

export async function runAuthorizeCommand(
  args: readonly string[],
  cwd: string,
): Promise<CommandResult> {
  const [target] = args;
  if (!target || args.length !== 1 || !/^https?:\/\//i.test(target))
    return {
      exitCode: 2,
      stderr: "Usage: specter authorize <url>\n",
    };
  try {
    const generated = await generateDomainAuthorization(target, defaultAuthorizationStore(cwd));
    if (generated.authorization.status === "local")
      return {
        exitCode: 0,
        stdout: "Localhost is automatically authorized for active testing.\n",
      };
    return {
      exitCode: 0,
      stdout: [
        "SPECTER ACTIVE SECURITY",
        "",
        "Authorization",
        "UNVERIFIED",
        "",
        "Publish this file on the exact hostname:",
        generated.path,
        "",
        "Expected content:",
        generated.content,
        "",
        "Then run:",
        `specter verify ${target}`,
        "",
      ].join("\n"),
    };
  } catch (error: unknown) {
    return {
      exitCode: 2,
      stderr: `${error instanceof Error ? error.message : "Authorization generation failed"}\n`,
    };
  }
}

export async function runVerifyCommand(
  args: readonly string[],
  cwd: string,
): Promise<CommandResult> {
  const [target] = args;
  if (!target || args.length !== 1 || !/^https?:\/\//i.test(target))
    return {
      exitCode: 2,
      stderr: "Usage: specter verify <url>\n",
    };
  try {
    const authorization = await verifyDomainAuthorization(target, defaultAuthorizationStore(cwd));
    if (authorization.status !== "verified") {
      return {
        exitCode: 3,
        stderr: `Authorization is ${authorization.status.toUpperCase()}.\n`,
      };
    }
    return {
      exitCode: 0,
      stdout: [
        "SPECTER ACTIVE SECURITY",
        "",
        "Authorization",
        "VERIFIED",
        "",
        "Hostname",
        authorization.hostname,
        "",
        "Active testing is now permitted for this exact hostname.",
        "",
      ].join("\n"),
    };
  } catch (error: unknown) {
    return {
      exitCode: 3,
      stderr: `${error instanceof Error ? error.message : "Verification failed"}\n`,
    };
  }
}
