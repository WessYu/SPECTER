import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { loadConfig } from "./config-loader.js";
import type { ScanResult, Severity } from "@specter/types";
import { compareScans, evaluateSecurityGate, executeLocalScan, executeRemoteScan, renderReport } from "./scan.js";
import type { CommandResult } from "./commands.js";

interface ParsedScanArgs {
  readonly target?: string;
  readonly format: "terminal" | "json" | "sarif";
  readonly ci: boolean;
  readonly failOn?: Severity | "none";
  readonly maxScoreDrop?: number;
  readonly baselinePath?: string;
  readonly output?: string;
  readonly runtime?: boolean;
  readonly offline: boolean;
  readonly build?: boolean;
  readonly dependencies?: boolean;
}

function needValue(args: readonly string[], index: number, flag: string): string {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value.`);
  return value;
}

function parseScanArgs(args: readonly string[]): ParsedScanArgs {
  let target: string | undefined;
  let format: ParsedScanArgs["format"] = "terminal";
  let ci = false;
  let failOn: ParsedScanArgs["failOn"];
  let maxScoreDrop: number | undefined;
  let baselinePath: string | undefined;
  let output: string | undefined;
  let runtime: boolean | undefined;
  let offline = false;
  let build: boolean | undefined;
  let dependencies: boolean | undefined;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") { if (format === "sarif") throw new Error("--json and --sarif are mutually exclusive."); format = "json"; continue; }
    if (arg === "--sarif") { if (format === "json") throw new Error("--json and --sarif are mutually exclusive."); format = "sarif"; continue; }
    if (arg === "--ci") { ci = true; continue; }
    if (arg === "--runtime") { runtime = true; continue; }
    if (arg === "--no-runtime") { runtime = false; continue; }
    if (arg === "--offline") { offline = true; continue; }
    if (arg === "--no-build") { build = false; continue; }
    if (arg === "--no-dependencies") { dependencies = false; continue; }
    if (arg === "--fail-on") {
      const value = needValue(args, index, arg);
      if (!["critical", "high", "medium", "low", "none"].includes(value)) throw new Error("--fail-on must be critical, high, medium, low or none.");
      failOn = value as Severity | "none"; index += 1; continue;
    }
    if (arg === "--max-score-drop") {
      const value = Number(needValue(args, index, arg));
      if (!Number.isFinite(value) || value < 0 || value > 100) throw new Error("--max-score-drop must be between 0 and 100.");
      maxScoreDrop = value; index += 1; continue;
    }
    if (arg === "--baseline") { baselinePath = needValue(args, index, arg); index += 1; continue; }
    if (arg === "--output") { output = needValue(args, index, arg); index += 1; continue; }
    if (arg?.startsWith("-")) throw new Error(`Unknown scan option: ${arg}`);
    if (target) throw new Error("Only one scan target may be supplied.");
    target = arg;
  }
  return {
    ...(target ? { target } : {}), format, ci,
    ...(failOn !== undefined ? { failOn } : {}),
    ...(maxScoreDrop !== undefined ? { maxScoreDrop } : {}),
    ...(baselinePath ? { baselinePath } : {}), ...(output ? { output } : {}),
    ...(runtime !== undefined ? { runtime } : {}), offline,
    ...(build !== undefined ? { build } : {}),
    ...(dependencies !== undefined ? { dependencies } : {}),
  };
}

function validateLoadedScan(value: unknown, source: string): ScanResult {
  if (!value || typeof value !== "object") throw new Error(`Invalid scan report: ${source}`);
  const candidate = value as Partial<ScanResult>;
  if (candidate.schemaVersion !== "1" || typeof candidate.scanId !== "string" || !candidate.target || !candidate.score || !Array.isArray(candidate.findings)) throw new Error(`Unsupported or invalid SPECTER scan report: ${source}`);
  return candidate as ScanResult;
}

export async function readScanReport(file: string): Promise<ScanResult> {
  return validateLoadedScan(JSON.parse(await readFile(path.resolve(file), "utf8")), file);
}

async function persistReport(scan: ScanResult, requested: string | undefined, format: ParsedScanArgs["format"], cwd: string): Promise<string> {
  const extension = format === "sarif" ? ".sarif" : ".json";
  let file: string;
  if (!requested) file = path.join(cwd, ".specter", `report${extension}`);
  else {
    const absolute = path.resolve(cwd, requested);
    file = /\.(?:json|sarif)$/i.test(absolute) ? absolute : path.join(absolute, `specter${extension}`);
  }
  await mkdir(path.dirname(file), { recursive: true });
  const machineFormat = format === "sarif" ? "sarif" : "json";
  await writeFile(file, renderReport(scan, machineFormat), "utf8");
  return file;
}

export async function runScanCommand(args: readonly string[], cwd: string): Promise<CommandResult> {
  let parsed: ParsedScanArgs;
  try { parsed = parseScanArgs(args); }
  catch (error: unknown) { return { exitCode: 2, stderr: `${error instanceof Error ? error.message : "Invalid scan configuration"}\n` }; }

  let baseline: ScanResult | undefined;
  try { if (parsed.baselinePath) baseline = await readScanReport(path.resolve(cwd, parsed.baselinePath)); }
  catch (error: unknown) { return { exitCode: 2, stderr: `${error instanceof Error ? error.message : "Unable to read baseline"}\n` }; }

  let loadedConfig: Awaited<ReturnType<typeof loadConfig>>;
  try { loadedConfig = await loadConfig(cwd); }
  catch (error: unknown) { return { exitCode: 2, stderr: `${error instanceof Error ? error.message : "Unable to load SPECTER config"}\n` }; }

  const target = parsed.target ?? cwd;
  let scan: ScanResult;
  try {
    scan = /^https?:\/\//i.test(target)
      ? await executeRemoteScan(target, { ...(baseline ? { baseline } : {}), ...(parsed.runtime !== undefined ? { runtime: parsed.runtime } : {}), config: loadedConfig.config })
      : await executeLocalScan(path.resolve(cwd, target), { ...(baseline ? { baseline } : {}), offline: parsed.offline, ...(parsed.build !== undefined ? { build: parsed.build } : {}), ...(parsed.dependencies !== undefined ? { dependencies: parsed.dependencies } : {}), config: loadedConfig.config });
  } catch (error: unknown) {
    return { exitCode: 3, stderr: `Scan failed: ${error instanceof Error ? error.message : "Unknown scan error"}\n` };
  }

  let saved: string | undefined;
  try { saved = await persistReport(scan, parsed.output, parsed.format, cwd); }
  catch (error: unknown) { return { exitCode: 3, stderr: `Scan completed but report could not be saved: ${error instanceof Error ? error.message : "Unknown output error"}\n` }; }

  const rendered = renderReport(scan, parsed.format);
  const withLocation = parsed.format === "terminal" ? `${rendered}\nReport saved:\n${saved}\n` : rendered;
  if (parsed.ci) {
    const gate = evaluateSecurityGate(scan, baseline, { failOn: parsed.failOn ?? loadedConfig.config.failOn, maxScoreDrop: parsed.maxScoreDrop ?? loadedConfig.config.maxScoreDrop });
    if (!gate.passed) return { exitCode: 1, stdout: withLocation, stderr: `Security gate failed:\n${gate.failures.map((failure) => `- ${failure.message}`).join("\n")}\n` };
  }
  return { exitCode: 0, stdout: withLocation };
}

export async function runCompareCommand(args: readonly string[]): Promise<CommandResult> {
  const [previousPath, currentPath] = args;
  if (!previousPath || !currentPath || args.length !== 2) return { exitCode: 2, stderr: "Usage: specter compare <previous.json> <current.json>\n" };
  try {
    const [previous, current] = await Promise.all([readScanReport(previousPath), readScanReport(currentPath)]);
    const diff = compareScans(previous, current);
    const lines = [
      "SECURITY REGRESSION", "", "Score", `${diff.score.previous} → ${diff.score.current} (${diff.score.delta >= 0 ? "+" : ""}${diff.score.delta})`, "",
      "New findings", ...diff.new.map((finding) => `+ ${finding.severity.toUpperCase()} ${finding.title}`), "",
      "Resolved", ...diff.resolved.map((finding) => `- ${finding.severity.toUpperCase()} ${finding.title}`), "",
      "Severity changed", ...diff.severityChanged.map((change) => `~ ${change.previous} → ${change.current} ${change.finding.title}`), "",
    ];
    return { exitCode: 0, stdout: `${lines.join("\n")}\n` };
  } catch (error: unknown) { return { exitCode: 2, stderr: `${error instanceof Error ? error.message : "Compare failed"}\n` }; }
}
