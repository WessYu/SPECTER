import { randomUUID } from "node:crypto";
import path from "node:path";
import { compareScans, evaluateSecurityGate } from "@specter/core";
import { defaultConfig } from "@specter/config";
import { calculateRiskScore, summarizeSeverity } from "@specter/risk-engine";
import { serializeJsonReport, serializeSarif } from "@specter/reporter";
import { scanBuild } from "@specter/scanner-build";
import { OsvProvider, inspectDependencies, scanDependencies } from "@specter/scanner-dependencies";
import { scanSecrets } from "@specter/scanner-secrets";
import { scanSource } from "@specter/scanner-static";
import { discoverSurface, scanRemote } from "@specter/scanner-web";
import type { Finding, ScanError, ScanModuleResult, ScanResult, Severity } from "@specter/types";

export interface ScanExecutionOptions {
  readonly offline?: boolean;
  readonly runtime?: boolean;
  readonly build?: boolean;
  readonly dependencies?: boolean;
  readonly baseline?: ScanResult;
}

function elapsed(started: number): number { return Math.max(0, Date.now() - started); }
function deduplicate(findings: readonly Finding[]): Finding[] {
  const unique = new Map<string, Finding>();
  for (const finding of findings) {
    const current = unique.get(finding.fingerprint);
    if (!current) unique.set(finding.fingerprint, finding);
    else {
      const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
      if (rank[finding.severity] > rank[current.severity]) unique.set(finding.fingerprint, finding);
    }
  }
  return [...unique.values()];
}

function moduleResult(name: string, started: number, findingCount: number, status: ScanModuleResult["status"] = findingCount ? "warning" : "passed"): ScanModuleResult {
  return { name, durationMs: elapsed(started), findingCount, status };
}

export async function executeLocalScan(target: string, options: ScanExecutionOptions = {}): Promise<ScanResult> {
  const absolute = path.resolve(target);
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const findings: Finding[] = [];
  const modules: ScanModuleResult[] = [];
  const errors: ScanError[] = [];

  let mark = Date.now();
  const source = await scanSource(absolute, { maxFileBytes: defaultConfig.limits.maxFileBytes });
  findings.push(...source.findings);
  modules.push(moduleResult("source", mark, source.findings.length));

  mark = Date.now();
  const secrets = await scanSecrets(absolute, { maxFileBytes: defaultConfig.limits.maxFileBytes });
  findings.push(...secrets.findings);
  modules.push(moduleResult("secrets", mark, secrets.findings.length));

  if (options.dependencies !== false) {
    mark = Date.now();
    if (options.offline) {
      const inventory = await inspectDependencies(absolute);
      modules.push({ name: `dependencies (${inventory.dependencies.length} inventoried; advisory query offline)`, durationMs: elapsed(mark), findingCount: 0, status: "skipped" });
    } else {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), Math.min(defaultConfig.limits.requestTimeoutMs, 8_000));
      try {
        const dependencies = await scanDependencies(absolute, new OsvProvider(), controller.signal);
        findings.push(...dependencies.findings);
        modules.push(moduleResult(`dependencies:${dependencies.provider}`, mark, dependencies.findings.length));
      } catch (error: unknown) {
        modules.push({ name: "dependencies:osv.dev", durationMs: elapsed(mark), findingCount: 0, status: "skipped" });
        errors.push({ code: "DEPENDENCY_PROVIDER_UNAVAILABLE", message: error instanceof Error ? error.message : "Dependency provider failed", module: "dependencies", recoverable: true });
      } finally { clearTimeout(timer); }
    }
  } else modules.push({ name: "dependencies", durationMs: 0, findingCount: 0, status: "skipped" });

  if (options.build !== false) {
    mark = Date.now();
    const build = await scanBuild(absolute, { maxFileBytes: defaultConfig.limits.maxFileBytes * 2 });
    findings.push(...build.findings);
    modules.push({ name: `build:${build.framework}`, durationMs: elapsed(mark), findingCount: build.findings.length, status: build.outputs.length === 0 ? "skipped" : build.findings.length ? "warning" : "passed" });
  } else modules.push({ name: "build", durationMs: 0, findingCount: 0, status: "skipped" });

  const unique = deduplicate(findings);
  const baselineFingerprints = options.baseline ? new Set(options.baseline.findings.map((finding) => finding.fingerprint)) : undefined;
  const score = calculateRiskScore(unique, baselineFingerprints ? { baselineFingerprints } : {});
  const completedMs = Date.now();
  return {
    schemaVersion: "1",
    scanId: randomUUID(),
    target: { kind: "project", value: absolute, displayName: path.basename(absolute) },
    startedAt,
    completedAt: new Date(completedMs).toISOString(),
    durationMs: completedMs - startedMs,
    status: "completed",
    score,
    summary: summarizeSeverity(unique),
    findings: unique,
    modules,
    errors,
  };
}

export async function executeRemoteScan(target: string, options: ScanExecutionOptions = {}): Promise<ScanResult> {
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const findings: Finding[] = [];
  const modules: ScanModuleResult[] = [];
  const errors: ScanError[] = [];
  const requestOptions = {
    requestTimeoutMs: defaultConfig.limits.requestTimeoutMs,
    totalTimeoutMs: defaultConfig.limits.scanTimeoutMs,
    maxRedirects: defaultConfig.limits.maxRedirects,
    maxResponseBytes: defaultConfig.limits.maxResponseBytes,
  };
  let mark = Date.now();
  const remote = await scanRemote(target, requestOptions);
  findings.push(...remote.findings);
  modules.push(moduleResult("remote", mark, remote.findings.length));

  mark = Date.now();
  try {
    const surface = await discoverSurface(remote.response.url, { ...requestOptions, maxPages: defaultConfig.limits.maxPages, includeRuntime: options.runtime ?? false });
    modules.push({ name: `surface:${surface.routes.length} routes/${surface.externalDomains.length} domains`, durationMs: elapsed(mark), findingCount: 0, status: "passed" });
  } catch (error: unknown) {
    modules.push({ name: "surface", durationMs: elapsed(mark), findingCount: 0, status: "skipped" });
    errors.push({ code: "SURFACE_DISCOVERY_PARTIAL", message: error instanceof Error ? error.message : "Surface discovery failed", module: "surface", recoverable: true });
  }

  const unique = deduplicate(findings);
  const baselineFingerprints = options.baseline ? new Set(options.baseline.findings.map((finding) => finding.fingerprint)) : undefined;
  const score = calculateRiskScore(unique, baselineFingerprints ? { baselineFingerprints } : {});
  const completedMs = Date.now();
  return {
    schemaVersion: "1",
    scanId: randomUUID(),
    target: { kind: "url", value: remote.response.url, displayName: new URL(remote.response.url).hostname },
    startedAt,
    completedAt: new Date(completedMs).toISOString(),
    durationMs: completedMs - startedMs,
    status: "completed",
    score,
    summary: summarizeSeverity(unique),
    findings: unique,
    modules,
    errors,
  };
}

export function renderReport(scan: ScanResult, format: "terminal" | "json" | "sarif"): string {
  if (format === "json") return serializeJsonReport(scan);
  if (format === "sarif") return serializeSarif(scan);
  const counts = scan.summary;
  const lines = [
    scan.target.kind === "url" ? "SPECTER LIVE" : "SPECTER",
    "Application security from source to production.",
    "",
    "Target",
    scan.target.value,
    "",
    "Scanning",
    ...scan.modules.map((module) => `${module.status === "passed" ? "✓" : module.status === "warning" ? "!" : module.status === "skipped" ? "-" : "x"} ${module.name} (${module.findingCount})`),
    "",
    "Security Score",
    `${scan.score.value}/100`,
    "",
    `CRITICAL     ${counts.critical}`,
    `HIGH         ${counts.high}`,
    `MEDIUM       ${counts.medium}`,
    `LOW          ${counts.low}`,
    `INFO         ${counts.info}`,
    "",
    `${scan.findings.length} findings require review.`,
  ];
  if (scan.errors.length) lines.push("", "Partial errors", ...scan.errors.map((error) => `- ${error.code}: ${error.message}`));
  return `${lines.join("\n")}\n`;
}

export { compareScans, evaluateSecurityGate };
