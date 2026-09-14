import { randomUUID } from "node:crypto";
import path from "node:path";
import { applySuppressions, compareScans, evaluateSecurityGate } from "@specter/core";
import { defaultConfig, type SpecterConfig } from "@specter/config";
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
  readonly config?: SpecterConfig;
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
  const config = options.config ?? defaultConfig;
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const findings: Finding[] = [];
  const modules: ScanModuleResult[] = [];
  const errors: ScanError[] = [];

  let mark = Date.now();
  if (config.scan.source) {
    const source = await scanSource(absolute, { maxFileBytes: config.limits.maxFileBytes });
    findings.push(...source.findings);
    modules.push(moduleResult("source", mark, source.findings.length));

    mark = Date.now();
    const secrets = await scanSecrets(absolute, { maxFileBytes: config.limits.maxFileBytes });
    findings.push(...secrets.findings);
    modules.push(moduleResult("secrets", mark, secrets.findings.length));
  } else {
    modules.push({ name: "source", durationMs: 0, findingCount: 0, status: "skipped" });
    modules.push({ name: "secrets", durationMs: 0, findingCount: 0, status: "skipped" });
  }

  if ((options.dependencies ?? config.scan.dependencies) !== false) {
    mark = Date.now();
    if (options.offline) {
      const inventory = await inspectDependencies(absolute);
      modules.push({ name: `dependencies (${inventory.dependencies.length} inventoried; advisory query offline)`, durationMs: elapsed(mark), findingCount: 0, status: "skipped" });
    } else {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), Math.min(config.limits.requestTimeoutMs, 8_000));
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

  if ((options.build ?? config.scan.build) !== false) {
    mark = Date.now();
    const build = await scanBuild(absolute, { maxFileBytes: config.limits.maxFileBytes * 2 });
    findings.push(...build.findings);
    modules.push({ name: `build:${build.framework}`, durationMs: elapsed(mark), findingCount: build.findings.length, status: build.outputs.length === 0 ? "skipped" : build.findings.length ? "warning" : "passed" });
  } else modules.push({ name: "build", durationMs: 0, findingCount: 0, status: "skipped" });

  const unique = deduplicate(findings);
  const suppressions = [
    ...config.ignore.map((ruleId) => ({ ruleId, reason: "Ignored by SPECTER configuration" })),
    ...config.suppressions,
  ];
  const suppressionResult = applySuppressions(unique, suppressions);
  const reportFindings = [...suppressionResult.findings, ...suppressionResult.suppressed];
  const baselineFingerprints = options.baseline ? new Set(options.baseline.findings.map((finding) => finding.fingerprint)) : undefined;
  const score = calculateRiskScore(reportFindings, baselineFingerprints ? { baselineFingerprints } : {});
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
    summary: summarizeSeverity(suppressionResult.findings),
    findings: reportFindings,
    modules,
    errors,
  };
}

export async function executeRemoteScan(target: string, options: ScanExecutionOptions = {}): Promise<ScanResult> {
  const config = options.config ?? defaultConfig;
  if (!config.scan.remote) throw new Error("Remote scanning is disabled by SPECTER configuration.");
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const findings: Finding[] = [];
  const modules: ScanModuleResult[] = [];
  const errors: ScanError[] = [];
  const requestOptions = {
    requestTimeoutMs: config.limits.requestTimeoutMs,
    totalTimeoutMs: config.limits.scanTimeoutMs,
    maxRedirects: config.limits.maxRedirects,
    maxResponseBytes: config.limits.maxResponseBytes,
  };
  let mark = Date.now();
  const remote = await scanRemote(target, requestOptions);
  findings.push(...remote.findings);
  modules.push(moduleResult("remote", mark, remote.findings.length));

  mark = Date.now();
  let discoveredSurface: Awaited<ReturnType<typeof discoverSurface>> | undefined;
  try {
    discoveredSurface = await discoverSurface(remote.response.url, { ...requestOptions, maxPages: config.limits.maxPages, concurrency: config.limits.concurrency, includeRuntime: options.runtime ?? config.scan.runtime });
    modules.push({ name: `surface:${discoveredSurface.routes.length} routes/${discoveredSurface.externalDomains.length} domains`, durationMs: elapsed(mark), findingCount: 0, status: "passed" });
  } catch (error: unknown) {
    modules.push({ name: "surface", durationMs: elapsed(mark), findingCount: 0, status: "skipped" });
    errors.push({ code: "SURFACE_DISCOVERY_PARTIAL", message: error instanceof Error ? error.message : "Surface discovery failed", module: "surface", recoverable: true });
  }

  const unique = deduplicate(findings);
  const suppressions = [
    ...config.ignore.map((ruleId) => ({ ruleId, reason: "Ignored by SPECTER configuration" })),
    ...config.suppressions,
  ];
  const suppressionResult = applySuppressions(unique, suppressions);
  const reportFindings = [...suppressionResult.findings, ...suppressionResult.suppressed];
  const baselineFingerprints = options.baseline ? new Set(options.baseline.findings.map((finding) => finding.fingerprint)) : undefined;
  const score = calculateRiskScore(reportFindings, baselineFingerprints ? { baselineFingerprints } : {});
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
    summary: summarizeSeverity(suppressionResult.findings),
    findings: reportFindings,
    modules,
    errors,
    ...(discoveredSurface ? { surface: { routes: discoveredSurface.routes, externalDomains: discoveredSurface.externalDomains, removedDomains: discoveredSurface.removedDomains } } : {}),
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
    `${scan.findings.filter((finding) => finding.status !== "suppressed").length} findings require review.`,
  ];
  if (scan.errors.length) lines.push("", "Partial errors", ...scan.errors.map((error) => `- ${error.code}: ${error.message}`));
  return `${lines.join("\n")}\n`;
}

export { compareScans, evaluateSecurityGate };
