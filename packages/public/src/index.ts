import {
  executeLocalScan as internalExecuteLocalScan,
  executeRemoteScan as internalExecuteRemoteScan,
  runCli as internalRunCli,
} from "@specter-security/cli";
import { runActiveScan as internalExecuteActiveScan } from "@specter/scanner-active";

export const SPECTER_VERSION = "0.1.0" as const;

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type FindingStatus = "open" | "resolved" | "suppressed";

export interface FindingLocation {
  readonly file?: string;
  readonly line?: number;
  readonly column?: number;
  readonly url?: string;
}

export interface Finding {
  readonly schemaVersion: "1";
  readonly id: string;
  readonly ruleId: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: string;
  readonly confidence: "low" | "medium" | "high";
  readonly source: string;
  readonly fingerprint: string;
  readonly location?: FindingLocation;
  readonly evidence?: unknown;
  readonly remediation?: string;
  readonly documentationUrl?: string;
  readonly status?: FindingStatus;
}

export interface SeveritySummary {
  readonly info: number;
  readonly low: number;
  readonly medium: number;
  readonly high: number;
  readonly critical: number;
}

export interface ScanError {
  readonly code: string;
  readonly message: string;
  readonly module?: string;
  readonly recoverable: boolean;
}

export interface ScanModuleResult {
  readonly name: string;
  readonly status: "passed" | "warning" | "failed" | "skipped";
  readonly durationMs: number;
  readonly findingCount: number;
}

export interface RiskScore {
  readonly value: number;
  readonly band: "excellent" | "good" | "fair" | "poor" | "critical";
  readonly deductions: readonly unknown[];
}

export interface ScanTarget {
  readonly kind: "project" | "build" | "url";
  readonly value: string;
  readonly displayName?: string;
}

export interface ScanResult {
  readonly schemaVersion: "1";
  readonly scanId: string;
  readonly target: ScanTarget;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;
  readonly status: "queued" | "running" | "completed" | "failed" | "cancelled";
  readonly score: RiskScore;
  readonly summary: SeveritySummary;
  readonly findings: readonly Finding[];
  readonly modules: readonly ScanModuleResult[];
  readonly errors: readonly ScanError[];
  readonly surface?: unknown;
  readonly active?: unknown;
}

export interface SpecterConfig {
  readonly failOn: "critical" | "high" | "medium" | "low" | "none";
  readonly maxScoreDrop: number;
  readonly ignore: readonly string[];
  readonly suppressions: readonly unknown[];
  readonly scan: {
    readonly source: boolean;
    readonly build: boolean;
    readonly dependencies: boolean;
    readonly remote: boolean;
    readonly runtime: boolean;
  };
  readonly active: ActiveScannerConfig;
  readonly limits: {
    readonly maxFileBytes: number;
    readonly requestTimeoutMs: number;
    readonly scanTimeoutMs: number;
    readonly maxRedirects: number;
    readonly maxPages: number;
    readonly maxResponseBytes: number;
    readonly concurrency: number;
  };
}

export interface ScanExecutionOptions {
  readonly offline?: boolean;
  readonly runtime?: boolean;
  readonly build?: boolean;
  readonly dependencies?: boolean;
  readonly baseline?: ScanResult;
  readonly config?: SpecterConfig;
}

export interface ActiveScannerConfig {
  readonly enabled: boolean;
  readonly profile: "safe" | "standard";
  readonly maxRequests: number;
  readonly maxRequestsPerSecond: number;
  readonly concurrency: number;
  readonly requestTimeoutMs: number;
  readonly maxEndpoints: number;
  readonly maxParametersPerEndpoint: number;
  readonly allowStateChangingMethods: boolean;
  readonly previewHosts: readonly string[];
}

export interface ActiveScanOptions {
  readonly config: ActiveScannerConfig;
  readonly storePath?: string;
  readonly authorization?: unknown;
  readonly observedRoutes?: readonly unknown[];
  readonly baseline?: ScanResult;
  readonly signal?: AbortSignal;
  readonly rules?: ReadonlySet<string>;
  readonly testUsername?: string;
  readonly testPassword?: string;
  readonly suppressions?: readonly unknown[];
}

export interface CliIo {
  readonly cwd: string;
  readonly args: readonly string[];
  readonly signal?: AbortSignal;
}

export interface CommandResult {
  readonly exitCode: number;
  readonly stdout?: string;
  readonly stderr?: string;
}

export async function executeLocalScan(
  target: string,
  options: ScanExecutionOptions = {},
): Promise<ScanResult> {
  return (await internalExecuteLocalScan(
    target,
    options as Parameters<typeof internalExecuteLocalScan>[1],
  )) as unknown as ScanResult;
}

export async function executeRemoteScan(
  target: string,
  options: ScanExecutionOptions = {},
): Promise<ScanResult> {
  return (await internalExecuteRemoteScan(
    target,
    options as Parameters<typeof internalExecuteRemoteScan>[1],
  )) as unknown as ScanResult;
}

export async function executeActiveScan(
  target: string,
  options: ActiveScanOptions,
): Promise<ScanResult> {
  return (await internalExecuteActiveScan(
    target,
    options as Parameters<typeof internalExecuteActiveScan>[1],
  )) as unknown as ScanResult;
}

export async function runCli(io: CliIo): Promise<CommandResult> {
  return (await internalRunCli(io)) as CommandResult;
}
