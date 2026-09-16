export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

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
  readonly status?: "open" | "resolved" | "suppressed";
}

export interface ScanResult {
  readonly schemaVersion: "1";
  readonly scanId: string;
  readonly target: {
    readonly kind: "project" | "build" | "url";
    readonly value: string;
    readonly displayName?: string;
  };
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;
  readonly status: ScanStatus;
  readonly score: {
    readonly value: number;
    readonly band: "excellent" | "good" | "fair" | "poor" | "critical";
    readonly deductions: readonly unknown[];
  };
  readonly summary: Record<Severity, number>;
  readonly findings: readonly Finding[];
  readonly modules: readonly {
    readonly name: string;
    readonly status: "passed" | "warning" | "failed" | "skipped";
    readonly durationMs: number;
    readonly findingCount: number;
  }[];
  readonly errors: readonly {
    readonly code: string;
    readonly message: string;
    readonly module?: string;
    readonly recoverable: boolean;
  }[];
  readonly surface?: unknown;
}

export interface ScanExecutionOptions {
  readonly offline?: boolean;
  readonly runtime?: boolean;
  readonly build?: boolean;
  readonly dependencies?: boolean;
  readonly baseline?: ScanResult;
  readonly config?: unknown;
}

export interface CommandResult {
  readonly exitCode: number;
  readonly stdout?: string;
  readonly stderr?: string;
}

export interface CliIo {
  readonly cwd: string;
  readonly args: readonly string[];
}

export const CLI_VERSION: string;
export function executeLocalScan(target: string, options?: ScanExecutionOptions): Promise<ScanResult>;
export function executeRemoteScan(target: string, options?: ScanExecutionOptions): Promise<ScanResult>;
export function renderReport(scan: ScanResult, format: "terminal" | "json" | "sarif"): string;
export function runCli(io: CliIo): Promise<CommandResult>;
export function compareScans(previous: ScanResult, current: ScanResult): unknown;
export function evaluateSecurityGate(...args: unknown[]): unknown;
