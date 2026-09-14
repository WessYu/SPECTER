export const SPECTER_SCHEMA_VERSION = "1" as const;

export type SchemaVersion = typeof SPECTER_SCHEMA_VERSION;
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type FindingCategory =
  | "secret"
  | "dependency"
  | "source"
  | "configuration"
  | "headers"
  | "cookies"
  | "cors"
  | "csp"
  | "tls"
  | "client-exposure"
  | "third-party"
  | "route"
  | "runtime"
  | "build";
export type FindingSource = "static" | "build" | "dependency" | "remote" | "runtime";
export type FindingStatus = "open" | "resolved" | "suppressed";
export type ScanTargetKind = "project" | "build" | "url";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface FindingLocation {
  readonly file?: string;
  readonly line?: number;
  readonly column?: number;
  readonly url?: string;
}

export interface Finding {
  readonly schemaVersion: SchemaVersion;
  readonly id: string;
  readonly ruleId: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: FindingCategory;
  readonly confidence: Confidence;
  readonly source: FindingSource;
  readonly fingerprint: string;
  readonly location?: FindingLocation;
  readonly evidence?: unknown;
  readonly remediation?: string;
  readonly documentationUrl?: string;
  readonly status?: FindingStatus;
  readonly firstDetectedAt?: string;
  readonly lastDetectedAt?: string;
}

export interface ScanTarget {
  readonly kind: ScanTargetKind;
  readonly value: string;
  readonly displayName?: string;
}

export interface SeveritySummary {
  readonly info: number;
  readonly low: number;
  readonly medium: number;
  readonly high: number;
  readonly critical: number;
}

export interface RiskScore {
  readonly value: number;
  readonly band: "excellent" | "good" | "fair" | "poor" | "critical";
  readonly deductions: readonly RiskDeduction[];
}

export interface RiskDeduction {
  readonly ruleId: string;
  readonly fingerprint: string;
  readonly points: number;
  readonly reason: string;
}

export interface ScanSurface {
  readonly routes: readonly RouteInfo[];
  readonly externalDomains: readonly ExternalDomain[];
  readonly removedDomains?: readonly string[];
}

export interface ScanResult {
  readonly schemaVersion: SchemaVersion;
  readonly scanId: string;
  readonly target: ScanTarget;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;
  readonly status: ScanStatus;
  readonly score: RiskScore;
  readonly summary: SeveritySummary;
  readonly findings: readonly Finding[];
  readonly modules: readonly ScanModuleResult[];
  readonly errors: readonly ScanError[];
  readonly surface?: ScanSurface;
}

export interface ScanModuleResult {
  readonly name: string;
  readonly status: "passed" | "warning" | "failed" | "skipped";
  readonly durationMs: number;
  readonly findingCount: number;
}

export interface ScanError {
  readonly code: string;
  readonly message: string;
  readonly module?: string;
  readonly recoverable: boolean;
}

export interface Scan {
  readonly id: string;
  readonly organizationId?: string;
  readonly projectId?: string;
  readonly result: ScanResult;
}

export interface RuleMetadata {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly category: FindingCategory;
  readonly defaultSeverity: Severity;
  readonly defaultConfidence: Confidence;
  readonly remediation: string;
  readonly documentationUrl?: string;
  readonly falsePositiveGuidance?: string;
}

export interface RuleContext {
  readonly target: ScanTarget;
  readonly file?: { readonly path: string; readonly content: string };
  readonly metadata?: Readonly<Record<string, unknown>>;
}

export interface Rule {
  readonly metadata: RuleMetadata;
  evaluate(context: RuleContext): readonly Finding[] | Promise<readonly Finding[]>;
}

export interface ScanDiff {
  readonly previousScanId: string;
  readonly currentScanId: string;
  readonly score: { readonly previous: number; readonly current: number; readonly delta: number };
  readonly new: readonly Finding[];
  readonly unchanged: readonly Finding[];
  readonly resolved: readonly Finding[];
  readonly severityChanged: readonly SeverityChange[];
}

export interface SeverityChange {
  readonly fingerprint: string;
  readonly previous: Severity;
  readonly current: Severity;
  readonly finding: Finding;
}

export interface SecurityRegression {
  readonly regressed: boolean;
  readonly scoreDrop: number;
  readonly newHighOrCritical: number;
  readonly severityIncreases: number;
  readonly diff: ScanDiff;
}

export interface ExternalDomain {
  readonly domain: string;
  readonly classification: "first-party" | "known-third-party" | "unknown" | "newly-introduced";
  readonly resourceTypes: readonly string[];
  readonly firstOccurrence?: string;
  readonly page?: string;
  readonly relatedScript?: string;
}

export interface RouteInfo {
  readonly url: string;
  readonly method: string;
  readonly status?: number;
  readonly contentType?: string;
  readonly authenticationObservable?: boolean;
  readonly cors?: string;
  readonly headers?: Readonly<Record<string, string>>;
}

export interface DependencyFinding extends Finding {
  readonly category: "dependency";
  readonly package: string;
  readonly installedVersion: string;
  readonly patchedVersion?: string;
  readonly advisory: string;
  readonly directDependency: boolean;
}

export interface Suppression {
  readonly ruleId?: string;
  readonly fingerprint?: string;
  readonly reason: string;
  readonly expiresAt?: string;
}
