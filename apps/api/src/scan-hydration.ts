import type {
  Confidence,
  ExternalDomain,
  Finding,
  FindingCategory,
  FindingSource,
  FindingStatus,
  RouteInfo,
  ScanError,
  ScanModuleResult,
  ScanResult,
  ScanStatus,
  ScanTargetKind,
  Severity,
  SeveritySummary,
} from "@specter/types";

interface FindingRow {
  readonly id: string;
  readonly ruleId: string;
  readonly title: string;
  readonly description: string;
  readonly severity: string;
  readonly category: string;
  readonly confidence: string;
  readonly source: string;
  readonly fingerprint: string;
  readonly remediation?: string | null;
  readonly documentationUrl?: string | null;
  readonly status?: string | null;
  readonly firstDetectedAt?: Date;
  readonly lastDetectedAt?: Date;
}
interface OccurrenceRow {
  readonly file?: string | null;
  readonly line?: number | null;
  readonly column?: number | null;
  readonly url?: string | null;
  readonly evidenceJson?: unknown;
  readonly severity?: string;
  readonly finding: FindingRow;
}
export interface PersistedScanRow {
  readonly id: string;
  readonly targetKind: string;
  readonly targetValue: string;
  readonly status: string;
  readonly score: number;
  readonly schemaVersion: string;
  readonly summaryJson: unknown;
  readonly modulesJson: unknown;
  readonly errorsJson: unknown;
  readonly surfaceJson?: unknown;
  readonly startedAt: Date;
  readonly completedAt: Date;
  readonly durationMs: number;
  readonly occurrences: readonly OccurrenceRow[];
}

const SEVERITIES = new Set<Severity>(["info", "low", "medium", "high", "critical"]);
const CATEGORIES = new Set<FindingCategory>(["secret", "dependency", "source", "configuration", "headers", "cookies", "cors", "csp", "tls", "client-exposure", "third-party", "route", "runtime", "build"]);
const CONFIDENCES = new Set<Confidence>(["low", "medium", "high"]);
const SOURCES = new Set<FindingSource>(["static", "build", "dependency", "remote", "runtime"]);
const STATUSES = new Set<FindingStatus>(["open", "resolved", "suppressed"]);
const SCAN_STATUSES = new Set<ScanStatus>(["queued", "running", "completed", "failed", "cancelled"]);
const TARGET_KINDS = new Set<ScanTargetKind>(["project", "build", "url"]);

function member<T extends string>(value: string, allowed: ReadonlySet<T>, fallback: T): T {
  return allowed.has(value as T) ? value as T : fallback;
}
function object(value: unknown): Readonly<Record<string, unknown>> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Readonly<Record<string, unknown>> : undefined;
}
function number(value: unknown): number | undefined { return typeof value === "number" && Number.isFinite(value) ? value : undefined; }
function string(value: unknown): string | undefined { return typeof value === "string" ? value : undefined; }

function hydrateSummary(value: unknown): SeveritySummary {
  const record = object(value);
  return {
    info: Math.max(0, number(record?.info) ?? 0),
    low: Math.max(0, number(record?.low) ?? 0),
    medium: Math.max(0, number(record?.medium) ?? 0),
    high: Math.max(0, number(record?.high) ?? 0),
    critical: Math.max(0, number(record?.critical) ?? 0),
  };
}
function hydrateModules(value: unknown): readonly ScanModuleResult[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const row = object(item);
    const name = string(row?.name);
    const status = string(row?.status);
    const durationMs = number(row?.durationMs);
    const findingCount = number(row?.findingCount);
    if (!name || !status || !["passed", "warning", "failed", "skipped"].includes(status) || durationMs === undefined || findingCount === undefined) return [];
    return [{ name, status: status as ScanModuleResult["status"], durationMs, findingCount }];
  });
}
function hydrateErrors(value: unknown): readonly ScanError[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    const row = object(item); const code = string(row?.code); const message = string(row?.message); const moduleName = string(row?.module);
    if (!code || !message) return [];
    return [{ code, message, ...(moduleName ? { module: moduleName } : {}), recoverable: row?.recoverable === true }];
  });
}

function hydrateFinding(occurrence: OccurrenceRow): Finding {
  const row = occurrence.finding;
  const location = {
    ...(occurrence.file ? { file: occurrence.file } : {}),
    ...(occurrence.line !== null && occurrence.line !== undefined ? { line: occurrence.line } : {}),
    ...(occurrence.column !== null && occurrence.column !== undefined ? { column: occurrence.column } : {}),
    ...(occurrence.url ? { url: occurrence.url } : {}),
  };
  return {
    schemaVersion: "1",
    id: row.id,
    ruleId: row.ruleId,
    title: row.title,
    description: row.description,
    severity: member(occurrence.severity ?? row.severity, SEVERITIES, "info"),
    category: member(row.category, CATEGORIES, "source"),
    confidence: member(row.confidence, CONFIDENCES, "low"),
    source: member(row.source, SOURCES, "static"),
    fingerprint: row.fingerprint,
    ...(Object.keys(location).length ? { location } : {}),
    ...(occurrence.evidenceJson !== undefined && occurrence.evidenceJson !== null ? { evidence: occurrence.evidenceJson } : {}),
    ...(row.remediation ? { remediation: row.remediation } : {}),
    ...(row.documentationUrl ? { documentationUrl: row.documentationUrl } : {}),
    ...(row.status ? { status: member(row.status, STATUSES, "open") } : {}),
    ...(row.firstDetectedAt ? { firstDetectedAt: row.firstDetectedAt.toISOString() } : {}),
    ...(row.lastDetectedAt ? { lastDetectedAt: row.lastDetectedAt.toISOString() } : {}),
  };
}

function riskBand(score: number): ScanResult["score"]["band"] {
  if (score >= 90) return "excellent";
  if (score >= 75) return "good";
  if (score >= 55) return "fair";
  if (score >= 30) return "poor";
  return "critical";
}

export function hydratePersistedScan(row: PersistedScanRow): ScanResult {
  if (row.schemaVersion !== "1") throw new Error(`Unsupported persisted scan schema: ${row.schemaVersion}`);
  const score = Math.max(0, Math.min(100, Number.isFinite(row.score) ? row.score : 0));
  const surface = hydrateSurface(row.surfaceJson);
  return {
    schemaVersion: "1",
    scanId: row.id,
    target: { kind: member(row.targetKind, TARGET_KINDS, "project"), value: row.targetValue },
    startedAt: row.startedAt.toISOString(),
    completedAt: row.completedAt.toISOString(),
    durationMs: Math.max(0, row.durationMs),
    status: member(row.status, SCAN_STATUSES, "failed"),
    score: { value: score, band: riskBand(score), deductions: [] },
    summary: hydrateSummary(row.summaryJson),
    findings: row.occurrences.map(hydrateFinding),
    modules: hydrateModules(row.modulesJson),
    errors: hydrateErrors(row.errorsJson),
    ...(surface ? { surface } : {}),
  };
}

export interface HydratedSurface { readonly routes: readonly RouteInfo[]; readonly externalDomains: readonly ExternalDomain[]; readonly removedDomains?: readonly string[]; }
export function hydrateSurface(value: unknown): HydratedSurface | undefined {
  const root = object(value);
  if (!root) return undefined;
  const routes: RouteInfo[] = [];
  if (Array.isArray(root.routes)) for (const item of root.routes) {
    const row = object(item); const url = string(row?.url); const method = string(row?.method);
    if (!url || !method) continue;
    const status = number(row?.status);
    const contentType = string(row?.contentType);
    const cors = string(row?.cors);
    routes.push({
      url, method,
      ...(status !== undefined ? { status } : {}),
      ...(contentType ? { contentType } : {}),
      ...(typeof row?.authenticationObservable === "boolean" ? { authenticationObservable: row.authenticationObservable } : {}),
      ...(cors ? { cors } : {}),
    });
  }
  const externalDomains: ExternalDomain[] = [];
  if (Array.isArray(root.externalDomains)) for (const item of root.externalDomains) {
    const row = object(item); const domain = string(row?.domain); const classification = string(row?.classification);
    if (!domain) continue;
    const allowed = new Set<ExternalDomain["classification"]>(["first-party", "known-third-party", "unknown", "newly-introduced"]);
    const firstOccurrence = string(row?.firstOccurrence);
    const page = string(row?.page);
    const relatedScript = string(row?.relatedScript);
    externalDomains.push({
      domain,
      classification: member(classification ?? "unknown", allowed, "unknown"),
      resourceTypes: Array.isArray(row?.resourceTypes) ? row.resourceTypes.filter((entry): entry is string => typeof entry === "string") : [],
      ...(firstOccurrence ? { firstOccurrence } : {}),
      ...(page ? { page } : {}),
      ...(relatedScript ? { relatedScript } : {}),
    });
  }
  const removedDomains = Array.isArray(root.removedDomains) ? root.removedDomains.filter((entry): entry is string => typeof entry === "string") : undefined;
  return { routes, externalDomains, ...(removedDomains ? { removedDomains } : {}) };
}
