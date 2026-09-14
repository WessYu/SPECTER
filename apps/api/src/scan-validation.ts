import type {
  Confidence,
  Finding,
  FindingCategory,
  FindingSource,
  FindingStatus,
  RiskScore,
  ScanError,
  ScanModuleResult,
  ScanResult,
  ScanStatus,
  ScanTargetKind,
  Severity,
  SeveritySummary,
} from "@specter/types";

const SEVERITIES = new Set<Severity>(["info", "low", "medium", "high", "critical"]);
const CATEGORIES = new Set<FindingCategory>([
  "secret",
  "dependency",
  "source",
  "configuration",
  "headers",
  "cookies",
  "cors",
  "csp",
  "tls",
  "client-exposure",
  "third-party",
  "route",
  "runtime",
  "build",
]);
const CONFIDENCES = new Set<Confidence>(["low", "medium", "high"]);
const SOURCES = new Set<FindingSource>(["static", "build", "dependency", "remote", "runtime"]);
const FINDING_STATUSES = new Set<FindingStatus>(["open", "resolved", "suppressed"]);
const SCAN_STATUSES = new Set<ScanStatus>([
  "queued",
  "running",
  "completed",
  "failed",
  "cancelled",
]);
const TARGET_KINDS = new Set<ScanTargetKind>(["project", "build", "url"]);
const MODULE_STATUSES = new Set<ScanModuleResult["status"]>([
  "passed",
  "warning",
  "failed",
  "skipped",
]);
const SCORE_BANDS = new Set<RiskScore["band"]>(["excellent", "good", "fair", "poor", "critical"]);
const MAX_FINDINGS = 10_000;
const MAX_MODULES = 100;
const MAX_ERRORS = 100;
const MAX_ROUTES = 5_000;
const MAX_DOMAINS = 5_000;
const MAX_STRING = 8_192;

function record(value: unknown, name: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${name} must be an object.`);
  return value as Record<string, unknown>;
}
function string(value: unknown, name: string, max = MAX_STRING): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max)
    throw new Error(`${name} must be a non-empty string up to ${max} characters.`);
  return value;
}
function finite(
  value: unknown,
  name: string,
  min = Number.NEGATIVE_INFINITY,
  max = Number.POSITIVE_INFINITY,
): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < min || value > max)
    throw new Error(`${name} must be a finite number between ${min} and ${max}.`);
  return value;
}
function integer(value: unknown, name: string, min = 0, max = 2_147_483_647): number {
  const number = finite(value, name, min, max);
  if (!Number.isInteger(number)) throw new Error(`${name} must be an integer.`);
  return number;
}
function enumValue<T extends string>(value: unknown, allowed: ReadonlySet<T>, name: string): T {
  if (typeof value !== "string" || !allowed.has(value as T)) throw new Error(`${name} is invalid.`);
  return value as T;
}
function dateTime(value: unknown, name: string): string {
  const input = string(value, name, 64);
  const parsed = Date.parse(input);
  if (!Number.isFinite(parsed)) throw new Error(`${name} must be a valid date-time.`);
  return new Date(parsed).toISOString();
}
function optionalString(value: unknown, name: string, max = MAX_STRING): string | undefined {
  return value === undefined || value === null ? undefined : string(value, name, max);
}

function validateSummary(value: unknown): SeveritySummary {
  const row = record(value, "summary");
  return {
    info: integer(row.info, "summary.info", 0, MAX_FINDINGS),
    low: integer(row.low, "summary.low", 0, MAX_FINDINGS),
    medium: integer(row.medium, "summary.medium", 0, MAX_FINDINGS),
    high: integer(row.high, "summary.high", 0, MAX_FINDINGS),
    critical: integer(row.critical, "summary.critical", 0, MAX_FINDINGS),
  };
}

function validateScore(value: unknown): RiskScore {
  const row = record(value, "score");
  const deductionsRaw = Array.isArray(row.deductions) ? row.deductions : [];
  if (deductionsRaw.length > MAX_FINDINGS) throw new Error("score.deductions is too large.");
  return {
    value: finite(row.value, "score.value", 0, 100),
    band: enumValue(row.band, SCORE_BANDS, "score.band"),
    deductions: deductionsRaw.map((item, index) => {
      const deduction = record(item, `score.deductions[${index}]`);
      return {
        ruleId: string(deduction.ruleId, `score.deductions[${index}].ruleId`, 200),
        fingerprint: string(deduction.fingerprint, `score.deductions[${index}].fingerprint`, 256),
        points: finite(deduction.points, `score.deductions[${index}].points`, 0, 100),
        reason: string(deduction.reason, `score.deductions[${index}].reason`, 1_000),
      };
    }),
  };
}

function validateFinding(value: unknown, index: number): Finding {
  const row = record(value, `findings[${index}]`);
  const locationRow =
    row.location === undefined ? undefined : record(row.location, `findings[${index}].location`);
  const locationFile = locationRow
    ? optionalString(locationRow.file, `findings[${index}].location.file`, 2_048)
    : undefined;
  const locationUrl = locationRow
    ? optionalString(locationRow.url, `findings[${index}].location.url`, 4_096)
    : undefined;
  const location = locationRow
    ? {
        ...(locationFile ? { file: locationFile } : {}),
        ...(locationRow.line !== undefined
          ? { line: integer(locationRow.line, `findings[${index}].location.line`, 1) }
          : {}),
        ...(locationRow.column !== undefined
          ? { column: integer(locationRow.column, `findings[${index}].location.column`, 1) }
          : {}),
        ...(locationUrl ? { url: locationUrl } : {}),
      }
    : undefined;
  const remediation = optionalString(row.remediation, `findings[${index}].remediation`, 8_192);
  const documentationUrl = optionalString(
    row.documentationUrl,
    `findings[${index}].documentationUrl`,
    4_096,
  );
  const status =
    row.status === undefined
      ? undefined
      : enumValue(row.status, FINDING_STATUSES, `findings[${index}].status`);
  return {
    schemaVersion: "1",
    id: string(row.id, `findings[${index}].id`, 256),
    ruleId: string(row.ruleId, `findings[${index}].ruleId`, 200),
    title: string(row.title, `findings[${index}].title`, 500),
    description: string(row.description, `findings[${index}].description`, 8_192),
    severity: enumValue(row.severity, SEVERITIES, `findings[${index}].severity`),
    category: enumValue(row.category, CATEGORIES, `findings[${index}].category`),
    confidence: enumValue(row.confidence, CONFIDENCES, `findings[${index}].confidence`),
    source: enumValue(row.source, SOURCES, `findings[${index}].source`),
    fingerprint: string(row.fingerprint, `findings[${index}].fingerprint`, 256),
    ...(location && Object.keys(location).length ? { location } : {}),
    ...(row.evidence !== undefined ? { evidence: row.evidence } : {}),
    ...(remediation ? { remediation } : {}),
    ...(documentationUrl ? { documentationUrl } : {}),
    ...(status ? { status } : {}),
    ...(row.firstDetectedAt !== undefined
      ? { firstDetectedAt: dateTime(row.firstDetectedAt, `findings[${index}].firstDetectedAt`) }
      : {}),
    ...(row.lastDetectedAt !== undefined
      ? { lastDetectedAt: dateTime(row.lastDetectedAt, `findings[${index}].lastDetectedAt`) }
      : {}),
  };
}

function validateModules(value: unknown): readonly ScanModuleResult[] {
  if (!Array.isArray(value) || value.length > MAX_MODULES)
    throw new Error(`modules must be an array with at most ${MAX_MODULES} items.`);
  return value.map((item, index) => {
    const row = record(item, `modules[${index}]`);
    return {
      name: string(row.name, `modules[${index}].name`, 200),
      status: enumValue(row.status, MODULE_STATUSES, `modules[${index}].status`),
      durationMs: integer(row.durationMs, `modules[${index}].durationMs`),
      findingCount: integer(row.findingCount, `modules[${index}].findingCount`, 0, MAX_FINDINGS),
    };
  });
}

function validateErrors(value: unknown): readonly ScanError[] {
  if (!Array.isArray(value) || value.length > MAX_ERRORS)
    throw new Error(`errors must be an array with at most ${MAX_ERRORS} items.`);
  return value.map((item, index) => {
    const row = record(item, `errors[${index}]`);
    const moduleName = optionalString(row.module, `errors[${index}].module`, 200);
    if (typeof row.recoverable !== "boolean")
      throw new Error(`errors[${index}].recoverable must be boolean.`);
    return {
      code: string(row.code, `errors[${index}].code`, 200),
      message: string(row.message, `errors[${index}].message`, 2_000),
      ...(moduleName ? { module: moduleName } : {}),
      recoverable: row.recoverable,
    };
  });
}

function validateSurface(value: unknown): ScanResult["surface"] {
  if (value === undefined) return undefined;
  const root = record(value, "surface");
  if (!Array.isArray(root.routes) || root.routes.length > MAX_ROUTES)
    throw new Error(`surface.routes must contain at most ${MAX_ROUTES} routes.`);
  if (!Array.isArray(root.externalDomains) || root.externalDomains.length > MAX_DOMAINS)
    throw new Error(`surface.externalDomains must contain at most ${MAX_DOMAINS} domains.`);
  const routes = root.routes.map((item, index) => {
    const row = record(item, `surface.routes[${index}]`);
    const contentType = optionalString(
      row.contentType,
      `surface.routes[${index}].contentType`,
      500,
    );
    const cors = optionalString(row.cors, `surface.routes[${index}].cors`, 2_048);
    return {
      url: string(row.url, `surface.routes[${index}].url`, 4_096),
      method: string(row.method, `surface.routes[${index}].method`, 16).toUpperCase(),
      ...(row.status !== undefined
        ? { status: integer(row.status, `surface.routes[${index}].status`, 0, 999) }
        : {}),
      ...(contentType ? { contentType } : {}),
      ...(typeof row.authenticationObservable === "boolean"
        ? { authenticationObservable: row.authenticationObservable }
        : {}),
      ...(cors ? { cors } : {}),
    };
  });
  const classifications = new Set([
    "first-party",
    "known-third-party",
    "unknown",
    "newly-introduced",
  ] as const);
  const externalDomains = root.externalDomains.map((item, index) => {
    const row = record(item, `surface.externalDomains[${index}]`);
    if (!Array.isArray(row.resourceTypes) || row.resourceTypes.length > 100)
      throw new Error(`surface.externalDomains[${index}].resourceTypes is invalid.`);
    const firstOccurrence = optionalString(
      row.firstOccurrence,
      `surface.externalDomains[${index}].firstOccurrence`,
      4_096,
    );
    const page = optionalString(row.page, `surface.externalDomains[${index}].page`, 4_096);
    const relatedScript = optionalString(
      row.relatedScript,
      `surface.externalDomains[${index}].relatedScript`,
      4_096,
    );
    return {
      domain: string(row.domain, `surface.externalDomains[${index}].domain`, 253).toLowerCase(),
      classification: enumValue(
        row.classification,
        classifications,
        `surface.externalDomains[${index}].classification`,
      ),
      resourceTypes: row.resourceTypes.map((entry, itemIndex) =>
        string(entry, `surface.externalDomains[${index}].resourceTypes[${itemIndex}]`, 100),
      ),
      ...(firstOccurrence ? { firstOccurrence } : {}),
      ...(page ? { page } : {}),
      ...(relatedScript ? { relatedScript } : {}),
    };
  });
  const removedDomains =
    root.removedDomains === undefined
      ? undefined
      : (() => {
          if (!Array.isArray(root.removedDomains) || root.removedDomains.length > MAX_DOMAINS)
            throw new Error("surface.removedDomains is invalid.");
          return root.removedDomains.map((entry, index) =>
            string(entry, `surface.removedDomains[${index}]`, 253).toLowerCase(),
          );
        })();
  return { routes, externalDomains, ...(removedDomains ? { removedDomains } : {}) };
}

export function validateScanResult(value: unknown): ScanResult {
  const row = record(value, "result");
  if (row.schemaVersion !== "1") throw new Error("Only scan schemaVersion '1' is supported.");
  const target = record(row.target, "target");
  const findingsRaw = row.findings;
  if (!Array.isArray(findingsRaw) || findingsRaw.length > MAX_FINDINGS)
    throw new Error(`findings must be an array with at most ${MAX_FINDINGS} items.`);
  const startedAt = dateTime(row.startedAt, "startedAt");
  const completedAt = dateTime(row.completedAt, "completedAt");
  if (Date.parse(completedAt) < Date.parse(startedAt))
    throw new Error("completedAt must not be earlier than startedAt.");
  const displayName = optionalString(target.displayName, "target.displayName", 500);
  const surface = validateSurface(row.surface);
  return {
    schemaVersion: "1",
    scanId: string(row.scanId, "scanId", 256),
    target: {
      kind: enumValue(target.kind, TARGET_KINDS, "target.kind"),
      value: string(target.value, "target.value", 4_096),
      ...(displayName ? { displayName } : {}),
    },
    startedAt,
    completedAt,
    durationMs: integer(row.durationMs, "durationMs"),
    status: enumValue(row.status, SCAN_STATUSES, "status"),
    score: validateScore(row.score),
    summary: validateSummary(row.summary),
    findings: findingsRaw.map(validateFinding),
    modules: validateModules(row.modules),
    errors: validateErrors(row.errors),
    ...(surface ? { surface } : {}),
  };
}
