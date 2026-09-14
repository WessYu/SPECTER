import type { ScanResult } from "@specter/types";

export interface JsonReportEnvelope {
  readonly schemaVersion: "1";
  readonly scanId: string;
  readonly scanType?: ScanResult["scanType"];
  readonly target: ScanResult["target"];
  readonly authorization?: ScanResult["authorization"];
  readonly profile?: ScanResult["profile"];
  readonly budget?: ScanResult["budget"];
  readonly endpointCount?: number;
  readonly confirmedCount?: number;
  readonly potentialCount?: number;
  readonly regressionDelta?: number;
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;
  readonly status: ScanResult["status"];
  readonly score: ScanResult["score"];
  readonly summary: ScanResult["summary"];
  readonly findings: ScanResult["findings"];
  readonly modules: ScanResult["modules"];
  readonly errors: ScanResult["errors"];
  readonly surface?: ScanResult["surface"];
}

export function toJsonReport(scan: ScanResult): JsonReportEnvelope {
  return {
    schemaVersion: "1",
    scanId: scan.scanId,
    ...(scan.scanType ? { scanType: scan.scanType } : {}),
    target: scan.target,
    ...(scan.authorization
      ? { authorization: scan.authorization }
      : {}),
    ...(scan.profile ? { profile: scan.profile } : {}),
    ...(scan.budget ? { budget: scan.budget } : {}),
    ...(scan.endpointCount !== undefined
      ? { endpointCount: scan.endpointCount }
      : {}),
    ...(scan.confirmedCount !== undefined
      ? { confirmedCount: scan.confirmedCount }
      : {}),
    ...(scan.potentialCount !== undefined
      ? { potentialCount: scan.potentialCount }
      : {}),
    ...(scan.regressionDelta !== undefined
      ? { regressionDelta: scan.regressionDelta }
      : {}),
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    durationMs: scan.durationMs,
    status: scan.status,
    score: scan.score,
    summary: scan.summary,
    findings: scan.findings,
    modules: scan.modules,
    errors: scan.errors,
    ...(scan.surface ? { surface: scan.surface } : {}),
  };
}

export function serializeJsonReport(
  scan: ScanResult,
  pretty = true,
): string {
  return `${JSON.stringify(
    toJsonReport(scan),
    null,
    pretty ? 2 : 0,
  )}\n`;
}
