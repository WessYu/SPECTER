import type { ScanResult } from "@specter/types";

export interface JsonReportEnvelope {
  readonly schemaVersion: "1";
  readonly scanId: string;
  readonly target: ScanResult["target"];
  readonly startedAt: string;
  readonly completedAt: string;
  readonly durationMs: number;
  readonly status: ScanResult["status"];
  readonly score: ScanResult["score"];
  readonly summary: ScanResult["summary"];
  readonly findings: ScanResult["findings"];
  readonly modules: ScanResult["modules"];
  readonly errors: ScanResult["errors"];
}

export function toJsonReport(scan: ScanResult): JsonReportEnvelope {
  return {
    schemaVersion: "1",
    scanId: scan.scanId,
    target: scan.target,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    durationMs: scan.durationMs,
    status: scan.status,
    score: scan.score,
    summary: scan.summary,
    findings: scan.findings,
    modules: scan.modules,
    errors: scan.errors,
  };
}

export function serializeJsonReport(scan: ScanResult, pretty = true): string {
  return `${JSON.stringify(toJsonReport(scan), null, pretty ? 2 : 0)}\n`;
}
