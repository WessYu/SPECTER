import type { Finding, ScanResult, Severity } from "@specter/types";

const SARIF_VERSION = "2.1.0" as const;
const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

function sarifLevel(severity: Severity): "error" | "warning" | "note" | "none" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  if (severity === "info") return "note";
  return "none";
}

function ruleFor(finding: Finding) {
  return {
    id: finding.ruleId,
    name: finding.title.replace(/[^A-Za-z0-9]+/g, " ").trim().replace(/\s+(.)/g, (_, char: string) => char.toUpperCase()),
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.description },
    help: {
      text: finding.remediation ?? "Review this finding and apply the documented remediation.",
      ...(finding.documentationUrl ? { markdown: `[Documentation](${finding.documentationUrl})\n\n${finding.remediation ?? ""}` } : {}),
    },
    properties: { category: finding.category, defaultSeverity: finding.severity, confidence: finding.confidence },
  };
}

function locationFor(finding: Finding) {
  if (!finding.location?.file) return undefined;
  return {
    physicalLocation: {
      artifactLocation: { uri: finding.location.file.replaceAll("\\", "/"), uriBaseId: "%SRCROOT%" },
      ...(finding.location.line !== undefined ? {
        region: {
          startLine: finding.location.line,
          ...(finding.location.column !== undefined ? { startColumn: finding.location.column } : {}),
        },
      } : {}),
    },
  };
}

export function toSarif(scan: ScanResult) {
  const ruleMap = new Map(scan.findings.map((finding) => [finding.ruleId, ruleFor(finding)]));
  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [{
      tool: { driver: { name: "SPECTER", semanticVersion: "0.1.0", informationUri: "https://github.com/WessYu/SPECTER", rules: [...ruleMap.values()] } },
      originalUriBaseIds: { "%SRCROOT%": { uri: "file:///" } },
      invocations: [{ executionSuccessful: scan.status === "completed", startTimeUtc: scan.startedAt, endTimeUtc: scan.completedAt }],
      results: scan.findings.map((finding) => ({
        ruleId: finding.ruleId,
        level: sarifLevel(finding.severity),
        message: { text: finding.description },
        fingerprints: { "specter/v1": finding.fingerprint },
        partialFingerprints: { "primaryLocationLineHash": finding.fingerprint.slice(0, 32) },
        ...(locationFor(finding) ? { locations: [locationFor(finding)] } : {}),
        properties: { severity: finding.severity, confidence: finding.confidence, category: finding.category, source: finding.source },
      })),
    }],
  } as const;
}

export function serializeSarif(scan: ScanResult, pretty = true): string {
  return `${JSON.stringify(toSarif(scan), null, pretty ? 2 : 0)}\n`;
}
