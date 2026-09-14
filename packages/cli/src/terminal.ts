import type { Finding, Severity } from "@specter/types";

const ORDER: readonly Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityCounts(findings: readonly Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

export function renderLocalScan(input: {
  readonly target: string;
  readonly filesScanned: number;
  readonly findings: readonly Finding[];
  readonly dependencyCount: number;
}): string {
  const counts = severityCounts(input.findings);
  const lines = [
    "SPECTER",
    "Application security from source to production.",
    "",
    "Target",
    input.target,
    "",
    "SOURCE",
    `✓ ${input.filesScanned} files scanned`,
    "",
    "DEPENDENCIES",
    `${input.dependencyCount} installed dependencies inventoried`,
    "",
    "FINDINGS",
  ];
  for (const severity of ORDER) lines.push(`${severity.toUpperCase().padEnd(10)} ${counts[severity]}`);
  lines.push("", `${input.findings.length} findings require review.`);
  return `${lines.join("\n")}\n`;
}
