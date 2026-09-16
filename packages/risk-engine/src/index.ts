import type {
  Confidence,
  Finding,
  FindingCategory,
  RiskDeduction,
  RiskScore,
  Severity,
  SeveritySummary,
} from "@specter/types";

const severityWeight: Readonly<Record<Severity, number>> = {
  critical: 28,
  high: 16,
  medium: 8,
  low: 3,
  info: 0,
};

const confidenceMultiplier: Readonly<Record<Confidence, number>> = {
  confirmed: 1.18,
  high: 1,
  medium: 0.72,
  low: 0.4,
};

const categoryMultiplier: Readonly<Record<FindingCategory, number>> = {
  secret: 1.25,
  dependency: 1,
  source: 1,
  configuration: 0.8,
  headers: 0.75,
  cookies: 0.9,
  cors: 1,
  csp: 0.85,
  tls: 1.1,
  "client-exposure": 1.15,
  "third-party": 0.7,
  route: 0.45,
  runtime: 1,
  build: 1,
};

export interface RiskContext {
  readonly baselineFingerprints?: ReadonlySet<string>;
}

export function summarizeSeverity(findings: readonly Finding[]): SeveritySummary {
  const summary: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) summary[finding.severity] += 1;
  return summary;
}

function scoreBand(value: number): RiskScore["band"] {
  if (value >= 90) return "excellent";
  if (value >= 75) return "good";
  if (value >= 55) return "fair";
  if (value >= 30) return "poor";
  return "critical";
}

function deductionFor(finding: Finding, context: RiskContext): RiskDeduction {
  const isNew = context.baselineFingerprints
    ? !context.baselineFingerprints.has(finding.fingerprint)
    : false;
  const noveltyMultiplier = isNew ? 1.12 : 1;
  const phaseMultiplier =
    finding.phase === "production" ? 1.12 : finding.phase === "preview" ? 1.05 : 1;
  const scannerMultiplier = finding.scanner === "active" ? 1.12 : 1;
  const validationMultiplier =
    finding.status === "confirmed"
      ? 1.12
      : finding.status === "potential"
        ? 0.88
        : finding.status === "inconclusive"
          ? 0
          : 1;
  const raw =
    severityWeight[finding.severity] *
    confidenceMultiplier[finding.confidence] *
    categoryMultiplier[finding.category] *
    noveltyMultiplier *
    phaseMultiplier *
    scannerMultiplier *
    validationMultiplier;
  const points = Math.min(35, Math.max(0, Math.round(raw * 10) / 10));
  return {
    ruleId: finding.ruleId,
    fingerprint: finding.fingerprint,
    points,
    reason: `${finding.severity}/${finding.confidence} ${finding.category}${isNew ? " (new)" : ""}`,
  };
}

export function calculateRiskScore(
  findings: readonly Finding[],
  context: RiskContext = {},
): RiskScore {
  const unique = new Map<string, Finding>();
  for (const finding of findings) {
    if (
      finding.status === "suppressed" ||
      finding.status === "inconclusive" ||
      finding.status === "resolved"
    )
      continue;
    const current = unique.get(finding.fingerprint);
    if (!current || severityWeight[finding.severity] > severityWeight[current.severity])
      unique.set(finding.fingerprint, finding);
  }

  const deductions = [...unique.values()]
    .map((finding) => deductionFor(finding, context))
    .filter((deduction) => deduction.points > 0)
    .sort((a, b) => b.points - a.points || a.fingerprint.localeCompare(b.fingerprint));

  // Diminishing aggregation avoids pretending that 20 low findings equal multiple critical flaws.
  let penalty = 0;
  for (let index = 0; index < deductions.length; index += 1) {
    const deduction = deductions[index];
    if (!deduction) continue;
    const diminishing = 1 / (1 + index * 0.055);
    penalty += deduction.points * diminishing;
  }

  const value = Math.max(0, Math.min(100, Math.round((100 - penalty) * 10) / 10));
  return { value, band: scoreBand(value), deductions };
}

export const riskModel = Object.freeze({
  severityWeight,
  confidenceMultiplier,
  categoryMultiplier,
  newFindingMultiplier: 1.12,
  activeScannerMultiplier: 1.12,
  confirmedValidationMultiplier: 1.12,
  potentialValidationMultiplier: 0.88,
  productionPhaseMultiplier: 1.12,
  previewPhaseMultiplier: 1.05,
  maxSingleFindingDeduction: 35,
});
