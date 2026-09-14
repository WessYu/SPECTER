import type { Finding, ScanResult, Severity } from "@specter/types";
import { compareScans } from "./regression.js";

const rank: Readonly<Record<Severity, number>> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface SecurityGatePolicy {
  readonly failOn: Severity | "none";
  readonly maxScoreDrop: number;
}

export interface SecurityGateFailure {
  readonly code: "NEW_FINDING" | "SEVERITY_INCREASE" | "SCORE_DROP";
  readonly message: string;
  readonly finding?: Finding;
}

export interface SecurityGateResult {
  readonly passed: boolean;
  readonly failures: readonly SecurityGateFailure[];
}

export function evaluateSecurityGate(
  current: ScanResult,
  baseline: ScanResult | undefined,
  policy: SecurityGatePolicy,
): SecurityGateResult {
  const failures: SecurityGateFailure[] = [];
  if (!baseline) {
    if (policy.failOn !== "none") {
      const threshold = rank[policy.failOn];
      for (const finding of current.findings) {
        if (finding.status === "suppressed" || finding.status === "inconclusive" || rank[finding.severity] < threshold) continue;
        failures.push({
          code: "NEW_FINDING",
          message: `${finding.severity.toUpperCase()} ${finding.ruleId}: ${finding.title}`,
          finding,
        });
      }
    }
    return { passed: failures.length === 0, failures };
  }

  const diff = compareScans(baseline, current);
  if (policy.failOn !== "none") {
    const threshold = rank[policy.failOn];
    for (const finding of diff.new) {
      if (finding.status !== "suppressed" && finding.status !== "inconclusive" && rank[finding.severity] >= threshold)
        failures.push({
          code: "NEW_FINDING",
          message: `New ${finding.severity.toUpperCase()} finding: ${finding.title}`,
          finding,
        });
    }
    for (const change of diff.severityChanged) {
      if (rank[change.current] > rank[change.previous] && rank[change.current] >= threshold)
        failures.push({
          code: "SEVERITY_INCREASE",
          message: `Severity increased ${change.previous} → ${change.current}: ${change.finding.title}`,
          finding: change.finding,
        });
    }
  }
  const scoreDrop = baseline.score.value - current.score.value;
  if (scoreDrop > policy.maxScoreDrop)
    failures.push({
      code: "SCORE_DROP",
      message: `Security score dropped by ${scoreDrop.toFixed(1)} points (allowed ${policy.maxScoreDrop}).`,
    });
  return { passed: failures.length === 0, failures };
}
