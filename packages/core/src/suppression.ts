import type { Finding, Suppression } from "@specter/types";

export interface SuppressionResult {
  readonly findings: readonly Finding[];
  readonly suppressed: readonly Finding[];
}

export function matchesSuppression(
  finding: Finding,
  suppression: Suppression,
  now = new Date(),
): boolean {
  if (suppression.expiresAt) {
    const expires = Date.parse(suppression.expiresAt);
    if (!Number.isFinite(expires) || expires <= now.getTime()) return false;
  }
  const hasSelector = Boolean(suppression.ruleId || suppression.fingerprint);
  if (!hasSelector) return false;
  if (suppression.ruleId && suppression.ruleId !== finding.ruleId) return false;
  if (suppression.fingerprint && suppression.fingerprint !== finding.fingerprint) return false;
  return true;
}

export function applySuppressions(
  findings: readonly Finding[],
  suppressions: readonly Suppression[],
  now = new Date(),
): SuppressionResult {
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const finding of findings) {
    if (suppressions.some((suppression) => matchesSuppression(finding, suppression, now))) {
      suppressed.push({ ...finding, status: "suppressed" });
    } else {
      active.push(finding.status === "suppressed" ? { ...finding, status: "open" } : finding);
    }
  }
  return { findings: active, suppressed };
}
