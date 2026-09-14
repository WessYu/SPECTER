import type {
  Finding,
  ScanDiff,
  ScanResult,
  SecurityRegression,
  Severity,
  SeverityChange,
} from "@specter/types";

const rank: Readonly<Record<Severity, number>> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function compareScans(previous: ScanResult, current: ScanResult): ScanDiff {
  const previousByFingerprint = new Map(
    previous.findings.map((finding) => [finding.fingerprint, finding]),
  );
  const currentByFingerprint = new Map(
    current.findings.map((finding) => [finding.fingerprint, finding]),
  );
  const newlyIntroduced: Finding[] = [];
  const unchanged: Finding[] = [];
  const resolved: Finding[] = [];
  const severityChanged: SeverityChange[] = [];

  for (const finding of current.findings) {
    const before = previousByFingerprint.get(finding.fingerprint);
    if (!before) {
      newlyIntroduced.push(finding);
      continue;
    }
    if (before.severity !== finding.severity) {
      severityChanged.push({
        fingerprint: finding.fingerprint,
        previous: before.severity,
        current: finding.severity,
        finding,
      });
    } else unchanged.push(finding);
  }

  for (const finding of previous.findings)
    if (!currentByFingerprint.has(finding.fingerprint)) resolved.push(finding);

  const bySeverityThenFingerprint = (a: Finding, b: Finding) =>
    rank[b.severity] - rank[a.severity] || a.fingerprint.localeCompare(b.fingerprint);
  newlyIntroduced.sort(bySeverityThenFingerprint);
  unchanged.sort(bySeverityThenFingerprint);
  resolved.sort(bySeverityThenFingerprint);
  severityChanged.sort(
    (a, b) => rank[b.current] - rank[a.current] || a.fingerprint.localeCompare(b.fingerprint),
  );

  return {
    previousScanId: previous.scanId,
    currentScanId: current.scanId,
    score: {
      previous: previous.score.value,
      current: current.score.value,
      delta: Math.round((current.score.value - previous.score.value) * 10) / 10,
    },
    new: newlyIntroduced,
    unchanged,
    resolved,
    severityChanged,
  };
}

export function evaluateRegression(previous: ScanResult, current: ScanResult): SecurityRegression {
  const diff = compareScans(previous, current);
  const scoreDrop = Math.max(0, Math.round((previous.score.value - current.score.value) * 10) / 10);
  const newHighOrCritical = diff.new.filter(
    (finding) => finding.severity === "high" || finding.severity === "critical",
  ).length;
  const severityIncreases = diff.severityChanged.filter(
    (change) => rank[change.current] > rank[change.previous],
  ).length;
  return {
    regressed: scoreDrop > 0 || newHighOrCritical > 0 || severityIncreases > 0,
    scoreDrop,
    newHighOrCritical,
    severityIncreases,
    diff,
  };
}
