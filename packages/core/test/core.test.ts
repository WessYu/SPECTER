import { describe, expect, it } from "vitest";
import { applySuppressions, compareScans, createFinding, createFingerprint, evaluateSecurityGate, redactEvidence } from "../src/index.js";
import type { Finding, RuleMetadata, ScanResult } from "@specter/types";

const rule: RuleMetadata = { id: "TEST-001", title: "Test finding", description: "Test", category: "source", defaultSeverity: "high", defaultConfidence: "high", remediation: "Fix it." };
function scan(id: string, score: number, findings: readonly Finding[]): ScanResult {
  return { schemaVersion: "1", scanId: id, target: { kind: "project", value: "/tmp/app" }, startedAt: "2026-01-01T00:00:00.000Z", completedAt: "2026-01-01T00:00:01.000Z", durationMs: 1000, status: "completed", score: { value: score, band: score >= 75 ? "good" : "fair", deductions: [] }, summary: { info: 0, low: 0, medium: 0, high: findings.length, critical: 0 }, findings, modules: [], errors: [] };
}

describe("core security primitives", () => {
  it("creates stable fingerprints independent of query order", () => {
    const a = createFingerprint({ ruleId: "R", category: "source", source: "static", file: "./SRC\\a.ts", url: "https://example.com/x?b=2&a=1" });
    const b = createFingerprint({ ruleId: "R", category: "source", source: "static", file: "src/a.ts", url: "https://example.com/x?a=1&b=2" });
    expect(a).toBe(b);
  });

  it("redacts nested sensitive values", () => {
    expect(redactEvidence({ token: "spt_test_Q7m9Z2x8N4v6K1r5T3w0", secret: "spt_test_Q7m9Z2x8N4v6K1r5T3w0" })).toEqual({ token: "[REDACTED]", secret: "[REDACTED]" });
  });

  it("applies explicit suppressions and ignores expired ones", () => {
    const finding = createFinding({ metadata: rule, source: "static", location: { file: "src/a.ts", line: 1 } });
    const active = applySuppressions([finding], [{ ruleId: rule.id, reason: "accepted risk" }], new Date("2026-01-01"));
    expect(active.findings).toHaveLength(0);
    expect(active.suppressed[0]?.status).toBe("suppressed");
    const expired = applySuppressions([finding], [{ ruleId: rule.id, reason: "expired risk", expiresAt: "2025-01-01T00:00:00.000Z" }], new Date("2026-01-01"));
    expect(expired.findings).toHaveLength(1);
  });

  it("detects regression and fails a new-high gate", () => {
    const finding = createFinding({ metadata: rule, source: "static", location: { file: "src/a.ts", line: 1 } });
    const previous = scan("before", 100, []);
    const current = scan("after", 80, [finding]);
    expect(compareScans(previous, current).new).toHaveLength(1);
    const gate = evaluateSecurityGate(current, previous, { failOn: "high", maxScoreDrop: 5 });
    expect(gate.passed).toBe(false);
    expect(gate.failures.map((item) => item.code)).toEqual(expect.arrayContaining(["NEW_FINDING", "SCORE_DROP"]));
  });
});
