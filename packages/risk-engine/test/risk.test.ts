import type { Finding } from "@specter/types";
import { describe, expect, it } from "vitest";
import { calculateRiskScore, summarizeSeverity } from "../src/index.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    schemaVersion: "1",
    id: "risk-finding",
    ruleId: "RISK-1",
    title: "Critical secret",
    description: "secret",
    severity: "critical",
    category: "secret",
    confidence: "high",
    source: "static",
    fingerprint: "risk-1",
    remediation: "rotate",
    status: "open",
    ...overrides,
  };
}

describe("risk engine", () => {
  it("is deterministic and excludes suppressed findings", () => {
    const finding = makeFinding({ location: { file: "a.ts", line: 1 } });
    const first = calculateRiskScore([finding]);
    const second = calculateRiskScore([finding]);
    expect(first).toEqual(second);
    expect(first.value).toBeLessThan(100);
    expect(calculateRiskScore([{ ...finding, status: "suppressed" }]).value).toBe(100);
  });

  it("summarizes severities without inventing counts", () => {
    expect(summarizeSeverity([makeFinding()])).toEqual({
      info: 0,
      low: 0,
      medium: 0,
      high: 0,
      critical: 1,
    });
  });
});
