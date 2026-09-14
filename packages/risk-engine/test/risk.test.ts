import { describe, expect, it } from "vitest";
import { createFinding } from "@specter/core";
import { calculateRiskScore, summarizeSeverity } from "../src/index.js";

const metadata = {
  id: "RISK-1",
  title: "Critical secret",
  description: "secret",
  category: "secret" as const,
  defaultSeverity: "critical" as const,
  defaultConfidence: "high" as const,
  remediation: "rotate",
};

describe("risk engine", () => {
  it("is deterministic and excludes suppressed findings", () => {
    const finding = createFinding({
      metadata,
      source: "static",
      location: { file: "a.ts", line: 1 },
    });
    const first = calculateRiskScore([finding]);
    const second = calculateRiskScore([finding]);
    expect(first).toEqual(second);
    expect(first.value).toBeLessThan(100);
    expect(calculateRiskScore([{ ...finding, status: "suppressed" }]).value).toBe(100);
  });

  it("summarizes severities without inventing counts", () => {
    const finding = createFinding({ metadata, source: "static" });
    expect(summarizeSeverity([finding])).toEqual({
      info: 0,
      low: 0,
      medium: 0,
      high: 0,
      critical: 1,
    });
  });
});
