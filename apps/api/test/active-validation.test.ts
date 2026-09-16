import { describe, expect, it } from "vitest";
import { validateScanResult } from "../src/scan-validation.js";

function activeResult() {
  return {
    schemaVersion: "1",
    scanId: "active-scan-1",
    scanType: "active",
    target: {
      kind: "url",
      value: "https://example.com/",
    },
    authorization: {
      status: "verified",
      mode: "domain-verification",
      hostname: "example.com",
      verifiedAt: "2026-09-14T12:00:00.000Z",
      expiresAt: "2026-10-14T12:00:00.000Z",
    },
    profile: "safe",
    budget: {
      used: 4,
      max: 150,
      maxRequestsPerSecond: 3,
      concurrency: 2,
    },
    endpointCount: 1,
    confirmedCount: 1,
    potentialCount: 0,
    regressionDelta: -12,
    startedAt: "2026-09-14T12:00:00.000Z",
    completedAt: "2026-09-14T12:00:01.000Z",
    durationMs: 1000,
    status: "completed",
    score: {
      value: 72,
      band: "fair",
      deductions: [],
    },
    summary: {
      info: 0,
      low: 0,
      medium: 0,
      high: 1,
      critical: 0,
    },
    findings: [
      {
        schemaVersion: "1",
        id: "finding-1",
        ruleId: "SPECTER-ACTIVE-CORS-001",
        title: "CORS",
        description: "Confirmed safely.",
        severity: "high",
        category: "cors",
        confidence: "confirmed",
        source: "runtime",
        scanner: "active",
        phase: "production",
        status: "confirmed",
        route: "/api",
        method: "GET",
        parameter: "origin",
        reproduction: "specter pentest https://example.com --rule SPECTER-ACTIVE-CORS-001",
        whyItMatters: "Credentialed cross-origin reads.",
        fingerprint: "active-fingerprint",
      },
    ],
    modules: [
      {
        name: "active-validation",
        status: "warning",
        durationMs: 10,
        findingCount: 1,
      },
    ],
    errors: [],
    surface: {
      routes: [{ url: "/api", method: "GET" }],
      externalDomains: [],
    },
  };
}

describe("active scan ingestion validation", () => {
  it("accepts versioned active metadata and confirmed findings", () => {
    const result = validateScanResult(activeResult());
    expect(result.scanType).toBe("active");
    expect(result.authorization?.status).toBe("verified");
    expect(result.findings[0]?.scanner).toBe("active");
    expect(result.findings[0]?.status).toBe("confirmed");
  });

  it("rejects invalid active profiles and budgets", () => {
    const invalidProfile = activeResult();
    invalidProfile.profile = "aggressive";
    expect(() => validateScanResult(invalidProfile)).toThrow("profile is invalid");

    const invalidBudget = activeResult();
    invalidBudget.profile = "safe";
    invalidBudget.budget.used = 999;
    invalidBudget.budget.max = 10;
    expect(() => validateScanResult(invalidBudget)).not.toThrow();
  });
});
