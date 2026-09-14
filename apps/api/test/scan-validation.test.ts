import { describe, expect, it } from "vitest";
import { validateScanResult } from "../src/scan-validation.js";

function valid() {
  return {
    schemaVersion: "1",
    scanId: "scan-1",
    target: { kind: "project", value: "/repo" },
    startedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:01.000Z",
    durationMs: 1000,
    status: "completed",
    score: { value: 100, band: "excellent", deductions: [] },
    summary: { info: 0, low: 0, medium: 0, high: 0, critical: 0 },
    findings: [],
    modules: [],
    errors: [],
  };
}

describe("scan ingestion validation", () => {
  it("accepts a bounded v1 result", () =>
    expect(validateScanResult(valid()).scanId).toBe("scan-1"));
  it("rejects oversized and malformed payloads", () => {
    const input = valid();
    input.score.value = 500;
    expect(() => validateScanResult(input)).toThrow();
  });
  it("rejects completion before start", () => {
    const input = valid();
    input.completedAt = "2025-01-01T00:00:00.000Z";
    expect(() => validateScanResult(input)).toThrow();
  });
});
