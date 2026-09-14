import { describe, expect, it } from "vitest";
import type { ScanResult } from "@specter/types";
import { serializeJsonReport, toSarif } from "../src/index.js";

const scan: ScanResult = { schemaVersion: "1", scanId: "scan-1", target: { kind: "project", value: "/repo" }, startedAt: "2026-01-01T00:00:00.000Z", completedAt: "2026-01-01T00:00:01.000Z", durationMs: 1000, status: "completed", score: { value: 100, band: "excellent", deductions: [] }, summary: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, findings: [], modules: [], errors: [] };

describe("reporters", () => {
  it("emits versioned JSON", () => expect(JSON.parse(serializeJsonReport(scan)).schemaVersion).toBe("1"));
  it("emits SARIF 2.1.0", () => expect(toSarif(scan).version).toBe("2.1.0"));
});
