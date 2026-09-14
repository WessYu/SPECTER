import { describe, expect, it } from "vitest";
import { parseConfigSource, validateConfig } from "../src/index.js";

describe("configuration", () => {
  it("parses safe TypeScript-style object literals", () => {
    const value = parseConfigSource(`export default { failOn: "critical", scan: { runtime: true }, suppressions: [{ ruleId: "R-1", reason: "accepted risk" }] };`);
    const config = validateConfig(value);
    expect(config.failOn).toBe("critical");
    expect(config.scan.runtime).toBe(true);
    expect(config.suppressions).toHaveLength(1);
  });

  it("rejects executable expressions and unknown keys", () => {
    expect(() => parseConfigSource(`export default { failOn: process.env.FAIL_ON };`)).toThrow();
    expect(() => validateConfig({ unknown: true })).toThrow(/Unknown SPECTER config keys/);
  });

  it("rejects suppressions without an auditable reason", () => {
    expect(() => validateConfig({ suppressions: [{ ruleId: "R-1", reason: "" }] })).toThrow();
  });
});
