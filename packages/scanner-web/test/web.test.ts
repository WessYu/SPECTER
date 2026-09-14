import { describe, expect, it } from "vitest";
import { analyzeTls, resolvePublicTarget } from "../src/index.js";

describe("remote scanner policy", () => {
  it("blocks local and metadata targets", async () => {
    await expect(resolvePublicTarget("http://127.0.0.1:8080")).rejects.toMatchObject({ code: "BLOCKED_HOST" });
    await expect(resolvePublicTarget("http://169.254.169.254/latest/meta-data")).rejects.toMatchObject({ code: "BLOCKED_HOST" });
  });
  it("reports plaintext and invalid TLS", () => {
    expect(analyzeTls("http://example.com", { applicable: false }).map((item) => item.ruleId)).toContain("SPECTER-TLS-006");
    const rules = analyzeTls("https://example.com", { applicable: true, authorized: false, hostnameValid: false, daysUntilExpiry: -1 }).map((item) => item.ruleId);
    expect(rules).toEqual(expect.arrayContaining(["SPECTER-TLS-003", "SPECTER-TLS-004", "SPECTER-TLS-005"]));
  });
});
