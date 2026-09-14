import { describe, expect, it } from "vitest";
import { formatDate, scoreDelta } from "../lib/format.js";

describe("dashboard formatting", () => {
  it("does not invent a regression without two scans", () =>
    expect(scoreDelta(undefined, 90).text).toBe("No baseline"));
  it("formats score changes with direction", () => expect(scoreDelta(81, 94).text).toBe("-13"));
  it("renders invalid dates honestly", () => expect(formatDate("not-a-date")).toBe("—"));
});
