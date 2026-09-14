export const projectBodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["name", "slug"],
  properties: {
    name: { type: "string", minLength: 1, maxLength: 120 },
    slug: { type: "string", pattern: "^[a-z0-9]+(?:-[a-z0-9]+)*$", maxLength: 80 },
  },
} as const;
export const scanBodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["projectId", "result"],
  properties: {
    projectId: { type: "string", minLength: 1 },
    result: {
      type: "object",
      required: [
        "schemaVersion",
        "scanId",
        "target",
        "score",
        "summary",
        "findings",
        "modules",
        "errors",
        "startedAt",
        "completedAt",
        "durationMs",
        "status",
      ],
    },
  },
} as const;
export const suppressionBodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["projectId", "reason"],
  properties: {
    projectId: { type: "string", minLength: 1 },
    ruleId: { type: "string" },
    fingerprint: { type: "string" },
    reason: { type: "string", minLength: 3, maxLength: 500 },
    expiresAt: { type: "string", format: "date-time" },
  },
  anyOf: [{ required: ["ruleId"] }, { required: ["fingerprint"] }],
} as const;
