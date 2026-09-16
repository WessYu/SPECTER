import { createFinding, redactEvidence } from "@specter/core";
import type {
  Finding,
  FindingCategory,
  FindingPhase,
  FindingStatus,
  Severity,
} from "@specter/types";
import type { ActiveFindingContext } from "./types.js";

interface ActiveFindingInput {
  readonly ruleId: string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly category: FindingCategory;
  readonly status: Extract<FindingStatus, "confirmed" | "potential" | "inconclusive">;
  readonly context: ActiveFindingContext;
  readonly route: string;
  readonly method?: string;
  readonly parameter?: string;
  readonly evidence?: unknown;
  readonly remediation: string;
  readonly whyItMatters: string;
  readonly discriminator?: string;
}

export function activeFinding(input: ActiveFindingInput): Finding {
  const confidence =
    input.status === "confirmed" ? "confirmed" : input.status === "potential" ? "high" : "medium";
  const finding = createFinding({
    metadata: {
      id: input.ruleId,
      title: input.title,
      description: input.description,
      category: input.category,
      defaultSeverity: input.severity,
      defaultConfidence: confidence,
      remediation: input.remediation,
    },
    source: "runtime",
    location: { url: input.route },
    evidence: redactEvidence(input.evidence),
    discriminator:
      input.discriminator ?? `${input.method ?? "GET"}:${input.route}:${input.parameter ?? ""}`,
    severity: input.severity,
    confidence,
  });

  return {
    ...finding,
    status: input.status,
    scanner: "active",
    phase: input.context.phase,
    route: input.route,
    ...(input.method ? { method: input.method } : {}),
    ...(input.parameter ? { parameter: input.parameter } : {}),
    whyItMatters: input.whyItMatters,
    reproduction: `specter pentest ${input.context.target} --rule ${input.ruleId}`,
  };
}

export function phaseForAuthorization(
  mode: "local" | "preview" | "domain-verification",
): FindingPhase {
  return mode === "domain-verification" ? "production" : "preview";
}
