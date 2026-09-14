import { randomUUID } from "node:crypto";
import {
  SPECTER_SCHEMA_VERSION,
  type Finding,
  type FindingLocation,
  type RuleMetadata,
} from "@specter/types";
import { createFingerprint } from "./fingerprint.js";

export interface CreateFindingInput {
  readonly metadata: RuleMetadata;
  readonly source: Finding["source"];
  readonly location?: FindingLocation;
  readonly evidence?: unknown;
  readonly discriminator?: string;
  readonly severity?: Finding["severity"];
  readonly confidence?: Finding["confidence"];
  readonly description?: string;
  readonly remediation?: string;
}

export function createFinding(input: CreateFindingInput): Finding {
  const fingerprint = createFingerprint({
    ruleId: input.metadata.id,
    category: input.metadata.category,
    source: input.source,
    ...(input.location?.file !== undefined ? { file: input.location.file } : {}),
    ...(input.location?.line !== undefined ? { line: input.location.line } : {}),
    ...(input.location?.url !== undefined ? { url: input.location.url } : {}),
    ...(input.discriminator !== undefined ? { discriminator: input.discriminator } : {}),
  });

  return {
    schemaVersion: SPECTER_SCHEMA_VERSION,
    id: randomUUID(),
    ruleId: input.metadata.id,
    title: input.metadata.title,
    description: input.description ?? input.metadata.description,
    severity: input.severity ?? input.metadata.defaultSeverity,
    category: input.metadata.category,
    confidence: input.confidence ?? input.metadata.defaultConfidence,
    source: input.source,
    fingerprint,
    ...(input.location ? { location: input.location } : {}),
    ...(input.evidence !== undefined ? { evidence: input.evidence } : {}),
    remediation: input.remediation ?? input.metadata.remediation,
    ...(input.metadata.documentationUrl
      ? { documentationUrl: input.metadata.documentationUrl }
      : {}),
    status: "open",
  };
}
