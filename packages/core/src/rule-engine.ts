import type { Finding, Rule, RuleContext, Suppression } from "@specter/types";
import { redactEvidence } from "./redaction.js";

export interface RuleEngineOptions {
  readonly suppressions?: readonly Suppression[];
  readonly now?: Date;
}

export interface RuleEngineResult {
  readonly findings: readonly Finding[];
  readonly suppressed: readonly Finding[];
  readonly errors: readonly RuleExecutionError[];
}

export interface RuleExecutionError {
  readonly ruleId: string;
  readonly message: string;
}

function isActiveSuppression(suppression: Suppression, finding: Finding, now: Date): boolean {
  if (suppression.expiresAt && Date.parse(suppression.expiresAt) <= now.getTime()) return false;
  const matchesRule = suppression.ruleId === undefined || suppression.ruleId === finding.ruleId;
  const matchesFingerprint =
    suppression.fingerprint === undefined || suppression.fingerprint === finding.fingerprint;
  return matchesRule && matchesFingerprint && Boolean(suppression.ruleId || suppression.fingerprint);
}

function sanitizeFinding(finding: Finding): Finding {
  if (finding.evidence === undefined) return finding;
  return { ...finding, evidence: redactEvidence(finding.evidence) };
}

export class RuleEngine {
  readonly #rules: readonly Rule[];

  constructor(rules: readonly Rule[]) {
    const ids = new Set<string>();
    for (const rule of rules) {
      if (ids.has(rule.metadata.id)) throw new Error(`Duplicate rule id: ${rule.metadata.id}`);
      ids.add(rule.metadata.id);
    }
    this.#rules = [...rules];
  }

  async run(context: RuleContext, options: RuleEngineOptions = {}): Promise<RuleEngineResult> {
    const findings: Finding[] = [];
    const suppressed: Finding[] = [];
    const errors: RuleExecutionError[] = [];
    const now = options.now ?? new Date();

    for (const rule of this.#rules) {
      try {
        const result = await rule.evaluate(context);
        for (const raw of result) {
          const finding = sanitizeFinding(raw);
          const suppression = options.suppressions?.find((item) => isActiveSuppression(item, finding, now));
          if (suppression) suppressed.push({ ...finding, status: "suppressed" });
          else findings.push(finding);
        }
      } catch (error: unknown) {
        errors.push({
          ruleId: rule.metadata.id,
          message: error instanceof Error ? error.message : "Unknown rule execution error",
        });
      }
    }

    return { findings, suppressed, errors };
  }
}
