import { createFinding } from "@specter/core";
import type { Finding, RuleMetadata } from "@specter/types";
import type { SafeResponse } from "./safe-request.js";

const rules = {
  unsafeInline: {
    id: "SPECTER-CSP-001",
    title: "CSP allows unsafe-inline",
    description:
      "The observed CSP contains unsafe-inline, weakening script/style injection protection.",
    category: "csp",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Replace unsafe-inline with nonces or hashes where feasible.",
  },
  unsafeEval: {
    id: "SPECTER-CSP-002",
    title: "CSP allows unsafe-eval",
    description: "The observed CSP permits eval-like JavaScript execution.",
    category: "csp",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation:
      "Remove unsafe-eval and refactor dependencies that require runtime string compilation.",
  },
  wildcard: {
    id: "SPECTER-CSP-003",
    title: "CSP contains broad wildcard source",
    description: "A CSP source list contains a broad wildcard that reduces origin restrictions.",
    category: "csp",
    defaultSeverity: "medium",
    defaultConfidence: "medium",
    remediation: "Replace wildcard sources with the minimum explicit origins required.",
  },
  objectSrc: {
    id: "SPECTER-CSP-004",
    title: "CSP does not define object-src",
    description: "The policy does not explicitly constrain plugin/object sources.",
    category: "csp",
    defaultSeverity: "low",
    defaultConfidence: "high",
    remediation: "Add object-src 'none' unless object/embed content is intentionally required.",
  },
  frameAncestors: {
    id: "SPECTER-CSP-005",
    title: "CSP does not define frame-ancestors",
    description: "The policy does not use frame-ancestors to control embedding.",
    category: "csp",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Add an application-appropriate frame-ancestors directive.",
  },
} satisfies Record<string, RuleMetadata>;

export type CspDirectives = Readonly<Record<string, readonly string[]>>;

export function parseCsp(value: string): CspDirectives {
  const directives: Record<string, string[]> = {};
  for (const segment of value.split(";")) {
    const parts = segment.trim().split(/\s+/).filter(Boolean);
    const name = parts.shift()?.toLowerCase();
    if (name) directives[name] = parts;
  }
  return directives;
}

export function analyzeCsp(response: SafeResponse): readonly Finding[] {
  const raw = response.headers["content-security-policy"];
  const value = typeof raw === "string" ? raw : raw ? [...raw].join("; ") : undefined;
  if (!value) return [];
  const directives = parseCsp(value);
  const findings: Finding[] = [];
  const location = { url: response.url };
  const sourceLists = Object.entries(directives).filter(
    ([name]) => /-src$/.test(name) || name === "default-src",
  );
  if (sourceLists.some(([, values]) => values.includes("'unsafe-inline'")))
    findings.push(
      createFinding({
        metadata: rules.unsafeInline,
        source: "remote",
        location,
        discriminator: "csp:unsafe-inline",
        evidence: {
          directives: sourceLists
            .filter(([, values]) => values.includes("'unsafe-inline'"))
            .map(([name]) => name),
        },
      }),
    );
  if (sourceLists.some(([, values]) => values.includes("'unsafe-eval'")))
    findings.push(
      createFinding({
        metadata: rules.unsafeEval,
        source: "remote",
        location,
        discriminator: "csp:unsafe-eval",
        evidence: {
          directives: sourceLists
            .filter(([, values]) => values.includes("'unsafe-eval'"))
            .map(([name]) => name),
        },
      }),
    );
  if (sourceLists.some(([, values]) => values.includes("*")))
    findings.push(
      createFinding({
        metadata: rules.wildcard,
        source: "remote",
        location,
        discriminator: "csp:wildcard",
        evidence: {
          directives: sourceLists
            .filter(([, values]) => values.includes("*"))
            .map(([name]) => name),
        },
      }),
    );
  if (!("object-src" in directives))
    findings.push(
      createFinding({
        metadata: rules.objectSrc,
        source: "remote",
        location,
        discriminator: "csp:no-object-src",
      }),
    );
  if (!("frame-ancestors" in directives))
    findings.push(
      createFinding({
        metadata: rules.frameAncestors,
        source: "remote",
        location,
        discriminator: "csp:no-frame-ancestors",
      }),
    );
  return findings;
}
