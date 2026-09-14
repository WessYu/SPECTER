import { createFinding } from "@specter/core";
import type { Finding, RuleMetadata } from "@specter/types";
import type { SafeResponse } from "./safe-request.js";

const rules = {
  cspMissing: {
    id: "SPECTER-HEADERS-001",
    title: "Content Security Policy missing",
    description: "No Content-Security-Policy header was observed on the response.",
    category: "headers",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation:
      "Define a restrictive Content-Security-Policy appropriate to the application's resource requirements.",
  },
  hstsMissing: {
    id: "SPECTER-HEADERS-002",
    title: "HSTS missing on HTTPS response",
    description: "Strict-Transport-Security was not observed on an HTTPS response.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "high",
    remediation:
      "After confirming HTTPS is enforced across the host, add a suitable Strict-Transport-Security policy.",
  },
  nosniffMissing: {
    id: "SPECTER-HEADERS-003",
    title: "X-Content-Type-Options missing",
    description: "The response does not opt out of MIME sniffing.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "high",
    remediation: "Set X-Content-Type-Options: nosniff.",
  },
  referrerMissing: {
    id: "SPECTER-HEADERS-004",
    title: "Referrer-Policy missing",
    description: "The response does not explicitly constrain referrer information.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation:
      "Set an application-appropriate Referrer-Policy such as strict-origin-when-cross-origin.",
  },
  permissionsMissing: {
    id: "SPECTER-HEADERS-005",
    title: "Permissions-Policy missing",
    description: "The response does not explicitly restrict browser capabilities.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Add a Permissions-Policy that enables only capabilities the application uses.",
  },
  frameMissing: {
    id: "SPECTER-HEADERS-006",
    title: "Frame embedding protections not observed",
    description: "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Use CSP frame-ancestors and, where compatibility requires it, X-Frame-Options.",
  },
  corsWildcard: {
    id: "SPECTER-CORS-001",
    title: "Permissive CORS wildcard",
    description: "Access-Control-Allow-Origin allows any origin.",
    category: "cors",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Allow only origins that need cross-origin access and validate them server-side.",
  },
  corsCredentials: {
    id: "SPECTER-CORS-002",
    title: "CORS wildcard combined with credentials",
    description: "A permissive origin policy was observed alongside credential allowance.",
    category: "cors",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation:
      "Never combine credentialed cross-origin access with broad origin allowance; use an explicit allow-list.",
  },
} satisfies Record<string, RuleMetadata>;

function header(response: SafeResponse, name: string): string | undefined {
  const value = response.headers[name.toLowerCase()];
  if (typeof value === "string") return value;
  if (value) return [...value].join(", ");
  return undefined;
}

export function analyzeSecurityHeaders(response: SafeResponse): readonly Finding[] {
  const findings: Finding[] = [];
  const location = { url: response.url };
  const csp = header(response, "content-security-policy");
  if (!csp)
    findings.push(
      createFinding({
        metadata: rules.cspMissing,
        source: "remote",
        location,
        discriminator: "missing-csp",
      }),
    );
  if (response.url.startsWith("https:") && !header(response, "strict-transport-security"))
    findings.push(
      createFinding({
        metadata: rules.hstsMissing,
        source: "remote",
        location,
        discriminator: "missing-hsts",
      }),
    );
  if ((header(response, "x-content-type-options") ?? "").toLowerCase() !== "nosniff")
    findings.push(
      createFinding({
        metadata: rules.nosniffMissing,
        source: "remote",
        location,
        discriminator: "missing-nosniff",
      }),
    );
  if (!header(response, "referrer-policy"))
    findings.push(
      createFinding({
        metadata: rules.referrerMissing,
        source: "remote",
        location,
        discriminator: "missing-referrer-policy",
      }),
    );
  if (!header(response, "permissions-policy"))
    findings.push(
      createFinding({
        metadata: rules.permissionsMissing,
        source: "remote",
        location,
        discriminator: "missing-permissions-policy",
      }),
    );
  if (!header(response, "x-frame-options") && !/(?:^|;)\s*frame-ancestors\b/i.test(csp ?? ""))
    findings.push(
      createFinding({
        metadata: rules.frameMissing,
        source: "remote",
        location,
        discriminator: "missing-frame-protection",
      }),
    );

  const allowOrigin = header(response, "access-control-allow-origin")?.trim();
  if (allowOrigin === "*") {
    const credentials =
      header(response, "access-control-allow-credentials")?.toLowerCase() === "true";
    findings.push(
      createFinding({
        metadata: credentials ? rules.corsCredentials : rules.corsWildcard,
        source: "remote",
        location,
        discriminator: credentials ? "cors:*:credentials" : "cors:*",
        evidence: { allowOrigin: "*", allowCredentials: credentials },
      }),
    );
  }
  return findings;
}
