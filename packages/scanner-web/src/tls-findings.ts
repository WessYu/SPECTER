import { createFinding } from "@specter/core";
import type { Finding, RuleMetadata } from "@specter/types";
import type { TlsInspection } from "./tls.js";

const rules = {
  expiring: {
    id: "SPECTER-TLS-001",
    title: "TLS certificate expires soon",
    description: "The observed certificate is close to expiration.",
    category: "tls",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation:
      "Renew and deploy the certificate before expiration, then verify the complete chain.",
  },
  oldProtocol: {
    id: "SPECTER-TLS-002",
    title: "Legacy TLS protocol negotiated",
    description: "A legacy TLS protocol was negotiated for the connection.",
    category: "tls",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Disable TLS 1.0/1.1 and require modern protocol versions.",
  },
  invalidCertificate: {
    id: "SPECTER-TLS-003",
    title: "TLS certificate is not trusted",
    description:
      "The observed TLS certificate chain could not be authorized by the runtime trust store.",
    category: "tls",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation:
      "Deploy a certificate issued by a trusted CA with a complete and valid certificate chain.",
  },
  hostnameMismatch: {
    id: "SPECTER-TLS-004",
    title: "TLS certificate does not match hostname",
    description: "The certificate identity does not match the requested hostname.",
    category: "tls",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Deploy a certificate whose SAN entries include the production hostname.",
  },
  expired: {
    id: "SPECTER-TLS-005",
    title: "TLS certificate is expired",
    description: "The observed TLS certificate is past its validity period.",
    category: "tls",
    defaultSeverity: "critical",
    defaultConfidence: "high",
    remediation:
      "Replace the expired certificate immediately and verify certificate renewal automation.",
  },
  plaintext: {
    id: "SPECTER-TLS-006",
    title: "Production response remains on plaintext HTTP",
    description:
      "The target completed without upgrading to HTTPS, leaving transport contents and credentials vulnerable to interception.",
    category: "tls",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation:
      "Serve the application over HTTPS and redirect HTTP traffic to the canonical HTTPS origin.",
  },
} satisfies Record<string, RuleMetadata>;

export function analyzeTls(target: string, inspection: TlsInspection): readonly Finding[] {
  const findings: Finding[] = [];
  const parsed = new URL(target);
  if (parsed.protocol !== "https:") {
    findings.push(
      createFinding({
        metadata: rules.plaintext,
        source: "remote",
        location: { url: target },
        discriminator: "tls:plaintext",
        evidence: { protocol: parsed.protocol },
      }),
    );
    return findings;
  }
  if (!inspection.applicable) return findings;
  if (inspection.authorized === false)
    findings.push(
      createFinding({
        metadata: rules.invalidCertificate,
        source: "remote",
        location: { url: target },
        discriminator: "tls:authorization",
        evidence: {
          authorizationError: inspection.authorizationError ?? "certificate authorization failed",
          issuer: inspection.issuer ?? "unknown",
        },
      }),
    );
  if (inspection.hostnameValid === false)
    findings.push(
      createFinding({
        metadata: rules.hostnameMismatch,
        source: "remote",
        location: { url: target },
        discriminator: "tls:hostname",
        evidence: { hostname: parsed.hostname, issuer: inspection.issuer ?? "unknown" },
      }),
    );
  if (inspection.daysUntilExpiry !== undefined && inspection.daysUntilExpiry < 0)
    findings.push(
      createFinding({
        metadata: rules.expired,
        source: "remote",
        location: { url: target },
        discriminator: "tls:expired",
        evidence: {
          daysUntilExpiry: inspection.daysUntilExpiry,
          validTo: inspection.validTo ?? "unknown",
        },
      }),
    );
  else if (inspection.daysUntilExpiry !== undefined && inspection.daysUntilExpiry <= 21)
    findings.push(
      createFinding({
        metadata: rules.expiring,
        source: "remote",
        location: { url: target },
        discriminator: "tls:expiry",
        evidence: {
          daysUntilExpiry: inspection.daysUntilExpiry,
          issuer: inspection.issuer ?? "unknown",
        },
      }),
    );
  if (inspection.protocol === "TLSv1" || inspection.protocol === "TLSv1.1")
    findings.push(
      createFinding({
        metadata: rules.oldProtocol,
        source: "remote",
        location: { url: target },
        discriminator: `tls:${inspection.protocol}`,
        evidence: { protocol: inspection.protocol },
      }),
    );
  return findings;
}
