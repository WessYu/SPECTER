import { createFinding } from "@specter/core";
import type { Finding, RuleMetadata } from "@specter/types";
import type { TlsInspection } from "./tls.js";

const rules = {
  expiring: { id: "SPECTER-TLS-001", title: "TLS certificate expires soon", description: "The observed certificate is close to expiration.", category: "tls", defaultSeverity: "medium", defaultConfidence: "high", remediation: "Renew and deploy the certificate before expiration, then verify the complete chain." },
  oldProtocol: { id: "SPECTER-TLS-002", title: "Legacy TLS protocol negotiated", description: "A legacy TLS protocol was negotiated for the connection.", category: "tls", defaultSeverity: "high", defaultConfidence: "high", remediation: "Disable TLS 1.0/1.1 and require modern protocol versions." },
} satisfies Record<string, RuleMetadata>;

export function analyzeTls(target: string, inspection: TlsInspection): readonly Finding[] {
  const findings: Finding[] = [];
  if (!inspection.applicable) return findings;
  if (inspection.daysUntilExpiry !== undefined && inspection.daysUntilExpiry >= 0 && inspection.daysUntilExpiry <= 21) findings.push(createFinding({ metadata: rules.expiring, source: "remote", location: { url: target }, discriminator: "tls:expiry", evidence: { daysUntilExpiry: inspection.daysUntilExpiry, issuer: inspection.issuer ?? "unknown" } }));
  if (inspection.protocol === "TLSv1" || inspection.protocol === "TLSv1.1") findings.push(createFinding({ metadata: rules.oldProtocol, source: "remote", location: { url: target }, discriminator: `tls:${inspection.protocol}`, evidence: { protocol: inspection.protocol } }));
  return findings;
}
