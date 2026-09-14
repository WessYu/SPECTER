import { checkServerIdentity, connect } from "node:tls";
import { resolvePublicTarget } from "./target-policy.js";

export interface TlsInspection {
  readonly applicable: boolean;
  readonly authorized?: boolean;
  readonly protocol?: string;
  readonly validFrom?: string;
  readonly validTo?: string;
  readonly daysUntilExpiry?: number;
  readonly hostnameValid?: boolean;
  readonly issuer?: string;
}

export async function inspectTls(input: string, timeoutMs = 10_000): Promise<TlsInspection> {
  const target = await resolvePublicTarget(input);
  if (target.url.protocol !== "https:") return { applicable: false };
  const hostname = target.url.hostname.replace(/^\[|\]$/g, "");
  const port = target.url.port ? Number(target.url.port) : 443;
  return new Promise((resolve, reject) => {
    const socket = connect({ host: target.address, port, servername: hostname, rejectUnauthorized: true });
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error("TLS inspection timed out.")));
    socket.once("error", reject);
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      const identityError = checkServerIdentity(hostname, certificate);
      const validToMs = certificate.valid_to ? Date.parse(certificate.valid_to) : Number.NaN;
      const protocol = socket.getProtocol();
      resolve({
        applicable: true,
        authorized: socket.authorized,
        ...(protocol ? { protocol } : {}),
        ...(certificate.valid_from ? { validFrom: new Date(certificate.valid_from).toISOString() } : {}),
        ...(certificate.valid_to ? { validTo: new Date(certificate.valid_to).toISOString() } : {}),
        ...(Number.isFinite(validToMs) ? { daysUntilExpiry: Math.floor((validToMs - Date.now()) / 86_400_000) } : {}),
        hostnameValid: !identityError,
        ...(certificate.issuer?.CN ? { issuer: certificate.issuer.CN } : {}),
      });
      socket.end();
    });
  });
}
