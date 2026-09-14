import { checkServerIdentity, connect } from "node:tls";
import { resolvePublicTarget } from "./target-policy.js";

export interface TlsInspection {
  readonly applicable: boolean;
  readonly authorized?: boolean;
  readonly authorizationError?: string;
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

  return await new Promise<TlsInspection>((resolve, reject) => {
    const socket = connect({
      host: target.address,
      port,
      servername: hostname,
      rejectUnauthorized: false,
    });
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error("TLS inspection timed out.")));
    socket.once("error", (error) => reject(error));
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      const identityError = certificate && Object.keys(certificate).length > 0
        ? checkServerIdentity(hostname, certificate)
        : new Error("Peer did not provide a certificate.");
      const validFromMs = certificate.valid_from ? Date.parse(certificate.valid_from) : Number.NaN;
      const validToMs = certificate.valid_to ? Date.parse(certificate.valid_to) : Number.NaN;
      const protocol = socket.getProtocol();
      const authorizationError = socket.authorizationError;
      const result: TlsInspection = {
        applicable: true,
        authorized: socket.authorized,
        ...(authorizationError ? { authorizationError: String(authorizationError) } : {}),
        ...(protocol ? { protocol } : {}),
        ...(Number.isFinite(validFromMs) ? { validFrom: new Date(validFromMs).toISOString() } : {}),
        ...(Number.isFinite(validToMs) ? { validTo: new Date(validToMs).toISOString() } : {}),
        ...(Number.isFinite(validToMs) ? { daysUntilExpiry: Math.floor((validToMs - Date.now()) / 86_400_000) } : {}),
        hostnameValid: !identityError,
        ...(certificate.issuer?.CN ? { issuer: certificate.issuer.CN } : {}),
      };
      socket.end();
      resolve(result);
    });
  });
}
