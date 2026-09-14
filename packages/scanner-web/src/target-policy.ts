import type { LookupAddress } from "node:dns";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { isBlockedIp, isLoopbackIp, isMetadataHostname } from "./ip-policy.js";

export interface ResolvedTarget {
  readonly url: URL;
  readonly address: string;
  readonly family: 4 | 6;
}

export interface ResolveTargetOptions {
  readonly allowLocalhost?: boolean;
}

export class TargetPolicyError extends Error {
  readonly code: "INVALID_SCHEME" | "BLOCKED_HOST" | "DNS_FAILURE";
  constructor(code: TargetPolicyError["code"], message: string) {
    super(message);
    this.name = "TargetPolicyError";
    this.code = code;
  }
}

function acceptedAddress(address: string, allowLocalhost: boolean): boolean {
  if (allowLocalhost && isLoopbackIp(address)) return true;
  return !isBlockedIp(address);
}

export async function resolvePublicTarget(
  input: string | URL,
  options: ResolveTargetOptions = {},
): Promise<ResolvedTarget> {
  const url = input instanceof URL ? new URL(input) : new URL(input);
  if (url.protocol !== "http:" && url.protocol !== "https:")
    throw new TargetPolicyError("INVALID_SCHEME", "Only HTTP and HTTPS targets are allowed.");
  if (url.username || url.password)
    throw new TargetPolicyError("BLOCKED_HOST", "Credentials embedded in target URLs are not allowed.");

  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  const allowLocalhost = options.allowLocalhost === true;
  if (isMetadataHostname(hostname))
    throw new TargetPolicyError("BLOCKED_HOST", `Blocked target hostname: ${hostname}`);

  if (isIP(hostname)) {
    if (!acceptedAddress(hostname, allowLocalhost))
      throw new TargetPolicyError("BLOCKED_HOST", `Blocked target address: ${hostname}`);
    return { url, address: hostname, family: isIP(hostname) as 4 | 6 };
  }

  if (hostname === "localhost" && !allowLocalhost)
    throw new TargetPolicyError("BLOCKED_HOST", "Blocked target hostname: localhost");

  let addresses: LookupAddress[];
  try {
    addresses = await lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new TargetPolicyError("DNS_FAILURE", `Unable to resolve ${hostname}`);
  }
  if (addresses.length === 0)
    throw new TargetPolicyError("DNS_FAILURE", `No addresses resolved for ${hostname}`);

  if (hostname === "localhost") {
    const chosen = addresses.find((item) => isLoopbackIp(item.address));
    if (!chosen)
      throw new TargetPolicyError("BLOCKED_HOST", "localhost did not resolve to a loopback address.");
    if (chosen.family !== 4 && chosen.family !== 6)
      throw new TargetPolicyError("DNS_FAILURE", "Unsupported localhost address family.");
    return { url, address: chosen.address, family: chosen.family };
  }

  if (addresses.some((item) => !acceptedAddress(item.address, false)))
    throw new TargetPolicyError("BLOCKED_HOST", `Target ${hostname} resolves to a non-public address.`);
  const chosen = addresses[0];
  if (!chosen)
    throw new TargetPolicyError("DNS_FAILURE", `No usable address resolved for ${hostname}`);
  if (chosen.family !== 4 && chosen.family !== 6)
    throw new TargetPolicyError("DNS_FAILURE", `Unsupported address family for ${hostname}`);
  return { url, address: chosen.address, family: chosen.family };
}
