import type { Finding } from "@specter/types";
import { safeGet, type SafeRequestOptions, type SafeResponse } from "./safe-request.js";

export interface RemoteScanResult {
  readonly target: string;
  readonly response: SafeResponse;
  readonly findings: readonly Finding[];
}

export async function scanRemote(target: string, options: SafeRequestOptions = {}): Promise<RemoteScanResult> {
  const response = await safeGet(target, options);
  return { target, response, findings: [] };
}

export * from "./ip-policy.js";
export * from "./safe-request.js";
export * from "./target-policy.js";
