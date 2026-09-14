import type { Finding } from "@specter/types";
import { analyzeCookies, type CookieAnalysis } from "./cookies.js";
import { analyzeCsp } from "./csp.js";
import { analyzeSecurityHeaders } from "./headers.js";
import { safeGet, type SafeRequestOptions, type SafeResponse } from "./safe-request.js";
import { analyzeTls } from "./tls-findings.js";
import { inspectTls, type TlsInspection } from "./tls.js";

export interface RemoteScanResult {
  readonly target: string;
  readonly response: SafeResponse;
  readonly tls: TlsInspection;
  readonly cookies: CookieAnalysis["cookies"];
  readonly findings: readonly Finding[];
}

export async function scanRemote(target: string, options: SafeRequestOptions = {}): Promise<RemoteScanResult> {
  const response = await safeGet(target, options);
  const cookieAnalysis = analyzeCookies(response);
  const tls = await inspectTls(response.url, options.requestTimeoutMs ?? 10_000).catch((): TlsInspection => ({ applicable: response.url.startsWith("https:"), authorized: false }));
  const findings = [
    ...analyzeSecurityHeaders(response),
    ...analyzeCsp(response),
    ...cookieAnalysis.findings,
    ...analyzeTls(response.url, tls),
  ];
  return { target, response, tls, cookies: cookieAnalysis.cookies, findings };
}

export * from "./cookies.js";
export * from "./csp.js";
export * from "./headers.js";
export * from "./ip-policy.js";
export * from "./safe-request.js";
export * from "./target-policy.js";
export * from "./tls.js";
export * from "./tls-findings.js";
export * from "./runtime.js";
