import * as http from "node:http";
import * as https from "node:https";
import { resolvePublicTarget } from "./target-policy.js";

export type SafeHttpMethod = "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface SafeRequestOptions {
  readonly requestTimeoutMs?: number;
  readonly totalTimeoutMs?: number;
  readonly maxRedirects?: number;
  readonly maxResponseBytes?: number;
  readonly userAgent?: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly signal?: AbortSignal;
  readonly method?: SafeHttpMethod;
  readonly body?: string;
  readonly followRedirects?: boolean;
  readonly requireSameHostname?: boolean;
  readonly allowLocalhost?: boolean;
  readonly allowInvalidTlsForInspection?: boolean;
}

export interface SafeResponse {
  readonly url: string;
  readonly status: number;
  readonly headers: Readonly<Record<string, string | readonly string[]>>;
  readonly body: string;
  readonly bytes: number;
  readonly redirects: readonly string[];
}

function normalizeHeaders(
  headers: http.IncomingHttpHeaders,
): Readonly<Record<string, string | readonly string[]>> {
  const output: Record<string, string | readonly string[]> = {};
  for (const [key, value] of Object.entries(headers))
    if (value !== undefined) output[key.toLowerCase()] = value;
  return output;
}

function once(
  target: Awaited<ReturnType<typeof resolvePublicTarget>>,
  options: SafeRequestOptions,
): Promise<{ response: SafeResponse; location?: string }> {
  return new Promise((resolve, reject) => {
    const client = target.url.protocol === "https:" ? https : http;
    const method = options.method ?? "GET";
    const body = options.body;
    const headers: Record<string, string> = {
      "user-agent": options.userAgent ?? "specter-security/0.1",
      accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
      ...options.headers,
    };
    if (body !== undefined && headers["content-length"] === undefined)
      headers["content-length"] = String(Buffer.byteLength(body));

    const req = client.request(
      {
        protocol: target.url.protocol,
        hostname: target.url.hostname,
        ...(target.url.port ? { port: target.url.port } : {}),
        path: `${target.url.pathname}${target.url.search}`,
        method,
        servername: target.url.hostname,
        ...(target.url.protocol === "https:"
          ? { rejectUnauthorized: options.allowInvalidTlsForInspection !== true }
          : {}),
        headers,
        lookup: (_hostname, _lookupOptions, callback) =>
          callback(null, target.address, target.family),
      },
      (incoming) => {
        const chunks: Uint8Array[] = [];
        let bytes = 0;
        const max = options.maxResponseBytes ?? 5_000_000;
        incoming.on("data", (chunk: Buffer) => {
          bytes += chunk.byteLength;
          if (bytes > max) {
            incoming.destroy(new Error(`Response exceeded ${max} bytes.`));
            return;
          }
          if (method !== "HEAD") chunks.push(chunk);
        });
        incoming.on("error", reject);
        incoming.on("end", () => {
          const status = incoming.statusCode ?? 0;
          const headersOut = normalizeHeaders(incoming.headers);
          const location =
            typeof incoming.headers.location === "string" ? incoming.headers.location : undefined;
          resolve({
            response: {
              url: target.url.toString(),
              status,
              headers: headersOut,
              body: method === "HEAD" ? "" : Buffer.concat(chunks).toString("utf8"),
              bytes,
              redirects: [],
            },
            ...(location ? { location } : {}),
          });
        });
      },
    );
    req.setTimeout(options.requestTimeoutMs ?? 10_000, () =>
      req.destroy(new Error("Request timed out.")),
    );
    req.on("error", reject);
    if (options.signal) {
      if (options.signal.aborted) req.destroy(new Error("Request aborted."));
      else
        options.signal.addEventListener("abort", () => req.destroy(new Error("Request aborted.")), {
          once: true,
        });
    }
    req.end(body);
  });
}

export async function safeRequest(
  input: string,
  options: SafeRequestOptions = {},
): Promise<SafeResponse> {
  const deadline = Date.now() + (options.totalTimeoutMs ?? 60_000);
  const maxRedirects = options.maxRedirects ?? 5;
  const initial = new URL(input);
  const initialHostname = initial.hostname.toLowerCase();
  let current = initial.toString();
  const redirects: string[] = [];

  for (let redirect = 0; redirect <= maxRedirects; redirect += 1) {
    if (Date.now() > deadline) throw new Error("Total scan request deadline exceeded.");
    const target = await resolvePublicTarget(
      current,
      options.allowLocalhost === undefined ? {} : { allowLocalhost: options.allowLocalhost },
    );
    const { response, location } = await once(target, options);
    if ([301, 302, 303, 307, 308].includes(response.status) && location) {
      if (options.followRedirects === false) return { ...response, redirects };
      if (redirect === maxRedirects) throw new Error(`Redirect limit exceeded (${maxRedirects}).`);
      const next = new URL(location, target.url);
      if (options.requireSameHostname === true && next.hostname.toLowerCase() !== initialHostname)
        throw new Error("Cross-host redirect blocked by active scanning policy.");
      redirects.push(next.toString());
      current = next.toString();
      continue;
    }
    return { ...response, redirects };
  }
  throw new Error("Unexpected redirect loop termination.");
}

export async function safeGet(
  input: string,
  options: SafeRequestOptions = {},
): Promise<SafeResponse> {
  return safeRequest(input, { ...options, method: "GET" });
}
