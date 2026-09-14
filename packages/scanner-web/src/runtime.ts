import type { ExternalDomain, RouteInfo } from "@specter/types";
import { resolvePublicTarget } from "./target-policy.js";

export interface RuntimeRequestRecord {
  readonly url: string;
  readonly method: string;
  readonly resourceType: string;
  readonly redirected: boolean;
}

export interface RuntimeResponseRecord {
  readonly url: string;
  readonly status: number;
  readonly contentType?: string;
  readonly headers: Readonly<Record<string, string>>;
}

export interface RuntimeCookieMetadata {
  readonly name: string;
  readonly domain: string;
  readonly path: string;
  readonly expires: number;
  readonly httpOnly: boolean;
  readonly secure: boolean;
  readonly sameSite: string;
}

export interface RuntimeScanResult {
  readonly finalUrl: string;
  readonly title: string;
  readonly requests: readonly RuntimeRequestRecord[];
  readonly responses: readonly RuntimeResponseRecord[];
  readonly consoleErrors: readonly string[];
  readonly pageErrors: readonly string[];
  readonly externalDomains: readonly ExternalDomain[];
  readonly routes: readonly RouteInfo[];
  readonly cookies: readonly RuntimeCookieMetadata[];
  readonly blockedRequests: readonly string[];
  readonly html: string;
}

export interface RuntimeScanOptions {
  readonly navigationTimeoutMs?: number;
  readonly maxHtmlBytes?: number;
}

function registrableHost(url: string): string | undefined {
  try { return new URL(url).hostname.toLowerCase(); } catch { return undefined; }
}

function sameSiteHost(candidate: string, root: string): boolean {
  return candidate === root || candidate.endsWith(`.${root}`) || root.endsWith(`.${candidate}`);
}

export async function scanRuntime(target: string, options: RuntimeScanOptions = {}): Promise<RuntimeScanResult> {
  const validated = await resolvePublicTarget(target);
  let playwright: typeof import("playwright");
  try { playwright = await import("playwright"); }
  catch { throw new Error("Playwright is required for runtime scans. Install optional dependency 'playwright' and its Chromium browser."); }

  const browser = await playwright.chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: false, serviceWorkers: "block", javaScriptEnabled: true });
  const page = await context.newPage();
  const requests: RuntimeRequestRecord[] = [];
  const responses: RuntimeResponseRecord[] = [];
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const blockedRequests: string[] = [];
  const external = new Map<string, Set<string>>();
  const observedRoutes = new Map<string, RouteInfo>();
  const rootHost = validated.url.hostname.toLowerCase();

  try {
    await page.route("**/*", async (route) => {
      const request = route.request();
      const method = request.method().toUpperCase();
      const url = request.url();
      if (!url.startsWith("http://") && !url.startsWith("https://")) { await route.continue(); return; }
      if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
        blockedRequests.push(`${method} ${url}`);
        await route.abort("blockedbyclient");
        return;
      }
      try { await resolvePublicTarget(url); await route.continue(); }
      catch { blockedRequests.push(`${method} ${url}`); await route.abort("blockedbyclient"); }
    });

    page.on("request", (request) => {
      const url = request.url();
      requests.push({ url, method: request.method(), resourceType: request.resourceType(), redirected: request.redirectedFrom() !== null });
      const host = registrableHost(url);
      if (host && !sameSiteHost(host, rootHost)) {
        const types = external.get(host) ?? new Set<string>();
        types.add(request.resourceType());
        external.set(host, types);
      }
    });
    page.on("response", async (response) => {
      const headers = await response.headers();
      const record: RuntimeResponseRecord = { url: response.url(), status: response.status(), headers, ...(headers["content-type"] ? { contentType: headers["content-type"] } : {}) };
      responses.push(record);
      try {
        const parsed = new URL(response.url());
        if (sameSiteHost(parsed.hostname.toLowerCase(), rootHost)) {
          observedRoutes.set(`${response.request().method()} ${parsed.pathname}`, {
            url: parsed.pathname + parsed.search,
            method: response.request().method(),
            status: response.status(),
            ...(headers["content-type"] ? { contentType: headers["content-type"] } : {}),
            ...(headers["access-control-allow-origin"] ? { cors: headers["access-control-allow-origin"] } : {}),
            headers,
          });
        }
      } catch { /* non-URL browser internals are ignored */ }
    });
    page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text().slice(0, 2_000)); });
    page.on("pageerror", (error) => pageErrors.push(error.message.slice(0, 2_000)));

    await page.goto(validated.url.toString(), { waitUntil: "domcontentloaded", timeout: options.navigationTimeoutMs ?? 20_000 });
    const finalUrl = page.url();
    await resolvePublicTarget(finalUrl);
    const title = await page.title();
    let html = await page.content();
    const maxHtmlBytes = options.maxHtmlBytes ?? 1_000_000;
    if (html.length > maxHtmlBytes) html = html.slice(0, maxHtmlBytes);
    const cookies = (await context.cookies()).map((cookie) => ({
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
      expires: cookie.expires,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
    }));

    return {
      finalUrl,
      title,
      requests,
      responses,
      consoleErrors,
      pageErrors,
      externalDomains: [...external.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([domain, resourceTypes]) => ({ domain, classification: "unknown", resourceTypes: [...resourceTypes].sort(), page: finalUrl })),
      routes: [...observedRoutes.values()].sort((a, b) => a.url.localeCompare(b.url)),
      cookies,
      blockedRequests,
      html,
    };
  } finally {
    await context.close().catch(() => undefined);
    await browser.close().catch(() => undefined);
  }
}
