import type { ExternalDomain, RouteInfo } from "@specter/types";
import { scanRuntime, type RuntimeScanResult } from "./runtime.js";
import { safeGet, type SafeRequestOptions } from "./safe-request.js";
import { resolvePublicTarget } from "./target-policy.js";

const KNOWN_THIRD_PARTY = new Set([
  "fonts.googleapis.com",
  "fonts.gstatic.com",
  "cdn.jsdelivr.net",
  "unpkg.com",
  "js.stripe.com",
  "stripe.com",
  "www.googletagmanager.com",
  "www.google-analytics.com",
  "connect.facebook.net",
  "cdn.segment.com",
]);

function hostOf(input: string): string | undefined {
  try {
    return new URL(input).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function firstParty(candidate: string, root: string): boolean {
  return candidate === root || candidate.endsWith(`.${root}`) || root.endsWith(`.${candidate}`);
}

function extractHtmlLinks(html: string, base: URL): readonly string[] {
  const links = new Set<string>();
  const pattern = /\b(?:href|src)\s*=\s*["']([^"'#]+)["']/gi;
  for (const match of html.matchAll(pattern)) {
    const raw = match[1]?.trim();
    if (!raw || /^(?:mailto:|tel:|javascript:|data:)/i.test(raw)) continue;
    try {
      const url = new URL(raw, base);
      if (url.protocol === "http:" || url.protocol === "https:") {
        url.hash = "";
        links.add(url.toString());
      }
    } catch {
      /* malformed link */
    }
  }
  return [...links];
}

function extractSitemapLinks(xml: string): readonly string[] {
  const links: string[] = [];
  const pattern = /<loc>\s*([^<]+?)\s*<\/loc>/gi;
  for (const match of xml.matchAll(pattern))
    if (match[1]) links.push(match[1].replaceAll("&amp;", "&").trim());
  return links;
}

function classifyDomain(
  domain: string,
  rootHost: string,
  previousDomains?: ReadonlySet<string>,
): ExternalDomain["classification"] {
  if (firstParty(domain, rootHost)) return "first-party";
  if (previousDomains && !previousDomains.has(domain)) return "newly-introduced";
  if (
    KNOWN_THIRD_PARTY.has(domain) ||
    [...KNOWN_THIRD_PARTY].some((known) => domain.endsWith(`.${known}`))
  )
    return "known-third-party";
  return "unknown";
}

export interface SurfaceDiscoveryOptions extends SafeRequestOptions {
  readonly maxPages?: number;
  readonly concurrency?: number;
  readonly includeRuntime?: boolean;
  readonly previousDomains?: ReadonlySet<string>;
}

export interface SurfaceDiscoveryResult {
  readonly routes: readonly RouteInfo[];
  readonly externalDomains: readonly ExternalDomain[];
  readonly removedDomains: readonly string[];
  readonly runtime?: RuntimeScanResult;
}

export async function discoverSurface(
  target: string,
  options: SurfaceDiscoveryOptions = {},
): Promise<SurfaceDiscoveryResult> {
  const initial = await resolvePublicTarget(target);
  const rootHost = initial.url.hostname.toLowerCase();
  const maxPages = Math.max(1, Math.min(options.maxPages ?? 20, 100));
  const concurrency = Math.max(1, Math.min(Math.floor(options.concurrency ?? 4), 12));
  const queue = [initial.url.toString()];
  const visited = new Set<string>();
  const routes = new Map<string, RouteInfo>();
  const domains = new Map<string, Set<string>>();
  const runtime =
    options.includeRuntime === false
      ? undefined
      : await scanRuntime(initial.url.toString(), {
          navigationTimeoutMs: options.requestTimeoutMs ?? 20_000,
        }).catch(() => undefined);

  if (runtime) {
    for (const route of runtime.routes) routes.set(`${route.method} ${route.url}`, route);
    for (const domain of runtime.externalDomains)
      domains.set(domain.domain, new Set(domain.resourceTypes));
    for (const link of extractHtmlLinks(runtime.html, new URL(runtime.finalUrl))) {
      const host = hostOf(link);
      if (host && firstParty(host, rootHost) && queue.length < maxPages * 4) queue.push(link);
      else if (host) {
        const types = domains.get(host) ?? new Set<string>();
        types.add("document-link");
        domains.set(host, types);
      }
    }
  }

  try {
    const sitemapUrl = new URL("/sitemap.xml", initial.url).toString();
    const sitemap = await safeGet(sitemapUrl, options);
    if (sitemap.status >= 200 && sitemap.status < 300) {
      for (const link of extractSitemapLinks(sitemap.body)) {
        const host = hostOf(link);
        if (host && firstParty(host, rootHost) && queue.length < maxPages * 6) queue.push(link);
      }
    }
  } catch {
    /* sitemap absence is not a finding */
  }

  const takeCandidate = (): string | undefined => {
    while (queue.length > 0 && visited.size < maxPages) {
      const candidate = queue.shift();
      if (!candidate) continue;
      let parsed: URL;
      try {
        parsed = new URL(candidate);
      } catch {
        continue;
      }
      if (!firstParty(parsed.hostname.toLowerCase(), rootHost)) continue;
      parsed.hash = "";
      const normalized = parsed.toString();
      if (visited.has(normalized)) continue;
      visited.add(normalized);
      return normalized;
    }
    return undefined;
  };

  const worker = async (): Promise<void> => {
    while (true) {
      const normalized = takeCandidate();
      if (!normalized) return;
      try {
        const response = await safeGet(normalized, options);
        const final = new URL(response.url);
        if (!firstParty(final.hostname.toLowerCase(), rootHost)) continue;
        const contentTypeRaw = response.headers["content-type"];
        const contentType =
          typeof contentTypeRaw === "string"
            ? contentTypeRaw
            : contentTypeRaw
              ? [...contentTypeRaw].join(", ")
              : undefined;
        const corsRaw = response.headers["access-control-allow-origin"];
        const cors =
          typeof corsRaw === "string" ? corsRaw : corsRaw ? [...corsRaw].join(", ") : undefined;
        const route: RouteInfo = {
          url: `${final.pathname}${final.search}`,
          method: "GET",
          status: response.status,
          ...(contentType ? { contentType } : {}),
          ...(cors ? { cors } : {}),
        };
        routes.set(`GET ${route.url}`, route);
        if (contentType?.includes("text/html")) {
          for (const link of extractHtmlLinks(response.body, final)) {
            const host = hostOf(link);
            if (!host) continue;
            if (firstParty(host, rootHost) && visited.size + queue.length < maxPages * 3)
              queue.push(link);
            else {
              const types = domains.get(host) ?? new Set<string>();
              types.add("document-link");
              domains.set(host, types);
            }
          }
        }
      } catch {
        /* inaccessible observed route is skipped */
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, maxPages) }, async () => worker()));

  const externalDomains: ExternalDomain[] = [...domains.entries()]
    .filter(([domain]) => !firstParty(domain, rootHost))
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([domain, resourceTypes]) => ({
      domain,
      classification: classifyDomain(domain, rootHost, options.previousDomains),
      resourceTypes: [...resourceTypes].sort(),
      page: initial.url.toString(),
    }));
  const current = new Set(externalDomains.map((item) => item.domain));
  const removedDomains = options.previousDomains
    ? [...options.previousDomains].filter((domain) => !current.has(domain)).sort()
    : [];

  return {
    routes: [...routes.values()].sort(
      (a, b) => a.url.localeCompare(b.url) || a.method.localeCompare(b.method),
    ),
    externalDomains,
    removedDomains,
    ...(runtime ? { runtime } : {}),
  };
}
