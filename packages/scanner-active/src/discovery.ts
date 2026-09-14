import type { SafeHttpMethod, SafeResponse } from "@specter/scanner-web";
import type { RouteInfo } from "@specter/types";
import type {
  ActiveDiscovery,
  ActiveEndpoint,
  ActiveForm,
  ActiveRequest,
  ActiveScannerConfig,
  ActiveSnapshot,
} from "./types.js";

function sameHost(candidate: URL, root: URL): boolean {
  return candidate.hostname.toLowerCase() === root.hostname.toLowerCase();
}

function normalizeUrl(input: string, base: URL): string | undefined {
  try {
    const url = new URL(input, base);
    if (url.protocol !== "http:" && url.protocol !== "https:") return undefined;
    url.hash = "";
    return url.toString();
  } catch {
    return undefined;
  }
}

function paramsOf(url: string, max: number): readonly string[] {
  return [...new URL(url).searchParams.keys()].slice(0, max);
}

function htmlLinks(html: string, base: URL): readonly string[] {
  const found = new Set<string>();
  for (const match of html.matchAll(/\b(?:href|src)\s*=\s*["']([^"'#]+)["']/gi)) {
    const raw = match[1]?.trim();
    if (!raw || /^(?:mailto:|tel:|javascript:|data:)/i.test(raw)) continue;
    const value = normalizeUrl(raw, base);
    if (value) found.add(value);
  }
  return [...found];
}

function parseForms(
  html: string,
  base: URL,
  maxParameters: number,
): readonly ActiveForm[] {
  const forms: ActiveForm[] = [];
  for (const match of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attributes = match[1] ?? "";
    const body = match[2] ?? "";
    const actionMatch = attributes.match(/\baction\s*=\s*["']([^"']+)["']/i);
    const methodMatch = attributes.match(/\bmethod\s*=\s*["']([^"']+)["']/i);
    const method = (methodMatch?.[1]?.toUpperCase() ?? "GET") as SafeHttpMethod;
    if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) continue;
    const action = normalizeUrl(actionMatch?.[1] ?? base.toString(), base);
    if (!action) continue;

    const fields: string[] = [];
    let usernameField: string | undefined;
    let passwordField: string | undefined;
    let hasCsrfToken = false;

    for (const input of body.matchAll(/<(?:input|textarea|select)\b([^>]*)>/gi)) {
      const attrs = input[1] ?? "";
      const name = attrs.match(/\bname\s*=\s*["']([^"']+)["']/i)?.[1];
      if (!name) continue;
      if (fields.length < maxParameters) fields.push(name);
      const type = attrs.match(/\btype\s*=\s*["']([^"']+)["']/i)?.[1]?.toLowerCase();
      if (type === "password") passwordField = name;
      if (
        !usernameField &&
        /(?:user|email|login)/i.test(name) &&
        type !== "hidden" &&
        type !== "password"
      )
        usernameField = name;
      if (/(?:csrf|xsrf|authenticity|requestverification)/i.test(name)) hasCsrfToken = true;
    }

    forms.push({
      action,
      method,
      parameters: fields,
      ...(usernameField ? { usernameField } : {}),
      ...(passwordField ? { passwordField } : {}),
      hasCsrfToken,
    });
  }
  return forms;
}

function jsRoutes(source: string, base: URL): readonly string[] {
  const found = new Set<string>();
  const patterns = [
    /\bfetch\s*\(\s*["']([^"']+)["']/g,
    /\baxios\.(?:get|post|put|patch|delete)\s*\(\s*["']([^"']+)["']/g,
    /["'](\/api\/[A-Za-z0-9_?=&./:-]+)["']/g,
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const value = match[1] ? normalizeUrl(match[1], base) : undefined;
      if (value) found.add(value);
    }
  }
  return [...found];
}

function sitemapRoutes(xml: string, base: URL): readonly string[] {
  const found: string[] = [];
  for (const match of xml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)) {
    const value = match[1]
      ? normalizeUrl(match[1].replaceAll("&amp;", "&"), base)
      : undefined;
    if (value) found.push(value);
  }
  return found;
}

function openApiRoutes(body: string, base: URL): readonly ActiveEndpoint[] {
  try {
    const parsed = JSON.parse(body) as {
      readonly paths?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
    };
    if (!parsed.paths) return [];
    const result: ActiveEndpoint[] = [];
    for (const [route, methods] of Object.entries(parsed.paths)) {
      const url = normalizeUrl(route, base);
      if (!url) continue;
      for (const method of Object.keys(methods)) {
        const upper = method.toUpperCase();
        if (!["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"].includes(upper))
          continue;
        result.push({
          url,
          method: upper as SafeHttpMethod,
          parameters: paramsOf(url, 10),
          source: "openapi",
        });
      }
    }
    return result;
  } catch {
    return [];
  }
}

export async function discoverActiveSurface(
  target: string,
  request: ActiveRequest,
  config: ActiveScannerConfig,
  observedRoutes: readonly RouteInfo[] = [],
): Promise<ActiveDiscovery> {
  const root = new URL(target);
  const endpoints = new Map<string, ActiveEndpoint>();
  const forms: ActiveForm[] = [];
  const snapshots: ActiveSnapshot[] = [];
  const queue: Array<{ url: string; source: ActiveEndpoint["source"] }> = [
    { url: root.toString(), source: "root" },
  ];
  const queued = new Set(queue.map((item) => item.url));

  for (const route of observedRoutes) {
    const url = normalizeUrl(route.url, root);
    if (!url || !sameHost(new URL(url), root)) continue;
    const method = route.method.toUpperCase();
    if (!["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"].includes(method))
      continue;
    endpoints.set(`${method} ${url}`, {
      url,
      method: method as SafeHttpMethod,
      parameters: paramsOf(url, config.maxParametersPerEndpoint),
      source: "observed",
    });
  }

  const addCandidate = (url: string, source: ActiveEndpoint["source"]) => {
    if (endpoints.size + queue.length >= config.maxEndpoints * 2) return;
    const parsed = new URL(url);
    if (!sameHost(parsed, root) || queued.has(url)) return;
    queued.add(url);
    queue.push({ url, source });
  };

  const sitemap = new URL("/sitemap.xml", root).toString();
  if (sitemap !== root.toString()) {
    try {
      const response = await request(sitemap, { method: "GET", followRedirects: false });
      if (response.status >= 200 && response.status < 300)
        for (const url of sitemapRoutes(response.body, root)) addCandidate(url, "sitemap");
    } catch {
      // Absence of a sitemap is not a finding.
    }
  }

  while (queue.length > 0 && endpoints.size < config.maxEndpoints) {
    const current = queue.shift();
    if (!current) break;

    const endpoint: ActiveEndpoint = {
      url: current.url,
      method: "GET",
      parameters: paramsOf(current.url, config.maxParametersPerEndpoint),
      source: current.source,
    };
    endpoints.set(`GET ${current.url}`, endpoint);

    let response: SafeResponse;
    try {
      response = await request(current.url, { method: "GET" });
    } catch {
      continue;
    }
    snapshots.push({ endpoint, response });

    const contentType = String(response.headers["content-type"] ?? "");
    if (!contentType.includes("text/html")) continue;

    const base = new URL(response.url);
    const links = htmlLinks(response.body, base);
    for (const link of links)
      if (sameHost(new URL(link), root)) addCandidate(link, "link");

    for (const form of parseForms(
      response.body,
      base,
      config.maxParametersPerEndpoint,
    )) {
      if (!sameHost(new URL(form.action), root)) continue;
      forms.push(form);
      endpoints.set(`${form.method} ${form.action}`, {
        url: form.action,
        method: form.method,
        parameters: form.parameters,
        source: "form",
      });
    }

    const scriptLimit = config.profile === "safe" ? 1 : 4;
    const scripts = links
      .filter((url) => /\.m?js(?:\?|$)/i.test(url))
      .slice(0, scriptLimit);

    for (const script of scripts) {
      try {
        const js = await request(script, {
          method: "GET",
          maxResponseBytes: 1_000_000,
        });
        for (const route of jsRoutes(js.body, base))
          if (sameHost(new URL(route), root)) addCandidate(route, "javascript");
      } catch {
        // Explicit script references can disappear during a scan.
      }
    }

    const publishedSpecs = links.filter((url) =>
      /(?:openapi|swagger).*(?:\.json|\.ya?ml)(?:\?|$)/i.test(url),
    );
    for (const spec of publishedSpecs.slice(0, config.profile === "safe" ? 1 : 3)) {
      try {
        const api = await request(spec, {
          method: "GET",
          maxResponseBytes: 1_000_000,
        });
        for (const discovered of openApiRoutes(api.body, new URL(spec)))
          if (sameHost(new URL(discovered.url), root))
            endpoints.set(
              `${discovered.method} ${discovered.url}`,
              discovered,
            );
      } catch {
        // Only explicitly published specs are inspected.
      }
    }
  }

  return {
    endpoints: [...endpoints.values()].slice(0, config.maxEndpoints),
    forms,
    snapshots,
  };
}
