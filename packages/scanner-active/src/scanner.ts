import { randomUUID } from "node:crypto";
import { applySuppressions } from "@specter/core";
import { calculateRiskScore, summarizeSeverity } from "@specter/risk-engine";
import { inspectTls, safeRequest, type SafeResponse } from "@specter/scanner-web";
import type {
  ActiveAuthorization,
  Finding,
  ScanError,
  ScanModuleResult,
  ScanResult,
  Severity,
} from "@specter/types";
import {
  ActiveAuthorizationError,
  defaultAuthorizationStore,
  isLocalActiveTarget,
  resolveActiveAuthorization,
} from "./authorization.js";
import { ActiveBudgetExceededError, ActiveRequestBudget } from "./budget.js";
import { discoverActiveSurface } from "./discovery.js";
import { activeFinding, phaseForAuthorization } from "./findings.js";
import type {
  ActiveDiscovery,
  ActiveEndpoint,
  ActiveFindingContext,
  ActiveForm,
  ActiveRequest,
  ActiveScanOptions,
} from "./types.js";

const REDIRECT_PARAMETERS = new Set([
  "redirect",
  "return",
  "returnurl",
  "next",
  "continue",
  "url",
  "callback",
]);

const SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
] as const;

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function header(response: SafeResponse, name: string): string | undefined {
  const value = response.headers[name.toLowerCase()];
  return typeof value === "string" ? value : value?.join(", ");
}

function setCookies(response: SafeResponse): readonly string[] {
  const value = response.headers["set-cookie"];
  return typeof value === "string" ? [value] : (value ?? []);
}

function cookiePair(cookie: string): string {
  return cookie.split(";")[0]?.trim() ?? "";
}

function cookieName(cookie: string): string {
  return cookiePair(cookie).split("=")[0]?.trim() ?? "";
}

function statusAllowed(ruleId: string, options: ActiveScanOptions): boolean {
  return !options.rules || options.rules.has(ruleId);
}

function abortIfNeeded(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  const error = new Error("Active scan cancelled.");
  error.name = "AbortError";
  throw error;
}

function markerContext(body: string, marker: string, contentType: string): string {
  if (/application\/(?:[a-z.+-]*\+)?json/i.test(contentType)) return "json";
  const escaped = marker.replace(/[.*+?^$()|[\]{}\\]/g, "\\$&");
  if (new RegExp(`<script\\b[^>]*>[\\s\\S]{0,2000}${escaped}`, "i").test(body)) return "javascript";
  if (new RegExp(`(?:href|src|action)\\s*=\\s*["'][^"']*${escaped}`, "i").test(body)) return "url";
  if (new RegExp(`\\b[A-Za-z_:][-A-Za-z0-9_:.]*\\s*=\\s*["'][^"']*${escaped}`, "i").test(body))
    return "attribute";
  return "html";
}

function domSignals(body: string): {
  readonly sources: readonly string[];
  readonly sinks: readonly string[];
} {
  const sources = [
    ["location.search", /\blocation\.search\b/],
    ["location.hash", /\blocation\.hash\b/],
    ["URLSearchParams", /\bURLSearchParams\s*\(/],
    ["document.URL", /\bdocument\.URL\b/],
    ["document.referrer", /\bdocument\.referrer\b/],
  ] as const;
  const sinks = [
    ["innerHTML", /\.innerHTML\s*=/],
    ["outerHTML", /\.outerHTML\s*=/],
    ["insertAdjacentHTML", /\.insertAdjacentHTML\s*\(/],
    ["document.write", /\bdocument\.write\s*\(/],
    ["eval", /\beval\s*\(/],
    ["Function", /\b(?:new\s+)?Function\s*\(/],
  ] as const;
  return {
    sources: sources.filter(([, pattern]) => pattern.test(body)).map(([name]) => name),
    sinks: sinks.filter(([, pattern]) => pattern.test(body)).map(([name]) => name),
  };
}

function leakSignals(body: string): readonly string[] {
  const signals: string[] = [];
  const tests: ReadonlyArray<readonly [string, RegExp]> = [
    [
      "stack-trace",
      /(?:\bat\s+[\w$.<>]+\s*\([^\n]+:\d+:\d+\)|Traceback \(most recent call last\))/i,
    ],
    ["internal-path", /(?:[A-Z]:\\[^\r\n"]+|\/(?:home|usr|var|app|srv)\/[A-Za-z0-9_./-]+)/i],
    [
      "database-error",
      /(?:SQLSTATE|SequelizeDatabaseError|PrismaClientKnownRequestError|MongoServerError|syntax error at or near)/i,
    ],
    [
      "framework-internals",
      /(?:webpack-internal|node_modules\/[^\s"]+\/src\/|__NEXT_DATA__[\s\S]{0,300}buildId)/i,
    ],
  ];
  for (const [name, pattern] of tests) if (pattern.test(body)) signals.push(name);
  return signals;
}

function bodySimilarity(a: string, b: string): number {
  if (a === b) return 1;
  if (!a || !b) return 0;
  const max = Math.max(a.length, b.length);
  const prefixLimit = Math.min(a.length, b.length);
  let same = 0;
  for (let index = 0; index < prefixLimit; index += 1) if (a[index] === b[index]) same += 1;
  return same / max;
}

function unexpectedMethods(value: string | undefined): readonly string[] {
  if (!value) return [];
  return value
    .split(",")
    .map((item) => item.trim().toUpperCase())
    .filter((item) => ["PUT", "PATCH", "DELETE", "TRACE", "CONNECT"].includes(item));
}

function authCookie(response: SafeResponse): string | undefined {
  const cookie = setCookies(response).find((item) =>
    /(?:session|sid|auth|token)/i.test(cookieName(item)),
  );
  return cookie ? cookiePair(cookie) : undefined;
}

function formBody(form: ActiveForm, username: string, password: string): string {
  const params = new URLSearchParams();
  if (form.usernameField) params.set(form.usernameField, username);
  if (form.passwordField) params.set(form.passwordField, password);
  for (const name of form.parameters) {
    if (!params.has(name) && !/(?:csrf|xsrf|authenticity|requestverification)/i.test(name))
      params.set(name, "");
  }
  return params.toString();
}

function findingSort(a: Finding, b: Finding): number {
  return (
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    a.fingerprint.localeCompare(b.fingerprint)
  );
}

function deduplicate(findings: readonly Finding[]): readonly Finding[] {
  const unique = new Map<string, Finding>();
  for (const finding of findings) {
    const current = unique.get(finding.fingerprint);
    if (!current || SEVERITY_RANK[finding.severity] > SEVERITY_RANK[current.severity])
      unique.set(finding.fingerprint, finding);
  }
  return [...unique.values()].sort(findingSort);
}

async function runTestAccountChecks(
  discovery: ActiveDiscovery,
  request: ActiveRequest,
  options: ActiveScanOptions,
  context: ActiveFindingContext,
  findings: Finding[],
): Promise<void> {
  const username = options.testUsername;
  const password = options.testPassword;
  if (!username || !password) return;

  const login = discovery.forms.find(
    (form) =>
      form.passwordField &&
      form.usernameField &&
      /(?:login|signin|session|auth)/i.test(new URL(form.action).pathname),
  );
  if (!login || login.method !== "POST") return;

  const anonymousCookie = discovery.snapshots
    .flatMap((item) => setCookies(item.response))
    .map(cookiePair)
    .find(Boolean);

  const loginResponse = await request(login.action, {
    method: "POST",
    followRedirects: false,
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: formBody(login, username, password),
  });
  const authenticatedCookie = authCookie(loginResponse);
  if (!authenticatedCookie) return;

  if (
    anonymousCookie &&
    cookieName(anonymousCookie) === cookieName(authenticatedCookie) &&
    anonymousCookie === authenticatedCookie &&
    statusAllowed("SPECTER-ACTIVE-SESSION-001", options)
  ) {
    findings.push(
      activeFinding({
        ruleId: "SPECTER-ACTIVE-SESSION-001",
        title: "Session identifier was not rotated after login",
        description:
          "The explicitly supplied test account retained the same session identifier across authentication.",
        severity: "high",
        category: "cookies",
        status: "confirmed",
        context,
        route: new URL(login.action).pathname,
        method: "POST",
        evidence: {
          cookieName: cookieName(authenticatedCookie),
          rotated: false,
        },
        remediation:
          "Rotate the server-side session identifier immediately after successful authentication.",
        whyItMatters:
          "Session fixation can let a previously known anonymous session become authenticated.",
      }),
    );
  }

  const privateCandidates = discovery.endpoints.filter((endpoint) =>
    /(?:private|account|dashboard|profile|me)(?:\/|$)/i.test(new URL(endpoint.url).pathname),
  );
  let verifiedPrivate:
    { readonly endpoint: ActiveEndpoint; readonly response: SafeResponse } | undefined;

  for (const endpoint of privateCandidates.slice(0, options.config.profile === "safe" ? 1 : 4)) {
    const anonymous = await request(endpoint.url, {
      method: "GET",
      followRedirects: false,
    });
    const authenticated = await request(endpoint.url, {
      method: "GET",
      followRedirects: false,
      headers: { cookie: authenticatedCookie },
    });
    if (authenticated.status >= 200 && authenticated.status < 400)
      verifiedPrivate = { endpoint, response: authenticated };

    const similarity = bodySimilarity(anonymous.body, authenticated.body);
    if (
      anonymous.status >= 200 &&
      anonymous.status < 400 &&
      authenticated.status >= 200 &&
      authenticated.status < 400 &&
      similarity > 0.92 &&
      statusAllowed("SPECTER-ACTIVE-AUTH-001", options)
    ) {
      findings.push(
        activeFinding({
          ruleId: "SPECTER-ACTIVE-AUTH-001",
          title: "Authentication guard is inconsistent",
          description:
            "A route that behaves like private application content returned materially equivalent content to anonymous and authenticated requests.",
          severity: "high",
          category: "runtime",
          status: "confirmed",
          context,
          route: new URL(endpoint.url).pathname,
          method: "GET",
          evidence: {
            anonymousStatus: anonymous.status,
            authenticatedStatus: authenticated.status,
            similarity: Math.round(similarity * 1000) / 1000,
          },
          remediation: "Enforce authorization server-side on every private route and API handler.",
          whyItMatters:
            "A missing guard can expose private content without any need to bypass authentication.",
        }),
      );
    }
  }

  if (verifiedPrivate && statusAllowed("SPECTER-ACTIVE-CACHE-001", options)) {
    const cacheControl = header(verifiedPrivate.response, "cache-control") ?? "";
    if (/(?:public|max-age\s*=\s*[1-9])/i.test(cacheControl) || !/no-store/i.test(cacheControl)) {
      findings.push(
        activeFinding({
          ruleId: "SPECTER-ACTIVE-CACHE-001",
          title: "Private response may be cacheable",
          description:
            "An authenticated test response did not clearly prevent persistent or shared caching.",
          severity: "medium",
          category: "configuration",
          status: "potential",
          context,
          route: new URL(verifiedPrivate.endpoint.url).pathname,
          method: "GET",
          evidence: { cacheControl: cacheControl || "(missing)" },
          remediation: "Use Cache-Control: no-store on responses containing private account data.",
          whyItMatters:
            "Private responses can remain accessible from browser or intermediary caches after the intended session.",
        }),
      );
    }
  }

  const logout = discovery.forms.find(
    (form) => /logout|signout/i.test(new URL(form.action).pathname) && form.method === "POST",
  );
  if (!logout || !verifiedPrivate) return;

  await request(logout.action, {
    method: "POST",
    followRedirects: false,
    headers: { cookie: authenticatedCookie },
  });

  const afterLogout = await request(verifiedPrivate.endpoint.url, {
    method: "GET",
    followRedirects: false,
    headers: { cookie: authenticatedCookie },
  });
  const similarity = bodySimilarity(afterLogout.body, verifiedPrivate.response.body);
  if (
    afterLogout.status >= 200 &&
    afterLogout.status < 400 &&
    similarity > 0.92 &&
    statusAllowed("SPECTER-ACTIVE-SESSION-002", options)
  ) {
    findings.push(
      activeFinding({
        ruleId: "SPECTER-ACTIVE-SESSION-002",
        title: "Logout did not invalidate the previous session",
        description: "The old test-session cookie remained usable after the observed logout flow.",
        severity: "high",
        category: "cookies",
        status: "confirmed",
        context,
        route: new URL(logout.action).pathname,
        method: "POST",
        evidence: {
          previousSessionAccepted: true,
          validationRoute: new URL(verifiedPrivate.endpoint.url).pathname,
        },
        remediation:
          "Invalidate the server-side session on logout and reject the previous identifier.",
        whyItMatters:
          "A copied session can remain valid after the user believes it has been terminated.",
      }),
    );
  }
}

export async function runActiveScan(
  target: string,
  options: ActiveScanOptions,
): Promise<ScanResult> {
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const root = new URL(target);
  const storePath = options.storePath ?? defaultAuthorizationStore(process.cwd());

  const authorization: ActiveAuthorization =
    options.authorization ??
    (await resolveActiveAuthorization(target, storePath, options.config.previewHosts));

  if (!["local", "preview", "verified"].includes(authorization.status))
    throw new ActiveAuthorizationError();

  const targetHostname = root.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (authorization.hostname.toLowerCase() !== targetHostname)
    throw new ActiveAuthorizationError(
      "Authorization hostname does not match the active scan target.",
    );

  const context: ActiveFindingContext = {
    target: root.origin,
    phase: phaseForAuthorization(authorization.mode),
  };
  const budget = new ActiveRequestBudget(
    options.config.maxRequests,
    options.config.maxRequestsPerSecond,
  );
  const findings: Finding[] = [];
  const errors: ScanError[] = [];
  const modules: ScanModuleResult[] = [];
  const allowLocalhost = isLocalActiveTarget(target);

  const request: ActiveRequest = async (url, requestOptions = {}): Promise<SafeResponse> => {
    abortIfNeeded(options.signal);
    await budget.consume(options.signal);
    return safeRequest(url, {
      ...requestOptions,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
      allowLocalhost,
      requireSameHostname: true,
      requestTimeoutMs: options.config.requestTimeoutMs,
      totalTimeoutMs: options.config.requestTimeoutMs + 1_000,
      maxRedirects: requestOptions.maxRedirects ?? 3,
      maxResponseBytes: requestOptions.maxResponseBytes ?? 1_000_000,
      userAgent: "specter-security-active/0.1",
    });
  };

  let discovery: ActiveDiscovery = {
    endpoints: [],
    forms: [],
    snapshots: [],
  };

  let mark = Date.now();
  try {
    discovery = await discoverActiveSurface(
      target,
      request,
      options.config,
      options.observedRoutes,
    );
  } catch (error: unknown) {
    if (error instanceof ActiveBudgetExceededError) {
      errors.push({
        code: "ACTIVE_BUDGET_EXHAUSTED",
        message: error.message,
        module: "active-discovery",
        recoverable: true,
      });
    } else {
      throw error;
    }
  }
  modules.push({
    name: "active-discovery",
    status: errors.some((error) => error.module === "active-discovery") ? "warning" : "passed",
    durationMs: Date.now() - mark,
    findingCount: 0,
  });

  mark = Date.now();

  for (const snapshot of discovery.snapshots) {
    abortIfNeeded(options.signal);
    const route = new URL(snapshot.endpoint.url).pathname;

    for (const cookie of setCookies(snapshot.response)) {
      const sensitive = /(?:session|sid|auth|token)/i.test(cookieName(cookie));
      if (!sensitive) continue;
      const missing: string[] = [];
      if (!/;\s*httponly(?:;|$)/i.test(cookie)) missing.push("HttpOnly");
      if (!/;\s*secure(?:;|$)/i.test(cookie)) missing.push("Secure");
      if (!/;\s*samesite=(?:lax|strict)(?:;|$)/i.test(cookie)) missing.push("SameSite");
      const domain = cookie.match(/;\s*domain=([^;]+)/i)?.[1]?.trim() ?? undefined;
      if (domain && domain.startsWith(".") && domain.split(".").filter(Boolean).length <= 2)
        missing.push("narrow Domain scope");

      if (missing.length > 0 && statusAllowed("SPECTER-ACTIVE-COOKIE-001", options)) {
        findings.push(
          activeFinding({
            ruleId: "SPECTER-ACTIVE-COOKIE-001",
            title: "Sensitive cookie attributes are insufficient",
            description:
              "A session-like cookie was observed without one or more defensive attributes.",
            severity: "medium",
            category: "cookies",
            status: "confirmed",
            context,
            route,
            method: "GET",
            evidence: {
              cookieName: cookieName(cookie),
              missing,
              domain: domain ?? "(host-only)",
            },
            remediation:
              "Set Secure, HttpOnly and an appropriate SameSite policy on sensitive cookies; constrain Domain, Path and lifetime.",
            whyItMatters:
              "Weak cookie attributes increase exposure to script access, transport downgrade and cross-site requests.",
          }),
        );
      }
    }

    const contentType = header(snapshot.response, "content-type") ?? "";
    const nosniff = header(snapshot.response, "x-content-type-options") ?? "";
    const trimmed = snapshot.response.body.trim();
    if (
      (trimmed.startsWith("{") || trimmed.startsWith("[")) &&
      !/application\/(?:[a-z.+-]*\+)?json/i.test(contentType) &&
      statusAllowed("SPECTER-ACTIVE-MIME-001", options)
    ) {
      findings.push(
        activeFinding({
          ruleId: "SPECTER-ACTIVE-MIME-001",
          title: "Response MIME type does not match JSON content",
          description: "A JSON-shaped response was served with a non-JSON Content-Type.",
          severity: "low",
          category: "headers",
          status: "confirmed",
          context,
          route,
          method: "GET",
          evidence: {
            contentType: contentType || "(missing)",
            nosniff: nosniff || "(missing)",
          },
          remediation: "Serve JSON with application/json and X-Content-Type-Options: nosniff.",
          whyItMatters:
            "MIME confusion can make clients interpret a response differently from the application contract.",
        }),
      );
    }

    const signals = leakSignals(snapshot.response.body);
    if (signals.length > 0 && statusAllowed("SPECTER-ACTIVE-LEAK-001", options)) {
      findings.push(
        activeFinding({
          ruleId: "SPECTER-ACTIVE-LEAK-001",
          title: "Runtime response leaks implementation details",
          description:
            "The live response exposed stack, filesystem, database or framework internals.",
          severity: "medium",
          category: "client-exposure",
          status: "confirmed",
          context,
          route,
          method: "GET",
          evidence: { signals },
          remediation: "Return stable public error envelopes and keep diagnostics server-side.",
          whyItMatters:
            "Implementation details reduce uncertainty and can disclose sensitive operational metadata.",
        }),
      );
    }
  }

  for (const endpoint of discovery.endpoints.filter(
    (item) => item.method === "GET" && item.parameters.length > 0,
  )) {
    const maxParameters =
      options.config.profile === "safe" ? 1 : options.config.maxParametersPerEndpoint;

    for (const parameter of endpoint.parameters.slice(0, maxParameters)) {
      if (budget.remaining <= 0) break;
      const canary = `SPECTER_CANARY_${randomUUID().replaceAll("-", "")}`;
      const canaryUrl = new URL(endpoint.url);
      canaryUrl.searchParams.set(parameter, canary);

      try {
        const response = await request(canaryUrl.toString(), {
          method: "GET",
          followRedirects: false,
        });
        if (
          response.body.includes(canary) &&
          statusAllowed("SPECTER-ACTIVE-REFLECTION-001", options)
        ) {
          const responseContentType = header(response, "content-type") ?? "";
          const contextName = markerContext(response.body, canary, responseContentType);
          findings.push(
            activeFinding({
              ruleId: "SPECTER-ACTIVE-REFLECTION-001",
              title: "Input is reflected by the live application",
              description:
                "A unique inert marker was reflected into the response. SPECTER did not execute script.",
              severity: "medium",
              category: "runtime",
              status:
                contextName === "javascript" || contextName === "attribute" || contextName === "url"
                  ? "confirmed"
                  : "potential",
              context,
              route: canaryUrl.pathname,
              method: "GET",
              parameter,
              evidence: {
                context: contextName,
                marker: "[INERT_CANARY]",
                status: response.status,
              },
              remediation:
                "Apply context-appropriate output encoding and keep user-controlled values out of executable DOM or script contexts.",
              whyItMatters:
                "Unsafe reflection can become client-side injection when user-controlled characters reach an executable context.",
            }),
          );

          const dom = domSignals(response.body);
          if (
            dom.sources.length > 0 &&
            dom.sinks.length > 0 &&
            statusAllowed("SPECTER-ACTIVE-DOM-001", options)
          ) {
            findings.push(
              activeFinding({
                ruleId: "SPECTER-ACTIVE-DOM-001",
                title: "Controllable input correlates with a dangerous DOM sink",
                description:
                  "An inert reflected marker was observed on a response containing both browser-controlled sources and executable DOM sinks.",
                severity: "high",
                category: "client-exposure",
                status: "potential",
                context,
                route: canaryUrl.pathname,
                method: "GET",
                parameter,
                evidence: {
                  marker: "[INERT_CANARY]",
                  sources: dom.sources,
                  sinks: dom.sinks,
                  executed: false,
                },
                remediation:
                  "Use textContent or safe DOM APIs and sanitize any HTML before it reaches an HTML/script sink.",
                whyItMatters:
                  "A source-to-sink path can turn otherwise harmless input into DOM-based script injection.",
              }),
            );
          }
        }

        if (
          REDIRECT_PARAMETERS.has(parameter.toLowerCase()) &&
          budget.remaining > 0 &&
          statusAllowed("SPECTER-ACTIVE-REDIRECT-001", options)
        ) {
          const redirectUrl = new URL(endpoint.url);
          redirectUrl.searchParams.set(parameter, "https://specter.invalid/");
          const redirectResponse = await request(redirectUrl.toString(), {
            method: "GET",
            followRedirects: false,
          });
          const location = header(redirectResponse, "location");
          if (location && [301, 302, 303, 307, 308].includes(redirectResponse.status)) {
            const destination = new URL(location, redirectUrl);
            if (destination.hostname === "specter.invalid") {
              findings.push(
                activeFinding({
                  ruleId: "SPECTER-ACTIVE-REDIRECT-001",
                  title: "Open redirect accepts an external destination",
                  description:
                    "A redirect-like parameter accepted the reserved specter.invalid destination. SPECTER did not follow it.",
                  severity: "medium",
                  category: "route",
                  status: "confirmed",
                  context,
                  route: redirectUrl.pathname,
                  method: "GET",
                  parameter,
                  evidence: {
                    status: redirectResponse.status,
                    locationHost: destination.hostname,
                    followed: false,
                  },
                  remediation:
                    "Allowlist local return destinations or map symbolic destinations to server-controlled routes.",
                  whyItMatters:
                    "Open redirects can make phishing and authorization flows appear to originate from a trusted application.",
                }),
              );
            }
          }
        }
      } catch (error: unknown) {
        if (error instanceof ActiveBudgetExceededError) break;
        if ((error as Error).name === "AbortError") throw error;
      }
    }
  }

  const representative = discovery.endpoints
    .filter((endpoint) => endpoint.method === "GET")
    .slice(0, options.config.profile === "safe" ? 4 : Math.min(12, options.config.maxEndpoints));

  for (const endpoint of representative) {
    if (budget.remaining <= 0) break;
    try {
      if (statusAllowed("SPECTER-ACTIVE-CORS-001", options)) {
        const cors = await request(endpoint.url, {
          method: "GET",
          followRedirects: false,
          headers: { origin: "https://specter.invalid" },
        });
        const allowOrigin = header(cors, "access-control-allow-origin");
        const allowCredentials = header(cors, "access-control-allow-credentials");
        if (
          (allowOrigin === "https://specter.invalid" || allowOrigin === "*") &&
          allowCredentials?.toLowerCase() === "true"
        ) {
          findings.push(
            activeFinding({
              ruleId: "SPECTER-ACTIVE-CORS-001",
              title: "CORS accepts an untrusted origin with credentials",
              description:
                "The application allowed the reserved untrusted Origin while enabling credentials.",
              severity: "high",
              category: "cors",
              status: "confirmed",
              context,
              route: new URL(endpoint.url).pathname,
              method: "GET",
              evidence: {
                allowOrigin,
                allowCredentials: true,
              },
              remediation:
                "Use an explicit origin allowlist and never combine arbitrary origins with credentialed CORS.",
              whyItMatters:
                "A hostile site can read authenticated cross-origin responses when arbitrary origins receive credentials.",
            }),
          );
        } else if (
          allowOrigin === "https://specter.invalid" &&
          statusAllowed("SPECTER-ACTIVE-CORS-002", options)
        ) {
          findings.push(
            activeFinding({
              ruleId: "SPECTER-ACTIVE-CORS-002",
              title: "CORS reflects arbitrary origins",
              description:
                "The application reflected the reserved untrusted Origin in Access-Control-Allow-Origin.",
              severity: "medium",
              category: "cors",
              status: "confirmed",
              context,
              route: new URL(endpoint.url).pathname,
              method: "GET",
              evidence: { allowOrigin },
              remediation:
                "Validate Origin against an explicit allowlist before setting CORS response headers.",
              whyItMatters:
                "Origin reflection broadens which sites can read responses and can become critical if credentials are enabled.",
            }),
          );
        }
      }

      if (budget.remaining > 0 && statusAllowed("SPECTER-ACTIVE-METHOD-001", options)) {
        const optionsResponse = await request(endpoint.url, {
          method: "OPTIONS",
          followRedirects: false,
        });
        const methods = unexpectedMethods(header(optionsResponse, "allow"));
        if (methods.length > 0) {
          findings.push(
            activeFinding({
              ruleId: "SPECTER-ACTIVE-METHOD-001",
              title: "Endpoint advertises unexpected state-changing methods",
              description:
                "OPTIONS advertised state-changing or uncommon methods. SPECTER did not invoke them.",
              severity: "low",
              category: "route",
              status: "potential",
              context,
              route: new URL(endpoint.url).pathname,
              method: "OPTIONS",
              evidence: {
                advertised: methods,
                invoked: false,
              },
              remediation:
                "Expose only methods the route needs and authorize every state-changing method server-side.",
              whyItMatters:
                "Unexpected methods expand the reachable application surface even when they are not exercised.",
            }),
          );
        }
      }

      if (budget.remaining > 0 && options.config.profile === "standard") {
        await request(endpoint.url, {
          method: "HEAD",
          followRedirects: false,
        });
      }
    } catch (error: unknown) {
      if (error instanceof ActiveBudgetExceededError) break;
      if ((error as Error).name === "AbortError") throw error;
    }
  }

  if (discovery.snapshots.length > 1 && statusAllowed("SPECTER-ACTIVE-HEADERS-001", options)) {
    for (const name of SECURITY_HEADERS) {
      const values = new Set(
        discovery.snapshots.map((item) => header(item.response, name) ?? "(missing)"),
      );
      if (values.size <= 1) continue;
      findings.push(
        activeFinding({
          ruleId: "SPECTER-ACTIVE-HEADERS-001",
          title: "Security header policy is inconsistent across routes",
          description: `${name} varied across observed application routes.`,
          severity: name === "content-security-policy" ? "medium" : "low",
          category: "headers",
          status: "confirmed",
          context,
          route: root.pathname || "/",
          method: "GET",
          evidence: {
            header: name,
            variants: [...values].slice(0, 5),
          },
          remediation:
            "Apply browser security headers centrally so every applicable route receives the same policy.",
          whyItMatters:
            "A single route with a weaker policy can undermine protections that appear correct elsewhere.",
          discriminator: name,
        }),
      );
    }
  }

  for (const form of discovery.forms) {
    if (
      ["POST", "PUT", "PATCH", "DELETE"].includes(form.method) &&
      !form.passwordField &&
      !/logout|signout/i.test(new URL(form.action).pathname) &&
      !form.hasCsrfToken &&
      statusAllowed("SPECTER-ACTIVE-CSRF-001", options)
    ) {
      findings.push(
        activeFinding({
          ruleId: "SPECTER-ACTIVE-CSRF-001",
          title: "CSRF protection could not be confirmed safely",
          description:
            "A state-changing form had no observable CSRF token. SPECTER did not submit it because mutation safety could not be proven.",
          severity: "low",
          category: "runtime",
          status: "inconclusive",
          context,
          route: new URL(form.action).pathname,
          method: form.method,
          evidence: {
            csrfTokenObserved: false,
            activeMutationSent: false,
          },
          remediation:
            "Use a session-bound CSRF token plus Origin validation for state-changing browser requests.",
          whyItMatters:
            "Without a verifiable anti-CSRF boundary, a cross-site request may be able to act with a user's session.",
        }),
      );
    }
  }

  if (budget.remaining > 0 && statusAllowed("SPECTER-ACTIVE-HOST-001", options)) {
    try {
      const forwarded = await request(root.toString(), {
        method: "GET",
        followRedirects: false,
        headers: {
          "x-forwarded-host": "specter.invalid",
          forwarded: "host=specter.invalid;proto=https",
        },
      });
      const location = header(forwarded, "location") ?? "";
      if (forwarded.body.includes("specter.invalid") || location.includes("specter.invalid")) {
        findings.push(
          activeFinding({
            ruleId: "SPECTER-ACTIVE-HOST-001",
            title: "Forwarded host input is reflected by the application",
            description:
              "A reserved invalid hostname supplied in proxy metadata appeared in the response.",
            severity: "medium",
            category: "configuration",
            status: "potential",
            context,
            route: root.pathname || "/",
            method: "GET",
            evidence: {
              reflectedIn: location.includes("specter.invalid") ? "location" : "body",
            },
            remediation:
              "Trust forwarded host headers only from known proxies and generate canonical URLs from configured origins.",
            whyItMatters:
              "Untrusted host metadata can poison generated links, redirects and cache keys.",
          }),
        );
      }

      if (options.config.profile === "standard" && budget.remaining > 0) {
        const directHost = await request(root.toString(), {
          method: "GET",
          followRedirects: false,
          headers: { host: "specter.invalid" },
        });
        const directLocation = header(directHost, "location") ?? "";
        if (
          (directHost.body.includes("specter.invalid") ||
            directLocation.includes("specter.invalid")) &&
          statusAllowed("SPECTER-ACTIVE-HOST-002", options)
        ) {
          findings.push(
            activeFinding({
              ruleId: "SPECTER-ACTIVE-HOST-002",
              title: "Host header influences application output",
              description:
                "The reserved invalid Host value appeared in the response while the TCP connection remained pinned to the authorized target.",
              severity: "medium",
              category: "configuration",
              status: "potential",
              context,
              route: root.pathname || "/",
              method: "GET",
              evidence: {
                reflectedIn: directLocation.includes("specter.invalid") ? "location" : "body",
              },
              remediation:
                "Validate Host against known application hostnames before using it to generate links or redirects.",
              whyItMatters:
                "Host-header trust can affect password reset links, redirects and intermediary cache keys.",
            }),
          );
        }
      }
    } catch (error: unknown) {
      if ((error as Error).name === "AbortError") throw error;
    }
  }

  if (options.testUsername && options.testPassword && budget.remaining > 0) {
    try {
      await runTestAccountChecks(discovery, request, options, context, findings);
    } catch (error: unknown) {
      if (error instanceof ActiveBudgetExceededError) {
        errors.push({
          code: "ACTIVE_BUDGET_EXHAUSTED",
          message: error.message,
          module: "active-auth",
          recoverable: true,
        });
      } else if ((error as Error).name === "AbortError") {
        throw error;
      } else {
        errors.push({
          code: "ACTIVE_AUTH_INCONCLUSIVE",
          message: error instanceof Error ? error.message : "Test account validation failed.",
          module: "active-auth",
          recoverable: true,
        });
      }
    }
  }

  if (root.protocol === "https:" && statusAllowed("SPECTER-ACTIVE-TLS-001", options)) {
    try {
      const tls = await inspectTls(root.toString(), options.config.requestTimeoutMs);
      const expired = tls.validTo !== undefined && Date.parse(tls.validTo) <= Date.now();
      if (tls.applicable && (!tls.authorized || expired)) {
        findings.push(
          activeFinding({
            ruleId: "SPECTER-ACTIVE-TLS-001",
            title: "TLS validation failed for the active target",
            description: "The target certificate was not currently trusted or valid.",
            severity: "high",
            category: "tls",
            status: "confirmed",
            context,
            route: "/",
            method: "GET",
            evidence: {
              authorized: tls.authorized,
              validTo: tls.validTo,
            },
            remediation: "Serve the hostname with a valid, trusted and unexpired certificate.",
            whyItMatters:
              "Broken TLS prevents clients from establishing an authenticated encrypted channel.",
          }),
        );
      }
    } catch (error: unknown) {
      errors.push({
        code: "ACTIVE_TLS_INCONCLUSIVE",
        message: error instanceof Error ? error.message : "TLS inspection failed.",
        module: "active-tls",
        recoverable: true,
      });
    }
  }

  if (
    root.protocol === "https:" &&
    !root.port &&
    budget.remaining > 0 &&
    statusAllowed("SPECTER-ACTIVE-HTTPS-001", options)
  ) {
    try {
      const httpUrl = new URL(root.toString());
      httpUrl.protocol = "http:";
      const response = await request(httpUrl.toString(), {
        method: "GET",
        followRedirects: false,
      });
      const location = header(response, "location");
      const redirectsToHttps =
        location !== undefined &&
        [301, 302, 303, 307, 308].includes(response.status) &&
        new URL(location, httpUrl).protocol === "https:";
      if (!redirectsToHttps) {
        findings.push(
          activeFinding({
            ruleId: "SPECTER-ACTIVE-HTTPS-001",
            title: "HTTP does not consistently redirect to HTTPS",
            description: "The authorized hostname did not present a direct HTTP to HTTPS redirect.",
            severity: "medium",
            category: "tls",
            status: "potential",
            context,
            route: root.pathname || "/",
            method: "GET",
            evidence: {
              httpStatus: response.status,
              location: location ? new URL(location, httpUrl).protocol : "(missing)",
            },
            remediation:
              "Redirect HTTP requests to the same hostname over HTTPS before serving application content.",
            whyItMatters:
              "Serving content over HTTP leaves a downgrade path outside the protected TLS channel.",
          }),
        );
      }
    } catch (error: unknown) {
      if ((error as Error).name === "AbortError") throw error;
      errors.push({
        code: "ACTIVE_HTTPS_INCONCLUSIVE",
        message: error instanceof Error ? error.message : "HTTP redirect validation failed.",
        module: "active-https",
        recoverable: true,
      });
    }
  }

  modules.push({
    name: "active-validation",
    status: findings.some(
      (finding) => finding.status !== "inconclusive" && finding.status !== "suppressed",
    )
      ? "warning"
      : "passed",
    durationMs: Date.now() - mark,
    findingCount: findings.length,
  });

  const suppressionResult = applySuppressions(deduplicate(findings), options.suppressions ?? []);
  const reportFindings = [...suppressionResult.findings, ...suppressionResult.suppressed].sort(
    findingSort,
  );

  const baselineFingerprints = options.baseline
    ? new Set(options.baseline.findings.map((finding) => finding.fingerprint))
    : undefined;
  const score = calculateRiskScore(
    reportFindings,
    baselineFingerprints ? { baselineFingerprints } : {},
  );
  const completedMs = Date.now();

  return {
    schemaVersion: "1",
    scanId: randomUUID(),
    target: {
      kind: "url",
      value: root.toString(),
      displayName: root.hostname,
    },
    startedAt,
    completedAt: new Date(completedMs).toISOString(),
    durationMs: completedMs - startedMs,
    status: options.signal?.aborted ? "cancelled" : "completed",
    scanType: "active",
    authorization,
    profile: options.config.profile,
    budget: {
      used: budget.used,
      max: budget.max,
      maxRequestsPerSecond: options.config.maxRequestsPerSecond,
      concurrency: options.config.concurrency,
    },
    endpointCount: discovery.endpoints.length,
    confirmedCount: reportFindings.filter((finding) => finding.status === "confirmed").length,
    potentialCount: reportFindings.filter((finding) => finding.status === "potential").length,
    ...(options.baseline
      ? {
          regressionDelta: Math.round((score.value - options.baseline.score.value) * 10) / 10,
        }
      : {}),
    score,
    summary: summarizeSeverity(reportFindings.filter((finding) => finding.status !== "suppressed")),
    findings: reportFindings,
    modules,
    errors,
    surface: {
      routes: discovery.endpoints.map((endpoint) => {
        const url = new URL(endpoint.url);
        return {
          url: `${url.pathname}${url.search}`,
          method: endpoint.method,
        };
      }),
      externalDomains: [],
    },
  };
}
