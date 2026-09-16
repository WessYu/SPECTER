import http from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { redactEvidence } from "@specter/core";
import {
  ActiveAuthorizationError,
  ActiveRequestBudget,
  discoverActiveSurface,
  generateDomainAuthorization,
  resolveActiveAuthorization,
  runActiveScan,
} from "../src/index.js";
import { activeFinding } from "../src/findings.js";
import type { ActiveScannerConfig } from "../src/types.js";

const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length > 0) {
    const cleanup = cleanups.pop();
    if (cleanup) await cleanup();
  }
});

const config: ActiveScannerConfig = {
  enabled: true,
  profile: "safe",
  maxRequests: 500,
  maxRequestsPerSecond: 100,
  concurrency: 2,
  requestTimeoutMs: 2_000,
  maxEndpoints: 40,
  maxParametersPerEndpoint: 10,
  allowStateChangingMethods: false,
  previewHosts: [],
};

async function fixtureServer(): Promise<string> {
  const fixedSession = "fixed-session";
  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);

    if (request.method === "OPTIONS") {
      response.writeHead(204, {
        allow: "GET, HEAD, OPTIONS, PUT, DELETE",
      });
      response.end();
      return;
    }

    if (request.headers["x-forwarded-host"] === "specter.invalid") {
      response.writeHead(200, {
        "content-type": "text/html",
      });
      response.end("https://specter.invalid/");
      return;
    }

    if (url.pathname === "/") {
      response.writeHead(200, {
        "content-type": "text/html",
        "set-cookie": `sid=${fixedSession}; Path=/; SameSite=None`,
      });
      response.end(`<a href="/reflect?q=hello">reflect</a>
<a href="/redirect?next=/">redirect</a>
<a href="/api/cors">cors</a>
<a href="/api/debug?mode=ok">debug</a>
<a href="/api/private">private</a>
<form action="/login" method="post">
<input name="username"><input name="password" type="password">
</form>
<form action="/logout" method="post"></form>
<form action="/profile" method="post"><input name="name"></form>`);
      return;
    }

    if (url.pathname === "/reflect") {
      const value = url.searchParams.get("q") ?? "";
      response.writeHead(200, {
        "content-type": "text/html",
        "content-security-policy": "default-src 'self'",
      });
      response.end(`<div id="o">${value}</div><script>
const p = new URLSearchParams(location.search);
document.querySelector("#o").innerHTML = p.get("q");
</script>`);
      return;
    }

    if (url.pathname === "/redirect") {
      response.writeHead(302, {
        location: url.searchParams.get("next") ?? "/",
      });
      response.end();
      return;
    }

    if (url.pathname === "/api/cors") {
      const origin = request.headers.origin;
      response.writeHead(200, {
        "content-type": "application/json",
        ...(typeof origin === "string" ? { "access-control-allow-origin": origin } : {}),
        "access-control-allow-credentials": "true",
      });
      response.end('{"ok":true}');
      return;
    }

    if (url.pathname === "/api/debug") {
      response.writeHead(500, {
        "content-type": "text/html",
      });
      response.end(
        '{"error":"PrismaClientKnownRequestError","stack":"at handler (/srv/app/api.ts:1:1)"}',
      );
      return;
    }

    if (url.pathname === "/login" && request.method === "POST") {
      response.writeHead(204, {
        "set-cookie": `sid=${fixedSession}; Path=/; SameSite=None`,
      });
      response.end();
      return;
    }

    if (url.pathname === "/logout" && request.method === "POST") {
      response.writeHead(204);
      response.end();
      return;
    }

    if (url.pathname === "/api/private") {
      response.writeHead(200, {
        "content-type": "application/json",
        "cache-control": "public, max-age=60",
      });
      response.end('{"account":"test"}');
      return;
    }

    response.writeHead(404, {
      "content-type": "text/plain",
    });
    response.end("not found");
  });

  const address = await new Promise<{ port: number }>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const bound = server.address();
      if (!bound || typeof bound === "string") {
        reject(new Error("invalid test address"));
        return;
      }
      resolve({ port: bound.port });
    });
  });
  cleanups.push(
    () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
      }),
  );
  return `http://127.0.0.1:${address.port}/`;
}

describe("active authorization", () => {
  it("automatically authorizes localhost only", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "specter-active-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const auth = await resolveActiveAuthorization(
      "http://127.0.0.1:3000",
      path.join(dir, "auth.json"),
      [],
    );
    expect(auth.status).toBe("local");
  });

  it("refuses an unverified remote hostname before scanning", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "specter-active-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    await expect(
      resolveActiveAuthorization("https://example.com", path.join(dir, "auth.json"), []),
    ).rejects.toBeInstanceOf(ActiveAuthorizationError);
  });

  it("generates a random verification token without persisting it in plaintext", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "specter-active-"));
    cleanups.push(() => rm(dir, { recursive: true, force: true }));
    const store = path.join(dir, "auth.json");
    const generated = await generateDomainAuthorization("https://example.com", store);
    expect(generated.content).toMatch(/^specter-verification=[a-f0-9]{48}$/);
    const persisted = await readFile(store, "utf8");
    expect(persisted).not.toContain(generated.token);
    expect(persisted).toContain("tokenHash");
  });
});

describe("request budget and cancellation", () => {
  it("never consumes more than maxRequests", async () => {
    const budget = new ActiveRequestBudget(2, 100);
    await budget.consume();
    await budget.consume();
    await expect(budget.consume()).rejects.toThrow("budget exhausted");
    expect(budget.used).toBe(2);
  });

  it("respects an already aborted signal", async () => {
    const controller = new AbortController();
    controller.abort();
    const budget = new ActiveRequestBudget(5, 100);
    await expect(budget.consume(controller.signal)).rejects.toMatchObject({ name: "AbortError" });
    expect(budget.used).toBe(0);
  });
});

describe("endpoint discovery", () => {
  it("uses observed links and forms without brute-force guesses", async () => {
    const requested: string[] = [];
    const request = async (url: string) => {
      requested.push(new URL(url).pathname);
      return {
        url,
        status: 200,
        headers: {
          "content-type": "text/html",
        },
        body: url.endsWith("sitemap.xml")
          ? "<urlset></urlset>"
          : '<a href="/known?q=1">known</a><form action="/login" method="post"><input name="username"><input name="password" type="password"></form>',
        bytes: 0,
        redirects: [],
      } as const;
    };
    const result = await discoverActiveSurface("https://example.com/", request, {
      ...config,
      maxEndpoints: 5,
    });
    expect(result.endpoints.some((item) => new URL(item.url).pathname === "/known")).toBe(true);
    expect(requested).not.toContain("/admin");
    expect(requested).not.toContain("/.git");
  });
});

describe("active validations", () => {
  it("confirms safe evidence without executing exploit payloads", async () => {
    const target = await fixtureServer();
    const result = await runActiveScan(target, {
      config,
      testUsername: "specter-test",
      testPassword: "never-reported",
    });
    const rules = new Set(result.findings.map((finding) => finding.ruleId));

    expect(rules).toContain("SPECTER-ACTIVE-REFLECTION-001");
    expect(rules).toContain("SPECTER-ACTIVE-DOM-001");
    expect(rules).toContain("SPECTER-ACTIVE-REDIRECT-001");
    expect(rules).toContain("SPECTER-ACTIVE-COOKIE-001");
    expect(rules).toContain("SPECTER-ACTIVE-CORS-001");
    expect(rules).toContain("SPECTER-ACTIVE-LEAK-001");
    expect(rules).toContain("SPECTER-ACTIVE-METHOD-001");
    expect(rules).toContain("SPECTER-ACTIVE-AUTH-001");
    expect(rules).toContain("SPECTER-ACTIVE-SESSION-001");
    expect(rules).toContain("SPECTER-ACTIVE-SESSION-002");
    expect(rules).toContain("SPECTER-ACTIVE-CACHE-001");

    const csrf = result.findings.find((finding) => finding.ruleId === "SPECTER-ACTIVE-CSRF-001");
    expect(csrf?.status).toBe("inconclusive");
    expect(result.budget?.used).toBeLessThanOrEqual(config.maxRequests);
    expect(result.score.value).toBeGreaterThanOrEqual(0);
    expect(result.score.value).toBeLessThanOrEqual(100);
  });

  it("produces stable fingerprints despite random reflection canaries", async () => {
    const target = await fixtureServer();
    const first = await runActiveScan(target, { config });
    const second = await runActiveScan(target, { config });
    const one = first.findings.find(
      (finding) => finding.ruleId === "SPECTER-ACTIVE-REFLECTION-001",
    );
    const two = second.findings.find(
      (finding) => finding.ruleId === "SPECTER-ACTIVE-REFLECTION-001",
    );
    expect(one?.fingerprint).toBe(two?.fingerprint);
  });

  it("stops before requests when cancelled", async () => {
    const target = await fixtureServer();
    const controller = new AbortController();
    controller.abort();
    await expect(
      runActiveScan(target, {
        config,
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ name: "AbortError" });
  });
});

describe("active evidence redaction", () => {
  it("redacts credentials, cookies and authorization values", () => {
    expect(
      redactEvidence({
        password: "secret-value",
        authorization: "Bearer token-value",
        cookie: "sid=session-value",
      }),
    ).toEqual({
      password: "[REDACTED]",
      authorization: "[REDACTED]",
      cookie: "[REDACTED]",
    });
  });

  it("keeps active finding fingerprints stable and reproduction secret-free", () => {
    const first = activeFinding({
      ruleId: "SPECTER-ACTIVE-CORS-001",
      title: "CORS",
      description: "test",
      severity: "high",
      category: "cors",
      status: "confirmed",
      context: {
        target: "https://example.com",
        phase: "production",
      },
      route: "/api",
      method: "GET",
      evidence: { authorization: "Bearer should-hide" },
      remediation: "fix",
      whyItMatters: "reason",
    });
    const second = activeFinding({
      ruleId: "SPECTER-ACTIVE-CORS-001",
      title: "CORS",
      description: "test",
      severity: "high",
      category: "cors",
      status: "confirmed",
      context: {
        target: "https://example.com",
        phase: "production",
      },
      route: "/api",
      method: "GET",
      evidence: { authorization: "different-secret" },
      remediation: "fix",
      whyItMatters: "reason",
    });
    expect(first.fingerprint).toBe(second.fingerprint);
    expect(first.evidence).toEqual({
      authorization: "[REDACTED]",
    });
    expect(first.reproduction).toBe(
      "specter pentest https://example.com --rule SPECTER-ACTIVE-CORS-001",
    );
  });
});
