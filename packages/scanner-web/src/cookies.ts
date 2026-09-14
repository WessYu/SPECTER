import { createFinding } from "@specter/core";
import type { Finding, RuleMetadata } from "@specter/types";
import type { SafeResponse } from "./safe-request.js";

const rules = {
  secure: {
    id: "SPECTER-COOKIE-001",
    title: "Cookie missing Secure flag",
    description: "A cookie set over HTTPS was observed without the Secure attribute.",
    category: "cookies",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Mark session and sensitive cookies Secure so browsers only send them over HTTPS.",
  },
  httpOnly: {
    id: "SPECTER-COOKIE-002",
    title: "Session-like cookie missing HttpOnly",
    description: "A session-like cookie can be read by browser JavaScript.",
    category: "cookies",
    defaultSeverity: "medium",
    defaultConfidence: "medium",
    remediation:
      "Use HttpOnly for cookies that do not need JavaScript access, especially session identifiers.",
  },
  sameSite: {
    id: "SPECTER-COOKIE-003",
    title: "Session-like cookie missing SameSite",
    description: "A session-like cookie does not declare an explicit SameSite policy.",
    category: "cookies",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation:
      "Set SameSite=Lax or Strict when compatible; use None only when cross-site usage is required and Secure is present.",
  },
  noneWithoutSecure: {
    id: "SPECTER-COOKIE-004",
    title: "SameSite=None cookie without Secure",
    description: "A cookie declares SameSite=None without Secure.",
    category: "cookies",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Cookies using SameSite=None must also use Secure.",
  },
} satisfies Record<string, RuleMetadata>;

interface CookieInfo {
  readonly name: string;
  readonly kind: "session" | "analytics" | "preference" | "unknown";
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite?: string;
  readonly domain?: string;
  readonly path?: string;
  readonly maxAge?: string;
}

function classify(name: string): CookieInfo["kind"] {
  const lower = name.toLowerCase();
  if (/(session|sess|sid|auth|token|jwt)/.test(lower)) return "session";
  if (/(_ga|analytics|utm|amplitude|mixpanel)/.test(lower)) return "analytics";
  if (/(pref|theme|locale|language|consent)/.test(lower)) return "preference";
  return "unknown";
}

function parseSetCookie(raw: string): CookieInfo | undefined {
  const [first, ...attributes] = raw.split(";").map((item) => item.trim());
  const separator = first?.indexOf("=") ?? -1;
  if (!first || separator <= 0) return undefined;
  const name = first.slice(0, separator);
  const map = new Map<string, string>();
  const flags = new Set<string>();
  for (const attribute of attributes) {
    const index = attribute.indexOf("=");
    if (index === -1) flags.add(attribute.toLowerCase());
    else map.set(attribute.slice(0, index).toLowerCase(), attribute.slice(index + 1));
  }
  const sameSite = map.get("samesite");
  const domain = map.get("domain");
  const cookiePath = map.get("path");
  const maxAge = map.get("max-age");
  return {
    name,
    kind: classify(name),
    secure: flags.has("secure"),
    httpOnly: flags.has("httponly"),
    ...(sameSite ? { sameSite } : {}),
    ...(domain ? { domain } : {}),
    ...(cookiePath ? { path: cookiePath } : {}),
    ...(maxAge ? { maxAge } : {}),
  };
}

export interface CookieAnalysis {
  readonly cookies: readonly CookieInfo[];
  readonly findings: readonly Finding[];
}

export function analyzeCookies(response: SafeResponse): CookieAnalysis {
  const raw = response.headers["set-cookie"];
  const values = raw === undefined ? [] : Array.isArray(raw) ? raw : [raw];
  const cookies = values.flatMap((item) => {
    const parsed = parseSetCookie(item);
    return parsed ? [parsed] : [];
  });
  const findings: Finding[] = [];
  for (const cookie of cookies) {
    const location = { url: response.url };
    const evidence = {
      name: cookie.name,
      kind: cookie.kind,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite ?? "unspecified",
      domain: cookie.domain ?? "host-only",
      path: cookie.path ?? "/",
      maxAge: cookie.maxAge ?? "unspecified",
    };
    if (
      response.url.startsWith("https:") &&
      !cookie.secure &&
      cookie.kind !== "analytics" &&
      cookie.kind !== "preference"
    )
      findings.push(
        createFinding({
          metadata: rules.secure,
          source: "remote",
          location,
          discriminator: `cookie:${cookie.name}:secure`,
          evidence,
        }),
      );
    if (cookie.kind === "session" && !cookie.httpOnly)
      findings.push(
        createFinding({
          metadata: rules.httpOnly,
          source: "remote",
          location,
          discriminator: `cookie:${cookie.name}:httponly`,
          evidence,
        }),
      );
    if (cookie.kind === "session" && !cookie.sameSite)
      findings.push(
        createFinding({
          metadata: rules.sameSite,
          source: "remote",
          location,
          discriminator: `cookie:${cookie.name}:samesite`,
          evidence,
        }),
      );
    if (cookie.sameSite?.toLowerCase() === "none" && !cookie.secure)
      findings.push(
        createFinding({
          metadata: rules.noneWithoutSecure,
          source: "remote",
          location,
          discriminator: `cookie:${cookie.name}:none-secure`,
          evidence,
        }),
      );
  }
  return { cookies, findings };
}
