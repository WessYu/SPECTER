import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const SESSION_BYTES = 32;
const OAUTH_STATE_BYTES = 32;

export const SESSION_COOKIE_NAME = "specter_session";
export const OAUTH_STATE_COOKIE_NAME = "specter_oauth_state";
export const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30;
export const OAUTH_STATE_TTL_SECONDS = 10 * 60;

export function hashOpaqueToken(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function generateSessionToken(): { readonly value: string; readonly hash: string } {
  const value = `sp_session_${randomBytes(SESSION_BYTES).toString("base64url")}`;
  return { value, hash: hashOpaqueToken(value) };
}

export function generateOAuthState(): string {
  return randomBytes(OAUTH_STATE_BYTES).toString("base64url");
}

export function constantTimeStringMatch(actual: string, expected: string): boolean {
  const left = createHash("sha256").update(actual).digest("hex");
  const right = createHash("sha256").update(expected).digest("hex");
  return timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

export function parseCookieHeader(raw: string | string[] | undefined): ReadonlyMap<string, string> {
  const value = Array.isArray(raw) ? raw[0] : raw;
  const cookies = new Map<string, string>();
  if (!value) return cookies;
  for (const part of value.split(";")) {
    const separator = part.indexOf("=");
    if (separator <= 0) continue;
    const name = part.slice(0, separator).trim();
    const cookieValue = part.slice(separator + 1).trim();
    if (!name) continue;
    try { cookies.set(name, decodeURIComponent(cookieValue)); }
    catch { /* malformed cookie is ignored */ }
  }
  return cookies;
}

function validatedCookieDomain(): string | undefined {
  const value = process.env.SPECTER_COOKIE_DOMAIN?.trim();
  if (!value) return undefined;
  return /^\.?[A-Za-z0-9.-]+$/.test(value) && !value.includes("..") ? value : undefined;
}

export function serializeCookie(name: string, value: string, maxAgeSeconds: number, path = "/"): string {
  const domain = validatedCookieDomain();
  const attributes = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  if (process.env.NODE_ENV === "production") attributes.push("Secure");
  if (domain) attributes.push(`Domain=${domain}`);
  return attributes.join("; ");
}

export function clearCookie(name: string, path = "/"): string {
  return serializeCookie(name, "", 0, path);
}
