import type { PrismaClient } from "@prisma/client";
import type { FastifyInstance } from "fastify";
import { getAuth, requireRole, type OrganizationRole } from "./auth.js";
import { generateApiKey } from "./api-key.js";
import {
  clearCookie,
  constantTimeStringMatch,
  generateOAuthState,
  generateSessionToken,
  hashOpaqueToken,
  OAUTH_STATE_COOKIE_NAME,
  OAUTH_STATE_TTL_SECONDS,
  parseCookieHeader,
  serializeCookie,
  SESSION_COOKIE_NAME,
  SESSION_TTL_SECONDS,
} from "./session.js";

interface GitHubUser { readonly id: number; readonly login: string; readonly name?: string | null; readonly avatar_url?: string | null; }
interface GitHubTokenResponse { readonly access_token?: string; readonly token_type?: string; readonly error?: string; }
interface UserRow { readonly id: string; readonly name: string | null; readonly avatarUrl: string | null; }
interface MembershipRow {
  readonly organizationId: string;
  readonly role: OrganizationRole;
  readonly organization: { readonly id: string; readonly name: string; readonly slug: string };
}
interface SessionRow { readonly id: string; readonly userId: string; readonly organizationId: string; }
interface OrgParams { readonly id: string; }
interface ApiKeyBody { readonly name: string; }
interface ApiKeyParams { readonly id: string; }

function env(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

function publicBaseUrl(): string {
  return env("SPECTER_API_PUBLIC_URL").replace(/\/$/, "");
}

function dashboardUrl(): string {
  return env("SPECTER_DASHBOARD_URL").replace(/\/$/, "");
}

function oauthStatePath(): string { return "/api/v1/auth/github"; }

function normalizeLogin(login: string): string {
  const normalized = login.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48);
  return normalized || "workspace";
}

async function exchangeGitHubCode(code: string): Promise<string> {
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { accept: "application/json", "content-type": "application/json", "user-agent": "specter-security" },
    body: JSON.stringify({
      client_id: env("GITHUB_CLIENT_ID"),
      client_secret: env("GITHUB_CLIENT_SECRET"),
      code,
      redirect_uri: `${publicBaseUrl()}/api/v1/auth/github/callback`,
    }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`GitHub OAuth token exchange failed (${response.status}).`);
  const body = await response.json() as GitHubTokenResponse;
  if (!body.access_token || body.error) throw new Error("GitHub OAuth token exchange returned no access token.");
  return body.access_token;
}

async function fetchGitHubUser(accessToken: string): Promise<GitHubUser> {
  const response = await fetch("https://api.github.com/user", {
    headers: { authorization: `Bearer ${accessToken}`, accept: "application/vnd.github+json", "user-agent": "specter-security" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`GitHub profile request failed (${response.status}).`);
  const body = await response.json() as Partial<GitHubUser>;
  if (typeof body.id !== "number" || typeof body.login !== "string" || !body.login) throw new Error("GitHub profile response is invalid.");
  return body as GitHubUser;
}

async function ensureUserWorkspace(prisma: PrismaClient, github: GitHubUser): Promise<{ readonly user: UserRow; readonly membership: MembershipRow }> {
  const githubId = String(github.id);
  const user = await prisma.user.upsert({
    where: { githubId },
    create: { githubId, name: github.name?.trim() || github.login, ...(github.avatar_url ? { avatarUrl: github.avatar_url } : {}) },
    update: { name: github.name?.trim() || github.login, ...(github.avatar_url ? { avatarUrl: github.avatar_url } : {}) },
    select: { id: true, name: true, avatarUrl: true },
  }) as UserRow;
  const existing = await prisma.organizationMember.findFirst({
    where: { userId: user.id },
    orderBy: { createdAt: "asc" },
    select: { organizationId: true, role: true, organization: { select: { id: true, name: true, slug: true } } },
  }) as MembershipRow | null;
  if (existing) return { user, membership: existing };

  const slug = `${normalizeLogin(github.login)}-${githubId}`.slice(0, 80);
  const membership = await prisma.$transaction(async (tx) => {
    const organization = await tx.organization.create({
      data: { name: `${github.login}'s workspace`, slug },
      select: { id: true, name: true, slug: true },
    }) as MembershipRow["organization"];
    return await tx.organizationMember.create({
      data: { organizationId: organization.id, userId: user.id, role: "owner" },
      select: { organizationId: true, role: true, organization: { select: { id: true, name: true, slug: true } } },
    }) as MembershipRow;
  });
  return { user, membership };
}

export function registerAuthRoutes(app: FastifyInstance, prisma: PrismaClient): void {
  app.get("/api/v1/auth/github/start", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (_request, reply) => {
    const state = generateOAuthState();
    const authorize = new URL("https://github.com/login/oauth/authorize");
    authorize.searchParams.set("client_id", env("GITHUB_CLIENT_ID"));
    authorize.searchParams.set("redirect_uri", `${publicBaseUrl()}/api/v1/auth/github/callback`);
    authorize.searchParams.set("scope", "read:user");
    authorize.searchParams.set("state", state);
    reply.header("set-cookie", serializeCookie(OAUTH_STATE_COOKIE_NAME, state, OAUTH_STATE_TTL_SECONDS, oauthStatePath()));
    return reply.code(302).header("location", authorize.toString()).send();
  });

  app.get<{ Querystring: { readonly code?: string; readonly state?: string; readonly error?: string } }>("/api/v1/auth/github/callback", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } } }, async (request, reply) => {
    const expectedState = parseCookieHeader(request.headers.cookie).get(OAUTH_STATE_COOKIE_NAME);
    reply.header("set-cookie", clearCookie(OAUTH_STATE_COOKIE_NAME, oauthStatePath()));
    if (request.query.error) return reply.code(302).header("location", `${dashboardUrl()}/login?error=github_denied`).send();
    if (!request.query.code || !request.query.state || !expectedState || !constantTimeStringMatch(request.query.state, expectedState)) {
      return reply.code(400).send({ error: "invalid_oauth_state" });
    }
    const accessToken = await exchangeGitHubCode(request.query.code);
    const github = await fetchGitHubUser(accessToken);
    const { user, membership } = await ensureUserWorkspace(prisma, github);
    const session = generateSessionToken();
    await prisma.session.create({ data: {
      tokenHash: session.hash, userId: user.id, organizationId: membership.organizationId,
      expiresAt: new Date(Date.now() + SESSION_TTL_SECONDS * 1000),
    } });
    reply.header("set-cookie", [
      clearCookie(OAUTH_STATE_COOKIE_NAME, oauthStatePath()),
      serializeCookie(SESSION_COOKIE_NAME, session.value, SESSION_TTL_SECONDS),
    ]);
    return reply.code(302).header("location", `${dashboardUrl()}/`).send();
  });

  app.get("/api/v1/auth/me", {}, async (request, reply) => {
    const auth = getAuth(request);
    if (auth.kind !== "session") return reply.send({ kind: "api-key", organizationId: auth.organizationId });
    const membership = await prisma.organizationMember.findFirst({
      where: { userId: auth.principalId, organizationId: auth.organizationId },
      select: {
        role: true,
        organization: { select: { id: true, name: true, slug: true } },
        user: { select: { id: true, name: true, avatarUrl: true } },
      },
    });
    return membership ? reply.send({ kind: "session", ...membership }) : reply.code(401).send({ error: "unauthorized" });
  });

  app.post("/api/v1/auth/logout", {}, async (request, reply) => {
    const auth = getAuth(request);
    if (auth.kind === "session") {
      const rawToken = parseCookieHeader(request.headers.cookie).get(SESSION_COOKIE_NAME);
      if (rawToken) await prisma.session.updateMany({ where: { tokenHash: hashOpaqueToken(rawToken), userId: auth.principalId }, data: { revokedAt: new Date() } });
    }
    reply.header("set-cookie", clearCookie(SESSION_COOKIE_NAME));
    return reply.code(204).send();
  });

  app.post<{ Params: OrgParams }>("/api/v1/auth/organizations/:id/activate", {}, async (request, reply) => {
    const auth = getAuth(request);
    if (auth.kind !== "session") return reply.code(403).send({ error: "session_required" });
    const membership = await prisma.organizationMember.findFirst({ where: { userId: auth.principalId, organizationId: request.params.id }, select: { role: true } });
    if (!membership) return reply.code(404).send({ error: "organization_not_found" });
    const rawToken = parseCookieHeader(request.headers.cookie).get(SESSION_COOKIE_NAME);
    if (!rawToken) return reply.code(401).send({ error: "unauthorized" });
    await prisma.session.updateMany({ where: { tokenHash: hashOpaqueToken(rawToken), userId: auth.principalId }, data: { organizationId: request.params.id } });
    return reply.send({ organizationId: request.params.id });
  });

  app.get("/api/v1/api-keys", {}, async (request, reply) => {
    const auth = getAuth(request);
    if (auth.kind !== "session" || !requireRole(auth, ["owner", "admin"])) return reply.code(403).send({ error: "forbidden" });
    return reply.send(await prisma.apiKey.findMany({ where: { organizationId: auth.organizationId }, select: { id: true, name: true, prefix: true, createdAt: true, lastUsedAt: true, revokedAt: true }, orderBy: { createdAt: "desc" } }));
  });

  app.post<{ Body: ApiKeyBody }>("/api/v1/api-keys", { config: { rateLimit: { max: 10, timeWindow: "1 minute" } }, schema: { body: { type: "object", additionalProperties: false, required: ["name"], properties: { name: { type: "string", minLength: 1, maxLength: 80 } } } } }, async (request, reply) => {
    const auth = getAuth(request);
    if (auth.kind !== "session" || !requireRole(auth, ["owner", "admin"])) return reply.code(403).send({ error: "forbidden" });
    const generated = generateApiKey();
    const record = await prisma.apiKey.create({ data: { organizationId: auth.organizationId, name: request.body.name.trim(), prefix: generated.prefix, keyHash: generated.hash, createdBy: auth.principalId }, select: { id: true, name: true, prefix: true, createdAt: true } }) as { readonly id: string; readonly name: string; readonly prefix: string; readonly createdAt: Date };
    return reply.code(201).send({ ...record, key: generated.value });
  });

  app.post<{ Params: ApiKeyParams }>("/api/v1/api-keys/:id/revoke", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } } }, async (request, reply) => {
    const auth = getAuth(request);
    if (auth.kind !== "session" || !requireRole(auth, ["owner", "admin"])) return reply.code(403).send({ error: "forbidden" });
    const updated = await prisma.apiKey.updateMany({ where: { id: request.params.id, organizationId: auth.organizationId, revokedAt: null }, data: { revokedAt: new Date() } });
    return updated.count > 0 ? reply.code(204).send() : reply.code(404).send({ error: "api_key_not_found" });
  });
}
