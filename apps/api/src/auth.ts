import type { PrismaClient } from "@prisma/client";
import type { FastifyReply, FastifyRequest } from "fastify";
import { constantTimeHashMatch, parseApiKeyPrefix } from "./api-key.js";
import { hashOpaqueToken, parseCookieHeader, SESSION_COOKIE_NAME } from "./session.js";

export type OrganizationRole = "owner" | "admin" | "member" | "viewer";
export interface AuthContext {
  readonly organizationId: string;
  readonly principalId: string;
  readonly kind: "api-key" | "session";
  readonly role?: OrganizationRole;
}
interface ApiKeyRow {
  readonly id: string;
  readonly organizationId: string;
  readonly keyHash: string;
  readonly revokedAt: Date | null;
}
interface SessionRow {
  readonly id: string;
  readonly userId: string;
  readonly organizationId: string;
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
  readonly user: {
    readonly memberships: ReadonlyArray<{
      readonly role: OrganizationRole;
      readonly organizationId: string;
    }>;
  };
}

const contexts = new WeakMap<object, AuthContext>();
export function getAuth(request: FastifyRequest): AuthContext {
  const context = contexts.get(request as object);
  if (!context) throw new Error("Authentication context is missing.");
  return context;
}

async function authenticateApiKey(
  prisma: PrismaClient,
  token: string,
): Promise<AuthContext | undefined> {
  const prefix = parseApiKeyPrefix(token);
  if (!prefix) return undefined;
  const record = (await prisma.apiKey.findUnique({
    where: { prefix },
    select: { id: true, organizationId: true, keyHash: true, revokedAt: true },
  })) as ApiKeyRow | null;
  if (!record || record.revokedAt || !constantTimeHashMatch(token, record.keyHash))
    return undefined;
  void prisma.apiKey
    .update({ where: { id: record.id }, data: { lastUsedAt: new Date() } })
    .catch(() => undefined);
  return { organizationId: record.organizationId, principalId: record.id, kind: "api-key" };
}

async function authenticateSession(
  prisma: PrismaClient,
  request: FastifyRequest,
): Promise<AuthContext | undefined> {
  const token = parseCookieHeader(request.headers.cookie).get(SESSION_COOKIE_NAME);
  if (!token?.startsWith("sp_session_")) return undefined;
  const record = (await prisma.session.findUnique({
    where: { tokenHash: hashOpaqueToken(token) },
    select: {
      id: true,
      userId: true,
      organizationId: true,
      expiresAt: true,
      revokedAt: true,
      user: {
        select: {
          memberships: {
            where: { organizationId: { not: "" } },
            select: { organizationId: true, role: true },
          },
        },
      },
    },
  })) as SessionRow | null;
  if (!record || record.revokedAt || record.expiresAt.getTime() <= Date.now()) return undefined;
  const membership = record.user.memberships.find(
    (item) => item.organizationId === record.organizationId,
  );
  if (!membership) return undefined;
  void prisma.session
    .update({ where: { id: record.id }, data: { lastUsedAt: new Date() } })
    .catch(() => undefined);
  return {
    organizationId: record.organizationId,
    principalId: record.userId,
    kind: "session",
    role: membership.role,
  };
}

export function createAuthHook(prisma: PrismaClient) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const raw = request.headers.authorization;
    const header = Array.isArray(raw) ? raw[0] : raw;
    const bearer = header?.startsWith("Bearer ") ? header.slice(7).trim() : undefined;
    const context = bearer
      ? await authenticateApiKey(prisma, bearer)
      : await authenticateSession(prisma, request);
    if (!context) {
      reply.code(401).send({ error: "unauthorized" });
      return;
    }
    contexts.set(request as object, context);
  };
}

export function requireRole(auth: AuthContext, allowed: readonly OrganizationRole[]): boolean {
  if (auth.kind === "api-key") return true;
  return auth.role !== undefined && allowed.includes(auth.role);
}
