import type { PrismaClient } from "@prisma/client";
import type { FastifyReply, FastifyRequest } from "fastify";
import { constantTimeHashMatch, parseApiKeyPrefix } from "./api-key.js";

export interface AuthContext { readonly organizationId: string; readonly principalId: string; readonly kind: "api-key"; }
interface ApiKeyRow { readonly id: string; readonly organizationId: string; readonly keyHash: string; readonly revokedAt: Date | null; }

const contexts = new WeakMap<object, AuthContext>();
export function getAuth(request: FastifyRequest): AuthContext {
  const context = contexts.get(request as object);
  if (!context) throw new Error("Authentication context is missing.");
  return context;
}

export function createAuthHook(prisma: PrismaClient) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (request.headers["x-specter-healthcheck"] === "1") return;
    const raw = request.headers.authorization;
    const header = Array.isArray(raw) ? raw[0] : raw;
    const token = header?.startsWith("Bearer ") ? header.slice(7).trim() : undefined;
    const prefix = token ? parseApiKeyPrefix(token) : undefined;
    if (!token || !prefix) { reply.code(401).send({ error: "unauthorized" }); return; }
    const record = await prisma.apiKey.findUnique({ where: { prefix }, select: { id: true, organizationId: true, keyHash: true, revokedAt: true } }) as ApiKeyRow | null;
    if (!record || record.revokedAt || !constantTimeHashMatch(token, record.keyHash)) { reply.code(401).send({ error: "unauthorized" }); return; }
    contexts.set(request as object, { organizationId: record.organizationId, principalId: record.id, kind: "api-key" });
    void prisma.apiKey.update({ where: { id: record.id }, data: { lastUsedAt: new Date() } }).catch(() => undefined);
  };
}
