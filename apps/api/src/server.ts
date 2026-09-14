import fastify, { type FastifyInstance } from "fastify";
import rateLimit from "@fastify/rate-limit";
import { PrismaClient } from "@prisma/client";
import { createAuthHook } from "./auth.js";
import { registerRoutes } from "./routes.js";
import { registerAuthRoutes } from "./auth-routes.js";

export function createServer(prisma = new PrismaClient()): FastifyInstance {
  const app = fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? "info",
      redact: ["req.headers.authorization", "req.headers.cookie", "res.headers.set-cookie", "body.password", "body.token", "body.secret"],
    },
    requestIdHeader: "x-request-id",
    bodyLimit: 1_000_000,
  });
  void app.register(rateLimit, { max: 120, timeWindow: "1 minute", keyGenerator: (request: { headers: Record<string, unknown> }) => String(request.headers["x-forwarded-for"] ?? "unknown") });
  const authHook = createAuthHook(prisma);
  app.addHook("onRequest", async (request, reply) => {
    const path = request.url.split("?", 1)[0] ?? request.url;
    if (path === "/health" || path === "/api/v1/auth/github/start" || path === "/api/v1/auth/github/callback") return;
    await authHook(request, reply);
  });
  registerAuthRoutes(app, prisma);
  registerRoutes(app, prisma);
  return app;
}
