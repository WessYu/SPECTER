import fastify, { type FastifyInstance } from "fastify";
import rateLimit from "@fastify/rate-limit";
import { PrismaClient } from "@prisma/client";
import { createAuthHook } from "./auth.js";
import { registerRoutes } from "./routes.js";

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
    if (request.url === "/health") return;
    await authHook(request, reply);
  });
  registerRoutes(app, prisma);
  return app;
}
