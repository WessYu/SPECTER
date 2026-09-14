import fastify, { type FastifyInstance } from "fastify";
import rateLimit from "@fastify/rate-limit";
import { PrismaClient } from "@prisma/client";
import { createAuthHook } from "./auth.js";
import { registerRoutes } from "./routes.js";
import { registerAuthRoutes } from "./auth-routes.js";
import { registerDashboardRoutes } from "./dashboard-routes.js";
import { registerHistoryRoutes } from "./history-routes.js";
import { registerActiveRoutes } from "./active-routes.js";

export function createServer(prisma = new PrismaClient()): FastifyInstance {
  const app = fastify({
    logger: {
      level: process.env.LOG_LEVEL ?? "info",
      redact: [
        "req.headers.authorization",
        "req.headers.cookie",
        "res.headers.set-cookie",
        "body.password",
        "body.token",
        "body.secret",
      ],
    },
    requestIdHeader: "x-request-id",
    bodyLimit: 1_000_000,
  });
  void app.register(rateLimit, {
    max: 120,
    timeWindow: "1 minute",
    keyGenerator: (request: { ip: string }) => request.ip,
  });
  app.addHook("onSend", async (_request, reply, payload) => {
    reply.header("x-content-type-options", "nosniff");
    reply.header("x-frame-options", "DENY");
    reply.header("referrer-policy", "no-referrer");
    reply.header("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()");
    reply.header(
      "content-security-policy",
      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    reply.header("cache-control", "no-store");
    if (process.env.NODE_ENV === "production")
      reply.header("strict-transport-security", "max-age=31536000");
    return payload;
  });
  const authHook = createAuthHook(prisma);
  app.addHook("onRequest", async (request, reply) => {
    const path = request.url.split("?", 1)[0] ?? request.url;
    if (
      path === "/health" ||
      path === "/api/v1/auth/github/start" ||
      path === "/api/v1/auth/github/callback"
    )
      return;
    await authHook(request, reply);
  });
  registerAuthRoutes(app, prisma);
  registerDashboardRoutes(app, prisma);
  registerHistoryRoutes(app, prisma);
  registerActiveRoutes(app, prisma);
  registerRoutes(app, prisma);
  return app;
}
