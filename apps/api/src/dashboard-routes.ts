import type { PrismaClient } from "@prisma/client";
import type { FastifyInstance } from "fastify";
import { getAuth } from "./auth.js";
import { requireProject } from "./persistence.js";

interface ProjectParams {
  readonly id: string;
}
interface FindingQuery {
  readonly severity?: string;
  readonly category?: string;
  readonly source?: string;
  readonly status?: string;
  readonly limit?: string;
}

const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
const STATUSES = new Set(["open", "resolved", "suppressed"]);
const SOURCES = new Set(["static", "build", "dependency", "remote", "runtime"]);
const CATEGORIES = new Set([
  "secret",
  "dependency",
  "source",
  "configuration",
  "headers",
  "cookies",
  "cors",
  "csp",
  "tls",
  "client-exposure",
  "third-party",
  "route",
  "runtime",
  "build",
]);

function one(
  value: string | undefined,
  allowed: ReadonlySet<string>,
  field: string,
): string | undefined {
  if (value === undefined || value === "") return undefined;
  if (!allowed.has(value)) throw new Error(`INVALID_${field.toUpperCase()}`);
  return value;
}

function boundedLimit(raw: string | undefined): number {
  if (!raw) return 100;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > 200) throw new Error("INVALID_LIMIT");
  return value;
}

export function registerDashboardRoutes(app: FastifyInstance, prisma: PrismaClient): void {
  app.get("/api/v1/overview", {}, async (request, reply) => {
    const auth = getAuth(request);
    const projects = await prisma.project.findMany({
      where: { organizationId: auth.organizationId },
      orderBy: { updatedAt: "desc" },
      select: {
        id: true,
        name: true,
        slug: true,
        updatedAt: true,
        domains: {
          select: { id: true, hostname: true, verifiedAt: true },
          orderBy: { createdAt: "asc" },
        },
        scans: {
          select: {
            id: true,
            score: true,
            status: true,
            completedAt: true,
            targetKind: true,
            targetValue: true,
          },
          orderBy: { completedAt: "desc" },
          take: 2,
        },
        findings: {
          where: { status: "open", severity: { in: ["critical", "high"] } },
          select: { id: true, severity: true },
        },
      },
    });
    return reply.send({ projects });
  });

  app.get<{ Params: ProjectParams }>(
    "/api/v1/projects/:id/overview",
    {},
    async (request, reply) => {
      const auth = getAuth(request);
      const project = await prisma.project.findFirst({
        where: { id: request.params.id, organizationId: auth.organizationId },
        select: {
          id: true,
          name: true,
          slug: true,
          createdAt: true,
          updatedAt: true,
          domains: {
            select: { id: true, hostname: true, verifiedAt: true },
            orderBy: { createdAt: "asc" },
          },
        },
      });
      if (!project) return reply.code(404).send({ error: "project_not_found" });

      const scans = await prisma.scan.findMany({
        where: { projectId: request.params.id },
        orderBy: { completedAt: "desc" },
        take: 2,
        select: {
          id: true,
          targetKind: true,
          targetValue: true,
          status: true,
          score: true,
          summaryJson: true,
          modulesJson: true,
          errorsJson: true,
          completedAt: true,
          durationMs: true,
        },
      });
      const latest = scans[0] as { readonly id?: string } | undefined;
      const latestFindings = latest?.id
        ? await prisma.finding.findMany({
            where: { projectId: request.params.id, occurrences: { some: { scanId: latest.id } } },
            orderBy: [{ severity: "desc" }, { lastDetectedAt: "desc" }],
            take: 20,
            select: {
              id: true,
              ruleId: true,
              title: true,
              severity: true,
              category: true,
              confidence: true,
              source: true,
              firstDetectedAt: true,
              lastDetectedAt: true,
              status: true,
            },
          })
        : [];
      return reply.send({
        project,
        scans,
        latestFindings,
        metrics: {
          codeSecurity: null,
          dependencies: null,
          clientExposure: null,
          runtimeConfiguration: null,
          attackSurface: null,
        },
      });
    },
  );

  app.get<{ Params: ProjectParams; Querystring: FindingQuery }>(
    "/api/v1/projects/:id/findings",
    {},
    async (request, reply) => {
      const auth = getAuth(request);
      if (!(await requireProject(prisma, auth.organizationId, request.params.id)))
        return reply.code(404).send({ error: "project_not_found" });
      try {
        const severity = one(request.query.severity, SEVERITIES, "severity");
        const category = one(request.query.category, CATEGORIES, "category");
        const source = one(request.query.source, SOURCES, "source");
        const status = one(request.query.status, STATUSES, "status");
        const limit = boundedLimit(request.query.limit);
        const findings = await prisma.finding.findMany({
          where: {
            projectId: request.params.id,
            ...(severity ? { severity } : {}),
            ...(category ? { category } : {}),
            ...(source ? { source } : {}),
            ...(status ? { status } : {}),
          },
          orderBy: [{ lastDetectedAt: "desc" }],
          take: limit,
          include: { occurrences: { orderBy: { observedAt: "desc" }, take: 1 } },
        });
        return reply.send({ findings });
      } catch (error: unknown) {
        if (error instanceof Error && error.message.startsWith("INVALID_"))
          return reply.code(400).send({ error: error.message.toLowerCase() });
        throw error;
      }
    },
  );
}
