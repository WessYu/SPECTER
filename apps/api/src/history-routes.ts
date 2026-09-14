import { Prisma, type PrismaClient } from "@prisma/client";
import type { FastifyInstance } from "fastify";
import { compareScans } from "@specter/core";
import { getAuth, requireRole } from "./auth.js";
import { requireProject } from "./persistence.js";
import { hydratePersistedScan, hydrateSurface, type PersistedScanRow } from "./scan-hydration.js";

interface ProjectParams {
  readonly id: string;
}
interface CompareQuery {
  readonly previous?: string;
  readonly current?: string;
}
interface DomainBody {
  readonly hostname: string;
}

function normalizeHostname(input: string): string | undefined {
  const value = input.trim().toLowerCase().replace(/\.$/, "");
  if (
    value.length < 1 ||
    value.length > 253 ||
    value.includes(":") ||
    value.includes("/") ||
    value.includes("@")
  )
    return undefined;
  if (
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
      value,
    )
  )
    return undefined;
  return value;
}

const scanInclude = {
  occurrences: {
    include: { finding: true },
  },
} as const;

export function registerHistoryRoutes(app: FastifyInstance, prisma: PrismaClient): void {
  app.get<{ Params: ProjectParams }>("/api/v1/projects/:id/history", {}, async (request, reply) => {
    const auth = getAuth(request);
    if (!(await requireProject(prisma, auth.organizationId, request.params.id)))
      return reply.code(404).send({ error: "project_not_found" });
    const scans = await prisma.scan.findMany({
      where: { projectId: request.params.id },
      select: {
        id: true,
        score: true,
        status: true,
        targetKind: true,
        targetValue: true,
        completedAt: true,
        durationMs: true,
        summaryJson: true,
      },
      orderBy: { completedAt: "asc" },
      take: 250,
    });
    return reply.send({ scans });
  });

  app.get<{ Params: ProjectParams; Querystring: CompareQuery }>(
    "/api/v1/projects/:id/compare",
    {},
    async (request, reply) => {
      const auth = getAuth(request);
      if (!(await requireProject(prisma, auth.organizationId, request.params.id)))
        return reply.code(404).send({ error: "project_not_found" });
      if (
        !request.query.previous ||
        !request.query.current ||
        request.query.previous === request.query.current
      )
        return reply.code(400).send({ error: "two_distinct_scan_ids_required" });
      const rows = (await prisma.scan.findMany({
        where: {
          projectId: request.params.id,
          id: { in: [request.query.previous, request.query.current] },
        },
        include: scanInclude,
      })) as unknown as PersistedScanRow[];
      const previousRow = rows.find((row) => row.id === request.query.previous);
      const currentRow = rows.find((row) => row.id === request.query.current);
      if (!previousRow || !currentRow) return reply.code(404).send({ error: "scan_not_found" });
      try {
        return reply.send(
          compareScans(hydratePersistedScan(previousRow), hydratePersistedScan(currentRow)),
        );
      } catch (error: unknown) {
        return reply.code(409).send({
          error: "unsupported_scan_schema",
          message: error instanceof Error ? error.message : "Unable to hydrate scan.",
        });
      }
    },
  );

  app.get<{ Params: ProjectParams }>(
    "/api/v1/projects/:id/attack-surface",
    {},
    async (request, reply) => {
      const auth = getAuth(request);
      if (!(await requireProject(prisma, auth.organizationId, request.params.id)))
        return reply.code(404).send({ error: "project_not_found" });
      const scans = (await prisma.scan.findMany({
        where: { projectId: request.params.id, surfaceJson: { not: Prisma.DbNull } },
        select: { id: true, completedAt: true, surfaceJson: true },
        orderBy: { completedAt: "desc" },
        take: 2,
      })) as unknown as Array<{
        readonly id: string;
        readonly completedAt: Date;
        readonly surfaceJson?: unknown;
      }>;
      const current = scans[0];
      const previous = scans[1];
      const currentSurface = hydrateSurface(current?.surfaceJson);
      const previousSurface = hydrateSurface(previous?.surfaceJson);
      const currentDomains = new Map(
        (currentSurface?.externalDomains ?? []).map((domain) => [domain.domain, domain]),
      );
      const previousDomains = new Map(
        (previousSurface?.externalDomains ?? []).map((domain) => [domain.domain, domain]),
      );
      const domains = [
        ...[...currentDomains.values()].map((domain) => ({
          ...domain,
          state: previousDomains.has(domain.domain) ? "unchanged" : "new",
        })),
        ...[...previousDomains.values()]
          .filter((domain) => !currentDomains.has(domain.domain))
          .map((domain) => ({ ...domain, state: "removed" })),
      ].sort((a, b) => a.domain.localeCompare(b.domain));
      return reply.send({
        currentScanId: current?.id ?? null,
        previousScanId: previous?.id ?? null,
        observedAt: current?.completedAt ?? null,
        routes: currentSurface?.routes ?? [],
        domains,
      });
    },
  );

  app.get<{ Params: ProjectParams }>("/api/v1/projects/:id/domains", {}, async (request, reply) => {
    const auth = getAuth(request);
    if (!(await requireProject(prisma, auth.organizationId, request.params.id)))
      return reply.code(404).send({ error: "project_not_found" });
    return reply.send(
      await prisma.domain.findMany({
        where: { projectId: request.params.id },
        orderBy: { createdAt: "asc" },
        select: { id: true, hostname: true, verifiedAt: true, createdAt: true },
      }),
    );
  });

  app.post<{ Params: ProjectParams; Body: DomainBody }>(
    "/api/v1/projects/:id/domains",
    {
      schema: {
        body: {
          type: "object",
          additionalProperties: false,
          required: ["hostname"],
          properties: { hostname: { type: "string", minLength: 1, maxLength: 253 } },
        },
      },
    },
    async (request, reply) => {
      const auth = getAuth(request);
      if (auth.kind !== "session" || !requireRole(auth, ["owner", "admin"]))
        return reply.code(403).send({ error: "forbidden" });
      if (!(await requireProject(prisma, auth.organizationId, request.params.id)))
        return reply.code(404).send({ error: "project_not_found" });
      const hostname = normalizeHostname(request.body.hostname);
      if (!hostname) return reply.code(400).send({ error: "invalid_hostname" });
      try {
        const domain = await prisma.domain.create({
          data: { projectId: request.params.id, hostname },
          select: { id: true, hostname: true, verifiedAt: true, createdAt: true },
        });
        return reply.code(201).send(domain);
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : "";
        if (message.includes("Unique constraint") || message.includes("P2002"))
          return reply.code(409).send({ error: "domain_exists" });
        throw error;
      }
    },
  );
}
