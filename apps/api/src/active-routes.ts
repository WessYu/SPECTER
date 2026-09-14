import { createHash, randomBytes } from "node:crypto";
import type { PrismaClient } from "@prisma/client";
import type { FastifyInstance } from "fastify";
import { defaultConfig } from "@specter/config";
import { runActiveScan } from "@specter/scanner-active";
import { safeGet } from "@specter/scanner-web";
import type {
  ActiveAuthorization,
  ActiveProfile,
  ScanResult,
} from "@specter/types";
import { getAuth, requireRole } from "./auth.js";
import { persistScan } from "./persistence.js";

interface ProjectParams {
  readonly id: string;
}

interface EntityParams {
  readonly id: string;
}

interface CreateTargetBody {
  readonly url: string;
}

interface VerificationBody {
  readonly action?: "create" | "check";
}

interface StartScanBody {
  readonly targetId: string;
  readonly profile?: ActiveProfile;
  readonly maxRequests?: number;
}

interface ActiveTargetRow {
  readonly id: string;
  readonly projectId: string;
  readonly url: string;
  readonly hostname: string;
  readonly authorizationStatus: string;
  readonly tokenHash: string | null;
  readonly verificationExpiresAt: Date | null;
  readonly verifiedAt: Date | null;
  readonly authorizationExpiresAt: Date | null;
  readonly project: {
    readonly organizationId: string;
  };
}

const AUTHORIZATION_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
const VERIFICATION_TTL_MS = 30 * 60 * 1_000;
const MAX_CONCURRENT_ACTIVE_JOBS = 2;
const controllers = new Map<string, AbortController>();
const pendingJobs: Array<() => Promise<void>> = [];
let activeJobs = 0;

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function normalizeTarget(input: string): URL {
  const url = new URL(input);
  if (url.protocol !== "http:" && url.protocol !== "https:")
    throw new Error("target_url_must_be_http_or_https");
  if (url.username || url.password)
    throw new Error("target_url_must_not_include_credentials");
  url.hash = "";
  return url;
}

function normalizedHostname(url: URL): string {
  return url.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
}

function enqueue(job: () => Promise<void>): void {
  pendingJobs.push(job);
  pump();
}

function pump(): void {
  while (
    activeJobs < MAX_CONCURRENT_ACTIVE_JOBS &&
    pendingJobs.length > 0
  ) {
    const next = pendingJobs.shift();
    if (!next) return;
    activeJobs += 1;
    void next().finally(() => {
      activeJobs -= 1;
      pump();
    });
  }
}

async function audit(
  prisma: PrismaClient,
  input: {
    readonly projectId: string;
    readonly targetId?: string;
    readonly activeScanId?: string;
    readonly principalId: string;
    readonly action: string;
    readonly metadata?: Record<string, string | number | boolean | null>;
  },
): Promise<void> {
  await prisma.activeAuditLog.create({
    data: {
      projectId: input.projectId,
      ...(input.targetId ? { targetId: input.targetId } : {}),
      ...(input.activeScanId
        ? { activeScanId: input.activeScanId }
        : {}),
      principalId: input.principalId,
      action: input.action,
      ...(input.metadata ? { metadataJson: input.metadata } : {}),
    },
  });
}

async function ownedTarget(
  prisma: PrismaClient,
  organizationId: string,
  targetId: string,
): Promise<ActiveTargetRow | undefined> {
  return (
    ((await prisma.activeTarget.findFirst({
      where: {
        id: targetId,
        project: { organizationId },
      },
      include: {
        project: {
          select: { organizationId: true },
        },
      },
    })) as ActiveTargetRow | null) ?? undefined
  );
}

function verifiedAuthorization(
  target: ActiveTargetRow,
): ActiveAuthorization | undefined {
  if (
    target.authorizationStatus !== "verified" ||
    !target.verifiedAt ||
    !target.authorizationExpiresAt ||
    target.authorizationExpiresAt.getTime() <= Date.now()
  )
    return undefined;
  return {
    status: "verified",
    mode: "domain-verification",
    hostname: target.hostname,
    verifiedAt: target.verifiedAt.toISOString(),
    expiresAt: target.authorizationExpiresAt.toISOString(),
  };
}

async function previousActiveScore(
  prisma: PrismaClient,
  projectId: string,
): Promise<number | undefined> {
  const previous = await prisma.scan.findFirst({
    where: {
      projectId,
      scanType: "active",
      status: "completed",
    },
    orderBy: { completedAt: "desc" },
    select: { score: true },
  });
  return previous?.score;
}

async function executeActiveJob(
  prisma: PrismaClient,
  activeScanId: string,
  principalId: string,
): Promise<void> {
  const queued = await prisma.activeScan.findUnique({
    where: { id: activeScanId },
    include: { target: true },
  });
  if (!queued || queued.status === "cancelled") return;

  const controller = new AbortController();
  controllers.set(activeScanId, controller);
  await prisma.activeScan.update({
    where: { id: activeScanId },
    data: {
      status: "running",
      startedAt: new Date(),
    },
  });

  await audit(prisma, {
    projectId: queued.projectId,
    targetId: queued.targetId,
    activeScanId,
    principalId,
    action: "active_scan_started",
    metadata: {
      profile: queued.profile,
      requestBudget: queued.requestBudget,
    },
  });

  try {
    const target = (await ownedTarget(
      prisma,
      (
        await prisma.project.findUniqueOrThrow({
          where: { id: queued.projectId },
          select: { organizationId: true },
        })
      ).organizationId,
      queued.targetId,
    ));
    if (!target) throw new Error("active_target_not_found");

    const authorization = verifiedAuthorization(target);
    if (!authorization)
      throw new Error(
        "Active scanning requires verified ownership or explicit authorization.",
      );

    const priorScore = await previousActiveScore(
      prisma,
      queued.projectId,
    );
    const result = await runActiveScan(target.url, {
      authorization,
      signal: controller.signal,
      config: {
        ...defaultConfig.active,
        enabled: true,
        profile:
          queued.profile === "standard" ? "standard" : "safe",
        maxRequests: queued.requestBudget,
      },
      ...(process.env.SPECTER_TEST_USERNAME
        ? {
            testUsername:
              process.env.SPECTER_TEST_USERNAME,
          }
        : {}),
      ...(process.env.SPECTER_TEST_PASSWORD
        ? {
            testPassword:
              process.env.SPECTER_TEST_PASSWORD,
          }
        : {}),
    });

    const finalResult: ScanResult =
      priorScore === undefined
        ? result
        : {
            ...result,
            regressionDelta:
              Math.round((result.score.value - priorScore) * 10) /
              10,
          };

    await persistScan(
      prisma,
      target.project.organizationId,
      queued.projectId,
      finalResult,
    );

    await prisma.activeScan.update({
      where: { id: activeScanId },
      data: {
        status: "completed",
        completedAt: new Date(finalResult.completedAt),
        requestCount: finalResult.budget?.used ?? 0,
        endpointCount: finalResult.endpointCount ?? 0,
        findingCount: finalResult.findings.length,
        confirmedCount: finalResult.confirmedCount ?? 0,
        score: finalResult.score.value,
        resultScanId: finalResult.scanId,
        error: null,
      },
    });

    await audit(prisma, {
      projectId: queued.projectId,
      targetId: queued.targetId,
      activeScanId,
      principalId,
      action: "active_scan_completed",
      metadata: {
        score: finalResult.score.value,
        requestCount: finalResult.budget?.used ?? 0,
        endpointCount: finalResult.endpointCount ?? 0,
        findingCount: finalResult.findings.length,
        confirmedCount: finalResult.confirmedCount ?? 0,
        regressionDelta:
          finalResult.regressionDelta ?? null,
      },
    });
  } catch (error: unknown) {
    const cancelled =
      controller.signal.aborted ||
      (error as Error).name === "AbortError";
    await prisma.activeScan.update({
      where: { id: activeScanId },
      data: {
        status: cancelled ? "cancelled" : "failed",
        completedAt: new Date(),
        error: cancelled
          ? null
          : (error instanceof Error
              ? error.message
              : "Active scan failed"
            ).slice(0, 2_000),
      },
    });
    await audit(prisma, {
      projectId: queued.projectId,
      targetId: queued.targetId,
      activeScanId,
      principalId,
      action: cancelled
        ? "active_scan_cancelled"
        : "active_scan_failed",
      metadata: {
        cancelled,
        error: cancelled
          ? null
          : error instanceof Error
            ? error.message.slice(0, 500)
            : "Active scan failed",
      },
    });
  } finally {
    controllers.delete(activeScanId);
  }
}

export function registerActiveRoutes(
  app: FastifyInstance,
  prisma: PrismaClient,
): void {
  app.post<{
    Params: ProjectParams;
    Body: CreateTargetBody;
  }>(
    "/api/v1/projects/:id/active-targets",
    {
      config: {
        rateLimit: { max: 20, timeWindow: "1 minute" },
      },
    },
    async (request, reply) => {
      const auth = getAuth(request);
      if (
        auth.kind !== "session" ||
        !requireRole(auth, ["owner", "admin", "member"])
      )
        return reply.code(403).send({ error: "forbidden" });

      const project = await prisma.project.findFirst({
        where: {
          id: request.params.id,
          organizationId: auth.organizationId,
        },
        select: { id: true },
      });
      if (!project)
        return reply
          .code(404)
          .send({ error: "project_not_found" });

      let url: URL;
      try {
        url = normalizeTarget(request.body.url);
      } catch (error: unknown) {
        return reply.code(400).send({
          error:
            error instanceof Error
              ? error.message
              : "invalid_target",
        });
      }

      const target = await prisma.activeTarget.upsert({
        where: {
          projectId_url: {
            projectId: project.id,
            url: url.toString(),
          },
        },
        create: {
          projectId: project.id,
          url: url.toString(),
          hostname: normalizedHostname(url),
        },
        update: {
          hostname: normalizedHostname(url),
        },
      });
      await audit(prisma, {
        projectId: project.id,
        targetId: target.id,
        principalId: auth.principalId,
        action: "active_target_created",
        metadata: { hostname: target.hostname },
      });
      return reply.code(201).send(target);
    },
  );

  app.get<{ Params: ProjectParams }>(
    "/api/v1/projects/:id/active-targets",
    {},
    async (request, reply) => {
      const auth = getAuth(request);
      const project = await prisma.project.findFirst({
        where: {
          id: request.params.id,
          organizationId: auth.organizationId,
        },
        select: { id: true },
      });
      if (!project)
        return reply
          .code(404)
          .send({ error: "project_not_found" });

      const now = new Date();
      await prisma.activeTarget.updateMany({
        where: {
          projectId: project.id,
          authorizationStatus: "verified",
          authorizationExpiresAt: { lte: now },
        },
        data: { authorizationStatus: "expired" },
      });

      return reply.send(
        await prisma.activeTarget.findMany({
          where: { projectId: project.id },
          orderBy: { createdAt: "desc" },
        }),
      );
    },
  );

  app.post<{
    Params: EntityParams;
    Body: VerificationBody;
  }>(
    "/api/v1/active-targets/:id/verification",
    {
      config: {
        rateLimit: { max: 12, timeWindow: "1 minute" },
      },
    },
    async (request, reply) => {
      const auth = getAuth(request);
      if (
        auth.kind !== "session" ||
        !requireRole(auth, ["owner", "admin"])
      )
        return reply.code(403).send({ error: "forbidden" });

      const target = await ownedTarget(
        prisma,
        auth.organizationId,
        request.params.id,
      );
      if (!target)
        return reply
          .code(404)
          .send({ error: "active_target_not_found" });

      if ((request.body.action ?? "create") === "create") {
        const token = randomBytes(24).toString("base64url");
        const content = `specter-verification=${token}`;
        const expiresAt = new Date(
          Date.now() + VERIFICATION_TTL_MS,
        );
        await prisma.activeTarget.update({
          where: { id: target.id },
          data: {
            authorizationStatus: "unverified",
            tokenHash: sha256(content),
            tokenPrefix: token.slice(0, 8),
            verificationExpiresAt: expiresAt,
            verifiedAt: null,
            authorizationExpiresAt: null,
          },
        });
        await audit(prisma, {
          projectId: target.projectId,
          targetId: target.id,
          principalId: auth.principalId,
          action: "active_verification_generated",
          metadata: {
            tokenPrefix: token.slice(0, 8),
            expiresAt: expiresAt.toISOString(),
          },
        });
        return reply.code(201).send({
          token,
          content,
          httpPath:
            "/.well-known/specter-verification.txt",
          expiresAt: expiresAt.toISOString(),
        });
      }

      if (
        !target.tokenHash ||
        !target.verificationExpiresAt ||
        target.verificationExpiresAt.getTime() <= Date.now()
      ) {
        await prisma.activeTarget.update({
          where: { id: target.id },
          data: { authorizationStatus: "expired" },
        });
        return reply
          .code(400)
          .send({ error: "verification_expired" });
      }

      const verificationUrl = new URL(
        "/.well-known/specter-verification.txt",
        target.url,
      );
      let matched = false;
      try {
        const response = await safeGet(
          verificationUrl.toString(),
          {
            requestTimeoutMs: 5_000,
            totalTimeoutMs: 8_000,
            maxRedirects: 0,
            maxResponseBytes: 8_192,
            followRedirects: false,
            requireSameHostname: true,
          },
        );
        matched =
          response.status === 200 &&
          normalizedHostname(new URL(response.url)) ===
            target.hostname &&
          sha256(response.body.trim()) === target.tokenHash;
      } catch {
        matched = false;
      }

      if (!matched)
        return reply
          .code(409)
          .send({ verified: false });

      const verifiedAt = new Date();
      const authorizationExpiresAt = new Date(
        verifiedAt.getTime() + AUTHORIZATION_TTL_MS,
      );
      const updated = await prisma.activeTarget.update({
        where: { id: target.id },
        data: {
          authorizationStatus: "verified",
          verifiedAt,
          authorizationExpiresAt,
          tokenHash: null,
          tokenPrefix: null,
          verificationExpiresAt: null,
        },
      });
      await audit(prisma, {
        projectId: target.projectId,
        targetId: target.id,
        principalId: auth.principalId,
        action: "active_target_verified",
        metadata: {
          verifiedAt: verifiedAt.toISOString(),
          authorizationExpiresAt:
            authorizationExpiresAt.toISOString(),
        },
      });
      return reply.send({
        verified: true,
        target: updated,
      });
    },
  );

  app.post<{ Body: StartScanBody }>(
    "/api/v1/active-scans",
    {
      config: {
        rateLimit: { max: 8, timeWindow: "1 minute" },
      },
    },
    async (request, reply) => {
      const auth = getAuth(request);
      if (
        auth.kind !== "session" ||
        !requireRole(auth, ["owner", "admin", "member"])
      )
        return reply.code(403).send({ error: "forbidden" });

      const target = await ownedTarget(
        prisma,
        auth.organizationId,
        request.body.targetId,
      );
      if (!target)
        return reply
          .code(404)
          .send({ error: "active_target_not_found" });

      if (!verifiedAuthorization(target))
        return reply.code(403).send({
          error: "active_target_not_authorized",
          message:
            "Active scanning requires verified ownership or explicit authorization.",
        });

      const profile =
        request.body.profile === "standard"
          ? "standard"
          : "safe";
      const maxRequests =
        request.body.maxRequests ??
        defaultConfig.active.maxRequests;
      if (
        !Number.isInteger(maxRequests) ||
        maxRequests < 1 ||
        maxRequests > 5_000
      )
        return reply.code(400).send({
          error: "invalid_request_budget",
        });

      const scan = await prisma.activeScan.create({
        data: {
          projectId: target.projectId,
          targetId: target.id,
          status: "queued",
          profile,
          requestBudget: maxRequests,
          createdBy: auth.principalId,
        },
      });
      await audit(prisma, {
        projectId: target.projectId,
        targetId: target.id,
        activeScanId: scan.id,
        principalId: auth.principalId,
        action: "active_scan_queued",
        metadata: {
          profile,
          requestBudget: maxRequests,
        },
      });

      enqueue(() =>
        executeActiveJob(
          prisma,
          scan.id,
          auth.principalId,
        ),
      );
      return reply.code(202).send(scan);
    },
  );

  app.get<{ Params: ProjectParams }>(
    "/api/v1/projects/:id/active-scans",
    {},
    async (request, reply) => {
      const auth = getAuth(request);
      const project = await prisma.project.findFirst({
        where: {
          id: request.params.id,
          organizationId: auth.organizationId,
        },
        select: { id: true },
      });
      if (!project)
        return reply
          .code(404)
          .send({ error: "project_not_found" });
      return reply.send(
        await prisma.activeScan.findMany({
          where: { projectId: project.id },
          include: {
            target: {
              select: {
                url: true,
                hostname: true,
                authorizationStatus: true,
              },
            },
          },
          orderBy: { createdAt: "desc" },
          take: 100,
        }),
      );
    },
  );

  app.get<{ Params: EntityParams }>(
    "/api/v1/active-scans/:id",
    {},
    async (request, reply) => {
      const auth = getAuth(request);
      const scan = await prisma.activeScan.findFirst({
        where: {
          id: request.params.id,
          project: {
            organizationId: auth.organizationId,
          },
        },
        include: {
          target: true,
          resultScan: true,
        },
      });
      return scan
        ? reply.send(scan)
        : reply
            .code(404)
            .send({ error: "active_scan_not_found" });
    },
  );

  app.post<{ Params: EntityParams }>(
    "/api/v1/active-scans/:id/cancel",
    {
      config: {
        rateLimit: { max: 20, timeWindow: "1 minute" },
      },
    },
    async (request, reply) => {
      const auth = getAuth(request);
      if (
        auth.kind !== "session" ||
        !requireRole(auth, ["owner", "admin", "member"])
      )
        return reply.code(403).send({ error: "forbidden" });

      const scan = await prisma.activeScan.findFirst({
        where: {
          id: request.params.id,
          project: {
            organizationId: auth.organizationId,
          },
        },
      });
      if (!scan)
        return reply
          .code(404)
          .send({ error: "active_scan_not_found" });
      if (
        scan.status !== "queued" &&
        scan.status !== "running"
      )
        return reply.code(409).send({
          error: "active_scan_not_cancellable",
        });

      controllers.get(scan.id)?.abort();
      const cancelled = await prisma.activeScan.update({
        where: { id: scan.id },
        data: {
          status: "cancelled",
          completedAt: new Date(),
        },
      });
      await audit(prisma, {
        projectId: scan.projectId,
        targetId: scan.targetId,
        activeScanId: scan.id,
        principalId: auth.principalId,
        action: "active_scan_cancel_requested",
      });
      return reply.send(cancelled);
    },
  );

  app.get<{ Params: ProjectParams }>(
    "/api/v1/projects/:id/active-findings",
    {},
    async (request, reply) => {
      const auth = getAuth(request);
      const project = await prisma.project.findFirst({
        where: {
          id: request.params.id,
          organizationId: auth.organizationId,
        },
        select: { id: true },
      });
      if (!project)
        return reply
          .code(404)
          .send({ error: "project_not_found" });
      return reply.send(
        await prisma.finding.findMany({
          where: {
            projectId: project.id,
            scanner: "active",
          },
          include: {
            occurrences: {
              orderBy: { observedAt: "desc" },
              take: 1,
            },
          },
          orderBy: [
            { lastDetectedAt: "desc" },
            { severity: "desc" },
          ],
          take: 500,
        }),
      );
    },
  );
}
