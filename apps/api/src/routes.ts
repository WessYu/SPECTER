import { createHash, randomBytes } from "node:crypto";
import { resolveTxt } from "node:dns/promises";
import type { PrismaClient } from "@prisma/client";
import type { FastifyInstance } from "fastify";
import { safeGet } from "@specter/scanner-web";
import type { ScanResult } from "@specter/types";
import { getAuth, requireRole } from "./auth.js";
import { persistScan, requireProject } from "./persistence.js";
import { projectBodySchema, scanBodySchema, suppressionBodySchema } from "./schemas.js";
import { validateScanResult } from "./scan-validation.js";

interface ProjectBody { readonly name: string; readonly slug: string; }
interface ScanBody { readonly projectId: string; readonly result: ScanResult; }
interface SuppressionBody { readonly projectId: string; readonly ruleId?: string; readonly fingerprint?: string; readonly reason: string; readonly expiresAt?: string; }
interface IdParams { readonly id: string; }
interface DomainRow { readonly id: string; readonly hostname: string; readonly project: { readonly organizationId: string } }
interface VerificationRow { readonly id: string; readonly tokenHash: string; readonly tokenPrefix: string; readonly expiresAt: Date; }

function sha256(value: string): string { return createHash("sha256").update(value).digest("hex"); }

export function registerRoutes(app: FastifyInstance, prisma: PrismaClient): void {
  app.get("/health", {}, async (_request, reply) => reply.send({ ok: true }));

  app.post<{ Body: ProjectBody }>("/api/v1/projects", { schema: { body: projectBodySchema } }, async (request, reply) => {
    const auth = getAuth(request);
    if (auth.kind !== "session" || !requireRole(auth, ["owner", "admin"])) return reply.code(403).send({ error: "forbidden" });
    const project = await prisma.project.create({ data: { organizationId: auth.organizationId, name: request.body.name.trim(), slug: request.body.slug } });
    return reply.code(201).send(project);
  });
  app.get("/api/v1/projects", {}, async (request, reply) => {
    const auth = getAuth(request);
    return reply.send(await prisma.project.findMany({ where: { organizationId: auth.organizationId }, orderBy: { updatedAt: "desc" } }));
  });
  app.get<{ Params: IdParams }>("/api/v1/projects/:id", {}, async (request, reply) => {
    const auth = getAuth(request);
    const project = await prisma.project.findFirst({ where: { id: request.params.id, organizationId: auth.organizationId } });
    return project ? reply.send(project) : reply.code(404).send({ error: "project_not_found" });
  });

  app.post<{ Body: ScanBody }>("/api/v1/scans", { config: { rateLimit: { max: 30, timeWindow: "1 minute" } }, schema: { body: scanBodySchema } }, async (request, reply) => {
    const auth = getAuth(request);
    let result: ScanResult;
    try { result = validateScanResult(request.body.result); }
    catch (error: unknown) { return reply.code(400).send({ error: "invalid_scan_result", message: error instanceof Error ? error.message : "Invalid scan result" }); }
    try { await persistScan(prisma, auth.organizationId, request.body.projectId, result); }
    catch (error: unknown) {
      if (error instanceof Error && error.message === "PROJECT_NOT_FOUND") return reply.code(404).send({ error: "project_not_found" });
      throw error;
    }
    return reply.code(201).send({ id: result.scanId });
  });
  app.get<{ Params: IdParams }>("/api/v1/scans/:id", {}, async (request, reply) => {
    const auth = getAuth(request);
    const scan = await prisma.scan.findFirst({ where: { id: request.params.id, project: { organizationId: auth.organizationId } }, include: { occurrences: { include: { finding: true } } } });
    return scan ? reply.send(scan) : reply.code(404).send({ error: "scan_not_found" });
  });
  app.get<{ Params: IdParams }>("/api/v1/projects/:id/scans", {}, async (request, reply) => {
    const auth = getAuth(request);
    if (!(await requireProject(prisma, auth.organizationId, request.params.id))) return reply.code(404).send({ error: "project_not_found" });
    return reply.send(await prisma.scan.findMany({ where: { projectId: request.params.id }, orderBy: { completedAt: "desc" }, take: 100 }));
  });
  app.get<{ Params: IdParams }>("/api/v1/findings/:id", {}, async (request, reply) => {
    const auth = getAuth(request);
    const finding = await prisma.finding.findFirst({ where: { id: request.params.id, project: { organizationId: auth.organizationId } }, include: { occurrences: { orderBy: { observedAt: "desc" }, take: 20 } } });
    return finding ? reply.send(finding) : reply.code(404).send({ error: "finding_not_found" });
  });

  app.post<{ Body: SuppressionBody }>("/api/v1/suppressions", { schema: { body: suppressionBodySchema } }, async (request, reply) => {
    const auth = getAuth(request);
    if (auth.kind !== "session" || !requireRole(auth, ["owner", "admin", "member"])) return reply.code(403).send({ error: "forbidden" });
    if (!(await requireProject(prisma, auth.organizationId, request.body.projectId))) return reply.code(404).send({ error: "project_not_found" });
    const suppression = await prisma.$transaction(async (tx) => {
      const created = await tx.suppression.create({ data: {
        projectId: request.body.projectId, ...(request.body.ruleId ? { ruleId: request.body.ruleId } : {}), ...(request.body.fingerprint ? { fingerprint: request.body.fingerprint } : {}),
        reason: request.body.reason.trim(), ...(request.body.expiresAt ? { expiresAt: new Date(request.body.expiresAt) } : {}), createdBy: auth.principalId,
      } });
      await tx.finding.updateMany({
        where: {
          projectId: request.body.projectId,
          ...(request.body.ruleId ? { ruleId: request.body.ruleId } : {}),
          ...(request.body.fingerprint ? { fingerprint: request.body.fingerprint } : {}),
        },
        data: { status: "suppressed" },
      });
      return created;
    });
    return reply.code(201).send(suppression);
  });

  app.post<{ Params: IdParams; Body: { readonly action?: "create" | "check" } }>("/api/v1/domains/:id/verify", { config: { rateLimit: { max: 20, timeWindow: "1 minute" } }, schema: { body: { type: "object", additionalProperties: false, properties: { action: { enum: ["create", "check"] } } } } }, async (request, reply) => {
    const auth = getAuth(request);
    if (auth.kind !== "session" || !requireRole(auth, ["owner", "admin"])) return reply.code(403).send({ error: "forbidden" });
    const domain = await prisma.domain.findFirst({ where: { id: request.params.id, project: { organizationId: auth.organizationId } }, select: { id: true, hostname: true, project: { select: { organizationId: true } } } }) as DomainRow | null;
    if (!domain) return reply.code(404).send({ error: "domain_not_found" });
    if ((request.body.action ?? "create") === "create") {
      const token = randomBytes(24).toString("base64url");
      const prefix = token.slice(0, 8);
      await prisma.domainVerification.create({ data: { domainId: domain.id, tokenHash: sha256(token), tokenPrefix: prefix, method: "dns-or-http", expiresAt: new Date(Date.now() + 30 * 60_000) } });
      return reply.code(201).send({ token, dns: `specter-verification=${token}`, httpPath: "/.well-known/specter-verification.txt", expiresInSeconds: 1800 });
    }
    const verification = await prisma.domainVerification.findFirst({ where: { domainId: domain.id, verifiedAt: null, expiresAt: { gt: new Date() } }, orderBy: { createdAt: "desc" } }) as VerificationRow | null;
    if (!verification) return reply.code(400).send({ error: "no_active_verification" });
    let matched = false;
    try {
      const records = (await resolveTxt(domain.hostname)).flat();
      matched = records.some((record) => record.startsWith("specter-verification=") && sha256(record.slice("specter-verification=".length)) === verification.tokenHash);
    } catch { /* DNS method optional */ }
    if (!matched) {
      try {
        const response = await safeGet(`https://${domain.hostname}/.well-known/specter-verification.txt`, { requestTimeoutMs: 5_000, maxRedirects: 2, maxResponseBytes: 4_096, totalTimeoutMs: 10_000 });
        matched = response.status === 200 && sha256(response.body.trim()) === verification.tokenHash;
      } catch { /* HTTP method optional */ }
    }
    if (!matched) return reply.code(409).send({ verified: false });
    await prisma.$transaction(async (tx) => {
      await tx.domain.update({ where: { id: domain.id }, data: { verifiedAt: new Date() } });
      await tx.domainVerification.update({ where: { id: verification.id }, data: { verifiedAt: new Date() } });
    });
    return reply.send({ verified: true });
  });
}
