import { Prisma, type PrismaClient } from "@prisma/client";
import { matchesSuppression, redactEvidence } from "@specter/core";
import type { Finding, FindingSource, ScanResult, Suppression } from "@specter/types";

interface ProjectRow {
  readonly id: string;
  readonly organizationId: string;
}
interface FindingRow {
  readonly id: string;
}
type DatabaseClient = PrismaClient | Prisma.TransactionClient;

interface SuppressionRow {
  readonly ruleId: string | null;
  readonly fingerprint: string | null;
  readonly reason: string;
  readonly expiresAt: Date | null;
}

export async function requireProject(
  prisma: DatabaseClient,
  organizationId: string,
  projectId: string,
): Promise<ProjectRow | undefined> {
  return (
    ((await prisma.project.findFirst({
      where: { id: projectId, organizationId },
      select: { id: true, organizationId: true },
    })) as ProjectRow | null) ?? undefined
  );
}

function toInputJson(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

function relevantSources(result: ScanResult): readonly FindingSource[] {
  return result.target.kind === "url" ? ["remote", "runtime"] : ["static", "build", "dependency"];
}

function toSuppression(row: SuppressionRow): Suppression {
  return {
    ...(row.ruleId ? { ruleId: row.ruleId } : {}),
    ...(row.fingerprint ? { fingerprint: row.fingerprint } : {}),
    reason: row.reason,
    ...(row.expiresAt ? { expiresAt: row.expiresAt.toISOString() } : {}),
  };
}

export async function persistScan(
  prisma: PrismaClient,
  organizationId: string,
  projectId: string,
  result: ScanResult,
): Promise<void> {
  const project = await requireProject(prisma, organizationId, projectId);
  if (!project) throw new Error("PROJECT_NOT_FOUND");
  await prisma.$transaction(async (tx) => {
    const now = new Date(result.completedAt);
    const suppressionRows = (await tx.suppression.findMany({
      where: { projectId, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
      select: { ruleId: true, fingerprint: true, reason: true, expiresAt: true },
    })) as SuppressionRow[];
    const suppressions = suppressionRows.map(toSuppression);

    await tx.scan.create({
      data: {
        id: result.scanId,
        projectId,
        targetKind: result.target.kind,
        targetValue: result.target.value,
        status: result.status,
        score: result.score.value,
        schemaVersion: result.schemaVersion,
        summaryJson: toInputJson(result.summary),
        modulesJson: toInputJson(result.modules),
        errorsJson: toInputJson(result.errors),
        ...(result.surface ? { surfaceJson: toInputJson(result.surface) } : {}),
        startedAt: new Date(result.startedAt),
        completedAt: now,
        durationMs: Math.round(result.durationMs),
      },
    });

    const observedFingerprints: string[] = [];
    for (const finding of result.findings) {
      observedFingerprints.push(finding.fingerprint);
      const suppressed =
        finding.status === "suppressed" ||
        suppressions.some((item) => matchesSuppression(finding, item, now));
      await persistFinding(tx, projectId, result, finding, suppressed ? "suppressed" : "open");
    }

    const sources = relevantSources(result);
    await tx.finding.updateMany({
      where: {
        projectId,
        source: { in: [...sources] },
        ...(observedFingerprints.length ? { fingerprint: { notIn: observedFingerprints } } : {}),
        status: { not: "suppressed" },
      },
      data: { status: "resolved" },
    });

    if (result.surface) {
      for (const domain of result.surface.externalDomains) {
        await tx.externalDomain.upsert({
          where: { projectId_domain: { projectId, domain: domain.domain } },
          create: {
            projectId,
            scanId: result.scanId,
            domain: domain.domain,
            classification: domain.classification,
            resourceTypes: [...domain.resourceTypes],
            firstSeenAt: now,
            lastSeenAt: now,
          },
          update: {
            scanId: result.scanId,
            classification: domain.classification,
            resourceTypes: [...domain.resourceTypes],
            lastSeenAt: now,
          },
        });
      }
      for (const route of result.surface.routes) {
        await tx.route.upsert({
          where: { projectId_method_url: { projectId, method: route.method, url: route.url } },
          create: {
            projectId,
            scanId: result.scanId,
            method: route.method,
            url: route.url,
            ...(route.status !== undefined ? { status: route.status } : {}),
            ...(route.contentType ? { contentType: route.contentType } : {}),
            ...(route.cors ? { cors: route.cors } : {}),
            ...(route.authenticationObservable !== undefined
              ? { authObservable: route.authenticationObservable }
              : {}),
            firstSeenAt: now,
            lastSeenAt: now,
          },
          update: {
            scanId: result.scanId,
            ...(route.status !== undefined ? { status: route.status } : {}),
            ...(route.contentType ? { contentType: route.contentType } : {}),
            ...(route.cors ? { cors: route.cors } : {}),
            ...(route.authenticationObservable !== undefined
              ? { authObservable: route.authenticationObservable }
              : {}),
            lastSeenAt: now,
          },
        });
      }
    }
  });
}

async function persistFinding(
  tx: Prisma.TransactionClient,
  projectId: string,
  result: ScanResult,
  finding: Finding,
  status: "open" | "suppressed",
): Promise<void> {
  const observedAt = new Date(result.completedAt);
  const record = (await tx.finding.upsert({
    where: { projectId_fingerprint: { projectId, fingerprint: finding.fingerprint } },
    create: {
      projectId,
      fingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      category: finding.category,
      confidence: finding.confidence,
      source: finding.source,
      ...(finding.remediation ? { remediation: finding.remediation } : {}),
      ...(finding.documentationUrl ? { documentationUrl: finding.documentationUrl } : {}),
      firstDetectedAt: observedAt,
      lastDetectedAt: observedAt,
      status,
    },
    update: {
      title: finding.title,
      description: finding.description,
      severity: finding.severity,
      confidence: finding.confidence,
      lastDetectedAt: observedAt,
      status,
      ...(finding.remediation ? { remediation: finding.remediation } : {}),
    },
    select: { id: true },
  })) as FindingRow;
  await tx.findingOccurrence.upsert({
    where: { findingId_scanId: { findingId: record.id, scanId: result.scanId } },
    create: {
      findingId: record.id,
      scanId: result.scanId,
      severity: finding.severity,
      observedAt,
      ...(finding.location?.file ? { file: finding.location.file } : {}),
      ...(finding.location?.line !== undefined ? { line: finding.location.line } : {}),
      ...(finding.location?.column !== undefined ? { column: finding.location.column } : {}),
      ...(finding.location?.url ? { url: finding.location.url } : {}),
      ...(finding.evidence !== undefined
        ? { evidenceJson: toInputJson(redactEvidence(finding.evidence)) }
        : {}),
    },
    update: {
      severity: finding.severity,
      observedAt,
      ...(finding.location?.file ? { file: finding.location.file } : {}),
      ...(finding.location?.line !== undefined ? { line: finding.location.line } : {}),
      ...(finding.location?.column !== undefined ? { column: finding.location.column } : {}),
      ...(finding.location?.url ? { url: finding.location.url } : {}),
      ...(finding.evidence !== undefined
        ? { evidenceJson: toInputJson(redactEvidence(finding.evidence)) }
        : {}),
    },
  });
}
