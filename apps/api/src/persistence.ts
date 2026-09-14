import type { PrismaClient } from "@prisma/client";
import { redactEvidence } from "@specter/core";
import type { Finding, ScanResult } from "@specter/types";

interface ProjectRow { readonly id: string; readonly organizationId: string; }
interface FindingRow { readonly id: string; }

export async function requireProject(prisma: PrismaClient, organizationId: string, projectId: string): Promise<ProjectRow | undefined> {
  return await prisma.project.findFirst({ where: { id: projectId, organizationId }, select: { id: true, organizationId: true } }) as ProjectRow | null ?? undefined;
}

export async function persistScan(prisma: PrismaClient, organizationId: string, projectId: string, result: ScanResult): Promise<void> {
  const project = await requireProject(prisma, organizationId, projectId);
  if (!project) throw new Error("PROJECT_NOT_FOUND");
  await prisma.$transaction(async (tx) => {
    await tx.scan.create({ data: {
      id: result.scanId, projectId, targetKind: result.target.kind, targetValue: result.target.value, status: result.status,
      score: result.score.value, schemaVersion: result.schemaVersion, summaryJson: result.summary, modulesJson: result.modules,
      errorsJson: result.errors, ...(result.surface ? { surfaceJson: result.surface } : {}), startedAt: new Date(result.startedAt), completedAt: new Date(result.completedAt), durationMs: Math.round(result.durationMs),
    } });
    for (const finding of result.findings) await persistFinding(tx, projectId, result, finding);
    if (result.surface) {
      for (const domain of result.surface.externalDomains) {
        await tx.externalDomain.upsert({
          where: { projectId_domain: { projectId, domain: domain.domain } },
          create: {
            projectId, scanId: result.scanId, domain: domain.domain, classification: domain.classification,
            resourceTypes: [...domain.resourceTypes], firstSeenAt: new Date(result.completedAt), lastSeenAt: new Date(result.completedAt),
          },
          update: {
            scanId: result.scanId, classification: domain.classification, resourceTypes: [...domain.resourceTypes], lastSeenAt: new Date(result.completedAt),
          },
        });
      }
      for (const route of result.surface.routes) {
        await tx.route.upsert({
          where: { projectId_method_url: { projectId, method: route.method, url: route.url } },
          create: {
            projectId, scanId: result.scanId, method: route.method, url: route.url,
            ...(route.status !== undefined ? { status: route.status } : {}),
            ...(route.contentType ? { contentType: route.contentType } : {}),
            ...(route.cors ? { cors: route.cors } : {}),
            ...(route.authenticationObservable !== undefined ? { authObservable: route.authenticationObservable } : {}),
            firstSeenAt: new Date(result.completedAt), lastSeenAt: new Date(result.completedAt),
          },
          update: {
            scanId: result.scanId,
            ...(route.status !== undefined ? { status: route.status } : {}),
            ...(route.contentType ? { contentType: route.contentType } : {}),
            ...(route.cors ? { cors: route.cors } : {}),
            ...(route.authenticationObservable !== undefined ? { authObservable: route.authenticationObservable } : {}),
            lastSeenAt: new Date(result.completedAt),
          },
        });
      }
    }
  });
}

async function persistFinding(tx: PrismaClient, projectId: string, result: ScanResult, finding: Finding): Promise<void> {
  const observedAt = new Date(result.completedAt);
  const record = await tx.finding.upsert({
    where: { projectId_fingerprint: { projectId, fingerprint: finding.fingerprint } },
    create: {
      projectId, fingerprint: finding.fingerprint, ruleId: finding.ruleId, title: finding.title, description: finding.description,
      severity: finding.severity, category: finding.category, confidence: finding.confidence, source: finding.source,
      ...(finding.remediation ? { remediation: finding.remediation } : {}), ...(finding.documentationUrl ? { documentationUrl: finding.documentationUrl } : {}),
      firstDetectedAt: observedAt, lastDetectedAt: observedAt, status: finding.status ?? "open",
    },
    update: {
      title: finding.title, description: finding.description, severity: finding.severity, confidence: finding.confidence,
      lastDetectedAt: observedAt, ...(finding.remediation ? { remediation: finding.remediation } : {}),
    }, select: { id: true },
  }) as FindingRow;
  await tx.findingOccurrence.upsert({
    where: { findingId_scanId: { findingId: record.id, scanId: result.scanId } },
    create: {
      findingId: record.id, scanId: result.scanId, severity: finding.severity, observedAt,
      ...(finding.location?.file ? { file: finding.location.file } : {}), ...(finding.location?.line !== undefined ? { line: finding.location.line } : {}),
      ...(finding.location?.column !== undefined ? { column: finding.location.column } : {}), ...(finding.location?.url ? { url: finding.location.url } : {}),
      ...(finding.evidence !== undefined ? { evidenceJson: redactEvidence(finding.evidence) } : {}),
    },
    update: { severity: finding.severity, observedAt, ...(finding.evidence !== undefined ? { evidenceJson: redactEvidence(finding.evidence) } : {}) },
  });
}
