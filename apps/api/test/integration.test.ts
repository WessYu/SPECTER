import { createHash } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer } from "../src/server.js";

const enabled = process.env.SPECTER_INTEGRATION_DATABASE === "1";
const integration = enabled ? describe : describe.skip;
const prisma = new PrismaClient();
const app = createServer(prisma);

function tokenHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function sessionCookie(token: string): string {
  return `specter_session=${encodeURIComponent(token)}`;
}

function scanResult(scanId: string) {
  return {
    schemaVersion: "1",
    scanId,
    target: { kind: "project", value: "/repo" },
    startedAt: "2026-09-14T12:00:00.000Z",
    completedAt: "2026-09-14T12:00:01.000Z",
    durationMs: 1000,
    status: "completed",
    score: {
      value: 82,
      band: "good",
      deductions: [
        {
          ruleId: "SPECTER-TEST-001",
          fingerprint: "fixture-fingerprint-1",
          points: 18,
          reason: "Synthetic integration finding",
        },
      ],
    },
    summary: { info: 0, low: 0, medium: 1, high: 0, critical: 0 },
    findings: [
      {
        schemaVersion: "1",
        id: "fixture-finding-1",
        ruleId: "SPECTER-TEST-001",
        title: "Synthetic integration finding",
        description: "Exercises persistence and tenant isolation.",
        severity: "medium",
        category: "configuration",
        confidence: "high",
        source: "static",
        fingerprint: "fixture-fingerprint-1",
        evidence: {
          authorization: "Bearer super-secret-ci-value",
          note: "non-sensitive",
        },
        remediation: "Use the secure configuration.",
      },
    ],
    modules: [
      {
        name: "integration",
        status: "warning",
        durationMs: 10,
        findingCount: 1,
      },
    ],
    errors: [],
  } as const;
}

integration("API PostgreSQL integration", () => {
  const suffix = `${process.pid}-${Date.now()}`;
  const orgASlug = `specter-ci-a-${suffix}`;
  const orgBSlug = `specter-ci-b-${suffix}`;
  const userAEmail = `specter-ci-a-${suffix}@example.invalid`;
  const userBEmail = `specter-ci-b-${suffix}@example.invalid`;
  const tokenA = `sp_session_${"a".repeat(43)}`;
  const tokenB = `sp_session_${"b".repeat(43)}`;
  let orgAId = "";
  let orgBId = "";
  let projectId = "";

  beforeAll(async () => {
    await app.ready();

    const userA = await prisma.user.create({ data: { email: userAEmail, name: "CI A" } });
    const userB = await prisma.user.create({ data: { email: userBEmail, name: "CI B" } });
    const orgA = await prisma.organization.create({ data: { name: "CI A", slug: orgASlug } });
    const orgB = await prisma.organization.create({ data: { name: "CI B", slug: orgBSlug } });
    orgAId = orgA.id;
    orgBId = orgB.id;

    await prisma.organizationMember.createMany({
      data: [
        { organizationId: orgA.id, userId: userA.id, role: "owner" },
        { organizationId: orgB.id, userId: userB.id, role: "owner" },
      ],
    });
    await prisma.session.createMany({
      data: [
        {
          tokenHash: tokenHash(tokenA),
          userId: userA.id,
          organizationId: orgA.id,
          expiresAt: new Date(Date.now() + 60_000),
        },
        {
          tokenHash: tokenHash(tokenB),
          userId: userB.id,
          organizationId: orgB.id,
          expiresAt: new Date(Date.now() + 60_000),
        },
      ],
    });
  });

  afterAll(async () => {
    if (orgAId || orgBId) {
      await prisma.organization.deleteMany({
        where: { id: { in: [orgAId, orgBId].filter(Boolean) } },
      });
    }
    await prisma.user.deleteMany({ where: { email: { in: [userAEmail, userBEmail] } } });
    await app.close();
    await prisma.$disconnect();
  });

  it("requires authentication", async () => {
    const response = await app.inject({ method: "GET", url: "/api/v1/projects" });
    expect(response.statusCode).toBe(401);
  });

  it("creates resources for one tenant and blocks cross-tenant reads", async () => {
    const created = await app.inject({
      method: "POST",
      url: "/api/v1/projects",
      headers: { cookie: sessionCookie(tokenA) },
      payload: { name: "Integration Project", slug: `integration-${suffix}` },
    });
    expect(created.statusCode).toBe(201);
    projectId = (created.json() as { id: string }).id;

    const ownerRead = await app.inject({
      method: "GET",
      url: `/api/v1/projects/${projectId}`,
      headers: { cookie: sessionCookie(tokenA) },
    });
    expect(ownerRead.statusCode).toBe(200);

    const foreignRead = await app.inject({
      method: "GET",
      url: `/api/v1/projects/${projectId}`,
      headers: { cookie: sessionCookie(tokenB) },
    });
    expect(foreignRead.statusCode).toBe(404);

    const scanId = `scan-${suffix}`;
    const ingest = await app.inject({
      method: "POST",
      url: "/api/v1/scans",
      headers: { cookie: sessionCookie(tokenA) },
      payload: { projectId, result: scanResult(scanId) },
    });
    expect(ingest.statusCode).toBe(201);

    const foreignScan = await app.inject({
      method: "GET",
      url: `/api/v1/scans/${scanId}`,
      headers: { cookie: sessionCookie(tokenB) },
    });
    expect(foreignScan.statusCode).toBe(404);

    const ownScan = await app.inject({
      method: "GET",
      url: `/api/v1/scans/${scanId}`,
      headers: { cookie: sessionCookie(tokenA) },
    });
    expect(ownScan.statusCode).toBe(200);

    const occurrence = await prisma.findingOccurrence.findFirstOrThrow({
      where: { scanId },
      select: { evidenceJson: true },
    });
    const evidence = JSON.stringify(occurrence.evidenceJson);
    expect(evidence).not.toContain("super-secret-ci-value");
    expect(evidence).toContain("[REDACTED]");
  });

  it("keeps project listings tenant scoped", async () => {
    const own = await app.inject({
      method: "GET",
      url: "/api/v1/projects",
      headers: { cookie: sessionCookie(tokenA) },
    });
    const foreign = await app.inject({
      method: "GET",
      url: "/api/v1/projects",
      headers: { cookie: sessionCookie(tokenB) },
    });
    expect(own.statusCode).toBe(200);
    expect(foreign.statusCode).toBe(200);
    expect((own.json() as Array<{ id: string }>).some((project) => project.id === projectId)).toBe(
      true,
    );
    expect(
      (foreign.json() as Array<{ id: string }>).some((project) => project.id === projectId),
    ).toBe(false);
  });
});
