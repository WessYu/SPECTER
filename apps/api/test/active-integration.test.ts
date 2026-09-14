import { createHash } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import {
  afterAll,
  beforeAll,
  describe,
  expect,
  it,
} from "vitest";
import { createServer } from "../src/server.js";

const enabled =
  process.env.SPECTER_INTEGRATION_DATABASE === "1";
const integration = enabled ? describe : describe.skip;
const prisma = new PrismaClient();
const app = createServer(prisma);

function tokenHash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function sessionCookie(token: string): string {
  return `specter_session=${encodeURIComponent(token)}`;
}

integration("active security PostgreSQL isolation", () => {
  const suffix = `${process.pid}-${Date.now()}`;
  const tokenA = `sp_session_${"c".repeat(43)}`;
  const tokenB = `sp_session_${"d".repeat(43)}`;
  const emails = [
    `active-a-${suffix}@example.invalid`,
    `active-b-${suffix}@example.invalid`,
  ];
  let orgAId = "";
  let orgBId = "";
  let projectId = "";
  let targetId = "";

  beforeAll(async () => {
    await app.ready();
    const userA = await prisma.user.create({
      data: { email: emails[0], name: "Active A" },
    });
    const userB = await prisma.user.create({
      data: { email: emails[1], name: "Active B" },
    });
    const orgA = await prisma.organization.create({
      data: {
        name: "Active A",
        slug: `active-a-${suffix}`,
      },
    });
    const orgB = await prisma.organization.create({
      data: {
        name: "Active B",
        slug: `active-b-${suffix}`,
      },
    });
    orgAId = orgA.id;
    orgBId = orgB.id;

    await prisma.organizationMember.createMany({
      data: [
        {
          organizationId: orgA.id,
          userId: userA.id,
          role: "owner",
        },
        {
          organizationId: orgB.id,
          userId: userB.id,
          role: "owner",
        },
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

    const project = await prisma.project.create({
      data: {
        organizationId: orgA.id,
        name: "Active Project",
        slug: `active-project-${suffix}`,
      },
    });
    projectId = project.id;
  });

  afterAll(async () => {
    if (orgAId || orgBId)
      await prisma.organization.deleteMany({
        where: {
          id: {
            in: [orgAId, orgBId].filter(Boolean),
          },
        },
      });
    await prisma.user.deleteMany({
      where: { email: { in: emails } },
    });
    await app.close();
    await prisma.$disconnect();
  });

  it("creates active targets only inside the authenticated tenant", async () => {
    const created = await app.inject({
      method: "POST",
      url: `/api/v1/projects/${projectId}/active-targets`,
      headers: { cookie: sessionCookie(tokenA) },
      payload: { url: "https://preview.example.com/" },
    });
    expect(created.statusCode).toBe(201);
    targetId = (created.json() as { id: string }).id;

    const foreignList = await app.inject({
      method: "GET",
      url: `/api/v1/projects/${projectId}/active-targets`,
      headers: { cookie: sessionCookie(tokenB) },
    });
    expect(foreignList.statusCode).toBe(404);

    const foreignVerification = await app.inject({
      method: "POST",
      url: `/api/v1/active-targets/${targetId}/verification`,
      headers: { cookie: sessionCookie(tokenB) },
      payload: { action: "create" },
    });
    expect(foreignVerification.statusCode).toBe(404);
  });

  it("hashes verification tokens and refuses unverified scans", async () => {
    const verification = await app.inject({
      method: "POST",
      url: `/api/v1/active-targets/${targetId}/verification`,
      headers: { cookie: sessionCookie(tokenA) },
      payload: { action: "create" },
    });
    expect(verification.statusCode).toBe(201);
    const payload = verification.json() as {
      token: string;
      content: string;
    };
    const stored = await prisma.activeTarget.findUniqueOrThrow({
      where: { id: targetId },
      select: {
        tokenHash: true,
        tokenPrefix: true,
      },
    });
    expect(stored.tokenHash).not.toBe(payload.token);
    expect(stored.tokenHash).not.toContain(payload.token);
    expect(stored.tokenPrefix).toBe(payload.token.slice(0, 8));

    const start = await app.inject({
      method: "POST",
      url: "/api/v1/active-scans",
      headers: { cookie: sessionCookie(tokenA) },
      payload: {
        targetId,
        profile: "safe",
        maxRequests: 50,
      },
    });
    expect(start.statusCode).toBe(403);
    expect(start.json()).toMatchObject({
      error: "active_target_not_authorized",
    });
  });

  it("keeps cancellation tenant scoped and auditable", async () => {
    await prisma.activeTarget.update({
      where: { id: targetId },
      data: {
        authorizationStatus: "verified",
        verifiedAt: new Date(),
        authorizationExpiresAt: new Date(
          Date.now() + 60_000,
        ),
      },
    });
    const queued = await prisma.activeScan.create({
      data: {
        projectId,
        targetId,
        profile: "safe",
        requestBudget: 25,
        createdBy: "integration-test",
      },
    });

    const foreignCancel = await app.inject({
      method: "POST",
      url: `/api/v1/active-scans/${queued.id}/cancel`,
      headers: { cookie: sessionCookie(tokenB) },
    });
    expect(foreignCancel.statusCode).toBe(404);

    const ownCancel = await app.inject({
      method: "POST",
      url: `/api/v1/active-scans/${queued.id}/cancel`,
      headers: { cookie: sessionCookie(tokenA) },
    });
    expect(ownCancel.statusCode).toBe(200);
    expect(
      (ownCancel.json() as { status: string }).status,
    ).toBe("cancelled");

    const audit = await prisma.activeAuditLog.findFirst({
      where: {
        activeScanId: queued.id,
        action: "active_scan_cancel_requested",
      },
    });
    expect(audit).not.toBeNull();
  });
});
