ALTER TABLE "Scan"
  ADD COLUMN "scanType" TEXT,
  ADD COLUMN "authorizationJson" JSONB,
  ADD COLUMN "profile" TEXT,
  ADD COLUMN "budgetJson" JSONB,
  ADD COLUMN "endpointCount" INTEGER,
  ADD COLUMN "confirmedCount" INTEGER,
  ADD COLUMN "potentialCount" INTEGER,
  ADD COLUMN "regressionDelta" DOUBLE PRECISION;

ALTER TABLE "Finding"
  ADD COLUMN "scanner" TEXT,
  ADD COLUMN "phase" TEXT,
  ADD COLUMN "validationStatus" TEXT,
  ADD COLUMN "method" TEXT,
  ADD COLUMN "route" TEXT,
  ADD COLUMN "parameter" TEXT,
  ADD COLUMN "reproduction" TEXT,
  ADD COLUMN "whyItMatters" TEXT;

CREATE TABLE "ActiveTarget" (
  "id" TEXT NOT NULL,
  "projectId" TEXT NOT NULL,
  "url" TEXT NOT NULL,
  "hostname" TEXT NOT NULL,
  "authorizationStatus" TEXT NOT NULL DEFAULT 'unverified',
  "tokenHash" TEXT,
  "tokenPrefix" TEXT,
  "verificationExpiresAt" TIMESTAMP(3),
  "verifiedAt" TIMESTAMP(3),
  "authorizationExpiresAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "ActiveTarget_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ActiveScan" (
  "id" TEXT NOT NULL,
  "projectId" TEXT NOT NULL,
  "targetId" TEXT NOT NULL,
  "status" "ScanStatus" NOT NULL DEFAULT 'queued',
  "profile" TEXT NOT NULL,
  "requestBudget" INTEGER NOT NULL,
  "requestCount" INTEGER NOT NULL DEFAULT 0,
  "endpointCount" INTEGER NOT NULL DEFAULT 0,
  "findingCount" INTEGER NOT NULL DEFAULT 0,
  "confirmedCount" INTEGER NOT NULL DEFAULT 0,
  "score" DOUBLE PRECISION,
  "resultScanId" TEXT,
  "startedAt" TIMESTAMP(3),
  "completedAt" TIMESTAMP(3),
  "error" TEXT,
  "createdBy" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ActiveScan_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ActiveAuditLog" (
  "id" TEXT NOT NULL,
  "projectId" TEXT NOT NULL,
  "targetId" TEXT,
  "activeScanId" TEXT,
  "principalId" TEXT NOT NULL,
  "action" TEXT NOT NULL,
  "metadataJson" JSONB,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ActiveAuditLog_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ActiveTarget_projectId_url_key"
  ON "ActiveTarget"("projectId", "url");
CREATE INDEX "ActiveTarget_projectId_authorizationStatus_idx"
  ON "ActiveTarget"("projectId", "authorizationStatus");
CREATE INDEX "ActiveTarget_hostname_idx"
  ON "ActiveTarget"("hostname");

CREATE UNIQUE INDEX "ActiveScan_resultScanId_key"
  ON "ActiveScan"("resultScanId");
CREATE INDEX "ActiveScan_projectId_createdAt_idx"
  ON "ActiveScan"("projectId", "createdAt" DESC);
CREATE INDEX "ActiveScan_targetId_createdAt_idx"
  ON "ActiveScan"("targetId", "createdAt" DESC);
CREATE INDEX "ActiveScan_projectId_status_idx"
  ON "ActiveScan"("projectId", "status");

CREATE INDEX "ActiveAuditLog_projectId_createdAt_idx"
  ON "ActiveAuditLog"("projectId", "createdAt" DESC);
CREATE INDEX "ActiveAuditLog_activeScanId_idx"
  ON "ActiveAuditLog"("activeScanId");

ALTER TABLE "ActiveTarget"
  ADD CONSTRAINT "ActiveTarget_projectId_fkey"
  FOREIGN KEY ("projectId") REFERENCES "Project"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ActiveScan"
  ADD CONSTRAINT "ActiveScan_projectId_fkey"
  FOREIGN KEY ("projectId") REFERENCES "Project"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ActiveScan"
  ADD CONSTRAINT "ActiveScan_targetId_fkey"
  FOREIGN KEY ("targetId") REFERENCES "ActiveTarget"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ActiveScan"
  ADD CONSTRAINT "ActiveScan_resultScanId_fkey"
  FOREIGN KEY ("resultScanId") REFERENCES "Scan"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ActiveAuditLog"
  ADD CONSTRAINT "ActiveAuditLog_projectId_fkey"
  FOREIGN KEY ("projectId") REFERENCES "Project"("id")
  ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ActiveAuditLog"
  ADD CONSTRAINT "ActiveAuditLog_targetId_fkey"
  FOREIGN KEY ("targetId") REFERENCES "ActiveTarget"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "ActiveAuditLog"
  ADD CONSTRAINT "ActiveAuditLog_activeScanId_fkey"
  FOREIGN KEY ("activeScanId") REFERENCES "ActiveScan"("id")
  ON DELETE SET NULL ON UPDATE CASCADE;
