export interface SessionMe {
  readonly kind: "session";
  readonly role: "owner" | "admin" | "member" | "viewer";
  readonly organization: { readonly id: string; readonly name: string; readonly slug: string };
  readonly user: { readonly id: string; readonly name: string | null; readonly avatarUrl: string | null };
}
export interface DomainSummary { readonly id: string; readonly hostname: string; readonly verifiedAt: string | null; }
export interface ScanSummary {
  readonly id: string; readonly targetKind: string; readonly targetValue: string; readonly status: string; readonly score: number;
  readonly summaryJson?: SeveritySummary; readonly modulesJson?: readonly unknown[]; readonly errorsJson?: readonly unknown[];
  readonly completedAt: string; readonly durationMs: number;
}
export interface SeveritySummary { readonly critical: number; readonly high: number; readonly medium: number; readonly low: number; readonly info: number; }
export interface ProjectSummary {
  readonly id: string; readonly name: string; readonly slug: string; readonly updatedAt: string;
  readonly domains: readonly DomainSummary[];
  readonly scans: readonly ScanSummary[];
  readonly findings: ReadonlyArray<{ readonly id: string; readonly severity: string }>;
}
export interface OverviewResponse { readonly projects: readonly ProjectSummary[]; }
export interface FindingSummary {
  readonly id: string; readonly ruleId: string; readonly title: string; readonly description?: string; readonly severity: string;
  readonly category: string; readonly confidence: string; readonly source: string; readonly remediation?: string | null;
  readonly documentationUrl?: string | null; readonly firstDetectedAt: string; readonly lastDetectedAt: string; readonly status: string;
  readonly fingerprint?: string;
  readonly occurrences?: readonly FindingOccurrence[];
}
export interface FindingOccurrence {
  readonly id: string; readonly scanId: string; readonly file?: string | null; readonly line?: number | null; readonly column?: number | null;
  readonly url?: string | null; readonly evidenceJson?: unknown; readonly severity: string; readonly observedAt: string;
}
export interface ProjectOverviewResponse {
  readonly project: { readonly id: string; readonly name: string; readonly slug: string; readonly createdAt: string; readonly updatedAt: string; readonly domains: readonly DomainSummary[] };
  readonly scans: readonly ScanSummary[];
  readonly latestFindings: readonly FindingSummary[];
  readonly metrics: { readonly codeSecurity: number | null; readonly dependencies: number | null; readonly clientExposure: number | null; readonly runtimeConfiguration: number | null; readonly attackSurface: number | null };
}
export interface ScanDetail extends ScanSummary {
  readonly schemaVersion: string; readonly surfaceJson?: unknown;
  readonly occurrences: ReadonlyArray<FindingOccurrence & { readonly finding: FindingSummary }>;
}
export interface ApiKeySummary { readonly id: string; readonly name: string; readonly prefix: string; readonly createdAt: string; readonly lastUsedAt: string | null; readonly revokedAt: string | null; }
