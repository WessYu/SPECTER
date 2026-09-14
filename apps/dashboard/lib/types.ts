export interface SessionMe {
  readonly kind: "session";
  readonly role: "owner" | "admin" | "member" | "viewer";
  readonly organization: { readonly id: string; readonly name: string; readonly slug: string };
  readonly user: {
    readonly id: string;
    readonly name: string | null;
    readonly avatarUrl: string | null;
  };
}
export interface DomainSummary {
  readonly id: string;
  readonly hostname: string;
  readonly verifiedAt: string | null;
}
export interface ScanSummary {
  readonly id: string;
  readonly targetKind: string;
  readonly targetValue: string;
  readonly status: string;
  readonly score: number;
  readonly summaryJson?: SeveritySummary;
  readonly modulesJson?: readonly unknown[];
  readonly errorsJson?: readonly unknown[];
  readonly completedAt: string;
  readonly durationMs: number;
  readonly scanType?: "standard" | "active" | null;
  readonly profile?: "safe" | "standard" | null;
  readonly endpointCount?: number | null;
  readonly confirmedCount?: number | null;
  readonly potentialCount?: number | null;
  readonly regressionDelta?: number | null;
}
export interface SeveritySummary {
  readonly critical: number;
  readonly high: number;
  readonly medium: number;
  readonly low: number;
  readonly info: number;
}
export interface ProjectSummary {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly updatedAt: string;
  readonly domains: readonly DomainSummary[];
  readonly scans: readonly ScanSummary[];
  readonly findings: ReadonlyArray<{ readonly id: string; readonly severity: string }>;
}
export interface OverviewResponse {
  readonly projects: readonly ProjectSummary[];
}
export interface FindingSummary {
  readonly id: string;
  readonly ruleId: string;
  readonly title: string;
  readonly description?: string;
  readonly severity: string;
  readonly category: string;
  readonly confidence: string;
  readonly source: string;
  readonly scanner?: string | null;
  readonly phase?: string | null;
  readonly validationStatus?: string | null;
  readonly method?: string | null;
  readonly route?: string | null;
  readonly parameter?: string | null;
  readonly reproduction?: string | null;
  readonly whyItMatters?: string | null;
  readonly remediation?: string | null;
  readonly documentationUrl?: string | null;
  readonly firstDetectedAt: string;
  readonly lastDetectedAt: string;
  readonly status: string;
  readonly fingerprint?: string;
  readonly occurrences?: readonly FindingOccurrence[];
}
export interface FindingOccurrence {
  readonly id: string;
  readonly scanId: string;
  readonly file?: string | null;
  readonly line?: number | null;
  readonly column?: number | null;
  readonly url?: string | null;
  readonly evidenceJson?: unknown;
  readonly severity: string;
  readonly observedAt: string;
}
export interface ProjectOverviewResponse {
  readonly project: {
    readonly id: string;
    readonly name: string;
    readonly slug: string;
    readonly createdAt: string;
    readonly updatedAt: string;
    readonly domains: readonly DomainSummary[];
  };
  readonly scans: readonly ScanSummary[];
  readonly latestFindings: readonly FindingSummary[];
  readonly metrics: {
    readonly codeSecurity: number | null;
    readonly dependencies: number | null;
    readonly clientExposure: number | null;
    readonly runtimeConfiguration: number | null;
    readonly attackSurface: number | null;
  };
}
export interface ScanDetail extends ScanSummary {
  readonly schemaVersion: string;
  readonly surfaceJson?: unknown;
  readonly occurrences: ReadonlyArray<FindingOccurrence & { readonly finding: FindingSummary }>;
}
export interface ApiKeySummary {
  readonly id: string;
  readonly name: string;
  readonly prefix: string;
  readonly createdAt: string;
  readonly lastUsedAt: string | null;
  readonly revokedAt: string | null;
}

export interface HistoryResponse {
  readonly scans: readonly ScanSummary[];
}
export interface SeverityChangeView {
  readonly fingerprint: string;
  readonly previous: string;
  readonly current: string;
  readonly finding: FindingSummary;
}
export interface ScanDiffResponse {
  readonly previousScanId: string;
  readonly currentScanId: string;
  readonly score: { readonly previous: number; readonly current: number; readonly delta: number };
  readonly new: readonly FindingSummary[];
  readonly unchanged: readonly FindingSummary[];
  readonly resolved: readonly FindingSummary[];
  readonly severityChanged: readonly SeverityChangeView[];
}
export interface SurfaceRoute {
  readonly url: string;
  readonly method: string;
  readonly status?: number;
  readonly contentType?: string;
  readonly authenticationObservable?: boolean;
  readonly cors?: string;
}
export interface SurfaceDomain {
  readonly domain: string;
  readonly classification: string;
  readonly resourceTypes: readonly string[];
  readonly page?: string;
  readonly state: "new" | "unchanged" | "removed";
}
export interface AttackSurfaceResponse {
  readonly currentScanId: string | null;
  readonly previousScanId: string | null;
  readonly observedAt: string | null;
  readonly routes: readonly SurfaceRoute[];
  readonly domains: readonly SurfaceDomain[];
}
export interface FirstPartyDomain {
  readonly id: string;
  readonly hostname: string;
  readonly verifiedAt: string | null;
  readonly createdAt: string;
}

export interface ActiveTargetSummary {
  readonly id: string;
  readonly projectId: string;
  readonly url: string;
  readonly hostname: string;
  readonly authorizationStatus: "unverified" | "verified" | "expired";
  readonly tokenPrefix?: string | null;
  readonly verificationExpiresAt?: string | null;
  readonly verifiedAt?: string | null;
  readonly authorizationExpiresAt?: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ActiveScanSummary {
  readonly id: string;
  readonly projectId: string;
  readonly targetId: string;
  readonly status: "queued" | "running" | "completed" | "failed" | "cancelled";
  readonly profile: "safe" | "standard";
  readonly requestBudget: number;
  readonly requestCount: number;
  readonly endpointCount: number;
  readonly findingCount: number;
  readonly confirmedCount: number;
  readonly score: number | null;
  readonly resultScanId?: string | null;
  readonly startedAt?: string | null;
  readonly completedAt?: string | null;
  readonly createdAt: string;
  readonly error?: string | null;
  readonly target: {
    readonly url: string;
    readonly hostname: string;
    readonly authorizationStatus: string;
  };
  readonly resultScan?: {
    readonly regressionDelta: number | null;
  } | null;
}
