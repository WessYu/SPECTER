import type {
  ActiveAuthorization,
  ActiveProfile,
  Finding,
  FindingPhase,
  RouteInfo,
  Suppression,
  ScanResult,
} from "@specter/types";
import type { SafeHttpMethod, SafeRequestOptions, SafeResponse } from "@specter/scanner-web";

export interface ActiveScannerConfig {
  readonly enabled: boolean;
  readonly profile: ActiveProfile;
  readonly maxRequests: number;
  readonly maxRequestsPerSecond: number;
  readonly concurrency: number;
  readonly requestTimeoutMs: number;
  readonly maxEndpoints: number;
  readonly maxParametersPerEndpoint: number;
  readonly allowStateChangingMethods: boolean;
  readonly previewHosts: readonly string[];
}

export interface ActiveEndpoint {
  readonly url: string;
  readonly method: SafeHttpMethod;
  readonly parameters: readonly string[];
  readonly source: "root" | "link" | "form" | "sitemap" | "javascript" | "openapi" | "observed";
}

export interface ActiveForm {
  readonly action: string;
  readonly method: SafeHttpMethod;
  readonly parameters: readonly string[];
  readonly usernameField?: string;
  readonly passwordField?: string;
  readonly hasCsrfToken: boolean;
}

export interface ActiveSnapshot {
  readonly endpoint: ActiveEndpoint;
  readonly response: SafeResponse;
}

export interface ActiveDiscovery {
  readonly endpoints: readonly ActiveEndpoint[];
  readonly forms: readonly ActiveForm[];
  readonly snapshots: readonly ActiveSnapshot[];
}

export interface ActiveScanOptions {
  readonly config: ActiveScannerConfig;
  readonly storePath?: string;
  readonly authorization?: ActiveAuthorization;
  readonly observedRoutes?: readonly RouteInfo[];
  readonly baseline?: ScanResult;
  readonly signal?: AbortSignal;
  readonly rules?: ReadonlySet<string>;
  readonly testUsername?: string;
  readonly testPassword?: string;
  readonly suppressions?: readonly Suppression[];
}

export interface ActiveRequest {
  (
    url: string,
    options?: Omit<SafeRequestOptions, "allowLocalhost" | "requireSameHostname">,
  ): Promise<SafeResponse>;
}

export interface ActiveFindingContext {
  readonly target: string;
  readonly phase: FindingPhase;
}

export interface ActiveScanOutput {
  readonly result: ScanResult;
  readonly findings: readonly Finding[];
}
