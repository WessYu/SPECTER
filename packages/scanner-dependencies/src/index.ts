import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { createFinding } from "@specter/core";
import type { DependencyFinding, Finding, RuleMetadata, Severity } from "@specter/types";

export interface DependencyRecord {
  readonly name: string;
  readonly version: string;
  readonly direct: boolean;
  readonly dev: boolean;
}

export interface Advisory {
  readonly id: string;
  readonly package: string;
  readonly affectedVersion: string;
  readonly severity: Severity;
  readonly summary: string;
  readonly url?: string;
  readonly patchedVersion?: string;
}

export interface VulnerabilityProvider {
  readonly name: string;
  query(dependencies: readonly DependencyRecord[], signal?: AbortSignal): Promise<readonly Advisory[]>;
}

const metadata: RuleMetadata = {
  id: "SPECTER-DEP-001",
  title: "Known vulnerable dependency",
  description: "An installed dependency version matches a known vulnerability advisory.",
  category: "dependency",
  defaultSeverity: "medium",
  defaultConfidence: "high",
  remediation: "Upgrade to a patched release after validating compatibility and reviewing the advisory.",
};

async function exists(file: string): Promise<boolean> {
  try { await access(file); return true; } catch { return false; }
}

function parseVersionFromSpecifier(specifier: string): string | undefined {
  const exact = specifier.match(/(?:^|@)(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)/);
  return exact?.[1];
}

async function readManifest(root: string): Promise<{ direct: Map<string, { version: string | undefined; dev: boolean }> }> {
  const raw = await readFile(path.join(root, "package.json"), "utf8");
  const parsed = JSON.parse(raw) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  const direct = new Map<string, { version: string | undefined; dev: boolean }>();
  for (const [name, specifier] of Object.entries(parsed.dependencies ?? {})) direct.set(name, { version: parseVersionFromSpecifier(specifier), dev: false });
  for (const [name, specifier] of Object.entries(parsed.devDependencies ?? {})) if (!direct.has(name)) direct.set(name, { version: parseVersionFromSpecifier(specifier), dev: true });
  return { direct };
}

async function parseNpmLock(root: string, direct: Map<string, { version: string | undefined; dev: boolean }>): Promise<DependencyRecord[]> {
  const parsed = JSON.parse(await readFile(path.join(root, "package-lock.json"), "utf8")) as {
    packages?: Record<string, { version?: string; dev?: boolean }>;
    dependencies?: Record<string, { version?: string; dev?: boolean }>;
  };
  const result = new Map<string, DependencyRecord>();
  if (parsed.packages) {
    for (const [key, value] of Object.entries(parsed.packages)) {
      if (!key.startsWith("node_modules/") || !value.version) continue;
      const name = key.slice("node_modules/".length);
      const directInfo = direct.get(name);
      result.set(`${name}@${value.version}`, { name, version: value.version, direct: Boolean(directInfo), dev: directInfo?.dev ?? Boolean(value.dev) });
    }
  } else {
    for (const [name, value] of Object.entries(parsed.dependencies ?? {})) {
      if (!value.version) continue;
      const directInfo = direct.get(name);
      result.set(`${name}@${value.version}`, { name, version: value.version, direct: Boolean(directInfo), dev: directInfo?.dev ?? Boolean(value.dev) });
    }
  }
  return [...result.values()];
}

async function parsePnpmLock(root: string, direct: Map<string, { version: string | undefined; dev: boolean }>): Promise<DependencyRecord[]> {
  const content = await readFile(path.join(root, "pnpm-lock.yaml"), "utf8");
  const result = new Map<string, DependencyRecord>();
  const packageKey = /^\s{2,}['"]?\/?(@?[^@\s:'"]+(?:\/[^@\s:'"]+)?)@(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)['"]?:\s*$/gm;
  for (const match of content.matchAll(packageKey)) {
    const name = match[1]; const version = match[2];
    if (!name || !version) continue;
    const directInfo = direct.get(name);
    result.set(`${name}@${version}`, { name, version, direct: Boolean(directInfo), dev: directInfo?.dev ?? false });
  }
  for (const [name, info] of direct) {
    if ([...result.values()].some((item) => item.name === name && item.direct)) continue;
    if (info.version) result.set(`${name}@${info.version}`, { name, version: info.version, direct: true, dev: info.dev });
  }
  return [...result.values()];
}

async function parseYarnLock(root: string, direct: Map<string, { version: string | undefined; dev: boolean }>): Promise<DependencyRecord[]> {
  const content = await readFile(path.join(root, "yarn.lock"), "utf8");
  const result = new Map<string, DependencyRecord>();
  const blocks = content.split(/\n(?=[^ \n#])/g);
  for (const block of blocks) {
    const header = block.match(/^([^:\n]+):/); const version = block.match(/^\s{2}version\s+["']([^"']+)["']/m)?.[1];
    if (!header || !version) continue;
    const firstSpecifier = header[1]?.split(",")[0]?.trim().replace(/^['"]|['"]$/g, "");
    if (!firstSpecifier) continue;
    let name: string;
    if (firstSpecifier.startsWith("@")) {
      const marker = firstSpecifier.indexOf("@", 1 + firstSpecifier.indexOf("/"));
      name = marker > 0 ? firstSpecifier.slice(0, marker) : firstSpecifier;
    } else name = firstSpecifier.split("@")[0] ?? firstSpecifier;
    const directInfo = direct.get(name);
    result.set(`${name}@${version}`, { name, version, direct: Boolean(directInfo), dev: directInfo?.dev ?? false });
  }
  return [...result.values()];
}

export interface DependencyInventory {
  readonly manager: "pnpm" | "npm" | "yarn" | "unknown";
  readonly dependencies: readonly DependencyRecord[];
}

export async function inspectDependencies(root: string): Promise<DependencyInventory> {
  const absolute = path.resolve(root);
  const { direct } = await readManifest(absolute);
  if (await exists(path.join(absolute, "pnpm-lock.yaml"))) return { manager: "pnpm", dependencies: await parsePnpmLock(absolute, direct) };
  if (await exists(path.join(absolute, "package-lock.json"))) return { manager: "npm", dependencies: await parseNpmLock(absolute, direct) };
  if (await exists(path.join(absolute, "yarn.lock"))) return { manager: "yarn", dependencies: await parseYarnLock(absolute, direct) };
  return { manager: "unknown", dependencies: [...direct].flatMap(([name, info]) => info.version ? [{ name, version: info.version, direct: true, dev: info.dev }] : []) };
}

function osvSeverity(vulnerability: OsvVulnerability): Severity {
  const database = vulnerability.database_specific;
  const value = typeof database?.severity === "string" ? database.severity.toLowerCase() : "";
  if (["critical", "high", "medium", "low"].includes(value)) return value as Severity;
  return "medium";
}

interface OsvVulnerability {
  readonly id: string;
  readonly summary?: string;
  readonly database_specific?: Readonly<Record<string, unknown>>;
  readonly references?: readonly { readonly url?: string }[];
  readonly affected?: readonly { readonly ranges?: readonly { readonly events?: readonly { readonly fixed?: string }[] }[] }[];
}

export class OsvProvider implements VulnerabilityProvider {
  readonly name = "osv.dev";
  readonly #endpoint: string;
  constructor(endpoint = "https://api.osv.dev/v1/querybatch") { this.#endpoint = endpoint; }

  async query(dependencies: readonly DependencyRecord[], signal?: AbortSignal): Promise<readonly Advisory[]> {
    if (dependencies.length === 0) return [];
    const response = await fetch(this.#endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "specter-security/0.1" },
      body: JSON.stringify({ queries: dependencies.map((dep) => ({ package: { ecosystem: "npm", name: dep.name }, version: dep.version })) }),
      ...(signal ? { signal } : {}),
    });
    if (!response.ok) throw new Error(`OSV request failed with HTTP ${response.status}`);
    const body = await response.json() as { results?: readonly { vulns?: readonly OsvVulnerability[] }[] };
    const advisories: Advisory[] = [];
    for (let index = 0; index < dependencies.length; index += 1) {
      const dependency = dependencies[index]; if (!dependency) continue;
      for (const vulnerability of body.results?.[index]?.vulns ?? []) {
        const fixed = vulnerability.affected?.flatMap((affected) => affected.ranges ?? []).flatMap((range) => range.events ?? []).map((event) => event.fixed).find((value): value is string => Boolean(value));
        advisories.push({
          id: vulnerability.id,
          package: dependency.name,
          affectedVersion: dependency.version,
          severity: osvSeverity(vulnerability),
          summary: vulnerability.summary ?? vulnerability.id,
          ...(vulnerability.references?.[0]?.url ? { url: vulnerability.references[0].url } : {}),
          ...(fixed ? { patchedVersion: fixed } : {}),
        });
      }
    }
    return advisories;
  }
}

export class StaticAdvisoryProvider implements VulnerabilityProvider {
  readonly name = "static";
  readonly #advisories: readonly Advisory[];
  constructor(advisories: readonly Advisory[]) { this.#advisories = advisories; }
  async query(dependencies: readonly DependencyRecord[]): Promise<readonly Advisory[]> {
    const installed = new Set(dependencies.map((item) => `${item.name}@${item.version}`));
    return this.#advisories.filter((item) => installed.has(`${item.package}@${item.affectedVersion}`));
  }
}

export interface DependencyScanResult extends DependencyInventory {
  readonly advisories: readonly Advisory[];
  readonly findings: readonly DependencyFinding[];
  readonly provider: string;
}

export async function scanDependencies(root: string, provider: VulnerabilityProvider, signal?: AbortSignal): Promise<DependencyScanResult> {
  const inventory = await inspectDependencies(root);
  const advisories = await provider.query(inventory.dependencies, signal);
  const lookup = new Map(inventory.dependencies.map((item) => [`${item.name}@${item.version}`, item]));
  const findings: DependencyFinding[] = advisories.map((advisory) => {
    const dependency = lookup.get(`${advisory.package}@${advisory.affectedVersion}`);
    const base = createFinding({
      metadata,
      source: "dependency",
      severity: advisory.severity,
      confidence: "high",
      discriminator: `${advisory.id}:${advisory.package}:${advisory.affectedVersion}`,
      evidence: { advisory: advisory.id, package: advisory.package, installedVersion: advisory.affectedVersion, directDependency: dependency?.direct ?? false },
      description: `${advisory.package}@${advisory.affectedVersion}: ${advisory.summary}`,
      remediation: advisory.patchedVersion ? `Upgrade ${advisory.package} to ${advisory.patchedVersion} or later after compatibility review.` : metadata.remediation,
    });
    return {
      ...base,
      category: "dependency",
      package: advisory.package,
      installedVersion: advisory.affectedVersion,
      ...(advisory.patchedVersion ? { patchedVersion: advisory.patchedVersion } : {}),
      advisory: advisory.id,
      directDependency: dependency?.direct ?? false,
    };
  });
  return { ...inventory, advisories, findings, provider: provider.name };
}
