import { spawn } from "node:child_process";
import { access, readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { createFinding } from "@specter/core";
import type { Finding, RuleMetadata } from "@specter/types";

export type DetectedFramework = "next" | "vite" | "react" | "unknown";

const BUILD_DIRS: Readonly<Record<DetectedFramework, readonly string[]>> = {
  next: [".next/static", "out"],
  vite: ["dist"],
  react: ["build", "dist"],
  unknown: ["dist", "build", "out"],
};

const rules = {
  sourceMap: { id: "SPECTER-BUILD-001", title: "Source map present in build output", description: "A JavaScript source map is present in generated artifacts and may expose original source when publicly deployed.", category: "build", defaultSeverity: "medium", defaultConfidence: "high", remediation: "Do not publish private source maps publicly; upload them only to trusted error-monitoring systems when required." },
  envFile: { id: "SPECTER-BUILD-002", title: "Environment file copied into build output", description: "An .env-style file appears in generated artifacts.", category: "build", defaultSeverity: "critical", defaultConfidence: "high", remediation: "Remove environment files from client/static output and rotate any exposed credentials." },
  secret: { id: "SPECTER-BUILD-003", title: "Credential-like value present in client artifact", description: "A secret-shaped value appears in generated JavaScript or static output.", category: "client-exposure", defaultSeverity: "critical", defaultConfidence: "high", remediation: "Remove the private value from browser code, rotate the credential and verify a clean rebuild." },
  privateUrl: { id: "SPECTER-BUILD-004", title: "Private/internal URL present in build output", description: "Generated client artifacts contain a private-network or internal hostname reference.", category: "client-exposure", defaultSeverity: "medium", defaultConfidence: "medium", remediation: "Keep internal endpoints server-side and expose only intended public API origins to browser code." },
  debugInfo: { id: "SPECTER-BUILD-005", title: "Debug or stack-trace information in build output", description: "Generated artifacts contain debug markers or stack traces that may reveal implementation details.", category: "build", defaultSeverity: "low", defaultConfidence: "medium", remediation: "Disable production debug output and ensure error responses/logging do not expose stack traces to clients." },
} satisfies Record<string, RuleMetadata>;

async function exists(file: string): Promise<boolean> { try { await access(file); return true; } catch { return false; } }

export async function detectFramework(root: string): Promise<DetectedFramework> {
  const manifestPath = path.join(path.resolve(root), "package.json");
  if (!(await exists(manifestPath))) return "unknown";
  const parsed = JSON.parse(await readFile(manifestPath, "utf8")) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  const all = { ...(parsed.dependencies ?? {}), ...(parsed.devDependencies ?? {}) };
  if ("next" in all) return "next";
  if ("vite" in all) return "vite";
  if ("react" in all) return "react";
  return "unknown";
}

export async function locateBuildOutput(root: string, framework?: DetectedFramework): Promise<readonly string[]> {
  const absolute = path.resolve(root);
  const resolvedFramework = framework ?? await detectFramework(absolute);
  const candidates = BUILD_DIRS[resolvedFramework];
  const found: string[] = [];
  for (const candidate of candidates) {
    const output = path.join(absolute, candidate);
    if (await exists(output)) found.push(output);
  }
  return found;
}

export interface TrustedBuildResult { readonly code: number; readonly stdout: string; readonly stderr: string; readonly durationMs: number; }

export function executeTrustedBuild(root: string, command: readonly [string, ...string[]], timeoutMs = 120_000): Promise<TrustedBuildResult> {
  const [program, ...args] = command;
  if (!program || /[;&|`$<>\n\r]/.test(program)) throw new Error("Invalid build executable.");
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const child = spawn(program, args, { cwd: path.resolve(root), shell: false, env: process.env, stdio: ["ignore", "pipe", "pipe"] });
    const stdout: Uint8Array[] = [];
    const stderr: Uint8Array[] = [];
    child.stdout?.on("data", (chunk) => stdout.push(chunk));
    child.stderr?.on("data", (chunk) => stderr.push(chunk));
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.on("error", (error) => { clearTimeout(timer); reject(error); });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? 1, stdout: Buffer.concat(stdout).toString("utf8"), stderr: Buffer.concat(stderr).toString("utf8"), durationMs: Date.now() - started });
    });
  });
}

const TEXT_ARTIFACT = /\.(?:js|mjs|cjs|css|html|json|txt|map|env)$/i;
const SECRET_PATTERN = /\b(?:sk_live_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s"'`]+)/g;
const GENERIC_SECRET_ASSIGNMENT = /\b(?:token|secret|password|api[_-]?key|private[_-]?key)\s*[:=]\s*["'`]([^"'`\s]{20,})["'`]/gi;
const PRIVATE_URL = /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[A-Za-z0-9.-]+\.internal)(?::\d+)?[^\s"'`]*/gi;

export interface BuildScanOptions { readonly maxFileBytes?: number; readonly outputDirectories?: readonly string[]; }
export interface BuildScanResult { readonly framework: DetectedFramework; readonly outputs: readonly string[]; readonly filesScanned: number; readonly findings: readonly Finding[]; readonly skippedLargeFiles: readonly string[]; }

function lineAt(content: string, offset: number): number { return content.slice(0, offset).split("\n").length; }

function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function isLikelyPlaceholder(value: string): boolean {
  return /^(?:example|sample|placeholder|changeme|your[_-])/i.test(value);
}

export async function scanBuild(root: string, options: BuildScanOptions = {}): Promise<BuildScanResult> {
  const absoluteRoot = path.resolve(root);
  const framework = await detectFramework(absoluteRoot);
  const outputs = options.outputDirectories?.map((item) => path.resolve(absoluteRoot, item)) ?? await locateBuildOutput(absoluteRoot, framework);
  const findings: Finding[] = [];
  const skippedLargeFiles: string[] = [];
  let filesScanned = 0;
  const maxFileBytes = options.maxFileBytes ?? 2_000_000;

  async function visit(directory: string): Promise<void> {
    let entries; try { entries = await readdir(directory, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) { await visit(absolute); continue; }
      if (!entry.isFile()) continue;
      const relative = path.relative(absoluteRoot, absolute).replaceAll(path.sep, "/");
      const isEnv = /^\.env(?:\.|$)/.test(entry.name);
      if (isEnv) findings.push(createFinding({ metadata: rules.envFile, source: "build", location: { file: relative }, discriminator: `env:${relative}`, evidence: { file: relative } }));
      if (entry.name.endsWith(".map")) findings.push(createFinding({ metadata: rules.sourceMap, source: "build", location: { file: relative }, discriminator: `sourcemap:${relative}`, evidence: { file: relative } }));
      if (!TEXT_ARTIFACT.test(entry.name) && !isEnv) continue;
      try {
        const info = await stat(absolute);
        if (info.size > maxFileBytes) { skippedLargeFiles.push(relative); continue; }
        const content = await readFile(absolute, "utf8"); filesScanned += 1;
        for (const match of content.matchAll(SECRET_PATTERN)) findings.push(createFinding({ metadata: rules.secret, source: "build", location: { file: relative, line: lineAt(content, match.index) }, discriminator: `secret:${relative}:${lineAt(content, match.index)}`, evidence: "[REDACTED]" }));
        for (const match of content.matchAll(GENERIC_SECRET_ASSIGNMENT)) {
          const value = match[1];
          if (!value || isLikelyPlaceholder(value) || shannonEntropy(value) < 3.5) continue;
          const line = lineAt(content, match.index + match[0].indexOf(value));
          findings.push(createFinding({ metadata: rules.secret, source: "build", location: { file: relative, line }, discriminator: `secret:${relative}:${line}`, evidence: "[REDACTED]" }));
        }
        for (const match of content.matchAll(PRIVATE_URL)) findings.push(createFinding({ metadata: rules.privateUrl, source: "build", location: { file: relative, line: lineAt(content, match.index) }, discriminator: `private-url:${relative}:${lineAt(content, match.index)}`, evidence: { urlClass: "private-or-internal" } }));
        if (/\b(?:DEBUG|development mode|Error:\s+[^\n]+\n\s+at\s+)/i.test(content)) findings.push(createFinding({ metadata: rules.debugInfo, source: "build", location: { file: relative }, discriminator: `debug:${relative}` }));
      } catch { /* unreadable artifacts are ignored but never executed */ }
    }
  }

  for (const output of outputs) await visit(output);
  return { framework, outputs: outputs.map((item) => path.relative(absoluteRoot, item).replaceAll(path.sep, "/")), filesScanned, findings, skippedLargeFiles };
}
