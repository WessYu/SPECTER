import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";
import { createFinding, redactString } from "@specter/core";
import type { Finding, RuleMetadata } from "@specter/types";

const TEXT_EXTENSIONS = new Set([
  ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml", ".ini", ".conf", ".env", ".txt",
]);
const IGNORE_DIRS = new Set(["node_modules", ".git", ".next", ".turbo", "dist", "build", "coverage", ".cache"]);
const SAFE_BASENAMES = new Set([".env.example", ".env.sample", ".env.template", ".env.defaults"]);
const SAFE_SEGMENTS = new Set(["fixtures", "__fixtures__", "docs", "documentation", "examples"]);
const TEST_FILE = /(?:^|\/)(?:__tests__\/|.*\.(?:test|spec)\.[cm]?[jt]sx?$)/i;

interface SecretPattern {
  readonly name: string;
  readonly regex: RegExp;
  readonly severity: Finding["severity"];
  readonly confidence: Finding["confidence"];
}

const PATTERNS: readonly SecretPattern[] = [
  { name: "Stripe secret key", regex: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g, severity: "critical", confidence: "high" },
  { name: "GitHub token", regex: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g, severity: "critical", confidence: "high" },
  { name: "AWS access key", regex: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high", confidence: "high" },
  { name: "Private key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "critical", confidence: "high" },
  { name: "Database URL", regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s"'`]+/gi, severity: "critical", confidence: "high" },
  { name: "JWT", regex: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g, severity: "high", confidence: "medium" },
  { name: "OAuth/client secret assignment", regex: /\b(?:client_secret|oauth_secret|api_secret|secret_key)\s*[:=]\s*["'`]([A-Za-z0-9_./+\-=]{16,})["'`]/gi, severity: "high", confidence: "medium" },
];

const metadata: RuleMetadata = {
  id: "SPECTER-SECRET-001",
  title: "Potential exposed secret",
  description: "A credential-like value appears to be committed in application files.",
  category: "secret",
  defaultSeverity: "high",
  defaultConfidence: "medium",
  remediation: "Revoke the exposed credential, remove it from source/history where appropriate, and load it from a secret manager or protected environment variable.",
  falsePositiveGuidance: "Example values, fixtures and documentation should use unmistakable placeholders and are excluded by default.",
};

function lineAt(content: string, offset: number): number {
  return content.slice(0, offset).split("\n").length;
}

function isSafePath(relative: string): boolean {
  const normalized = relative.replaceAll("\\", "/");
  const parts = normalized.split("/");
  if (SAFE_BASENAMES.has(parts.at(-1) ?? "")) return true;
  if (parts.some((segment) => SAFE_SEGMENTS.has(segment.toLowerCase()))) return true;
  return TEST_FILE.test(normalized);
}

function redactSecret(secret: string): string {
  const redacted = redactString(secret);
  if (redacted !== secret) return redacted;
  if (secret.length <= 8) return "[REDACTED]";
  return `${secret.slice(0, 4)}${"*".repeat(Math.min(12, Math.max(4, secret.length - 8)))}${secret.slice(-4)}`;
}

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

function genericHighEntropyMatches(content: string): readonly { value: string; index: number }[] {
  const result: { value: string; index: number }[] = [];
  const assignment = /\b(?:token|secret|password|api[_-]?key|private[_-]?key)\s*[:=]\s*["'`]([^"'`\s]{20,})["'`]/gi;
  for (const match of content.matchAll(assignment)) {
    const value = match[1];
    if (!value || /^(?:example|sample|placeholder|changeme|your[_-])/i.test(value)) continue;
    if (shannonEntropy(value) < 3.5) continue;
    result.push({ value, index: match.index + match[0].indexOf(value) });
  }
  return result;
}

export interface SecretScanOptions {
  readonly maxFileBytes?: number;
  readonly includeFixtures?: boolean;
}

export interface SecretScanResult {
  readonly filesScanned: number;
  readonly findings: readonly Finding[];
  readonly skippedFiles: readonly string[];
}

export async function scanSecrets(root: string, options: SecretScanOptions = {}): Promise<SecretScanResult> {
  const absoluteRoot = path.resolve(root);
  const maxFileBytes = options.maxFileBytes ?? 1_000_000;
  const findings: Finding[] = [];
  const skippedFiles: string[] = [];
  let filesScanned = 0;

  async function visit(directory: string): Promise<void> {
    let entries;
    try { entries = await readdir(directory, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) { await visit(absolute); continue; }
      if (!entry.isFile()) continue;
      const relative = path.relative(absoluteRoot, absolute).replaceAll(path.sep, "/");
      if (!options.includeFixtures && isSafePath(relative)) continue;
      const ext = path.extname(entry.name).toLowerCase();
      if (!TEXT_EXTENSIONS.has(ext) && !entry.name.startsWith(".env")) continue;
      try {
        const info = await stat(absolute);
        if (info.size > maxFileBytes) { skippedFiles.push(relative); continue; }
        const content = await readFile(absolute, "utf8");
        filesScanned += 1;
        const fingerprints = new Set<string>();
        for (const pattern of PATTERNS) {
          for (const match of content.matchAll(pattern.regex)) {
            const secret = match[1] ?? match[0];
            const finding = createFinding({
              metadata,
              source: "static",
              location: { file: relative, line: lineAt(content, match.index) },
              evidence: { kind: pattern.name, value: redactSecret(secret) },
              discriminator: `${pattern.name}:${lineAt(content, match.index)}`,
              severity: pattern.severity,
              confidence: pattern.confidence,
              description: `${pattern.name} detected in ${relative}. The value is redacted.`,
            });
            if (!fingerprints.has(finding.fingerprint)) { fingerprints.add(finding.fingerprint); findings.push(finding); }
          }
        }
        for (const generic of genericHighEntropyMatches(content)) {
          const finding = createFinding({
            metadata,
            source: "static",
            location: { file: relative, line: lineAt(content, generic.index) },
            evidence: { kind: "High entropy credential assignment", value: redactSecret(generic.value) },
            discriminator: `entropy:${lineAt(content, generic.index)}`,
            severity: "high",
            confidence: "medium",
          });
          if (!fingerprints.has(finding.fingerprint)) { fingerprints.add(finding.fingerprint); findings.push(finding); }
        }
      } catch { skippedFiles.push(relative); }
    }
  }

  await visit(absoluteRoot);
  return { filesScanned, findings, skippedFiles };
}

export { redactEvidence, redactString } from "@specter/core";
