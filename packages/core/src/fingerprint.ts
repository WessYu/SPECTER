import { createHash } from "node:crypto";
import type { FindingCategory, FindingSource } from "@specter/types";

export interface FingerprintInput {
  readonly ruleId: string;
  readonly category: FindingCategory;
  readonly source: FindingSource;
  readonly file?: string;
  readonly line?: number;
  readonly url?: string;
  readonly discriminator?: string;
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "").toLowerCase();
}

function normalizeUrl(value: string): string {
  try {
    const url = new URL(value);
    url.hash = "";
    const params = [...url.searchParams.entries()].sort(([a], [b]) => a.localeCompare(b));
    url.search = "";
    for (const [key, val] of params) url.searchParams.append(key, val);
    return url.toString();
  } catch {
    return value.trim().toLowerCase();
  }
}

export function createFingerprint(input: FingerprintInput): string {
  const canonical = JSON.stringify({
    ruleId: input.ruleId,
    category: input.category,
    source: input.source,
    file: input.file ? normalizePath(input.file) : undefined,
    line: input.line ?? undefined,
    url: input.url ? normalizeUrl(input.url) : undefined,
    discriminator: input.discriminator?.trim() || undefined,
  });

  return createHash("sha256").update(canonical).digest("hex");
}
