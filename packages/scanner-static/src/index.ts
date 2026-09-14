import type { Finding } from "@specter/types";
import { analyzeSourceFile } from "./rules.js";
import { walkSourceFiles, type WalkOptions } from "./walker.js";

export interface StaticScanResult {
  readonly filesScanned: number;
  readonly bytesScanned: number;
  readonly findings: readonly Finding[];
  readonly skippedLargeFiles: readonly string[];
  readonly unreadableFiles: readonly string[];
}

export async function scanSource(root: string, options: WalkOptions = {}): Promise<StaticScanResult> {
  const walked = await walkSourceFiles(root, options);
  const findings = walked.files.flatMap((file) => [...analyzeSourceFile(file)]);
  return {
    filesScanned: walked.files.length,
    bytesScanned: walked.files.reduce((sum, file) => sum + file.size, 0),
    findings,
    skippedLargeFiles: walked.skippedLargeFiles,
    unreadableFiles: walked.unreadableFiles,
  };
}

export * from "./lexical.js";
export * from "./rules.js";
export * from "./walker.js";
