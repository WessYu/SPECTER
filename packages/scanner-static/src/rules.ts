import { createFinding } from "@specter/core";
import { SPECTER_SCHEMA_VERSION, type Finding, type RuleMetadata } from "@specter/types";
import { findIdentifierCall, tokenizeCode } from "./lexical.js";
import type { SourceFile } from "./walker.js";

const metadata = {
  eval: {
    id: "SPECTER-SOURCE-001",
    title: "Dynamic code execution with eval",
    description: "Direct eval() execution can turn attacker-controlled strings into executable JavaScript.",
    category: "source",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Replace eval() with explicit parsing or a constrained operation map.",
    falsePositiveGuidance: "Review generated-code tooling separately; runtime application code should rarely need eval().",
  },
  newFunction: {
    id: "SPECTER-SOURCE-002",
    title: "Dynamic code execution with Function constructor",
    description: "new Function() compiles strings as JavaScript and can create code-injection paths.",
    category: "source",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Avoid compiling dynamic strings; use explicit functions or parsers.",
  },
  dangerousHtml: {
    id: "SPECTER-SOURCE-003",
    title: "Potential unsafe HTML injection",
    description: "dangerouslySetInnerHTML bypasses React escaping and requires trusted, sanitized HTML.",
    category: "source",
    defaultSeverity: "medium",
    defaultConfidence: "medium",
    remediation: "Avoid raw HTML when possible; otherwise sanitize with a proven allow-list sanitizer.",
  },
  documentWrite: {
    id: "SPECTER-SOURCE-004",
    title: "document.write usage",
    description: "document.write can introduce DOM injection and blocks modern rendering behavior.",
    category: "source",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Use safe DOM APIs and textContent instead of document.write.",
  },
  localStorageToken: {
    id: "SPECTER-SOURCE-005",
    title: "Sensitive token may be stored in localStorage",
    description: "Tokens in localStorage are readable by injected JavaScript and increase XSS impact.",
    category: "source",
    defaultSeverity: "medium",
    defaultConfidence: "medium",
    remediation: "Prefer HttpOnly Secure cookies for session material when architecture permits.",
  },
  plainHttp: {
    id: "SPECTER-SOURCE-006",
    title: "Plain HTTP URL in application source",
    description: "A non-local HTTP endpoint can expose data or create mixed-content behavior in production.",
    category: "configuration",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Use HTTPS endpoints for production traffic.",
  },
  clientExposure: {
    id: "SPECTER-SOURCE-007",
    title: "Suspicious private variable referenced in client-facing source",
    description: "A private credential-like environment variable appears in code that may execute in the browser.",
    category: "client-exposure",
    defaultSeverity: "high",
    defaultConfidence: "medium",
    remediation: "Keep private environment variables in server-only modules and verify generated bundles.",
  },
} satisfies Record<string, RuleMetadata>;

function lineOf(source: string, offset: number): number {
  return source.slice(0, offset).split("\n").length;
}

function lexicalFindings(file: SourceFile): Finding[] {
  const result: Finding[] = [];
  const tokens = tokenizeCode(file.content);
  for (const token of findIdentifierCall(tokens, "eval")) {
    result.push(createFinding({ metadata: metadata.eval, source: "static", location: { file: file.path, line: token.line, column: token.column }, evidence: "eval(...)" }));
  }
  for (let index = 0; index < tokens.length - 2; index += 1) {
    const current = tokens[index];
    const next = tokens[index + 1];
    const after = tokens[index + 2];
    if (current?.value === "new" && next?.value === "Function" && after?.value === "(") {
      result.push(createFinding({ metadata: metadata.newFunction, source: "static", location: { file: file.path, line: current.line, column: current.column }, evidence: "new Function(...)" }));
    }
    if (current?.value === "document" && next?.value === "." && after?.value === "write") {
      result.push(createFinding({ metadata: metadata.documentWrite, source: "static", location: { file: file.path, line: current.line, column: current.column }, evidence: "document.write(...)" }));
    }
  }
  return result;
}

function isClientFacing(file: SourceFile): boolean {
  const normalized = file.path.replaceAll("\\", "/").toLowerCase();
  const leading = file.content.slice(0, 512);
  return /^[\s;]*(?:["']use client["'];?)/.test(leading)
    || /(?:^|\/)(?:client|components?|pages?)\//.test(normalized)
    || /\.client\.[cm]?[jt]sx?$/.test(normalized)
    || /\b(?:window|document|localStorage|sessionStorage|navigator)\b/.test(file.content);
}

function patternFindings(file: SourceFile): Finding[] {
  const result: Finding[] = [];
  const patterns: readonly [RegExp, RuleMetadata, string][] = [
    [/dangerouslySetInnerHTML\s*=\s*\{/g, metadata.dangerousHtml, "dangerouslySetInnerHTML"],
    [/localStorage\.(?:setItem|getItem)\s*\(\s*["'`](?:token|accessToken|refreshToken|jwt|session)["'`]/gi, metadata.localStorageToken, "localStorage token access"],
    [/\bhttp:\/\/(?!localhost\b|127\.0\.0\.1\b|\[::1\])/gi, metadata.plainHttp, "http://..."],
    [/import\.meta\.env\.(?:DATABASE_URL|PRIVATE_KEY|SECRET_KEY|STRIPE_SECRET_KEY|INTERNAL_API_TOKEN)\b/g, metadata.clientExposure, "private import.meta.env variable"],
    [/(?:process\.env\.NEXT_PUBLIC_|import\.meta\.env\.VITE_)[A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE|PASSWORD|DATABASE|API_KEY)[A-Z0-9_]*\b/gi, metadata.clientExposure, "suspicious public environment variable"],
  ];
  for (const [pattern, rule, evidence] of patterns) {
    for (const match of file.content.matchAll(pattern)) {
      result.push(createFinding({ metadata: rule, source: "static", location: { file: file.path, line: lineOf(file.content, match.index) }, evidence }));
    }
  }
  if (isClientFacing(file)) {
    const privateProcessEnv = /process\.env\.(?:DATABASE_URL|PRIVATE_KEY|SECRET_KEY|STRIPE_SECRET_KEY|INTERNAL_API_TOKEN)\b/g;
    for (const match of file.content.matchAll(privateProcessEnv)) {
      result.push(createFinding({ metadata: metadata.clientExposure, source: "static", location: { file: file.path, line: lineOf(file.content, match.index) }, evidence: "private process.env variable in client-facing source" }));
    }
  }
  return result;
}

export function analyzeSourceFile(file: SourceFile): readonly Finding[] {
  return [...lexicalFindings(file), ...patternFindings(file)];
}

export const sourceRuleMetadata: readonly RuleMetadata[] = Object.values(metadata).map((rule) => ({ ...rule }));
export const sourceScannerSchemaVersion = SPECTER_SCHEMA_VERSION;
