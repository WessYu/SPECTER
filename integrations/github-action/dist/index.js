// ../../packages/cli/src/config-loader.ts
import { access, readFile } from "node:fs/promises";
import path from "node:path";

// ../../packages/config/src/index.ts
var defaultConfig = Object.freeze({
  failOn: "high",
  maxScoreDrop: 5,
  ignore: [],
  suppressions: [],
  scan: { source: true, build: true, dependencies: true, remote: true, runtime: false },
  limits: {
    maxFileBytes: 1e6,
    requestTimeoutMs: 1e4,
    scanTimeoutMs: 6e4,
    maxRedirects: 5,
    maxPages: 20,
    maxResponseBytes: 5e6,
    concurrency: 4
  }
});
function tokenizeConfig(source) {
  const tokens = [];
  let index = source.charCodeAt(0) === 65279 ? 1 : 0;
  const punctuation = /* @__PURE__ */ new Set(["{", "}", "[", "]", ":", ",", ";"]);
  while (index < source.length) {
    const char = source[index] ?? "";
    if (/\s/.test(char)) {
      index += 1;
      continue;
    }
    if (char === "/" && source[index + 1] === "/") {
      index += 2;
      while (index < source.length && source[index] !== "\n") index += 1;
      continue;
    }
    if (char === "/" && source[index + 1] === "*") {
      const start = index;
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/"))
        index += 1;
      if (index >= source.length)
        throw new Error(`Unterminated comment in SPECTER config at offset ${start}.`);
      index += 2;
      continue;
    }
    if (punctuation.has(char)) {
      tokens.push({ type: "punctuation", value: char, offset: index });
      index += 1;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      const quote = char;
      const start = index;
      index += 1;
      let value = "";
      let closed = false;
      while (index < source.length) {
        const current = source[index] ?? "";
        if (current === quote) {
          index += 1;
          closed = true;
          break;
        }
        if (current === "\\") {
          const escaped = source[index + 1];
          if (escaped === void 0) break;
          const map = {
            n: "\n",
            r: "\r",
            t: "	",
            b: "\b",
            f: "\f",
            v: "\v",
            "0": "\0"
          };
          value += map[escaped] ?? escaped;
          index += 2;
          continue;
        }
        if (quote === "`" && current === "$" && source[index + 1] === "{")
          throw new Error("Template interpolation is not allowed in specter.config.ts.");
        value += current;
        index += 1;
      }
      if (!closed) throw new Error(`Unterminated string in SPECTER config at offset ${start}.`);
      tokens.push({ type: "string", value, offset: start });
      continue;
    }
    if (char === "-" || /[0-9]/.test(char)) {
      const start = index;
      const match = source.slice(index).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
      if (!match) throw new Error(`Invalid number in SPECTER config at offset ${start}.`);
      tokens.push({ type: "number", value: match[0], offset: start });
      index += match[0].length;
      continue;
    }
    if (/[A-Za-z_$]/.test(char)) {
      const start = index;
      index += 1;
      while (index < source.length && /[A-Za-z0-9_$-]/.test(source[index] ?? "")) index += 1;
      tokens.push({ type: "identifier", value: source.slice(start, index), offset: start });
      continue;
    }
    throw new Error(`Unsupported token '${char}' in SPECTER config at offset ${index}.`);
  }
  return tokens;
}
var ConfigParser = class {
  #tokens;
  #index = 0;
  constructor(tokens) {
    this.#tokens = tokens;
  }
  #peek() {
    return this.#tokens[this.#index];
  }
  #take() {
    const token = this.#tokens[this.#index];
    if (!token) throw new Error("Unexpected end of SPECTER config.");
    this.#index += 1;
    return token;
  }
  #expect(value) {
    const token = this.#take();
    if (token.value !== value)
      throw new Error(`Expected '${value}' in SPECTER config at offset ${token.offset}.`);
  }
  parse() {
    if (this.#peek()?.value === "export") {
      this.#expect("export");
      this.#expect("default");
    }
    const value = this.#parseValue();
    if (this.#peek()?.value === ";") this.#take();
    const trailing = this.#peek();
    if (trailing)
      throw new Error(
        `Unexpected token '${trailing.value}' in SPECTER config at offset ${trailing.offset}.`
      );
    return value;
  }
  #parseValue() {
    const token = this.#peek();
    if (!token) throw new Error("Unexpected end of SPECTER config.");
    if (token.value === "{") return this.#parseObject();
    if (token.value === "[") return this.#parseArray();
    this.#take();
    if (token.type === "string") return token.value;
    if (token.type === "number") {
      const value = Number(token.value);
      if (!Number.isFinite(value)) throw new Error(`Invalid number at offset ${token.offset}.`);
      return value;
    }
    if (token.type === "identifier") {
      if (token.value === "true") return true;
      if (token.value === "false") return false;
      if (token.value === "null") return null;
    }
    throw new Error(
      `Only object literals, arrays, strings, numbers, booleans and null are allowed in specter.config.ts (offset ${token.offset}).`
    );
  }
  #parseObject() {
    this.#expect("{");
    const result = {};
    while (this.#peek() && this.#peek()?.value !== "}") {
      const keyToken = this.#take();
      if (keyToken.type !== "identifier" && keyToken.type !== "string")
        throw new Error(`Invalid object key at offset ${keyToken.offset}.`);
      this.#expect(":");
      if (Object.prototype.hasOwnProperty.call(result, keyToken.value))
        throw new Error(`Duplicate config key '${keyToken.value}'.`);
      result[keyToken.value] = this.#parseValue();
      if (this.#peek()?.value === ",") {
        this.#take();
        continue;
      }
      if (this.#peek()?.value !== "}") {
        const token = this.#peek();
        throw new Error(
          `Expected ',' or '}' in SPECTER config${token ? ` at offset ${token.offset}` : ""}.`
        );
      }
    }
    this.#expect("}");
    return result;
  }
  #parseArray() {
    this.#expect("[");
    const result = [];
    while (this.#peek() && this.#peek()?.value !== "]") {
      result.push(this.#parseValue());
      if (this.#peek()?.value === ",") {
        this.#take();
        continue;
      }
      if (this.#peek()?.value !== "]") {
        const token = this.#peek();
        throw new Error(
          `Expected ',' or ']' in SPECTER config${token ? ` at offset ${token.offset}` : ""}.`
        );
      }
    }
    this.#expect("]");
    return result;
  }
};
function parseConfigSource(source) {
  return new ConfigParser(tokenizeConfig(source)).parse();
}
function validateSuppressions(value) {
  if (value === void 0) return [];
  if (!Array.isArray(value)) throw new Error("suppressions must be an array.");
  return value.map((item, index) => {
    if (item === null || typeof item !== "object" || Array.isArray(item))
      throw new Error(`suppressions[${index}] must be an object.`);
    const row = item;
    const allowed = /* @__PURE__ */ new Set(["ruleId", "fingerprint", "reason", "expiresAt"]);
    const unknown = Object.keys(row).filter((key) => !allowed.has(key));
    if (unknown.length)
      throw new Error(`Unknown suppressions[${index}] keys: ${unknown.join(", ")}`);
    const ruleId = typeof row.ruleId === "string" && row.ruleId.trim() ? row.ruleId.trim() : void 0;
    const fingerprint = typeof row.fingerprint === "string" && row.fingerprint.trim() ? row.fingerprint.trim() : void 0;
    if (!ruleId && !fingerprint)
      throw new Error(`suppressions[${index}] requires ruleId or fingerprint.`);
    if (typeof row.reason !== "string" || row.reason.trim().length < 3)
      throw new Error(`suppressions[${index}].reason must contain at least 3 characters.`);
    if (row.expiresAt !== void 0 && (typeof row.expiresAt !== "string" || !Number.isFinite(Date.parse(row.expiresAt))))
      throw new Error(`suppressions[${index}].expiresAt must be a valid date-time string.`);
    return {
      ...ruleId ? { ruleId } : {},
      ...fingerprint ? { fingerprint } : {},
      reason: row.reason.trim(),
      ...typeof row.expiresAt === "string" ? { expiresAt: new Date(row.expiresAt).toISOString() } : {}
    };
  });
}
function validateConfig(input2) {
  if (input2 === void 0) return defaultConfig;
  if (input2 === null || typeof input2 !== "object" || Array.isArray(input2))
    throw new Error("SPECTER config must be an object.");
  const value = input2;
  const allowed = /* @__PURE__ */ new Set(["failOn", "maxScoreDrop", "ignore", "suppressions", "scan", "limits"]);
  const unknownKeys = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknownKeys.length) throw new Error(`Unknown SPECTER config keys: ${unknownKeys.join(", ")}`);
  const failOn = value.failOn ?? defaultConfig.failOn;
  if (!["critical", "high", "medium", "low", "none"].includes(String(failOn)))
    throw new Error("failOn must be critical, high, medium, low or none.");
  const maxScoreDrop = value.maxScoreDrop ?? defaultConfig.maxScoreDrop;
  if (typeof maxScoreDrop !== "number" || !Number.isFinite(maxScoreDrop) || maxScoreDrop < 0 || maxScoreDrop > 100)
    throw new Error("maxScoreDrop must be between 0 and 100.");
  const ignore = value.ignore ?? defaultConfig.ignore;
  if (!Array.isArray(ignore) || ignore.some((item) => typeof item !== "string" || item.trim().length === 0))
    throw new Error("ignore must be an array of non-empty rule ids.");
  const suppressions = validateSuppressions(value.suppressions);
  const mergeBooleanGroup = (raw, defaults, name) => {
    if (raw === void 0) return defaults;
    if (raw === null || typeof raw !== "object" || Array.isArray(raw))
      throw new Error(`${name} must be an object.`);
    const source = raw;
    const unknown = Object.keys(source).filter((key) => !(key in defaults));
    if (unknown.length) throw new Error(`Unknown ${name} keys: ${unknown.join(", ")}`);
    const result = { ...defaults };
    for (const key of Object.keys(defaults)) {
      if (source[key] !== void 0 && typeof source[key] !== "boolean")
        throw new Error(`${name}.${key} must be boolean.`);
      if (typeof source[key] === "boolean") result[key] = source[key];
    }
    return result;
  };
  const scan = mergeBooleanGroup(value.scan, defaultConfig.scan, "scan");
  const limitsRaw = value.limits;
  let limits = defaultConfig.limits;
  if (limitsRaw !== void 0) {
    if (limitsRaw === null || typeof limitsRaw !== "object" || Array.isArray(limitsRaw))
      throw new Error("limits must be an object.");
    const source = limitsRaw;
    const unknown = Object.keys(source).filter((key) => !(key in defaultConfig.limits));
    if (unknown.length) throw new Error(`Unknown limits keys: ${unknown.join(", ")}`);
    const mutable = { ...defaultConfig.limits };
    for (const key of Object.keys(defaultConfig.limits)) {
      const item = source[key];
      if (item === void 0) continue;
      if (typeof item !== "number" || !Number.isFinite(item) || item <= 0)
        throw new Error(`limits.${key} must be a positive number.`);
      mutable[key] = Math.floor(item);
    }
    limits = mutable;
  }
  return {
    failOn,
    maxScoreDrop,
    ignore: ignore.map((item) => item.trim()),
    suppressions,
    scan,
    limits
  };
}

// ../../packages/cli/src/config-loader.ts
async function fileExists(file) {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}
async function loadConfig(root) {
  const absolute = path.resolve(root);
  for (const name of ["specter.config.ts", "specter.config.json"]) {
    const file = path.join(absolute, name);
    if (!await fileExists(file)) continue;
    const raw = await readFile(file, "utf8");
    let parsed;
    try {
      parsed = name.endsWith(".json") ? JSON.parse(raw) : parseConfigSource(raw);
    } catch (error) {
      throw new Error(
        `Unable to parse ${name}: ${error instanceof Error ? error.message : "Invalid config"}`
      );
    }
    return { config: validateConfig(parsed), path: file };
  }
  return { config: defaultConfig };
}

// ../../packages/cli/src/commands.ts
import { access as access2, writeFile } from "node:fs/promises";
import path2 from "node:path";
async function fileExists2(file) {
  try {
    await access2(file);
    return true;
  } catch {
    return false;
  }
}
async function initConfig(root) {
  const file = path2.join(path2.resolve(root), "specter.config.ts");
  if (await fileExists2(file)) return { exitCode: 2, stderr: "specter.config.ts already exists.\n" };
  const content = `export default {
  failOn: "high",
  maxScoreDrop: 5,
  ignore: [],
  suppressions: [],
  scan: {
    source: true,
    build: true,
    dependencies: true,
    remote: true,
    runtime: false,
  },
};
`;
  await writeFile(file, content, "utf8");
  return { exitCode: 0, stdout: `Created ${file}
` };
}
async function doctor(root) {
  const checks = [
    ["Node.js >= 20", Number(process.version.slice(1).split(".")[0]) >= 20],
    ["package.json", await fileExists2(path2.join(path2.resolve(root), "package.json"))]
  ];
  const failed = checks.filter(([, passed]) => !passed);
  const stdout = [
    "SPECTER DOCTOR",
    "",
    ...checks.map(([name, passed]) => `${passed ? "PASS" : "FAIL"}  ${name}`),
    ""
  ].join("\n");
  return { exitCode: failed.length ? 2 : 0, stdout };
}

// ../../packages/cli/src/scan-command.ts
import { mkdir, readFile as readFile6, writeFile as writeFile2 } from "node:fs/promises";
import path8 from "node:path";

// ../../packages/cli/src/scan.ts
import { randomUUID as randomUUID2 } from "node:crypto";
import path7 from "node:path";

// ../../packages/core/src/fingerprint.ts
import { createHash } from "node:crypto";
function normalizePath(path9) {
  return path9.replaceAll("\\", "/").replace(/^\.\//, "").toLowerCase();
}
function normalizeUrl(value) {
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
function createFingerprint(input2) {
  const canonical = JSON.stringify({
    ruleId: input2.ruleId,
    category: input2.category,
    source: input2.source,
    file: input2.file ? normalizePath(input2.file) : void 0,
    line: input2.line ?? void 0,
    url: input2.url ? normalizeUrl(input2.url) : void 0,
    discriminator: input2.discriminator?.trim() || void 0
  });
  return createHash("sha256").update(canonical).digest("hex");
}

// ../../packages/core/src/findings.ts
import { randomUUID } from "node:crypto";

// ../../packages/types/src/index.ts
var SPECTER_SCHEMA_VERSION = "1";

// ../../packages/core/src/findings.ts
function createFinding(input2) {
  const fingerprint = createFingerprint({
    ruleId: input2.metadata.id,
    category: input2.metadata.category,
    source: input2.source,
    ...input2.location?.file !== void 0 ? { file: input2.location.file } : {},
    ...input2.location?.line !== void 0 ? { line: input2.location.line } : {},
    ...input2.location?.url !== void 0 ? { url: input2.location.url } : {},
    ...input2.discriminator !== void 0 ? { discriminator: input2.discriminator } : {}
  });
  return {
    schemaVersion: SPECTER_SCHEMA_VERSION,
    id: randomUUID(),
    ruleId: input2.metadata.id,
    title: input2.metadata.title,
    description: input2.description ?? input2.metadata.description,
    severity: input2.severity ?? input2.metadata.defaultSeverity,
    category: input2.metadata.category,
    confidence: input2.confidence ?? input2.metadata.defaultConfidence,
    source: input2.source,
    fingerprint,
    ...input2.location ? { location: input2.location } : {},
    ...input2.evidence !== void 0 ? { evidence: input2.evidence } : {},
    remediation: input2.remediation ?? input2.metadata.remediation,
    ...input2.metadata.documentationUrl ? { documentationUrl: input2.metadata.documentationUrl } : {},
    status: "open"
  };
}

// ../../packages/core/src/redaction.ts
var SECRET_PATTERNS = [
  /\bsk_(?:live|test)_[A-Za-z0-9]{8,}\b/g,
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s"']+\b/gi,
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g
];
function redactString(value) {
  let redacted = value;
  for (const pattern of SECRET_PATTERNS) redacted = redacted.replace(pattern, "[REDACTED]");
  return redacted;
}

// ../../packages/core/src/suppression.ts
function matchesSuppression(finding, suppression, now = /* @__PURE__ */ new Date()) {
  if (suppression.expiresAt) {
    const expires = Date.parse(suppression.expiresAt);
    if (!Number.isFinite(expires) || expires <= now.getTime()) return false;
  }
  const hasSelector = Boolean(suppression.ruleId || suppression.fingerprint);
  if (!hasSelector) return false;
  if (suppression.ruleId && suppression.ruleId !== finding.ruleId) return false;
  if (suppression.fingerprint && suppression.fingerprint !== finding.fingerprint) return false;
  return true;
}
function applySuppressions(findings, suppressions, now = /* @__PURE__ */ new Date()) {
  const active = [];
  const suppressed = [];
  for (const finding of findings) {
    if (suppressions.some((suppression) => matchesSuppression(finding, suppression, now))) {
      suppressed.push({ ...finding, status: "suppressed" });
    } else {
      active.push(finding.status === "suppressed" ? { ...finding, status: "open" } : finding);
    }
  }
  return { findings: active, suppressed };
}

// ../../packages/core/src/regression.ts
var rank = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};
function compareScans(previous, current) {
  const previousByFingerprint = new Map(
    previous.findings.map((finding) => [finding.fingerprint, finding])
  );
  const currentByFingerprint = new Map(
    current.findings.map((finding) => [finding.fingerprint, finding])
  );
  const newlyIntroduced = [];
  const unchanged = [];
  const resolved = [];
  const severityChanged = [];
  for (const finding of current.findings) {
    const before = previousByFingerprint.get(finding.fingerprint);
    if (!before) {
      newlyIntroduced.push(finding);
      continue;
    }
    if (before.severity !== finding.severity) {
      severityChanged.push({
        fingerprint: finding.fingerprint,
        previous: before.severity,
        current: finding.severity,
        finding
      });
    } else unchanged.push(finding);
  }
  for (const finding of previous.findings)
    if (!currentByFingerprint.has(finding.fingerprint)) resolved.push(finding);
  const bySeverityThenFingerprint = (a, b) => rank[b.severity] - rank[a.severity] || a.fingerprint.localeCompare(b.fingerprint);
  newlyIntroduced.sort(bySeverityThenFingerprint);
  unchanged.sort(bySeverityThenFingerprint);
  resolved.sort(bySeverityThenFingerprint);
  severityChanged.sort(
    (a, b) => rank[b.current] - rank[a.current] || a.fingerprint.localeCompare(b.fingerprint)
  );
  return {
    previousScanId: previous.scanId,
    currentScanId: current.scanId,
    score: {
      previous: previous.score.value,
      current: current.score.value,
      delta: Math.round((current.score.value - previous.score.value) * 10) / 10
    },
    new: newlyIntroduced,
    unchanged,
    resolved,
    severityChanged
  };
}

// ../../packages/core/src/gate.ts
var rank2 = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};
function evaluateSecurityGate(current, baseline, policy) {
  const failures = [];
  if (!baseline) {
    if (policy.failOn !== "none") {
      const threshold = rank2[policy.failOn];
      for (const finding of current.findings) {
        if (finding.status === "suppressed" || rank2[finding.severity] < threshold) continue;
        failures.push({
          code: "NEW_FINDING",
          message: `${finding.severity.toUpperCase()} ${finding.ruleId}: ${finding.title}`,
          finding
        });
      }
    }
    return { passed: failures.length === 0, failures };
  }
  const diff = compareScans(baseline, current);
  if (policy.failOn !== "none") {
    const threshold = rank2[policy.failOn];
    for (const finding of diff.new) {
      if (finding.status !== "suppressed" && rank2[finding.severity] >= threshold)
        failures.push({
          code: "NEW_FINDING",
          message: `New ${finding.severity.toUpperCase()} finding: ${finding.title}`,
          finding
        });
    }
    for (const change of diff.severityChanged) {
      if (rank2[change.current] > rank2[change.previous] && rank2[change.current] >= threshold)
        failures.push({
          code: "SEVERITY_INCREASE",
          message: `Severity increased ${change.previous} \u2192 ${change.current}: ${change.finding.title}`,
          finding: change.finding
        });
    }
  }
  const scoreDrop = baseline.score.value - current.score.value;
  if (scoreDrop > policy.maxScoreDrop)
    failures.push({
      code: "SCORE_DROP",
      message: `Security score dropped by ${scoreDrop.toFixed(1)} points (allowed ${policy.maxScoreDrop}).`
    });
  return { passed: failures.length === 0, failures };
}

// ../../packages/risk-engine/src/index.ts
var severityWeight = {
  critical: 28,
  high: 16,
  medium: 8,
  low: 3,
  info: 0
};
var confidenceMultiplier = {
  high: 1,
  medium: 0.72,
  low: 0.4
};
var categoryMultiplier = {
  secret: 1.25,
  dependency: 1,
  source: 1,
  configuration: 0.8,
  headers: 0.75,
  cookies: 0.9,
  cors: 1,
  csp: 0.85,
  tls: 1.1,
  "client-exposure": 1.15,
  "third-party": 0.7,
  route: 0.45,
  runtime: 1,
  build: 1
};
function summarizeSeverity(findings) {
  const summary = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const finding of findings) summary[finding.severity] += 1;
  return summary;
}
function scoreBand(value) {
  if (value >= 90) return "excellent";
  if (value >= 75) return "good";
  if (value >= 55) return "fair";
  if (value >= 30) return "poor";
  return "critical";
}
function deductionFor(finding, context) {
  const isNew = context.baselineFingerprints ? !context.baselineFingerprints.has(finding.fingerprint) : false;
  const noveltyMultiplier = isNew ? 1.12 : 1;
  const raw = severityWeight[finding.severity] * confidenceMultiplier[finding.confidence] * categoryMultiplier[finding.category] * noveltyMultiplier;
  const points = Math.min(35, Math.max(0, Math.round(raw * 10) / 10));
  return {
    ruleId: finding.ruleId,
    fingerprint: finding.fingerprint,
    points,
    reason: `${finding.severity}/${finding.confidence} ${finding.category}${isNew ? " (new)" : ""}`
  };
}
function calculateRiskScore(findings, context = {}) {
  const unique = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    if (finding.status === "suppressed") continue;
    const current = unique.get(finding.fingerprint);
    if (!current || severityWeight[finding.severity] > severityWeight[current.severity])
      unique.set(finding.fingerprint, finding);
  }
  const deductions = [...unique.values()].map((finding) => deductionFor(finding, context)).filter((deduction) => deduction.points > 0).sort((a, b) => b.points - a.points || a.fingerprint.localeCompare(b.fingerprint));
  let penalty = 0;
  for (let index = 0; index < deductions.length; index += 1) {
    const deduction = deductions[index];
    if (!deduction) continue;
    const diminishing = 1 / (1 + index * 0.055);
    penalty += deduction.points * diminishing;
  }
  const value = Math.max(0, Math.min(100, Math.round((100 - penalty) * 10) / 10));
  return { value, band: scoreBand(value), deductions };
}
var riskModel = Object.freeze({
  severityWeight,
  confidenceMultiplier,
  categoryMultiplier,
  newFindingMultiplier: 1.12,
  maxSingleFindingDeduction: 35
});

// ../../packages/reporter/src/json.ts
function toJsonReport(scan) {
  return {
    schemaVersion: "1",
    scanId: scan.scanId,
    target: scan.target,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    durationMs: scan.durationMs,
    status: scan.status,
    score: scan.score,
    summary: scan.summary,
    findings: scan.findings,
    modules: scan.modules,
    errors: scan.errors,
    ...scan.surface ? { surface: scan.surface } : {}
  };
}
function serializeJsonReport(scan, pretty = true) {
  return `${JSON.stringify(toJsonReport(scan), null, pretty ? 2 : 0)}
`;
}

// ../../packages/reporter/src/sarif.ts
var SARIF_VERSION = "2.1.0";
var SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
function sarifLevel(severity) {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium" || severity === "low") return "warning";
  if (severity === "info") return "note";
  return "none";
}
function ruleFor(finding) {
  return {
    id: finding.ruleId,
    name: finding.title.replace(/[^A-Za-z0-9]+/g, " ").trim().replace(/\s+(.)/g, (_, char) => char.toUpperCase()),
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.description },
    help: {
      text: finding.remediation ?? "Review this finding and apply the documented remediation.",
      ...finding.documentationUrl ? {
        markdown: `[Documentation](${finding.documentationUrl})

${finding.remediation ?? ""}`
      } : {}
    },
    properties: {
      category: finding.category,
      defaultSeverity: finding.severity,
      confidence: finding.confidence
    }
  };
}
function locationFor(finding) {
  if (!finding.location?.file) return void 0;
  return {
    physicalLocation: {
      artifactLocation: {
        uri: finding.location.file.replaceAll("\\", "/"),
        uriBaseId: "%SRCROOT%"
      },
      ...finding.location.line !== void 0 ? {
        region: {
          startLine: finding.location.line,
          ...finding.location.column !== void 0 ? { startColumn: finding.location.column } : {}
        }
      } : {}
    }
  };
}
function toSarif(scan) {
  const ruleMap = new Map(scan.findings.map((finding) => [finding.ruleId, ruleFor(finding)]));
  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "SPECTER",
            semanticVersion: "0.1.0",
            informationUri: "https://github.com/WessYu/SPECTER",
            rules: [...ruleMap.values()]
          }
        },
        originalUriBaseIds: { "%SRCROOT%": { uri: "file:///" } },
        invocations: [
          {
            executionSuccessful: scan.status === "completed",
            startTimeUtc: scan.startedAt,
            endTimeUtc: scan.completedAt
          }
        ],
        results: scan.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: sarifLevel(finding.severity),
          message: { text: finding.description },
          fingerprints: { "specter/v1": finding.fingerprint },
          partialFingerprints: { primaryLocationLineHash: finding.fingerprint.slice(0, 32) },
          ...locationFor(finding) ? { locations: [locationFor(finding)] } : {},
          properties: {
            severity: finding.severity,
            confidence: finding.confidence,
            category: finding.category,
            source: finding.source
          }
        }))
      }
    ]
  };
}
function serializeSarif(scan, pretty = true) {
  return `${JSON.stringify(toSarif(scan), null, pretty ? 2 : 0)}
`;
}

// ../../packages/scanner-build/src/index.ts
import { access as access3, readdir, readFile as readFile2, stat } from "node:fs/promises";
import path3 from "node:path";
var BUILD_DIRS = {
  next: [".next/static", "out"],
  vite: ["dist"],
  react: ["build", "dist"],
  unknown: ["dist", "build", "out"]
};
var rules = {
  sourceMap: {
    id: "SPECTER-BUILD-001",
    title: "Source map present in build output",
    description: "A JavaScript source map is present in generated artifacts and may expose original source when publicly deployed.",
    category: "build",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Do not publish private source maps publicly; upload them only to trusted error-monitoring systems when required."
  },
  envFile: {
    id: "SPECTER-BUILD-002",
    title: "Environment file copied into build output",
    description: "An .env-style file appears in generated artifacts.",
    category: "build",
    defaultSeverity: "critical",
    defaultConfidence: "high",
    remediation: "Remove environment files from client/static output and rotate any exposed credentials."
  },
  secret: {
    id: "SPECTER-BUILD-003",
    title: "Credential-like value present in client artifact",
    description: "A secret-shaped value appears in generated JavaScript or static output.",
    category: "client-exposure",
    defaultSeverity: "critical",
    defaultConfidence: "high",
    remediation: "Remove the private value from browser code, rotate the credential and verify a clean rebuild."
  },
  privateUrl: {
    id: "SPECTER-BUILD-004",
    title: "Private/internal URL present in build output",
    description: "Generated client artifacts contain a private-network or internal hostname reference.",
    category: "client-exposure",
    defaultSeverity: "medium",
    defaultConfidence: "medium",
    remediation: "Keep internal endpoints server-side and expose only intended public API origins to browser code."
  },
  debugInfo: {
    id: "SPECTER-BUILD-005",
    title: "Debug or stack-trace information in build output",
    description: "Generated artifacts contain debug markers or stack traces that may reveal implementation details.",
    category: "build",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Disable production debug output and ensure error responses/logging do not expose stack traces to clients."
  }
};
async function exists(file) {
  try {
    await access3(file);
    return true;
  } catch {
    return false;
  }
}
async function detectFramework(root) {
  const manifestPath = path3.join(path3.resolve(root), "package.json");
  if (!await exists(manifestPath)) return "unknown";
  const parsed = JSON.parse(await readFile2(manifestPath, "utf8"));
  const all = { ...parsed.dependencies ?? {}, ...parsed.devDependencies ?? {} };
  if ("next" in all) return "next";
  if ("vite" in all) return "vite";
  if ("react" in all) return "react";
  return "unknown";
}
async function locateBuildOutput(root, framework) {
  const absolute = path3.resolve(root);
  const resolvedFramework = framework ?? await detectFramework(absolute);
  const candidates = BUILD_DIRS[resolvedFramework];
  const found = [];
  for (const candidate of candidates) {
    const output = path3.join(absolute, candidate);
    if (await exists(output)) found.push(output);
  }
  return found;
}
var TEXT_ARTIFACT = /\.(?:js|mjs|cjs|css|html|json|txt|map|env)$/i;
var SECRET_PATTERN = /\b(?:sk_live_[A-Za-z0-9]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s"'`]+)/g;
var GENERIC_SECRET_ASSIGNMENT = /\b(?:token|secret|password|api[_-]?key|private[_-]?key)\s*[:=]\s*["'`]([^"'`\s]{20,})["'`]/gi;
var PRIVATE_URL = /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[A-Za-z0-9.-]+\.internal)(?::\d+)?[^\s"'`]*/gi;
function lineAt(content, offset) {
  return content.slice(0, offset).split("\n").length;
}
function shannonEntropy(value) {
  if (value.length === 0) return 0;
  const counts = /* @__PURE__ */ new Map();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}
function isLikelyPlaceholder(value) {
  return /^(?:example|sample|placeholder|changeme|your[_-])/i.test(value);
}
async function scanBuild(root, options = {}) {
  const absoluteRoot = path3.resolve(root);
  const framework = await detectFramework(absoluteRoot);
  const outputs = options.outputDirectories?.map((item) => path3.resolve(absoluteRoot, item)) ?? await locateBuildOutput(absoluteRoot, framework);
  const findings = [];
  const skippedLargeFiles = [];
  let filesScanned = 0;
  const maxFileBytes = options.maxFileBytes ?? 2e6;
  async function visit(directory) {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const absolute = path3.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
        continue;
      }
      if (!entry.isFile()) continue;
      const relative = path3.relative(absoluteRoot, absolute).replaceAll(path3.sep, "/");
      const isEnv = /^\.env(?:\.|$)/.test(entry.name);
      if (isEnv)
        findings.push(
          createFinding({
            metadata: rules.envFile,
            source: "build",
            location: { file: relative },
            discriminator: `env:${relative}`,
            evidence: { file: relative }
          })
        );
      if (entry.name.endsWith(".map"))
        findings.push(
          createFinding({
            metadata: rules.sourceMap,
            source: "build",
            location: { file: relative },
            discriminator: `sourcemap:${relative}`,
            evidence: { file: relative }
          })
        );
      if (!TEXT_ARTIFACT.test(entry.name) && !isEnv) continue;
      try {
        const info = await stat(absolute);
        if (info.size > maxFileBytes) {
          skippedLargeFiles.push(relative);
          continue;
        }
        const content = await readFile2(absolute, "utf8");
        filesScanned += 1;
        for (const match of content.matchAll(SECRET_PATTERN))
          findings.push(
            createFinding({
              metadata: rules.secret,
              source: "build",
              location: { file: relative, line: lineAt(content, match.index) },
              discriminator: `secret:${relative}:${lineAt(content, match.index)}`,
              evidence: "[REDACTED]"
            })
          );
        for (const match of content.matchAll(GENERIC_SECRET_ASSIGNMENT)) {
          const value = match[1];
          if (!value || isLikelyPlaceholder(value) || shannonEntropy(value) < 3.5) continue;
          const line = lineAt(content, match.index + match[0].indexOf(value));
          findings.push(
            createFinding({
              metadata: rules.secret,
              source: "build",
              location: { file: relative, line },
              discriminator: `secret:${relative}:${line}`,
              evidence: "[REDACTED]"
            })
          );
        }
        for (const match of content.matchAll(PRIVATE_URL))
          findings.push(
            createFinding({
              metadata: rules.privateUrl,
              source: "build",
              location: { file: relative, line: lineAt(content, match.index) },
              discriminator: `private-url:${relative}:${lineAt(content, match.index)}`,
              evidence: { urlClass: "private-or-internal" }
            })
          );
        if (/\b(?:DEBUG|development mode|Error:\s+[^\n]+\n\s+at\s+)/i.test(content))
          findings.push(
            createFinding({
              metadata: rules.debugInfo,
              source: "build",
              location: { file: relative },
              discriminator: `debug:${relative}`
            })
          );
      } catch {
      }
    }
  }
  for (const output of outputs) await visit(output);
  return {
    framework,
    outputs: outputs.map((item) => path3.relative(absoluteRoot, item).replaceAll(path3.sep, "/")),
    filesScanned,
    findings,
    skippedLargeFiles
  };
}

// ../../packages/scanner-dependencies/src/index.ts
import { access as access4, readFile as readFile3 } from "node:fs/promises";
import path4 from "node:path";
var metadata = {
  id: "SPECTER-DEP-001",
  title: "Known vulnerable dependency",
  description: "An installed dependency version matches a known vulnerability advisory.",
  category: "dependency",
  defaultSeverity: "medium",
  defaultConfidence: "high",
  remediation: "Upgrade to a patched release after validating compatibility and reviewing the advisory."
};
async function exists2(file) {
  try {
    await access4(file);
    return true;
  } catch {
    return false;
  }
}
function parseVersionFromSpecifier(specifier) {
  const exact = specifier.match(/(?:^|@)(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)/);
  return exact?.[1];
}
async function readManifest(root) {
  const raw = await readFile3(path4.join(root, "package.json"), "utf8");
  const parsed = JSON.parse(raw);
  const direct = /* @__PURE__ */ new Map();
  for (const [name, specifier] of Object.entries(parsed.dependencies ?? {}))
    direct.set(name, { version: parseVersionFromSpecifier(specifier), dev: false });
  for (const [name, specifier] of Object.entries(parsed.devDependencies ?? {}))
    if (!direct.has(name))
      direct.set(name, { version: parseVersionFromSpecifier(specifier), dev: true });
  return { direct };
}
async function parseNpmLock(root, direct) {
  const parsed = JSON.parse(await readFile3(path4.join(root, "package-lock.json"), "utf8"));
  const result = /* @__PURE__ */ new Map();
  if (parsed.packages) {
    for (const [key, value] of Object.entries(parsed.packages)) {
      if (!key.startsWith("node_modules/") || !value.version) continue;
      const name = key.slice("node_modules/".length);
      const directInfo = direct.get(name);
      result.set(`${name}@${value.version}`, {
        name,
        version: value.version,
        direct: Boolean(directInfo),
        dev: directInfo?.dev ?? Boolean(value.dev)
      });
    }
  } else {
    for (const [name, value] of Object.entries(parsed.dependencies ?? {})) {
      if (!value.version) continue;
      const directInfo = direct.get(name);
      result.set(`${name}@${value.version}`, {
        name,
        version: value.version,
        direct: Boolean(directInfo),
        dev: directInfo?.dev ?? Boolean(value.dev)
      });
    }
  }
  return [...result.values()];
}
async function parsePnpmLock(root, direct) {
  const content = await readFile3(path4.join(root, "pnpm-lock.yaml"), "utf8");
  const result = /* @__PURE__ */ new Map();
  const packageKey = /^\s{2,}['"]?\/?(@?[^@\s:'"]+(?:\/[^@\s:'"]+)?)@(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)['"]?:\s*$/gm;
  for (const match of content.matchAll(packageKey)) {
    const name = match[1];
    const version = match[2];
    if (!name || !version) continue;
    const directInfo = direct.get(name);
    result.set(`${name}@${version}`, {
      name,
      version,
      direct: Boolean(directInfo),
      dev: directInfo?.dev ?? false
    });
  }
  for (const [name, info] of direct) {
    if ([...result.values()].some((item) => item.name === name && item.direct)) continue;
    if (info.version)
      result.set(`${name}@${info.version}`, {
        name,
        version: info.version,
        direct: true,
        dev: info.dev
      });
  }
  return [...result.values()];
}
async function parseYarnLock(root, direct) {
  const content = await readFile3(path4.join(root, "yarn.lock"), "utf8");
  const result = /* @__PURE__ */ new Map();
  const blocks = content.split(/\n(?=[^ \n#])/g);
  for (const block of blocks) {
    const header2 = block.match(/^([^:\n]+):/);
    const version = block.match(/^\s{2}version\s+["']([^"']+)["']/m)?.[1];
    if (!header2 || !version) continue;
    const firstSpecifier = header2[1]?.split(",")[0]?.trim().replace(/^['"]|['"]$/g, "");
    if (!firstSpecifier) continue;
    let name;
    if (firstSpecifier.startsWith("@")) {
      const marker = firstSpecifier.indexOf("@", 1 + firstSpecifier.indexOf("/"));
      name = marker > 0 ? firstSpecifier.slice(0, marker) : firstSpecifier;
    } else name = firstSpecifier.split("@")[0] ?? firstSpecifier;
    const directInfo = direct.get(name);
    result.set(`${name}@${version}`, {
      name,
      version,
      direct: Boolean(directInfo),
      dev: directInfo?.dev ?? false
    });
  }
  return [...result.values()];
}
async function inspectDependencies(root) {
  const absolute = path4.resolve(root);
  const { direct } = await readManifest(absolute);
  if (await exists2(path4.join(absolute, "pnpm-lock.yaml")))
    return { manager: "pnpm", dependencies: await parsePnpmLock(absolute, direct) };
  if (await exists2(path4.join(absolute, "package-lock.json")))
    return { manager: "npm", dependencies: await parseNpmLock(absolute, direct) };
  if (await exists2(path4.join(absolute, "yarn.lock")))
    return { manager: "yarn", dependencies: await parseYarnLock(absolute, direct) };
  return {
    manager: "unknown",
    dependencies: [...direct].flatMap(
      ([name, info]) => info.version ? [{ name, version: info.version, direct: true, dev: info.dev }] : []
    )
  };
}
function osvSeverity(vulnerability) {
  const database = vulnerability.database_specific;
  const value = typeof database?.severity === "string" ? database.severity.toLowerCase() : "";
  if (["critical", "high", "medium", "low"].includes(value)) return value;
  return "medium";
}
var OsvProvider = class {
  name = "osv.dev";
  #endpoint;
  constructor(endpoint = "https://api.osv.dev/v1/querybatch") {
    this.#endpoint = endpoint;
  }
  async query(dependencies, signal) {
    if (dependencies.length === 0) return [];
    const response = await fetch(this.#endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "specter-security/0.1" },
      body: JSON.stringify({
        queries: dependencies.map((dep) => ({
          package: { ecosystem: "npm", name: dep.name },
          version: dep.version
        }))
      }),
      ...signal ? { signal } : {}
    });
    if (!response.ok) throw new Error(`OSV request failed with HTTP ${response.status}`);
    const body = await response.json();
    const advisories = [];
    for (let index = 0; index < dependencies.length; index += 1) {
      const dependency = dependencies[index];
      if (!dependency) continue;
      for (const vulnerability of body.results?.[index]?.vulns ?? []) {
        const fixed = vulnerability.affected?.flatMap((affected) => affected.ranges ?? []).flatMap((range) => range.events ?? []).map((event) => event.fixed).find((value) => Boolean(value));
        advisories.push({
          id: vulnerability.id,
          package: dependency.name,
          affectedVersion: dependency.version,
          severity: osvSeverity(vulnerability),
          summary: vulnerability.summary ?? vulnerability.id,
          ...vulnerability.references?.[0]?.url ? { url: vulnerability.references[0].url } : {},
          ...fixed ? { patchedVersion: fixed } : {}
        });
      }
    }
    return advisories;
  }
};
async function scanDependencies(root, provider, signal) {
  const inventory = await inspectDependencies(root);
  const advisories = await provider.query(inventory.dependencies, signal);
  const lookup2 = new Map(
    inventory.dependencies.map((item) => [`${item.name}@${item.version}`, item])
  );
  const findings = advisories.map((advisory) => {
    const dependency = lookup2.get(`${advisory.package}@${advisory.affectedVersion}`);
    const base = createFinding({
      metadata,
      source: "dependency",
      severity: advisory.severity,
      confidence: "high",
      discriminator: `${advisory.id}:${advisory.package}:${advisory.affectedVersion}`,
      evidence: {
        advisory: advisory.id,
        package: advisory.package,
        installedVersion: advisory.affectedVersion,
        directDependency: dependency?.direct ?? false
      },
      description: `${advisory.package}@${advisory.affectedVersion}: ${advisory.summary}`,
      remediation: advisory.patchedVersion ? `Upgrade ${advisory.package} to ${advisory.patchedVersion} or later after compatibility review.` : metadata.remediation
    });
    return {
      ...base,
      category: "dependency",
      package: advisory.package,
      installedVersion: advisory.affectedVersion,
      ...advisory.patchedVersion ? { patchedVersion: advisory.patchedVersion } : {},
      advisory: advisory.id,
      directDependency: dependency?.direct ?? false
    };
  });
  return { ...inventory, advisories, findings, provider: provider.name };
}

// ../../packages/scanner-secrets/src/index.ts
import { readdir as readdir2, readFile as readFile4, stat as stat2 } from "node:fs/promises";
import path5 from "node:path";
var TEXT_EXTENSIONS = /* @__PURE__ */ new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".mjs",
  ".cjs",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".ini",
  ".conf",
  ".env",
  ".txt"
]);
var IGNORE_DIRS = /* @__PURE__ */ new Set([
  "node_modules",
  ".git",
  ".next",
  ".turbo",
  "dist",
  "build",
  "coverage",
  ".cache"
]);
var SAFE_BASENAMES = /* @__PURE__ */ new Set([".env.example", ".env.sample", ".env.template", ".env.defaults"]);
var SAFE_SEGMENTS = /* @__PURE__ */ new Set(["fixtures", "__fixtures__", "docs", "documentation"]);
var TEST_FILE = /(?:^|\/)(?:__tests__\/|.*\.(?:test|spec)\.[cm]?[jt]sx?$)/i;
var PATTERNS = [
  {
    name: "Stripe secret key",
    regex: /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    severity: "critical",
    confidence: "high"
  },
  {
    name: "GitHub token",
    regex: /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/g,
    severity: "critical",
    confidence: "high"
  },
  { name: "AWS access key", regex: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high", confidence: "high" },
  {
    name: "Private key",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{20,}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
    confidence: "high"
  },
  {
    name: "Database URL",
    regex: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^\s"'`]+/gi,
    severity: "critical",
    confidence: "high"
  },
  {
    name: "JWT",
    regex: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
    severity: "high",
    confidence: "medium"
  },
  {
    name: "OAuth/client secret assignment",
    regex: /\b(?:client_secret|oauth_secret|api_secret|secret_key)\s*[:=]\s*["'`]([A-Za-z0-9_./+\-=]{16,})["'`]/gi,
    severity: "high",
    confidence: "medium"
  }
];
var metadata2 = {
  id: "SPECTER-SECRET-001",
  title: "Potential exposed secret",
  description: "A credential-like value appears to be committed in application files.",
  category: "secret",
  defaultSeverity: "high",
  defaultConfidence: "medium",
  remediation: "Revoke the exposed credential, remove it from source/history where appropriate, and load it from a secret manager or protected environment variable.",
  falsePositiveGuidance: "Example values, fixtures and documentation should use unmistakable placeholders and are excluded by default."
};
function lineAt2(content, offset) {
  return content.slice(0, offset).split("\n").length;
}
function isSafePath(relative) {
  const normalized = relative.replaceAll("\\", "/");
  const parts = normalized.split("/");
  if (SAFE_BASENAMES.has(parts.at(-1) ?? "")) return true;
  if (parts.some((segment) => SAFE_SEGMENTS.has(segment.toLowerCase()))) return true;
  return TEST_FILE.test(normalized);
}
function redactSecret(secret) {
  const redacted = redactString(secret);
  if (redacted !== secret) return redacted;
  if (secret.length <= 8) return "[REDACTED]";
  return `${secret.slice(0, 4)}${"*".repeat(Math.min(12, Math.max(4, secret.length - 8)))}${secret.slice(-4)}`;
}
function shannonEntropy2(value) {
  if (value.length === 0) return 0;
  const counts = /* @__PURE__ */ new Map();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}
function genericHighEntropyMatches(content) {
  const result = [];
  const assignment = /\b(?:token|secret|password|api[_-]?key|private[_-]?key)\s*[:=]\s*["'`]([^"'`\s]{20,})["'`]/gi;
  for (const match of content.matchAll(assignment)) {
    const value = match[1];
    if (!value || /^(?:example|sample|placeholder|changeme|your[_-])/i.test(value)) continue;
    if (shannonEntropy2(value) < 3.5) continue;
    result.push({ value, index: match.index + match[0].indexOf(value) });
  }
  return result;
}
async function scanSecrets(root, options = {}) {
  const absoluteRoot = path5.resolve(root);
  const maxFileBytes = options.maxFileBytes ?? 1e6;
  const findings = [];
  const skippedFiles = [];
  let filesScanned = 0;
  async function visit(directory) {
    let entries;
    try {
      entries = await readdir2(directory, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (IGNORE_DIRS.has(entry.name)) continue;
      const absolute = path5.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
        continue;
      }
      if (!entry.isFile()) continue;
      const relative = path5.relative(absoluteRoot, absolute).replaceAll(path5.sep, "/");
      if (!options.includeFixtures && isSafePath(relative)) continue;
      const ext = path5.extname(entry.name).toLowerCase();
      if (!TEXT_EXTENSIONS.has(ext) && !entry.name.startsWith(".env")) continue;
      try {
        const info = await stat2(absolute);
        if (info.size > maxFileBytes) {
          skippedFiles.push(relative);
          continue;
        }
        const content = await readFile4(absolute, "utf8");
        filesScanned += 1;
        const fingerprints = /* @__PURE__ */ new Set();
        for (const pattern of PATTERNS) {
          for (const match of content.matchAll(pattern.regex)) {
            const secret = match[1] ?? match[0];
            const finding = createFinding({
              metadata: metadata2,
              source: "static",
              location: { file: relative, line: lineAt2(content, match.index) },
              evidence: { kind: pattern.name, value: redactSecret(secret) },
              discriminator: `${pattern.name}:${lineAt2(content, match.index)}`,
              severity: pattern.severity,
              confidence: pattern.confidence,
              description: `${pattern.name} detected in ${relative}. The value is redacted.`
            });
            if (!fingerprints.has(finding.fingerprint)) {
              fingerprints.add(finding.fingerprint);
              findings.push(finding);
            }
          }
        }
        for (const generic of genericHighEntropyMatches(content)) {
          const finding = createFinding({
            metadata: metadata2,
            source: "static",
            location: { file: relative, line: lineAt2(content, generic.index) },
            evidence: {
              kind: "High entropy credential assignment",
              value: redactSecret(generic.value)
            },
            discriminator: `entropy:${lineAt2(content, generic.index)}`,
            severity: "high",
            confidence: "medium"
          });
          if (!fingerprints.has(finding.fingerprint)) {
            fingerprints.add(finding.fingerprint);
            findings.push(finding);
          }
        }
      } catch {
        skippedFiles.push(relative);
      }
    }
  }
  await visit(absoluteRoot);
  return { filesScanned, findings, skippedFiles };
}

// ../../packages/scanner-static/src/lexical.ts
function isIdentifierStart(char) {
  return /[A-Za-z_$]/.test(char);
}
function isIdentifierPart(char) {
  return /[A-Za-z0-9_$]/.test(char);
}
function tokenizeCode(source) {
  const tokens = [];
  let index = 0;
  let line = 1;
  let column = 1;
  const advance = () => {
    const char = source[index] ?? "";
    index += 1;
    if (char === "\n") {
      line += 1;
      column = 1;
    } else column += 1;
    return char;
  };
  while (index < source.length) {
    const char = source[index] ?? "";
    if (/\s/.test(char)) {
      advance();
      continue;
    }
    if (char === "/" && source[index + 1] === "/") {
      while (index < source.length) {
        if (advance() === "\n") break;
      }
      continue;
    }
    if (char === "/" && source[index + 1] === "*") {
      advance();
      advance();
      while (index < source.length) {
        const current = advance();
        if (current === "*" && source[index] === "/") {
          advance();
          break;
        }
      }
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      const quote = advance();
      let escaped = false;
      while (index < source.length) {
        const current = advance();
        if (escaped) {
          escaped = false;
          continue;
        }
        if (current === "\\") {
          escaped = true;
          continue;
        }
        if (current === quote) break;
      }
      continue;
    }
    if (isIdentifierStart(char)) {
      const startLine = line;
      const startColumn = column;
      let value = advance();
      while (index < source.length && isIdentifierPart(source[index] ?? "")) value += advance();
      tokens.push({ value, line: startLine, column: startColumn });
      continue;
    }
    tokens.push({ value: advance(), line, column: Math.max(1, column - 1) });
  }
  return tokens;
}
function findIdentifierCall(tokens, identifier) {
  const matches = [];
  for (let index = 0; index < tokens.length - 1; index += 1) {
    const token = tokens[index];
    const next = tokens[index + 1];
    const previous = index > 0 ? tokens[index - 1] : void 0;
    if (token?.value === identifier && next?.value === "(" && previous?.value !== ".")
      matches.push(token);
  }
  return matches;
}

// ../../packages/scanner-static/src/rules.ts
var metadata3 = {
  eval: {
    id: "SPECTER-SOURCE-001",
    title: "Dynamic code execution with eval",
    description: "Direct eval() execution can turn attacker-controlled strings into executable JavaScript.",
    category: "source",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Replace eval() with explicit parsing or a constrained operation map.",
    falsePositiveGuidance: "Review generated-code tooling separately; runtime application code should rarely need eval()."
  },
  newFunction: {
    id: "SPECTER-SOURCE-002",
    title: "Dynamic code execution with Function constructor",
    description: "new Function() compiles strings as JavaScript and can create code-injection paths.",
    category: "source",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Avoid compiling dynamic strings; use explicit functions or parsers."
  },
  dangerousHtml: {
    id: "SPECTER-SOURCE-003",
    title: "Potential unsafe HTML injection",
    description: "dangerouslySetInnerHTML bypasses React escaping and requires trusted, sanitized HTML.",
    category: "source",
    defaultSeverity: "medium",
    defaultConfidence: "medium",
    remediation: "Avoid raw HTML when possible; otherwise sanitize with a proven allow-list sanitizer."
  },
  documentWrite: {
    id: "SPECTER-SOURCE-004",
    title: "document.write usage",
    description: "document.write can introduce DOM injection and blocks modern rendering behavior.",
    category: "source",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Use safe DOM APIs and textContent instead of document.write."
  },
  localStorageToken: {
    id: "SPECTER-SOURCE-005",
    title: "Sensitive token may be stored in localStorage",
    description: "Tokens in localStorage are readable by injected JavaScript and increase XSS impact.",
    category: "source",
    defaultSeverity: "medium",
    defaultConfidence: "medium",
    remediation: "Prefer HttpOnly Secure cookies for session material when architecture permits."
  },
  plainHttp: {
    id: "SPECTER-SOURCE-006",
    title: "Plain HTTP URL in application source",
    description: "A non-local HTTP endpoint can expose data or create mixed-content behavior in production.",
    category: "configuration",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Use HTTPS endpoints for production traffic."
  },
  clientExposure: {
    id: "SPECTER-SOURCE-007",
    title: "Suspicious private variable referenced in client-facing source",
    description: "A private credential-like environment variable appears in code that may execute in the browser.",
    category: "client-exposure",
    defaultSeverity: "high",
    defaultConfidence: "medium",
    remediation: "Keep private environment variables in server-only modules and verify generated bundles."
  }
};
function lineOf(source, offset) {
  return source.slice(0, offset).split("\n").length;
}
function lexicalFindings(file) {
  const result = [];
  const tokens = tokenizeCode(file.content);
  for (const token of findIdentifierCall(tokens, "eval")) {
    result.push(
      createFinding({
        metadata: metadata3.eval,
        source: "static",
        location: { file: file.path, line: token.line, column: token.column },
        evidence: "eval(...)"
      })
    );
  }
  for (let index = 0; index < tokens.length - 2; index += 1) {
    const current = tokens[index];
    const next = tokens[index + 1];
    const after = tokens[index + 2];
    if (current?.value === "new" && next?.value === "Function" && after?.value === "(") {
      result.push(
        createFinding({
          metadata: metadata3.newFunction,
          source: "static",
          location: { file: file.path, line: current.line, column: current.column },
          evidence: "new Function(...)"
        })
      );
    }
    if (current?.value === "document" && next?.value === "." && after?.value === "write") {
      result.push(
        createFinding({
          metadata: metadata3.documentWrite,
          source: "static",
          location: { file: file.path, line: current.line, column: current.column },
          evidence: "document.write(...)"
        })
      );
    }
  }
  return result;
}
function isClientFacing(file) {
  const normalized = file.path.replaceAll("\\", "/").toLowerCase();
  const leading = file.content.slice(0, 512);
  return /^[\s;]*(?:["']use client["'];?)/.test(leading) || /(?:^|\/)(?:client|components?|pages?)\//.test(normalized) || /\.client\.[cm]?[jt]sx?$/.test(normalized) || /\b(?:window|document|localStorage|sessionStorage|navigator)\b/.test(file.content);
}
function patternFindings(file) {
  const result = [];
  const patterns = [
    [/dangerouslySetInnerHTML\s*=\s*\{/g, metadata3.dangerousHtml, "dangerouslySetInnerHTML"],
    [
      /localStorage\.(?:setItem|getItem)\s*\(\s*["'`](?:token|accessToken|refreshToken|jwt|session)["'`]/gi,
      metadata3.localStorageToken,
      "localStorage token access"
    ],
    [/\bhttp:\/\/(?!localhost\b|127\.0\.0\.1\b|\[::1\])/gi, metadata3.plainHttp, "http://..."],
    [
      /import\.meta\.env\.(?:DATABASE_URL|PRIVATE_KEY|SECRET_KEY|STRIPE_SECRET_KEY|INTERNAL_API_TOKEN)\b/g,
      metadata3.clientExposure,
      "private import.meta.env variable"
    ],
    [
      /(?:process\.env\.NEXT_PUBLIC_|import\.meta\.env\.VITE_)[A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE|PASSWORD|DATABASE|API_KEY)[A-Z0-9_]*\b/gi,
      metadata3.clientExposure,
      "suspicious public environment variable"
    ]
  ];
  for (const [pattern, rule, evidence] of patterns) {
    for (const match of file.content.matchAll(pattern)) {
      result.push(
        createFinding({
          metadata: rule,
          source: "static",
          location: { file: file.path, line: lineOf(file.content, match.index) },
          evidence
        })
      );
    }
  }
  if (isClientFacing(file)) {
    const privateProcessEnv = /process\.env\.(?:DATABASE_URL|PRIVATE_KEY|SECRET_KEY|STRIPE_SECRET_KEY|INTERNAL_API_TOKEN)\b/g;
    for (const match of file.content.matchAll(privateProcessEnv)) {
      result.push(
        createFinding({
          metadata: metadata3.clientExposure,
          source: "static",
          location: { file: file.path, line: lineOf(file.content, match.index) },
          evidence: "private process.env variable in client-facing source"
        })
      );
    }
  }
  return result;
}
function analyzeSourceFile(file) {
  return [...lexicalFindings(file), ...patternFindings(file)];
}
var sourceRuleMetadata = Object.values(metadata3).map((rule) => ({
  ...rule
}));

// ../../packages/scanner-static/src/walker.ts
import { readdir as readdir3, readFile as readFile5, stat as stat3 } from "node:fs/promises";
import path6 from "node:path";
var SOURCE_EXTENSIONS = /* @__PURE__ */ new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);
var DEFAULT_IGNORES = /* @__PURE__ */ new Set([
  "node_modules",
  ".git",
  ".next",
  ".turbo",
  "coverage",
  "dist",
  "build",
  ".cache"
]);
async function walkSourceFiles(root, options = {}) {
  const absoluteRoot = path6.resolve(root);
  const maxFileBytes = options.maxFileBytes ?? 1e6;
  const ignores = new Set(DEFAULT_IGNORES);
  if (options.includeBuildDirectories) {
    ignores.delete("dist");
    ignores.delete("build");
    ignores.delete(".next");
  }
  for (const entry of options.ignores ?? []) ignores.add(entry);
  const files = [];
  const skippedLargeFiles = [];
  const unreadableFiles = [];
  async function visit(directory) {
    let entries;
    try {
      entries = await readdir3(directory, { withFileTypes: true });
    } catch {
      unreadableFiles.push(path6.relative(absoluteRoot, directory) || ".");
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (ignores.has(entry.name)) continue;
      const absolute = path6.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
        continue;
      }
      if (!entry.isFile() || !SOURCE_EXTENSIONS.has(path6.extname(entry.name).toLowerCase()))
        continue;
      try {
        const metadata4 = await stat3(absolute);
        const relative = path6.relative(absoluteRoot, absolute).replaceAll(path6.sep, "/");
        if (metadata4.size > maxFileBytes) {
          skippedLargeFiles.push(relative);
          continue;
        }
        files.push({
          path: relative,
          absolutePath: absolute,
          content: await readFile5(absolute, "utf8"),
          size: metadata4.size
        });
      } catch {
        unreadableFiles.push(path6.relative(absoluteRoot, absolute).replaceAll(path6.sep, "/"));
      }
    }
  }
  await visit(absoluteRoot);
  return { files, skippedLargeFiles, unreadableFiles };
}

// ../../packages/scanner-static/src/index.ts
async function scanSource(root, options = {}) {
  const walked = await walkSourceFiles(root, options);
  const findings = walked.files.flatMap((file) => [...analyzeSourceFile(file)]);
  return {
    filesScanned: walked.files.length,
    bytesScanned: walked.files.reduce((sum, file) => sum + file.size, 0),
    findings,
    skippedLargeFiles: walked.skippedLargeFiles,
    unreadableFiles: walked.unreadableFiles
  };
}

// ../../packages/scanner-web/src/cookies.ts
var rules2 = {
  secure: {
    id: "SPECTER-COOKIE-001",
    title: "Cookie missing Secure flag",
    description: "A cookie set over HTTPS was observed without the Secure attribute.",
    category: "cookies",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Mark session and sensitive cookies Secure so browsers only send them over HTTPS."
  },
  httpOnly: {
    id: "SPECTER-COOKIE-002",
    title: "Session-like cookie missing HttpOnly",
    description: "A session-like cookie can be read by browser JavaScript.",
    category: "cookies",
    defaultSeverity: "medium",
    defaultConfidence: "medium",
    remediation: "Use HttpOnly for cookies that do not need JavaScript access, especially session identifiers."
  },
  sameSite: {
    id: "SPECTER-COOKIE-003",
    title: "Session-like cookie missing SameSite",
    description: "A session-like cookie does not declare an explicit SameSite policy.",
    category: "cookies",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Set SameSite=Lax or Strict when compatible; use None only when cross-site usage is required and Secure is present."
  },
  noneWithoutSecure: {
    id: "SPECTER-COOKIE-004",
    title: "SameSite=None cookie without Secure",
    description: "A cookie declares SameSite=None without Secure.",
    category: "cookies",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Cookies using SameSite=None must also use Secure."
  }
};
function classify(name) {
  const lower = name.toLowerCase();
  if (/(session|sess|sid|auth|token|jwt)/.test(lower)) return "session";
  if (/(_ga|analytics|utm|amplitude|mixpanel)/.test(lower)) return "analytics";
  if (/(pref|theme|locale|language|consent)/.test(lower)) return "preference";
  return "unknown";
}
function parseSetCookie(raw) {
  const [first, ...attributes] = raw.split(";").map((item) => item.trim());
  const separator = first?.indexOf("=") ?? -1;
  if (!first || separator <= 0) return void 0;
  const name = first.slice(0, separator);
  const map = /* @__PURE__ */ new Map();
  const flags = /* @__PURE__ */ new Set();
  for (const attribute of attributes) {
    const index = attribute.indexOf("=");
    if (index === -1) flags.add(attribute.toLowerCase());
    else map.set(attribute.slice(0, index).toLowerCase(), attribute.slice(index + 1));
  }
  const sameSite = map.get("samesite");
  const domain = map.get("domain");
  const cookiePath = map.get("path");
  const maxAge = map.get("max-age");
  return {
    name,
    kind: classify(name),
    secure: flags.has("secure"),
    httpOnly: flags.has("httponly"),
    ...sameSite ? { sameSite } : {},
    ...domain ? { domain } : {},
    ...cookiePath ? { path: cookiePath } : {},
    ...maxAge ? { maxAge } : {}
  };
}
function analyzeCookies(response) {
  const raw = response.headers["set-cookie"];
  const values = raw === void 0 ? [] : Array.isArray(raw) ? raw : [raw];
  const cookies = values.flatMap((item) => {
    const parsed = parseSetCookie(item);
    return parsed ? [parsed] : [];
  });
  const findings = [];
  for (const cookie of cookies) {
    const location = { url: response.url };
    const evidence = {
      name: cookie.name,
      kind: cookie.kind,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite ?? "unspecified",
      domain: cookie.domain ?? "host-only",
      path: cookie.path ?? "/",
      maxAge: cookie.maxAge ?? "unspecified"
    };
    if (response.url.startsWith("https:") && !cookie.secure && cookie.kind !== "analytics" && cookie.kind !== "preference")
      findings.push(
        createFinding({
          metadata: rules2.secure,
          source: "remote",
          location,
          discriminator: `cookie:${cookie.name}:secure`,
          evidence
        })
      );
    if (cookie.kind === "session" && !cookie.httpOnly)
      findings.push(
        createFinding({
          metadata: rules2.httpOnly,
          source: "remote",
          location,
          discriminator: `cookie:${cookie.name}:httponly`,
          evidence
        })
      );
    if (cookie.kind === "session" && !cookie.sameSite)
      findings.push(
        createFinding({
          metadata: rules2.sameSite,
          source: "remote",
          location,
          discriminator: `cookie:${cookie.name}:samesite`,
          evidence
        })
      );
    if (cookie.sameSite?.toLowerCase() === "none" && !cookie.secure)
      findings.push(
        createFinding({
          metadata: rules2.noneWithoutSecure,
          source: "remote",
          location,
          discriminator: `cookie:${cookie.name}:none-secure`,
          evidence
        })
      );
  }
  return { cookies, findings };
}

// ../../packages/scanner-web/src/csp.ts
var rules3 = {
  unsafeInline: {
    id: "SPECTER-CSP-001",
    title: "CSP allows unsafe-inline",
    description: "The observed CSP contains unsafe-inline, weakening script/style injection protection.",
    category: "csp",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Replace unsafe-inline with nonces or hashes where feasible."
  },
  unsafeEval: {
    id: "SPECTER-CSP-002",
    title: "CSP allows unsafe-eval",
    description: "The observed CSP permits eval-like JavaScript execution.",
    category: "csp",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Remove unsafe-eval and refactor dependencies that require runtime string compilation."
  },
  wildcard: {
    id: "SPECTER-CSP-003",
    title: "CSP contains broad wildcard source",
    description: "A CSP source list contains a broad wildcard that reduces origin restrictions.",
    category: "csp",
    defaultSeverity: "medium",
    defaultConfidence: "medium",
    remediation: "Replace wildcard sources with the minimum explicit origins required."
  },
  objectSrc: {
    id: "SPECTER-CSP-004",
    title: "CSP does not define object-src",
    description: "The policy does not explicitly constrain plugin/object sources.",
    category: "csp",
    defaultSeverity: "low",
    defaultConfidence: "high",
    remediation: "Add object-src 'none' unless object/embed content is intentionally required."
  },
  frameAncestors: {
    id: "SPECTER-CSP-005",
    title: "CSP does not define frame-ancestors",
    description: "The policy does not use frame-ancestors to control embedding.",
    category: "csp",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Add an application-appropriate frame-ancestors directive."
  }
};
function parseCsp(value) {
  const directives = {};
  for (const segment of value.split(";")) {
    const parts = segment.trim().split(/\s+/).filter(Boolean);
    const name = parts.shift()?.toLowerCase();
    if (name) directives[name] = parts;
  }
  return directives;
}
function analyzeCsp(response) {
  const raw = response.headers["content-security-policy"];
  const value = typeof raw === "string" ? raw : raw ? [...raw].join("; ") : void 0;
  if (!value) return [];
  const directives = parseCsp(value);
  const findings = [];
  const location = { url: response.url };
  const sourceLists = Object.entries(directives).filter(
    ([name]) => /-src$/.test(name) || name === "default-src"
  );
  if (sourceLists.some(([, values]) => values.includes("'unsafe-inline'")))
    findings.push(
      createFinding({
        metadata: rules3.unsafeInline,
        source: "remote",
        location,
        discriminator: "csp:unsafe-inline",
        evidence: {
          directives: sourceLists.filter(([, values]) => values.includes("'unsafe-inline'")).map(([name]) => name)
        }
      })
    );
  if (sourceLists.some(([, values]) => values.includes("'unsafe-eval'")))
    findings.push(
      createFinding({
        metadata: rules3.unsafeEval,
        source: "remote",
        location,
        discriminator: "csp:unsafe-eval",
        evidence: {
          directives: sourceLists.filter(([, values]) => values.includes("'unsafe-eval'")).map(([name]) => name)
        }
      })
    );
  if (sourceLists.some(([, values]) => values.includes("*")))
    findings.push(
      createFinding({
        metadata: rules3.wildcard,
        source: "remote",
        location,
        discriminator: "csp:wildcard",
        evidence: {
          directives: sourceLists.filter(([, values]) => values.includes("*")).map(([name]) => name)
        }
      })
    );
  if (!("object-src" in directives))
    findings.push(
      createFinding({
        metadata: rules3.objectSrc,
        source: "remote",
        location,
        discriminator: "csp:no-object-src"
      })
    );
  if (!("frame-ancestors" in directives))
    findings.push(
      createFinding({
        metadata: rules3.frameAncestors,
        source: "remote",
        location,
        discriminator: "csp:no-frame-ancestors"
      })
    );
  return findings;
}

// ../../packages/scanner-web/src/headers.ts
var rules4 = {
  cspMissing: {
    id: "SPECTER-HEADERS-001",
    title: "Content Security Policy missing",
    description: "No Content-Security-Policy header was observed on the response.",
    category: "headers",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Define a restrictive Content-Security-Policy appropriate to the application's resource requirements."
  },
  hstsMissing: {
    id: "SPECTER-HEADERS-002",
    title: "HSTS missing on HTTPS response",
    description: "Strict-Transport-Security was not observed on an HTTPS response.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "high",
    remediation: "After confirming HTTPS is enforced across the host, add a suitable Strict-Transport-Security policy."
  },
  nosniffMissing: {
    id: "SPECTER-HEADERS-003",
    title: "X-Content-Type-Options missing",
    description: "The response does not opt out of MIME sniffing.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "high",
    remediation: "Set X-Content-Type-Options: nosniff."
  },
  referrerMissing: {
    id: "SPECTER-HEADERS-004",
    title: "Referrer-Policy missing",
    description: "The response does not explicitly constrain referrer information.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Set an application-appropriate Referrer-Policy such as strict-origin-when-cross-origin."
  },
  permissionsMissing: {
    id: "SPECTER-HEADERS-005",
    title: "Permissions-Policy missing",
    description: "The response does not explicitly restrict browser capabilities.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Add a Permissions-Policy that enables only capabilities the application uses."
  },
  frameMissing: {
    id: "SPECTER-HEADERS-006",
    title: "Frame embedding protections not observed",
    description: "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
    category: "headers",
    defaultSeverity: "low",
    defaultConfidence: "medium",
    remediation: "Use CSP frame-ancestors and, where compatibility requires it, X-Frame-Options."
  },
  corsWildcard: {
    id: "SPECTER-CORS-001",
    title: "Permissive CORS wildcard",
    description: "Access-Control-Allow-Origin allows any origin.",
    category: "cors",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Allow only origins that need cross-origin access and validate them server-side."
  },
  corsCredentials: {
    id: "SPECTER-CORS-002",
    title: "CORS wildcard combined with credentials",
    description: "A permissive origin policy was observed alongside credential allowance.",
    category: "cors",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Never combine credentialed cross-origin access with broad origin allowance; use an explicit allow-list."
  }
};
function header(response, name) {
  const value = response.headers[name.toLowerCase()];
  if (typeof value === "string") return value;
  if (value) return [...value].join(", ");
  return void 0;
}
function analyzeSecurityHeaders(response) {
  const findings = [];
  const location = { url: response.url };
  const csp = header(response, "content-security-policy");
  if (!csp)
    findings.push(
      createFinding({
        metadata: rules4.cspMissing,
        source: "remote",
        location,
        discriminator: "missing-csp"
      })
    );
  if (response.url.startsWith("https:") && !header(response, "strict-transport-security"))
    findings.push(
      createFinding({
        metadata: rules4.hstsMissing,
        source: "remote",
        location,
        discriminator: "missing-hsts"
      })
    );
  if ((header(response, "x-content-type-options") ?? "").toLowerCase() !== "nosniff")
    findings.push(
      createFinding({
        metadata: rules4.nosniffMissing,
        source: "remote",
        location,
        discriminator: "missing-nosniff"
      })
    );
  if (!header(response, "referrer-policy"))
    findings.push(
      createFinding({
        metadata: rules4.referrerMissing,
        source: "remote",
        location,
        discriminator: "missing-referrer-policy"
      })
    );
  if (!header(response, "permissions-policy"))
    findings.push(
      createFinding({
        metadata: rules4.permissionsMissing,
        source: "remote",
        location,
        discriminator: "missing-permissions-policy"
      })
    );
  if (!header(response, "x-frame-options") && !/(?:^|;)\s*frame-ancestors\b/i.test(csp ?? ""))
    findings.push(
      createFinding({
        metadata: rules4.frameMissing,
        source: "remote",
        location,
        discriminator: "missing-frame-protection"
      })
    );
  const allowOrigin = header(response, "access-control-allow-origin")?.trim();
  if (allowOrigin === "*") {
    const credentials = header(response, "access-control-allow-credentials")?.toLowerCase() === "true";
    findings.push(
      createFinding({
        metadata: credentials ? rules4.corsCredentials : rules4.corsWildcard,
        source: "remote",
        location,
        discriminator: credentials ? "cors:*:credentials" : "cors:*",
        evidence: { allowOrigin: "*", allowCredentials: credentials }
      })
    );
  }
  return findings;
}

// ../../packages/scanner-web/src/safe-request.ts
import * as http from "node:http";
import * as https from "node:https";

// ../../packages/scanner-web/src/target-policy.ts
import { lookup } from "node:dns/promises";
import { isIP as isIP2 } from "node:net";

// ../../packages/scanner-web/src/ip-policy.ts
import { isIP } from "node:net";
function parseIpv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) return void 0;
  const numbers = parts.map(Number);
  if (numbers.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return void 0;
  return numbers;
}
function isPrivateIpv4(value) {
  const octets = parseIpv4(value);
  if (!octets) return false;
  const [a = 0, b = 0] = octets;
  return a === 0 || a === 10 || a === 127 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 0 || a === 192 && b === 168 || a === 198 && (b === 18 || b === 19) || a >= 224;
}
function normalizeIpv6(value) {
  return value.toLowerCase().split("%")[0] ?? value.toLowerCase();
}
function isPrivateIpv6(value) {
  const normalized = normalizeIpv6(value);
  if (normalized === "::" || normalized === "::1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (/^fe[89ab]/.test(normalized)) return true;
  if (normalized.startsWith("ff")) return true;
  const mapped = normalized.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return mapped?.[1] ? isPrivateIpv4(mapped[1]) : false;
}
function isBlockedIp(address) {
  const family = isIP(address);
  if (family === 4) return isPrivateIpv4(address);
  if (family === 6) return isPrivateIpv6(address);
  return true;
}
function isMetadataHostname(hostname) {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return normalized === "metadata.google.internal" || normalized === "metadata" || normalized.endsWith(".internal") || normalized === "instance-data";
}

// ../../packages/scanner-web/src/target-policy.ts
var TargetPolicyError = class extends Error {
  code;
  constructor(code, message) {
    super(message);
    this.name = "TargetPolicyError";
    this.code = code;
  }
};
async function resolvePublicTarget(input2) {
  const url = input2 instanceof URL ? new URL(input2) : new URL(input2);
  if (url.protocol !== "http:" && url.protocol !== "https:")
    throw new TargetPolicyError("INVALID_SCHEME", "Only HTTP and HTTPS targets are allowed.");
  if (url.username || url.password)
    throw new TargetPolicyError(
      "BLOCKED_HOST",
      "Credentials embedded in target URLs are not allowed."
    );
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".localhost") || isMetadataHostname(hostname))
    throw new TargetPolicyError("BLOCKED_HOST", `Blocked target hostname: ${hostname}`);
  if (isIP2(hostname)) {
    if (isBlockedIp(hostname))
      throw new TargetPolicyError("BLOCKED_HOST", `Blocked target address: ${hostname}`);
    return { url, address: hostname, family: isIP2(hostname) };
  }
  let addresses;
  try {
    addresses = await lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw new TargetPolicyError("DNS_FAILURE", `Unable to resolve ${hostname}`);
  }
  if (addresses.length === 0)
    throw new TargetPolicyError("DNS_FAILURE", `No addresses resolved for ${hostname}`);
  if (addresses.some((item) => isBlockedIp(item.address)))
    throw new TargetPolicyError(
      "BLOCKED_HOST",
      `Target ${hostname} resolves to a non-public address.`
    );
  const chosen = addresses[0];
  if (!chosen)
    throw new TargetPolicyError("DNS_FAILURE", `No usable address resolved for ${hostname}`);
  if (chosen.family !== 4 && chosen.family !== 6)
    throw new TargetPolicyError("DNS_FAILURE", `Unsupported address family for ${hostname}`);
  return { url, address: chosen.address, family: chosen.family };
}

// ../../packages/scanner-web/src/safe-request.ts
function normalizeHeaders(headers) {
  const output = {};
  for (const [key, value] of Object.entries(headers))
    if (value !== void 0) output[key.toLowerCase()] = value;
  return output;
}
function once(target, options) {
  return new Promise((resolve, reject) => {
    const client = target.url.protocol === "https:" ? https : http;
    const req = client.request(
      {
        protocol: target.url.protocol,
        hostname: target.url.hostname,
        ...target.url.port ? { port: target.url.port } : {},
        path: `${target.url.pathname}${target.url.search}`,
        method: "GET",
        servername: target.url.hostname,
        ...target.url.protocol === "https:" ? { rejectUnauthorized: options.allowInvalidTlsForInspection !== true } : {},
        headers: {
          "user-agent": options.userAgent ?? "specter-security/0.1",
          accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
          ...options.headers
        },
        lookup: (_hostname, _lookupOptions, callback) => callback(null, target.address, target.family)
      },
      (incoming) => {
        const chunks = [];
        let bytes = 0;
        const max = options.maxResponseBytes ?? 5e6;
        incoming.on("data", (chunk) => {
          bytes += chunk.byteLength;
          if (bytes > max) {
            incoming.destroy(new Error(`Response exceeded ${max} bytes.`));
            return;
          }
          chunks.push(chunk);
        });
        incoming.on("error", reject);
        incoming.on("end", () => {
          const status = incoming.statusCode ?? 0;
          const headers = normalizeHeaders(incoming.headers);
          const location = typeof incoming.headers.location === "string" ? incoming.headers.location : void 0;
          resolve({
            response: {
              url: target.url.toString(),
              status,
              headers,
              body: Buffer.concat(chunks).toString("utf8"),
              bytes,
              redirects: []
            },
            ...location ? { location } : {}
          });
        });
      }
    );
    req.setTimeout(
      options.requestTimeoutMs ?? 1e4,
      () => req.destroy(new Error("Request timed out."))
    );
    req.on("error", reject);
    if (options.signal) {
      if (options.signal.aborted) req.destroy(new Error("Request aborted."));
      else
        options.signal.addEventListener("abort", () => req.destroy(new Error("Request aborted.")), {
          once: true
        });
    }
    req.end();
  });
}
async function safeGet(input2, options = {}) {
  const deadline = Date.now() + (options.totalTimeoutMs ?? 6e4);
  const maxRedirects = options.maxRedirects ?? 5;
  let current = input2;
  const redirects = [];
  for (let redirect = 0; redirect <= maxRedirects; redirect += 1) {
    if (Date.now() > deadline) throw new Error("Total scan request deadline exceeded.");
    const target = await resolvePublicTarget(current);
    const { response, location } = await once(target, options);
    if ([301, 302, 303, 307, 308].includes(response.status) && location) {
      if (redirect === maxRedirects) throw new Error(`Redirect limit exceeded (${maxRedirects}).`);
      const next = new URL(location, target.url).toString();
      redirects.push(next);
      current = next;
      continue;
    }
    return { ...response, redirects };
  }
  throw new Error("Unexpected redirect loop termination.");
}

// ../../packages/scanner-web/src/tls-findings.ts
var rules5 = {
  expiring: {
    id: "SPECTER-TLS-001",
    title: "TLS certificate expires soon",
    description: "The observed certificate is close to expiration.",
    category: "tls",
    defaultSeverity: "medium",
    defaultConfidence: "high",
    remediation: "Renew and deploy the certificate before expiration, then verify the complete chain."
  },
  oldProtocol: {
    id: "SPECTER-TLS-002",
    title: "Legacy TLS protocol negotiated",
    description: "A legacy TLS protocol was negotiated for the connection.",
    category: "tls",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Disable TLS 1.0/1.1 and require modern protocol versions."
  },
  invalidCertificate: {
    id: "SPECTER-TLS-003",
    title: "TLS certificate is not trusted",
    description: "The observed TLS certificate chain could not be authorized by the runtime trust store.",
    category: "tls",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Deploy a certificate issued by a trusted CA with a complete and valid certificate chain."
  },
  hostnameMismatch: {
    id: "SPECTER-TLS-004",
    title: "TLS certificate does not match hostname",
    description: "The certificate identity does not match the requested hostname.",
    category: "tls",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Deploy a certificate whose SAN entries include the production hostname."
  },
  expired: {
    id: "SPECTER-TLS-005",
    title: "TLS certificate is expired",
    description: "The observed TLS certificate is past its validity period.",
    category: "tls",
    defaultSeverity: "critical",
    defaultConfidence: "high",
    remediation: "Replace the expired certificate immediately and verify certificate renewal automation."
  },
  plaintext: {
    id: "SPECTER-TLS-006",
    title: "Production response remains on plaintext HTTP",
    description: "The target completed without upgrading to HTTPS, leaving transport contents and credentials vulnerable to interception.",
    category: "tls",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Serve the application over HTTPS and redirect HTTP traffic to the canonical HTTPS origin."
  }
};
function analyzeTls(target, inspection) {
  const findings = [];
  const parsed = new URL(target);
  if (parsed.protocol !== "https:") {
    findings.push(
      createFinding({
        metadata: rules5.plaintext,
        source: "remote",
        location: { url: target },
        discriminator: "tls:plaintext",
        evidence: { protocol: parsed.protocol }
      })
    );
    return findings;
  }
  if (!inspection.applicable) return findings;
  if (inspection.authorized === false)
    findings.push(
      createFinding({
        metadata: rules5.invalidCertificate,
        source: "remote",
        location: { url: target },
        discriminator: "tls:authorization",
        evidence: {
          authorizationError: inspection.authorizationError ?? "certificate authorization failed",
          issuer: inspection.issuer ?? "unknown"
        }
      })
    );
  if (inspection.hostnameValid === false)
    findings.push(
      createFinding({
        metadata: rules5.hostnameMismatch,
        source: "remote",
        location: { url: target },
        discriminator: "tls:hostname",
        evidence: { hostname: parsed.hostname, issuer: inspection.issuer ?? "unknown" }
      })
    );
  if (inspection.daysUntilExpiry !== void 0 && inspection.daysUntilExpiry < 0)
    findings.push(
      createFinding({
        metadata: rules5.expired,
        source: "remote",
        location: { url: target },
        discriminator: "tls:expired",
        evidence: {
          daysUntilExpiry: inspection.daysUntilExpiry,
          validTo: inspection.validTo ?? "unknown"
        }
      })
    );
  else if (inspection.daysUntilExpiry !== void 0 && inspection.daysUntilExpiry <= 21)
    findings.push(
      createFinding({
        metadata: rules5.expiring,
        source: "remote",
        location: { url: target },
        discriminator: "tls:expiry",
        evidence: {
          daysUntilExpiry: inspection.daysUntilExpiry,
          issuer: inspection.issuer ?? "unknown"
        }
      })
    );
  if (inspection.protocol === "TLSv1" || inspection.protocol === "TLSv1.1")
    findings.push(
      createFinding({
        metadata: rules5.oldProtocol,
        source: "remote",
        location: { url: target },
        discriminator: `tls:${inspection.protocol}`,
        evidence: { protocol: inspection.protocol }
      })
    );
  return findings;
}

// ../../packages/scanner-web/src/tls.ts
import { checkServerIdentity, connect } from "node:tls";
async function inspectTls(input2, timeoutMs = 1e4) {
  const target = await resolvePublicTarget(input2);
  if (target.url.protocol !== "https:") return { applicable: false };
  const hostname = target.url.hostname.replace(/^\[|\]$/g, "");
  const port = target.url.port ? Number(target.url.port) : 443;
  return await new Promise((resolve, reject) => {
    const socket = connect({
      host: target.address,
      port,
      servername: hostname,
      rejectUnauthorized: false
    });
    socket.setTimeout(timeoutMs, () => socket.destroy(new Error("TLS inspection timed out.")));
    socket.once("error", (error) => reject(error));
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      const identityError = certificate && Object.keys(certificate).length > 0 ? checkServerIdentity(hostname, certificate) : new Error("Peer did not provide a certificate.");
      const validFromMs = certificate.valid_from ? Date.parse(certificate.valid_from) : Number.NaN;
      const validToMs = certificate.valid_to ? Date.parse(certificate.valid_to) : Number.NaN;
      const protocol = socket.getProtocol();
      const authorizationError = socket.authorizationError;
      const issuerCommonName = certificate.issuer?.CN;
      const issuer = Array.isArray(issuerCommonName) ? issuerCommonName.join(", ") : issuerCommonName;
      const result = {
        applicable: true,
        authorized: socket.authorized,
        ...authorizationError ? { authorizationError: String(authorizationError) } : {},
        ...protocol ? { protocol } : {},
        ...Number.isFinite(validFromMs) ? { validFrom: new Date(validFromMs).toISOString() } : {},
        ...Number.isFinite(validToMs) ? { validTo: new Date(validToMs).toISOString() } : {},
        ...Number.isFinite(validToMs) ? { daysUntilExpiry: Math.floor((validToMs - Date.now()) / 864e5) } : {},
        hostnameValid: !identityError,
        ...issuer ? { issuer } : {}
      };
      socket.end();
      resolve(result);
    });
  });
}

// ../../packages/scanner-web/src/runtime.ts
function registrableHost(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return void 0;
  }
}
function sameSiteHost(candidate, root) {
  return candidate === root || candidate.endsWith(`.${root}`) || root.endsWith(`.${candidate}`);
}
async function scanRuntime(target, options = {}) {
  const validated = await resolvePublicTarget(target);
  let playwright;
  try {
    playwright = await import("playwright");
  } catch {
    throw new Error(
      "Playwright is required for runtime scans. Install optional dependency 'playwright' and its Chromium browser."
    );
  }
  const browser = await playwright.chromium.launch({ headless: true });
  const context = await browser.newContext({
    ignoreHTTPSErrors: false,
    serviceWorkers: "block",
    javaScriptEnabled: true
  });
  const page = await context.newPage();
  const requests = [];
  const responses = [];
  const consoleErrors = [];
  const pageErrors = [];
  const blockedRequests = [];
  const external = /* @__PURE__ */ new Map();
  const observedRoutes = /* @__PURE__ */ new Map();
  const rootHost = validated.url.hostname.toLowerCase();
  try {
    await page.route("**/*", async (route) => {
      const request = route.request();
      const method = request.method().toUpperCase();
      const url = request.url();
      if (!url.startsWith("http://") && !url.startsWith("https://")) {
        await route.continue();
        return;
      }
      if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
        blockedRequests.push(`${method} ${url}`);
        await route.abort("blockedbyclient");
        return;
      }
      try {
        await resolvePublicTarget(url);
        await route.continue();
      } catch {
        blockedRequests.push(`${method} ${url}`);
        await route.abort("blockedbyclient");
      }
    });
    page.on("request", (request) => {
      const url = request.url();
      requests.push({
        url,
        method: request.method(),
        resourceType: request.resourceType(),
        redirected: request.redirectedFrom() !== null
      });
      const host = registrableHost(url);
      if (host && !sameSiteHost(host, rootHost)) {
        const types = external.get(host) ?? /* @__PURE__ */ new Set();
        types.add(request.resourceType());
        external.set(host, types);
      }
    });
    page.on("response", async (response) => {
      const headers = await response.headers();
      const record = {
        url: response.url(),
        status: response.status(),
        headers,
        ...headers["content-type"] ? { contentType: headers["content-type"] } : {}
      };
      responses.push(record);
      try {
        const parsed = new URL(response.url());
        if (sameSiteHost(parsed.hostname.toLowerCase(), rootHost)) {
          observedRoutes.set(`${response.request().method()} ${parsed.pathname}`, {
            url: parsed.pathname + parsed.search,
            method: response.request().method(),
            status: response.status(),
            ...headers["content-type"] ? { contentType: headers["content-type"] } : {},
            ...headers["access-control-allow-origin"] ? { cors: headers["access-control-allow-origin"] } : {},
            headers
          });
        }
      } catch {
      }
    });
    page.on("console", (message) => {
      if (message.type() === "error") consoleErrors.push(message.text().slice(0, 2e3));
    });
    page.on("pageerror", (error) => pageErrors.push(error.message.slice(0, 2e3)));
    await page.goto(validated.url.toString(), {
      waitUntil: "domcontentloaded",
      timeout: options.navigationTimeoutMs ?? 2e4
    });
    const finalUrl = page.url();
    await resolvePublicTarget(finalUrl);
    const title = await page.title();
    let html = await page.content();
    const maxHtmlBytes = options.maxHtmlBytes ?? 1e6;
    if (html.length > maxHtmlBytes) html = html.slice(0, maxHtmlBytes);
    const cookies = (await context.cookies()).map((cookie) => ({
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
      expires: cookie.expires,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite
    }));
    return {
      finalUrl,
      title,
      requests,
      responses,
      consoleErrors,
      pageErrors,
      externalDomains: [...external.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([domain, resourceTypes]) => ({
        domain,
        classification: "unknown",
        resourceTypes: [...resourceTypes].sort(),
        page: finalUrl
      })),
      routes: [...observedRoutes.values()].sort((a, b) => a.url.localeCompare(b.url)),
      cookies,
      blockedRequests,
      html
    };
  } finally {
    await context.close().catch(() => void 0);
    await browser.close().catch(() => void 0);
  }
}

// ../../packages/scanner-web/src/discovery.ts
var KNOWN_THIRD_PARTY = /* @__PURE__ */ new Set([
  "fonts.googleapis.com",
  "fonts.gstatic.com",
  "cdn.jsdelivr.net",
  "unpkg.com",
  "js.stripe.com",
  "stripe.com",
  "www.googletagmanager.com",
  "www.google-analytics.com",
  "connect.facebook.net",
  "cdn.segment.com"
]);
function hostOf(input2) {
  try {
    return new URL(input2).hostname.toLowerCase();
  } catch {
    return void 0;
  }
}
function firstParty(candidate, root) {
  return candidate === root || candidate.endsWith(`.${root}`) || root.endsWith(`.${candidate}`);
}
function extractHtmlLinks(html, base) {
  const links = /* @__PURE__ */ new Set();
  const pattern = /\b(?:href|src)\s*=\s*["']([^"'#]+)["']/gi;
  for (const match of html.matchAll(pattern)) {
    const raw = match[1]?.trim();
    if (!raw || /^(?:mailto:|tel:|javascript:|data:)/i.test(raw)) continue;
    try {
      const url = new URL(raw, base);
      if (url.protocol === "http:" || url.protocol === "https:") {
        url.hash = "";
        links.add(url.toString());
      }
    } catch {
    }
  }
  return [...links];
}
function extractSitemapLinks(xml) {
  const links = [];
  const pattern = /<loc>\s*([^<]+?)\s*<\/loc>/gi;
  for (const match of xml.matchAll(pattern))
    if (match[1]) links.push(match[1].replaceAll("&amp;", "&").trim());
  return links;
}
function classifyDomain(domain, rootHost, previousDomains) {
  if (firstParty(domain, rootHost)) return "first-party";
  if (previousDomains && !previousDomains.has(domain)) return "newly-introduced";
  if (KNOWN_THIRD_PARTY.has(domain) || [...KNOWN_THIRD_PARTY].some((known) => domain.endsWith(`.${known}`)))
    return "known-third-party";
  return "unknown";
}
async function discoverSurface(target, options = {}) {
  const initial = await resolvePublicTarget(target);
  const rootHost = initial.url.hostname.toLowerCase();
  const maxPages = Math.max(1, Math.min(options.maxPages ?? 20, 100));
  const concurrency = Math.max(1, Math.min(Math.floor(options.concurrency ?? 4), 12));
  const queue = [initial.url.toString()];
  const visited = /* @__PURE__ */ new Set();
  const routes = /* @__PURE__ */ new Map();
  const domains = /* @__PURE__ */ new Map();
  const runtime = options.includeRuntime === false ? void 0 : await scanRuntime(initial.url.toString(), {
    navigationTimeoutMs: options.requestTimeoutMs ?? 2e4
  }).catch(() => void 0);
  if (runtime) {
    for (const route of runtime.routes) routes.set(`${route.method} ${route.url}`, route);
    for (const domain of runtime.externalDomains)
      domains.set(domain.domain, new Set(domain.resourceTypes));
    for (const link of extractHtmlLinks(runtime.html, new URL(runtime.finalUrl))) {
      const host = hostOf(link);
      if (host && firstParty(host, rootHost) && queue.length < maxPages * 4) queue.push(link);
      else if (host) {
        const types = domains.get(host) ?? /* @__PURE__ */ new Set();
        types.add("document-link");
        domains.set(host, types);
      }
    }
  }
  try {
    const sitemapUrl = new URL("/sitemap.xml", initial.url).toString();
    const sitemap = await safeGet(sitemapUrl, options);
    if (sitemap.status >= 200 && sitemap.status < 300) {
      for (const link of extractSitemapLinks(sitemap.body)) {
        const host = hostOf(link);
        if (host && firstParty(host, rootHost) && queue.length < maxPages * 6) queue.push(link);
      }
    }
  } catch {
  }
  const takeCandidate = () => {
    while (queue.length > 0 && visited.size < maxPages) {
      const candidate = queue.shift();
      if (!candidate) continue;
      let parsed;
      try {
        parsed = new URL(candidate);
      } catch {
        continue;
      }
      if (!firstParty(parsed.hostname.toLowerCase(), rootHost)) continue;
      parsed.hash = "";
      const normalized = parsed.toString();
      if (visited.has(normalized)) continue;
      visited.add(normalized);
      return normalized;
    }
    return void 0;
  };
  const worker = async () => {
    while (true) {
      const normalized = takeCandidate();
      if (!normalized) return;
      try {
        const response = await safeGet(normalized, options);
        const final = new URL(response.url);
        if (!firstParty(final.hostname.toLowerCase(), rootHost)) continue;
        const contentTypeRaw = response.headers["content-type"];
        const contentType = typeof contentTypeRaw === "string" ? contentTypeRaw : contentTypeRaw ? [...contentTypeRaw].join(", ") : void 0;
        const corsRaw = response.headers["access-control-allow-origin"];
        const cors = typeof corsRaw === "string" ? corsRaw : corsRaw ? [...corsRaw].join(", ") : void 0;
        const route = {
          url: `${final.pathname}${final.search}`,
          method: "GET",
          status: response.status,
          ...contentType ? { contentType } : {},
          ...cors ? { cors } : {}
        };
        routes.set(`GET ${route.url}`, route);
        if (contentType?.includes("text/html")) {
          for (const link of extractHtmlLinks(response.body, final)) {
            const host = hostOf(link);
            if (!host) continue;
            if (firstParty(host, rootHost) && visited.size + queue.length < maxPages * 3)
              queue.push(link);
            else {
              const types = domains.get(host) ?? /* @__PURE__ */ new Set();
              types.add("document-link");
              domains.set(host, types);
            }
          }
        }
      } catch {
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, maxPages) }, async () => worker()));
  const externalDomains = [...domains.entries()].filter(([domain]) => !firstParty(domain, rootHost)).sort(([a], [b]) => a.localeCompare(b)).map(([domain, resourceTypes]) => ({
    domain,
    classification: classifyDomain(domain, rootHost, options.previousDomains),
    resourceTypes: [...resourceTypes].sort(),
    page: initial.url.toString()
  }));
  const current = new Set(externalDomains.map((item) => item.domain));
  const removedDomains = options.previousDomains ? [...options.previousDomains].filter((domain) => !current.has(domain)).sort() : [];
  return {
    routes: [...routes.values()].sort(
      (a, b) => a.url.localeCompare(b.url) || a.method.localeCompare(b.method)
    ),
    externalDomains,
    removedDomains,
    ...runtime ? { runtime } : {}
  };
}

// ../../packages/scanner-web/src/index.ts
async function scanRemote(target, options = {}) {
  const response = await safeGet(target, { ...options, allowInvalidTlsForInspection: true });
  const cookieAnalysis = analyzeCookies(response);
  const tls = await inspectTls(response.url, options.requestTimeoutMs ?? 1e4).catch(
    () => ({ applicable: response.url.startsWith("https:"), authorized: false })
  );
  const findings = [
    ...analyzeSecurityHeaders(response),
    ...analyzeCsp(response),
    ...cookieAnalysis.findings,
    ...analyzeTls(response.url, tls)
  ];
  return { target, response, tls, cookies: cookieAnalysis.cookies, findings };
}

// ../../packages/cli/src/scan.ts
function elapsed(started) {
  return Math.max(0, Date.now() - started);
}
function deduplicate(findings) {
  const unique = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    const current = unique.get(finding.fingerprint);
    if (!current) unique.set(finding.fingerprint, finding);
    else {
      const rank3 = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
      if (rank3[finding.severity] > rank3[current.severity]) unique.set(finding.fingerprint, finding);
    }
  }
  return [...unique.values()];
}
function moduleResult(name, started, findingCount, status = findingCount ? "warning" : "passed") {
  return { name, durationMs: elapsed(started), findingCount, status };
}
async function executeLocalScan(target, options = {}) {
  const absolute = path7.resolve(target);
  const config = options.config ?? defaultConfig;
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const findings = [];
  const modules = [];
  const errors = [];
  let mark = Date.now();
  if (config.scan.source) {
    const source = await scanSource(absolute, { maxFileBytes: config.limits.maxFileBytes });
    findings.push(...source.findings);
    modules.push(moduleResult("source", mark, source.findings.length));
    mark = Date.now();
    const secrets = await scanSecrets(absolute, { maxFileBytes: config.limits.maxFileBytes });
    findings.push(...secrets.findings);
    modules.push(moduleResult("secrets", mark, secrets.findings.length));
  } else {
    modules.push({ name: "source", durationMs: 0, findingCount: 0, status: "skipped" });
    modules.push({ name: "secrets", durationMs: 0, findingCount: 0, status: "skipped" });
  }
  if ((options.dependencies ?? config.scan.dependencies) !== false) {
    mark = Date.now();
    if (options.offline) {
      const inventory = await inspectDependencies(absolute);
      modules.push({
        name: `dependencies (${inventory.dependencies.length} inventoried; advisory query offline)`,
        durationMs: elapsed(mark),
        findingCount: 0,
        status: "skipped"
      });
    } else {
      const controller = new AbortController();
      const timer = setTimeout(
        () => controller.abort(),
        Math.min(config.limits.requestTimeoutMs, 8e3)
      );
      try {
        const dependencies = await scanDependencies(absolute, new OsvProvider(), controller.signal);
        findings.push(...dependencies.findings);
        modules.push(
          moduleResult(`dependencies:${dependencies.provider}`, mark, dependencies.findings.length)
        );
      } catch (error) {
        modules.push({
          name: "dependencies:osv.dev",
          durationMs: elapsed(mark),
          findingCount: 0,
          status: "skipped"
        });
        errors.push({
          code: "DEPENDENCY_PROVIDER_UNAVAILABLE",
          message: error instanceof Error ? error.message : "Dependency provider failed",
          module: "dependencies",
          recoverable: true
        });
      } finally {
        clearTimeout(timer);
      }
    }
  } else modules.push({ name: "dependencies", durationMs: 0, findingCount: 0, status: "skipped" });
  if ((options.build ?? config.scan.build) !== false) {
    mark = Date.now();
    const build = await scanBuild(absolute, { maxFileBytes: config.limits.maxFileBytes * 2 });
    findings.push(...build.findings);
    modules.push({
      name: `build:${build.framework}`,
      durationMs: elapsed(mark),
      findingCount: build.findings.length,
      status: build.outputs.length === 0 ? "skipped" : build.findings.length ? "warning" : "passed"
    });
  } else modules.push({ name: "build", durationMs: 0, findingCount: 0, status: "skipped" });
  const unique = deduplicate(findings);
  const suppressions = [
    ...config.ignore.map((ruleId) => ({ ruleId, reason: "Ignored by SPECTER configuration" })),
    ...config.suppressions
  ];
  const suppressionResult = applySuppressions(unique, suppressions);
  const reportFindings = [...suppressionResult.findings, ...suppressionResult.suppressed];
  const baselineFingerprints = options.baseline ? new Set(options.baseline.findings.map((finding) => finding.fingerprint)) : void 0;
  const score = calculateRiskScore(
    reportFindings,
    baselineFingerprints ? { baselineFingerprints } : {}
  );
  const completedMs = Date.now();
  return {
    schemaVersion: "1",
    scanId: randomUUID2(),
    target: { kind: "project", value: absolute, displayName: path7.basename(absolute) },
    startedAt,
    completedAt: new Date(completedMs).toISOString(),
    durationMs: completedMs - startedMs,
    status: "completed",
    score,
    summary: summarizeSeverity(suppressionResult.findings),
    findings: reportFindings,
    modules,
    errors
  };
}
async function executeRemoteScan(target, options = {}) {
  const config = options.config ?? defaultConfig;
  if (!config.scan.remote) throw new Error("Remote scanning is disabled by SPECTER configuration.");
  const startedMs = Date.now();
  const startedAt = new Date(startedMs).toISOString();
  const findings = [];
  const modules = [];
  const errors = [];
  const requestOptions = {
    requestTimeoutMs: config.limits.requestTimeoutMs,
    totalTimeoutMs: config.limits.scanTimeoutMs,
    maxRedirects: config.limits.maxRedirects,
    maxResponseBytes: config.limits.maxResponseBytes
  };
  let mark = Date.now();
  const remote = await scanRemote(target, requestOptions);
  findings.push(...remote.findings);
  modules.push(moduleResult("remote", mark, remote.findings.length));
  mark = Date.now();
  let discoveredSurface;
  try {
    discoveredSurface = await discoverSurface(remote.response.url, {
      ...requestOptions,
      maxPages: config.limits.maxPages,
      concurrency: config.limits.concurrency,
      includeRuntime: options.runtime ?? config.scan.runtime
    });
    modules.push({
      name: `surface:${discoveredSurface.routes.length} routes/${discoveredSurface.externalDomains.length} domains`,
      durationMs: elapsed(mark),
      findingCount: 0,
      status: "passed"
    });
  } catch (error) {
    modules.push({
      name: "surface",
      durationMs: elapsed(mark),
      findingCount: 0,
      status: "skipped"
    });
    errors.push({
      code: "SURFACE_DISCOVERY_PARTIAL",
      message: error instanceof Error ? error.message : "Surface discovery failed",
      module: "surface",
      recoverable: true
    });
  }
  const unique = deduplicate(findings);
  const suppressions = [
    ...config.ignore.map((ruleId) => ({ ruleId, reason: "Ignored by SPECTER configuration" })),
    ...config.suppressions
  ];
  const suppressionResult = applySuppressions(unique, suppressions);
  const reportFindings = [...suppressionResult.findings, ...suppressionResult.suppressed];
  const baselineFingerprints = options.baseline ? new Set(options.baseline.findings.map((finding) => finding.fingerprint)) : void 0;
  const score = calculateRiskScore(
    reportFindings,
    baselineFingerprints ? { baselineFingerprints } : {}
  );
  const completedMs = Date.now();
  return {
    schemaVersion: "1",
    scanId: randomUUID2(),
    target: {
      kind: "url",
      value: remote.response.url,
      displayName: new URL(remote.response.url).hostname
    },
    startedAt,
    completedAt: new Date(completedMs).toISOString(),
    durationMs: completedMs - startedMs,
    status: "completed",
    score,
    summary: summarizeSeverity(suppressionResult.findings),
    findings: reportFindings,
    modules,
    errors,
    ...discoveredSurface ? {
      surface: {
        routes: discoveredSurface.routes,
        externalDomains: discoveredSurface.externalDomains,
        removedDomains: discoveredSurface.removedDomains
      }
    } : {}
  };
}
function renderReport(scan, format) {
  if (format === "json") return serializeJsonReport(scan);
  if (format === "sarif") return serializeSarif(scan);
  const counts = scan.summary;
  const lines = [
    scan.target.kind === "url" ? "SPECTER LIVE" : "SPECTER",
    "Application security from source to production.",
    "",
    "Target",
    scan.target.value,
    "",
    "Scanning",
    ...scan.modules.map(
      (module) => `${module.status === "passed" ? "\u2713" : module.status === "warning" ? "!" : module.status === "skipped" ? "-" : "x"} ${module.name} (${module.findingCount})`
    ),
    "",
    "Security Score",
    `${scan.score.value}/100`,
    "",
    `CRITICAL     ${counts.critical}`,
    `HIGH         ${counts.high}`,
    `MEDIUM       ${counts.medium}`,
    `LOW          ${counts.low}`,
    `INFO         ${counts.info}`,
    "",
    `${scan.findings.filter((finding) => finding.status !== "suppressed").length} findings require review.`
  ];
  if (scan.errors.length)
    lines.push(
      "",
      "Partial errors",
      ...scan.errors.map((error) => `- ${error.code}: ${error.message}`)
    );
  return `${lines.join("\n")}
`;
}

// ../../packages/cli/src/scan-command.ts
function needValue(args, index, flag) {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value.`);
  return value;
}
function parseScanArgs(args) {
  let target;
  let format = "terminal";
  let ci = false;
  let failOn;
  let maxScoreDrop;
  let baselinePath;
  let output;
  let runtime;
  let offline = false;
  let build;
  let dependencies;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--json") {
      if (format === "sarif") throw new Error("--json and --sarif are mutually exclusive.");
      format = "json";
      continue;
    }
    if (arg === "--sarif") {
      if (format === "json") throw new Error("--json and --sarif are mutually exclusive.");
      format = "sarif";
      continue;
    }
    if (arg === "--ci") {
      ci = true;
      continue;
    }
    if (arg === "--runtime") {
      runtime = true;
      continue;
    }
    if (arg === "--no-runtime") {
      runtime = false;
      continue;
    }
    if (arg === "--offline") {
      offline = true;
      continue;
    }
    if (arg === "--no-build") {
      build = false;
      continue;
    }
    if (arg === "--no-dependencies") {
      dependencies = false;
      continue;
    }
    if (arg === "--fail-on") {
      const value = needValue(args, index, arg);
      if (!["critical", "high", "medium", "low", "none"].includes(value))
        throw new Error("--fail-on must be critical, high, medium, low or none.");
      failOn = value;
      index += 1;
      continue;
    }
    if (arg === "--max-score-drop") {
      const value = Number(needValue(args, index, arg));
      if (!Number.isFinite(value) || value < 0 || value > 100)
        throw new Error("--max-score-drop must be between 0 and 100.");
      maxScoreDrop = value;
      index += 1;
      continue;
    }
    if (arg === "--baseline") {
      baselinePath = needValue(args, index, arg);
      index += 1;
      continue;
    }
    if (arg === "--output") {
      output = needValue(args, index, arg);
      index += 1;
      continue;
    }
    if (arg?.startsWith("-")) throw new Error(`Unknown scan option: ${arg}`);
    if (target) throw new Error("Only one scan target may be supplied.");
    target = arg;
  }
  return {
    ...target ? { target } : {},
    format,
    ci,
    ...failOn !== void 0 ? { failOn } : {},
    ...maxScoreDrop !== void 0 ? { maxScoreDrop } : {},
    ...baselinePath ? { baselinePath } : {},
    ...output ? { output } : {},
    ...runtime !== void 0 ? { runtime } : {},
    offline,
    ...build !== void 0 ? { build } : {},
    ...dependencies !== void 0 ? { dependencies } : {}
  };
}
function validateLoadedScan(value, source) {
  if (!value || typeof value !== "object") throw new Error(`Invalid scan report: ${source}`);
  const candidate = value;
  if (candidate.schemaVersion !== "1" || typeof candidate.scanId !== "string" || !candidate.target || !candidate.score || !Array.isArray(candidate.findings))
    throw new Error(`Unsupported or invalid SPECTER scan report: ${source}`);
  return candidate;
}
async function readScanReport(file) {
  return validateLoadedScan(JSON.parse(await readFile6(path8.resolve(file), "utf8")), file);
}
async function persistReport(scan, requested, format, cwd) {
  const extension = format === "sarif" ? ".sarif" : ".json";
  let file;
  if (!requested) file = path8.join(cwd, ".specter", `report${extension}`);
  else {
    const absolute = path8.resolve(cwd, requested);
    file = /\.(?:json|sarif)$/i.test(absolute) ? absolute : path8.join(absolute, `specter${extension}`);
  }
  await mkdir(path8.dirname(file), { recursive: true });
  const machineFormat = format === "sarif" ? "sarif" : "json";
  await writeFile2(file, renderReport(scan, machineFormat), "utf8");
  return file;
}
async function runScanCommand(args, cwd) {
  let parsed;
  try {
    parsed = parseScanArgs(args);
  } catch (error) {
    return {
      exitCode: 2,
      stderr: `${error instanceof Error ? error.message : "Invalid scan configuration"}
`
    };
  }
  let baseline;
  try {
    if (parsed.baselinePath)
      baseline = await readScanReport(path8.resolve(cwd, parsed.baselinePath));
  } catch (error) {
    return {
      exitCode: 2,
      stderr: `${error instanceof Error ? error.message : "Unable to read baseline"}
`
    };
  }
  let loadedConfig;
  try {
    loadedConfig = await loadConfig(cwd);
  } catch (error) {
    return {
      exitCode: 2,
      stderr: `${error instanceof Error ? error.message : "Unable to load SPECTER config"}
`
    };
  }
  const target = parsed.target ?? cwd;
  let scan;
  try {
    scan = /^https?:\/\//i.test(target) ? await executeRemoteScan(target, {
      ...baseline ? { baseline } : {},
      ...parsed.runtime !== void 0 ? { runtime: parsed.runtime } : {},
      config: loadedConfig.config
    }) : await executeLocalScan(path8.resolve(cwd, target), {
      ...baseline ? { baseline } : {},
      offline: parsed.offline,
      ...parsed.build !== void 0 ? { build: parsed.build } : {},
      ...parsed.dependencies !== void 0 ? { dependencies: parsed.dependencies } : {},
      config: loadedConfig.config
    });
  } catch (error) {
    return {
      exitCode: 3,
      stderr: `Scan failed: ${error instanceof Error ? error.message : "Unknown scan error"}
`
    };
  }
  let saved;
  try {
    saved = await persistReport(scan, parsed.output, parsed.format, cwd);
  } catch (error) {
    return {
      exitCode: 3,
      stderr: `Scan completed but report could not be saved: ${error instanceof Error ? error.message : "Unknown output error"}
`
    };
  }
  const rendered = renderReport(scan, parsed.format);
  const withLocation = parsed.format === "terminal" ? `${rendered}
Report saved:
${saved}
` : rendered;
  if (parsed.ci) {
    const gate = evaluateSecurityGate(scan, baseline, {
      failOn: parsed.failOn ?? loadedConfig.config.failOn,
      maxScoreDrop: parsed.maxScoreDrop ?? loadedConfig.config.maxScoreDrop
    });
    if (!gate.passed)
      return {
        exitCode: 1,
        stdout: withLocation,
        stderr: `Security gate failed:
${gate.failures.map((failure) => `- ${failure.message}`).join("\n")}
`
      };
  }
  return { exitCode: 0, stdout: withLocation };
}
async function runCompareCommand(args) {
  const [previousPath, currentPath] = args;
  if (!previousPath || !currentPath || args.length !== 2)
    return { exitCode: 2, stderr: "Usage: specter compare <previous.json> <current.json>\n" };
  try {
    const [previous, current] = await Promise.all([
      readScanReport(previousPath),
      readScanReport(currentPath)
    ]);
    const diff = compareScans(previous, current);
    const lines = [
      "SECURITY REGRESSION",
      "",
      "Score",
      `${diff.score.previous} \u2192 ${diff.score.current} (${diff.score.delta >= 0 ? "+" : ""}${diff.score.delta})`,
      "",
      "New findings",
      ...diff.new.map((finding) => `+ ${finding.severity.toUpperCase()} ${finding.title}`),
      "",
      "Resolved",
      ...diff.resolved.map((finding) => `- ${finding.severity.toUpperCase()} ${finding.title}`),
      "",
      "Severity changed",
      ...diff.severityChanged.map(
        (change) => `~ ${change.previous} \u2192 ${change.current} ${change.finding.title}`
      ),
      ""
    ];
    return { exitCode: 0, stdout: `${lines.join("\n")}
` };
  } catch (error) {
    return {
      exitCode: 2,
      stderr: `${error instanceof Error ? error.message : "Compare failed"}
`
    };
  }
}

// ../../packages/cli/src/index.ts
var CLI_VERSION = "0.1.0";
async function runCli(io) {
  const [command = "help", ...rest] = io.args;
  if (command === "scan") return runScanCommand(rest, io.cwd);
  if (command === "compare") return runCompareCommand(rest);
  if (command === "doctor") return doctor(io.cwd);
  if (command === "init") return initConfig(io.cwd);
  if (command === "config") {
    try {
      const loaded = await loadConfig(io.cwd);
      return {
        exitCode: 0,
        stdout: `${JSON.stringify({ ...loaded.path ? { path: loaded.path } : {}, config: loaded.config }, null, 2)}
`
      };
    } catch (error) {
      return {
        exitCode: 2,
        stderr: `${error instanceof Error ? error.message : "Unable to load SPECTER config"}
`
      };
    }
  }
  if (command === "version" || command === "--version" || command === "-v")
    return { exitCode: 0, stdout: `${CLI_VERSION}
` };
  if (command === "help" || command === "--help" || command === "-h") {
    return {
      exitCode: 0,
      stdout: [
        "SPECTER",
        "Application security from source to production.",
        "",
        "Usage:",
        "  specter scan [path|url] [--json|--sarif] [--ci] [--fail-on high] [--max-score-drop 5]",
        "  specter scan [target] --baseline <report.json> [--output <path>]",
        "  specter compare <previous.json> <current.json>",
        "  specter doctor",
        "  specter init",
        "  specter config",
        "  specter version",
        ""
      ].join("\n")
    };
  }
  return { exitCode: 2, stderr: `Unknown command: ${command}
` };
}

// src/index.ts
function input(name, fallback = "") {
  const key = `INPUT_${name.toUpperCase().replaceAll("-", "_")}`;
  return (process.env[key] ?? fallback).trim();
}
function commandEscape(value) {
  return value.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
}
async function main() {
  const target = input("target", ".");
  const failOn = input("fail-on", "high");
  const maxScoreDrop = input("max-score-drop", "5");
  const baseline = input("baseline");
  const offline = input("offline", "false").toLowerCase() === "true";
  const args = [
    "scan",
    target,
    "--ci",
    "--fail-on",
    failOn,
    "--max-score-drop",
    maxScoreDrop,
    "--json"
  ];
  if (baseline) args.push("--baseline", baseline);
  if (offline) args.push("--offline");
  const result = await runCli({ cwd: process.cwd(), args });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  const reportPath = `${process.cwd()}/.specter/report.json`;
  process.stdout.write(`::notice title=SPECTER report::${commandEscape(reportPath)}
`);
  if (result.exitCode !== 0) {
    process.stdout.write(
      `::error title=SPECTER security gate::SPECTER exited with code ${result.exitCode}. Review the report and findings.
`
    );
    process.exitCode = result.exitCode;
  }
}
main().catch((error) => {
  const message = error instanceof Error ? error.message : "Unknown SPECTER Action failure";
  process.stdout.write(`::error title=SPECTER action failed::${commandEscape(message)}
`);
  process.exitCode = 3;
});
