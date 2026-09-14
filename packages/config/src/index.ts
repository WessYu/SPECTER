export interface ConfigSuppression {
  readonly ruleId?: string;
  readonly fingerprint?: string;
  readonly reason: string;
  readonly expiresAt?: string;
}

export interface SpecterConfig {
  readonly failOn: "critical" | "high" | "medium" | "low" | "none";
  readonly maxScoreDrop: number;
  readonly ignore: readonly string[];
  readonly suppressions: readonly ConfigSuppression[];
  readonly scan: {
    readonly source: boolean;
    readonly build: boolean;
    readonly dependencies: boolean;
    readonly remote: boolean;
    readonly runtime: boolean;
  };
  readonly active: {
    readonly enabled: boolean;
    readonly profile: "safe" | "standard";
    readonly maxRequests: number;
    readonly maxRequestsPerSecond: number;
    readonly concurrency: number;
    readonly requestTimeoutMs: number;
    readonly maxEndpoints: number;
    readonly maxParametersPerEndpoint: number;
    readonly allowStateChangingMethods: boolean;
    readonly previewHosts: readonly string[];
  };
  readonly limits: {
    readonly maxFileBytes: number;
    readonly requestTimeoutMs: number;
    readonly scanTimeoutMs: number;
    readonly maxRedirects: number;
    readonly maxPages: number;
    readonly maxResponseBytes: number;
    readonly concurrency: number;
  };
}

export const defaultConfig: SpecterConfig = Object.freeze({
  failOn: "high",
  maxScoreDrop: 5,
  ignore: [],
  suppressions: [],
  scan: { source: true, build: true, dependencies: true, remote: true, runtime: false },
  active: {
    enabled: false,
    profile: "safe",
    maxRequests: 150,
    maxRequestsPerSecond: 3,
    concurrency: 2,
    requestTimeoutMs: 5_000,
    maxEndpoints: 40,
    maxParametersPerEndpoint: 10,
    allowStateChangingMethods: false,
    previewHosts: [],
  },
  limits: {
    maxFileBytes: 1_000_000,
    requestTimeoutMs: 10_000,
    scanTimeoutMs: 60_000,
    maxRedirects: 5,
    maxPages: 20,
    maxResponseBytes: 5_000_000,
    concurrency: 4,
  },
});

interface Token {
  readonly type: "punctuation" | "string" | "number" | "identifier";
  readonly value: string;
  readonly offset: number;
}

function tokenizeConfig(source: string): readonly Token[] {
  const tokens: Token[] = [];
  let index = source.charCodeAt(0) === 0xfeff ? 1 : 0;
  const punctuation = new Set(["{", "}", "[", "]", ":", ",", ";"]);

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
          if (escaped === undefined) break;
          const map: Readonly<Record<string, string>> = {
            n: "\n",
            r: "\r",
            t: "\t",
            b: "\b",
            f: "\f",
            v: "\v",
            "0": "\0",
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

class ConfigParser {
  readonly #tokens: readonly Token[];
  #index = 0;

  constructor(tokens: readonly Token[]) {
    this.#tokens = tokens;
  }

  #peek(): Token | undefined {
    return this.#tokens[this.#index];
  }
  #take(): Token {
    const token = this.#tokens[this.#index];
    if (!token) throw new Error("Unexpected end of SPECTER config.");
    this.#index += 1;
    return token;
  }
  #expect(value: string): void {
    const token = this.#take();
    if (token.value !== value)
      throw new Error(`Expected '${value}' in SPECTER config at offset ${token.offset}.`);
  }

  parse(): unknown {
    if (this.#peek()?.value === "export") {
      this.#expect("export");
      this.#expect("default");
    }
    const value = this.#parseValue();
    if (this.#peek()?.value === ";") this.#take();
    const trailing = this.#peek();
    if (trailing)
      throw new Error(
        `Unexpected token '${trailing.value}' in SPECTER config at offset ${trailing.offset}.`,
      );
    return value;
  }

  #parseValue(): unknown {
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
      `Only object literals, arrays, strings, numbers, booleans and null are allowed in specter.config.ts (offset ${token.offset}).`,
    );
  }

  #parseObject(): Readonly<Record<string, unknown>> {
    this.#expect("{");
    const result: Record<string, unknown> = {};
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
          `Expected ',' or '}' in SPECTER config${token ? ` at offset ${token.offset}` : ""}.`,
        );
      }
    }
    this.#expect("}");
    return result;
  }

  #parseArray(): readonly unknown[] {
    this.#expect("[");
    const result: unknown[] = [];
    while (this.#peek() && this.#peek()?.value !== "]") {
      result.push(this.#parseValue());
      if (this.#peek()?.value === ",") {
        this.#take();
        continue;
      }
      if (this.#peek()?.value !== "]") {
        const token = this.#peek();
        throw new Error(
          `Expected ',' or ']' in SPECTER config${token ? ` at offset ${token.offset}` : ""}.`,
        );
      }
    }
    this.#expect("]");
    return result;
  }
}

export function parseConfigSource(source: string): unknown {
  return new ConfigParser(tokenizeConfig(source)).parse();
}

function validateSuppressions(value: unknown): readonly ConfigSuppression[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new Error("suppressions must be an array.");
  return value.map((item, index) => {
    if (item === null || typeof item !== "object" || Array.isArray(item))
      throw new Error(`suppressions[${index}] must be an object.`);
    const row = item as Record<string, unknown>;
    const allowed = new Set(["ruleId", "fingerprint", "reason", "expiresAt"]);
    const unknown = Object.keys(row).filter((key) => !allowed.has(key));
    if (unknown.length)
      throw new Error(`Unknown suppressions[${index}] keys: ${unknown.join(", ")}`);
    const ruleId =
      typeof row.ruleId === "string" && row.ruleId.trim() ? row.ruleId.trim() : undefined;
    const fingerprint =
      typeof row.fingerprint === "string" && row.fingerprint.trim()
        ? row.fingerprint.trim()
        : undefined;
    if (!ruleId && !fingerprint)
      throw new Error(`suppressions[${index}] requires ruleId or fingerprint.`);
    if (typeof row.reason !== "string" || row.reason.trim().length < 3)
      throw new Error(`suppressions[${index}].reason must contain at least 3 characters.`);
    if (
      row.expiresAt !== undefined &&
      (typeof row.expiresAt !== "string" || !Number.isFinite(Date.parse(row.expiresAt)))
    )
      throw new Error(`suppressions[${index}].expiresAt must be a valid date-time string.`);
    return {
      ...(ruleId ? { ruleId } : {}),
      ...(fingerprint ? { fingerprint } : {}),
      reason: row.reason.trim(),
      ...(typeof row.expiresAt === "string"
        ? { expiresAt: new Date(row.expiresAt).toISOString() }
        : {}),
    };
  });
}

export function validateConfig(input: unknown): SpecterConfig {
  if (input === undefined) return defaultConfig;
  if (input === null || typeof input !== "object" || Array.isArray(input))
    throw new Error("SPECTER config must be an object.");
  const value = input as Record<string, unknown>;
  const allowed = new Set(["failOn", "maxScoreDrop", "ignore", "suppressions", "scan", "active", "limits"]);
  const unknownKeys = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknownKeys.length) throw new Error(`Unknown SPECTER config keys: ${unknownKeys.join(", ")}`);

  const failOn = value.failOn ?? defaultConfig.failOn;
  if (!["critical", "high", "medium", "low", "none"].includes(String(failOn)))
    throw new Error("failOn must be critical, high, medium, low or none.");
  const maxScoreDrop = value.maxScoreDrop ?? defaultConfig.maxScoreDrop;
  if (
    typeof maxScoreDrop !== "number" ||
    !Number.isFinite(maxScoreDrop) ||
    maxScoreDrop < 0 ||
    maxScoreDrop > 100
  )
    throw new Error("maxScoreDrop must be between 0 and 100.");
  const ignore = value.ignore ?? defaultConfig.ignore;
  if (
    !Array.isArray(ignore) ||
    ignore.some((item) => typeof item !== "string" || item.trim().length === 0)
  )
    throw new Error("ignore must be an array of non-empty rule ids.");
  const suppressions = validateSuppressions(value.suppressions);

  const mergeBooleanGroup = <T extends Record<string, boolean>>(
    raw: unknown,
    defaults: T,
    name: string,
  ): T => {
    if (raw === undefined) return defaults;
    if (raw === null || typeof raw !== "object" || Array.isArray(raw))
      throw new Error(`${name} must be an object.`);
    const source = raw as Record<string, unknown>;
    const unknown = Object.keys(source).filter((key) => !(key in defaults));
    if (unknown.length) throw new Error(`Unknown ${name} keys: ${unknown.join(", ")}`);
    const result = { ...defaults } as Record<string, boolean>;
    for (const key of Object.keys(defaults)) {
      if (source[key] !== undefined && typeof source[key] !== "boolean")
        throw new Error(`${name}.${key} must be boolean.`);
      if (typeof source[key] === "boolean") result[key] = source[key];
    }
    return result as T;
  };

  const scan = mergeBooleanGroup(value.scan, defaultConfig.scan, "scan");

  const activeRaw = value.active;
  let active = defaultConfig.active;
  if (activeRaw !== undefined) {
    if (activeRaw === null || typeof activeRaw !== "object" || Array.isArray(activeRaw))
      throw new Error("active must be an object.");
    const source = activeRaw as Record<string, unknown>;
    const unknown = Object.keys(source).filter((key) => !(key in defaultConfig.active));
    if (unknown.length) throw new Error(`Unknown active keys: ${unknown.join(", ")}`);
    const profile = source.profile ?? defaultConfig.active.profile;
    if (profile !== "safe" && profile !== "standard")
      throw new Error("active.profile must be safe or standard.");
    const enabled = source.enabled ?? defaultConfig.active.enabled;
    const allowStateChangingMethods = source.allowStateChangingMethods ?? defaultConfig.active.allowStateChangingMethods;
    if (typeof enabled !== "boolean") throw new Error("active.enabled must be boolean.");
    if (typeof allowStateChangingMethods !== "boolean")
      throw new Error("active.allowStateChangingMethods must be boolean.");

    const positiveInteger = (key: keyof typeof defaultConfig.active, maximum: number): number => {
      const raw = source[key] ?? defaultConfig.active[key];
      if (typeof raw !== "number" || !Number.isInteger(raw) || raw <= 0 || raw > maximum)
        throw new Error(`active.${key} must be an integer between 1 and ${maximum}.`);
      return raw;
    };

    const previewHostsRaw = source.previewHosts ?? defaultConfig.active.previewHosts;
    if (!Array.isArray(previewHostsRaw) || previewHostsRaw.some((item) => typeof item !== "string" || item.trim().length === 0))
      throw new Error("active.previewHosts must be an array of hostnames.");

    active = {
      enabled,
      profile,
      maxRequests: positiveInteger("maxRequests", 5_000),
      maxRequestsPerSecond: positiveInteger("maxRequestsPerSecond", 20),
      concurrency: positiveInteger("concurrency", 8),
      requestTimeoutMs: positiveInteger("requestTimeoutMs", 60_000),
      maxEndpoints: positiveInteger("maxEndpoints", 200),
      maxParametersPerEndpoint: positiveInteger("maxParametersPerEndpoint", 50),
      allowStateChangingMethods,
      previewHosts: previewHostsRaw.map((item) => (item as string).trim().toLowerCase().replace(/\.$/, "")),
    };
  }

  const limitsRaw = value.limits;
  let limits = defaultConfig.limits;
  if (limitsRaw !== undefined) {
    if (limitsRaw === null || typeof limitsRaw !== "object" || Array.isArray(limitsRaw))
      throw new Error("limits must be an object.");
    const source = limitsRaw as Record<string, unknown>;
    const unknown = Object.keys(source).filter((key) => !(key in defaultConfig.limits));
    if (unknown.length) throw new Error(`Unknown limits keys: ${unknown.join(", ")}`);
    const mutable = { ...defaultConfig.limits };
    for (const key of Object.keys(defaultConfig.limits) as (keyof typeof defaultConfig.limits)[]) {
      const item = source[key];
      if (item === undefined) continue;
      if (typeof item !== "number" || !Number.isFinite(item) || item <= 0)
        throw new Error(`limits.${key} must be a positive number.`);
      mutable[key] = Math.floor(item);
    }
    limits = mutable;
  }

  return {
    failOn: failOn as SpecterConfig["failOn"],
    maxScoreDrop,
    ignore: ignore.map((item) => item.trim()),
    suppressions,
    scan,
    active,
    limits,
  };
}
