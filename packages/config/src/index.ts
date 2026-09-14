export interface SpecterConfig {
  readonly failOn: "critical" | "high" | "medium" | "low" | "none";
  readonly maxScoreDrop: number;
  readonly ignore: readonly string[];
  readonly scan: {
    readonly source: boolean;
    readonly build: boolean;
    readonly dependencies: boolean;
    readonly remote: boolean;
    readonly runtime: boolean;
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
  scan: { source: true, build: true, dependencies: true, remote: true, runtime: false },
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

export function validateConfig(input: unknown): SpecterConfig {
  if (input === undefined) return defaultConfig;
  if (input === null || typeof input !== "object" || Array.isArray(input)) throw new Error("SPECTER config must be an object.");
  const value = input as Record<string, unknown>;
  const allowed = new Set(["failOn", "maxScoreDrop", "ignore", "scan", "limits"]);
  const unknownKeys = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknownKeys.length) throw new Error(`Unknown SPECTER config keys: ${unknownKeys.join(", ")}`);

  const failOn = value.failOn ?? defaultConfig.failOn;
  if (!["critical", "high", "medium", "low", "none"].includes(String(failOn))) throw new Error("failOn must be critical, high, medium, low or none.");
  const maxScoreDrop = value.maxScoreDrop ?? defaultConfig.maxScoreDrop;
  if (typeof maxScoreDrop !== "number" || !Number.isFinite(maxScoreDrop) || maxScoreDrop < 0 || maxScoreDrop > 100) throw new Error("maxScoreDrop must be between 0 and 100.");
  const ignore = value.ignore ?? defaultConfig.ignore;
  if (!Array.isArray(ignore) || ignore.some((item) => typeof item !== "string")) throw new Error("ignore must be an array of rule ids.");

  const mergeBooleanGroup = <T extends Record<string, boolean>>(raw: unknown, defaults: T, name: string): T => {
    if (raw === undefined) return defaults;
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${name} must be an object.`);
    const source = raw as Record<string, unknown>;
    const unknown = Object.keys(source).filter((key) => !(key in defaults));
    if (unknown.length) throw new Error(`Unknown ${name} keys: ${unknown.join(", ")}`);
    const result = { ...defaults } as Record<string, boolean>;
    for (const key of Object.keys(defaults)) {
      if (source[key] !== undefined && typeof source[key] !== "boolean") throw new Error(`${name}.${key} must be boolean.`);
      if (typeof source[key] === "boolean") result[key] = source[key];
    }
    return result as T;
  };

  const scan = mergeBooleanGroup(value.scan, defaultConfig.scan, "scan");
  const limitsRaw = value.limits;
  let limits = defaultConfig.limits;
  if (limitsRaw !== undefined) {
    if (limitsRaw === null || typeof limitsRaw !== "object" || Array.isArray(limitsRaw)) throw new Error("limits must be an object.");
    const source = limitsRaw as Record<string, unknown>;
    const unknown = Object.keys(source).filter((key) => !(key in defaultConfig.limits));
    if (unknown.length) throw new Error(`Unknown limits keys: ${unknown.join(", ")}`);
    const mutable = { ...defaultConfig.limits };
    for (const key of Object.keys(defaultConfig.limits) as (keyof typeof defaultConfig.limits)[]) {
      const item = source[key];
      if (item === undefined) continue;
      if (typeof item !== "number" || !Number.isFinite(item) || item <= 0) throw new Error(`limits.${key} must be a positive number.`);
      mutable[key] = Math.floor(item);
    }
    limits = mutable;
  }

  return { failOn: failOn as SpecterConfig["failOn"], maxScoreDrop, ignore: [...ignore], scan, limits };
}
