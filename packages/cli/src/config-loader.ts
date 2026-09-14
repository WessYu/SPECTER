import { access, readFile } from "node:fs/promises";
import path from "node:path";
import {
  defaultConfig,
  parseConfigSource,
  validateConfig,
  type SpecterConfig,
} from "@specter/config";

async function fileExists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

export interface LoadedConfig {
  readonly config: SpecterConfig;
  readonly path?: string;
}

export async function loadConfig(root: string): Promise<LoadedConfig> {
  const absolute = path.resolve(root);
  for (const name of ["specter.config.ts", "specter.config.json"] as const) {
    const file = path.join(absolute, name);
    if (!(await fileExists(file))) continue;
    const raw = await readFile(file, "utf8");
    let parsed: unknown;
    try {
      parsed = name.endsWith(".json") ? JSON.parse(raw) : parseConfigSource(raw);
    } catch (error: unknown) {
      throw new Error(
        `Unable to parse ${name}: ${error instanceof Error ? error.message : "Invalid config"}`,
      );
    }
    return { config: validateConfig(parsed), path: file };
  }
  return { config: defaultConfig };
}
