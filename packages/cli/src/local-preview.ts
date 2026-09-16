import { readFile } from "node:fs/promises";
import net from "node:net";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { safeGet } from "@specter/scanner-web";

interface PreviewManifest {
  readonly command: string;
  readonly args?: readonly string[];
  readonly healthPath?: string;
}

export interface LocalPreview {
  readonly url: string;
  stop(): Promise<void>;
}

function validateManifest(value: unknown): PreviewManifest {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("specter.active.json must contain an object.");
  const row = value as Record<string, unknown>;
  if (typeof row.command !== "string" || row.command.trim().length === 0)
    throw new Error("specter.active.json requires a command.");
  if (
    row.args !== undefined &&
    (!Array.isArray(row.args) || row.args.some((item) => typeof item !== "string"))
  )
    throw new Error("specter.active.json args must be an array of strings.");
  if (
    row.healthPath !== undefined &&
    (typeof row.healthPath !== "string" || !row.healthPath.startsWith("/"))
  )
    throw new Error("specter.active.json healthPath must begin with /.");
  return {
    command: row.command.trim(),
    ...(Array.isArray(row.args) ? { args: row.args as readonly string[] } : {}),
    ...(typeof row.healthPath === "string" ? { healthPath: row.healthPath } : {}),
  };
}

async function findFreePort(): Promise<number> {
  return new Promise<number>((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Unable to reserve a local preview port."));
        return;
      }
      const port = address.port;
      server.close((error) => {
        if (error) reject(error);
        else resolve(port);
      });
    });
  });
}

async function waitForPreview(
  url: string,
  healthPath: string,
  processRef: ChildProcess,
  signal?: AbortSignal,
): Promise<void> {
  const deadline = Date.now() + 10_000;
  const healthUrl = new URL(healthPath, url).toString();
  while (Date.now() < deadline) {
    if (signal?.aborted) {
      const error = new Error("Active scan cancelled.");
      error.name = "AbortError";
      throw error;
    }
    if (processRef.exitCode !== null)
      throw new Error(`Local preview exited before becoming ready (code ${processRef.exitCode}).`);
    try {
      const response = await safeGet(healthUrl, {
        allowLocalhost: true,
        requestTimeoutMs: 800,
        totalTimeoutMs: 1_000,
        maxRedirects: 0,
        maxResponseBytes: 16_384,
        ...(signal === undefined ? {} : { signal }),
      });
      if (response.status > 0) return;
    } catch (error: unknown) {
      if ((error as Error).name === "AbortError") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("Local preview did not become ready within 10 seconds.");
}

export async function startLocalPreview(
  targetPath: string,
  signal?: AbortSignal,
): Promise<LocalPreview> {
  const root = path.resolve(targetPath);
  const manifestPath = path.join(root, "specter.active.json");
  const manifest = validateManifest(JSON.parse(await readFile(manifestPath, "utf8")));
  const port = await findFreePort();
  const child = spawn(manifest.command, [...(manifest.args ?? [])], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(port),
      HOST: "127.0.0.1",
      SPECTER_ACTIVE_PREVIEW: "1",
    },
    stdio: "ignore",
    windowsHide: true,
    shell: false,
  });
  const url = `http://127.0.0.1:${port}/`;
  try {
    await waitForPreview(url, manifest.healthPath ?? "/", child, signal);
  } catch (error: unknown) {
    child.kill();
    throw error;
  }

  return {
    url,
    async stop(): Promise<void> {
      if (child.exitCode !== null || child.killed) return;
      child.kill();
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, 1_500);
        child.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
      });
    },
  };
}
