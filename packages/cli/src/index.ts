import { loadConfig } from "./config-loader.js";
import { doctor, initConfig, type CommandResult } from "./commands.js";
import { runCompareCommand, runScanCommand } from "./scan-command.js";

export const CLI_VERSION = "0.1.0";

export interface CliIo {
  readonly cwd: string;
  readonly args: readonly string[];
}

export async function runCli(io: CliIo): Promise<CommandResult> {
  const [command = "help", ...rest] = io.args;
  if (command === "scan") return runScanCommand(rest, io.cwd);
  if (command === "compare") return runCompareCommand(rest);
  if (command === "doctor") return doctor(io.cwd);
  if (command === "init") return initConfig(io.cwd);
  if (command === "config") {
    try {
      const loaded = await loadConfig(io.cwd);
      return { exitCode: 0, stdout: `${JSON.stringify({ ...(loaded.path ? { path: loaded.path } : {}), config: loaded.config }, null, 2)}\n` };
    } catch (error: unknown) {
      return { exitCode: 2, stderr: `${error instanceof Error ? error.message : "Unable to load SPECTER config"}\n` };
    }
  }
  if (command === "version" || command === "--version" || command === "-v") return { exitCode: 0, stdout: `${CLI_VERSION}\n` };
  if (command === "help" || command === "--help" || command === "-h") {
    return { exitCode: 0, stdout: [
      "SPECTER", "Application security from source to production.", "", "Usage:",
      "  specter scan [path|url] [--json|--sarif] [--ci] [--fail-on high] [--max-score-drop 5]", "  specter scan [target] --baseline <report.json> [--output <path>]", "  specter compare <previous.json> <current.json>", "  specter doctor", "  specter init", "  specter config", "  specter version", "",
    ].join("\n") };
  }
  return { exitCode: 2, stderr: `Unknown command: ${command}\n` };
}

export * from "./commands.js";
export * from "./scan-command.js";
export * from "./scan.js";

export * from "./config-loader.js";
