import { loadConfig } from "./config-loader.js";
import { doctor, initConfig, type CommandResult } from "./commands.js";
import { runCompareCommand, runScanCommand } from "./scan-command.js";

export const CLI_VERSION = "0.1.0";

export interface CliIo {
  readonly cwd: string;
  readonly args: readonly string[];
}

function renderHelp(): string {
  const ghost = [
    '       .-""""-.',
    "      /        \\",
    "     /  o    o  \\",
    "    |     __     |",
    "    |    (__)    |",
    "     \\          /",
    "      \\   /\\   /",
    "       \\_/  \\_/",
  ];

  const help = [
    `SPECTER v${CLI_VERSION}`,
    "Application security from source to production.",
    "",
    "COMMANDS",
    "specter scan [path|url]          scan source, build or a published app",
    "specter compare <old> <new>      compare two SPECTER reports",
    "specter doctor                   check the local environment",
    "specter init                     create specter.config.ts",
    "specter config                   print the resolved configuration",
    "specter version                  print the CLI version",
    "specter help                     show this screen",
    "",
    "COMMON FLAGS",
    "--json  --sarif  --ci  --baseline <report>  --output <path>",
  ];

  const width = Math.max(...ghost.map((line) => line.length));
  const rows = Math.max(ghost.length, help.length);

  return (
    Array.from({ length: rows }, (_, index) => {
      const left = ghost[index] ?? "";
      const right = help[index] ?? "";
      return `${left.padEnd(width)}    ${right}`.trimEnd();
    }).join("\n") + "\n"
  );
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
      return {
        exitCode: 0,
        stdout: `${JSON.stringify({ ...(loaded.path ? { path: loaded.path } : {}), config: loaded.config }, null, 2)}\n`,
      };
    } catch (error: unknown) {
      return {
        exitCode: 2,
        stderr: `${error instanceof Error ? error.message : "Unable to load SPECTER config"}\n`,
      };
    }
  }
  if (command === "version" || command === "--version" || command === "-v")
    return { exitCode: 0, stdout: `${CLI_VERSION}\n` };
  if (command === "help" || command === "--help" || command === "-h") {
    return {
      exitCode: 0,
      stdout: renderHelp(),
    };
  }
  return { exitCode: 2, stderr: `Unknown command: ${command}\n` };
}

export * from "./commands.js";
export * from "./scan-command.js";
export * from "./scan.js";

export * from "./config-loader.js";
