import { defaultConfig } from "@specter/config";
import { doctor, initConfig, runLocalScan, type CommandResult } from "./commands.js";

export const CLI_VERSION = "0.1.0";

export interface CliIo {
  readonly cwd: string;
  readonly args: readonly string[];
}

export async function runCli(io: CliIo): Promise<CommandResult> {
  const [command = "help", ...rest] = io.args;
  if (command === "scan") {
    const target = rest.find((arg) => !arg.startsWith("-")) ?? io.cwd;
    if (/^https?:\/\//i.test(target)) return { exitCode: 2, stderr: "Remote scanning is not enabled in this build yet.\n" };
    return runLocalScan(target);
  }
  if (command === "doctor") return doctor(io.cwd);
  if (command === "init") return initConfig(io.cwd);
  if (command === "config") return { exitCode: 0, stdout: `${JSON.stringify(defaultConfig, null, 2)}\n` };
  if (command === "version" || command === "--version" || command === "-v") return { exitCode: 0, stdout: `${CLI_VERSION}\n` };
  if (command === "help" || command === "--help" || command === "-h") {
    return { exitCode: 0, stdout: "SPECTER\n\nUsage:\n  specter scan [path]\n  specter doctor\n  specter init\n  specter config\n  specter version\n" };
  }
  return { exitCode: 2, stderr: `Unknown command: ${command}\n` };
}

export * from "./commands.js";
export * from "./terminal.js";
