import { loadConfig } from "./config-loader.js";
import { doctor, initConfig, type CommandResult } from "./commands.js";
import { runCompareCommand, runScanCommand } from "./scan-command.js";

export const CLI_VERSION = "0.1.0";

export interface CliIo {
  readonly cwd: string;
  readonly args: readonly string[];
}

const ANSI = {
  reset: "\u001B[0m",
  bold: "\u001B[1m",
  dim: "\u001B[2m",
  mint: "\u001B[38;2;76;255;170m",
  cyan: "\u001B[38;2;64;205;255m",
  ice: "\u001B[38;2;218;228;240m",
  muted: "\u001B[38;2;141;153;174m",
} as const;

function paint(text: string, code: string, enabled: boolean): string {
  return enabled ? `${code}${text}${ANSI.reset}` : text;
}

function supportsColor(): boolean {
  if (process.env.NO_COLOR !== undefined) return false;
  if (process.env.FORCE_COLOR !== undefined) return process.env.FORCE_COLOR !== "0";
  return Boolean(process.stdout.isTTY);
}

function renderHelp(): string {
  const color = supportsColor();
  const mint = (text: string) => paint(text, ANSI.mint, color);
  const cyan = (text: string) => paint(text, ANSI.cyan, color);
  const ice = (text: string) => paint(text, ANSI.ice, color);
  const muted = (text: string) => paint(text, ANSI.muted, color);
  const bold = (text: string) => paint(text, ANSI.bold, color);
  const dim = (text: string) => paint(text, ANSI.dim, color);

  const ghost = [
    "             .-─────────-.",
    "          .-'             '-.",
    "        .'       ╭───╮       '.",
    "       /        ╱     ╲        \\",
    "      /        │  ◢ ◣  │        \\",
    "     │         │   ▾   │         │",
    "     │         ╲  ───  ╱         │",
    "      \\         '───'         /",
    "       '.       ╱│   │╲       .'",
    "         '-._  ╱ │   │ ╲  _.-'",
    "             '╲  │   │  ╱'",
    "               ╲│   │╱",
    "                ╲   ╱",
    "                 ╲ ╱",
    "                  ╵",
  ];

  const logo = ["┏━┓┏━┓┏━╸┏━╸╺┳╸┏━╸┏━┓", "┗━┓┣━┛┣╸ ┃   ┃ ┣╸ ┣┳┛", "┗━┛╹  ┗━╸┗━╸ ╹ ┗━╸╹┗╸"];

  const command = (syntax: string, description: string): string =>
    `${mint(syntax.padEnd(34))}${muted(description)}`;

  const help = [
    cyan(bold(logo[0]!)),
    cyan(bold(logo[1]!)),
    `${cyan(bold(logo[2]!))}  ${mint(`v${CLI_VERSION}`)}`,
    dim(ice("Application security from source to production.")),
    "",
    `${cyan(bold("COMMANDS"))} ${cyan("────────────────────────────────────────")}`,
    command("specter scan [path|url]", "scan source, build or a published app"),
    command("specter compare <old> <new>", "compare two SPECTER reports"),
    command("specter doctor", "check the local environment"),
    command("specter init", "create specter.config.ts"),
    command("specter config", "print the resolved configuration"),
    command("specter version", "print the CLI version"),
    command("specter help", "show this screen"),
    "",
    `${cyan(bold("COMMON FLAGS"))} ${cyan("────────────────────────────────────")}`,
    ice("--json  --sarif  --ci  --baseline <report>  --output <path>"),
  ];

  const ghostWidth = Math.max(...ghost.map((line) => line.length));
  const terminalWidth = process.stdout.columns ?? 120;

  if (terminalWidth < 100) {
    return [
      ...help.slice(0, 4),
      "",
      ...ghost.map((line, index) => (index < 8 ? cyan(line) : mint(line))),
      "",
      ...help.slice(5),
      "",
    ].join("\n");
  }

  const rows = Math.max(ghost.length, help.length);
  return (
    Array.from({ length: rows }, (_, index) => {
      const rawGhost = ghost[index] ?? "";
      const left = rawGhost.padEnd(ghostWidth);
      const coloredGhost = index < 8 ? cyan(left) : mint(left);
      const divider = cyan("│");
      const right = help[index] ?? "";
      return `${coloredGhost}  ${divider}  ${right}`.trimEnd();
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
