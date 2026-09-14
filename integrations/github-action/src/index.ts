import { runCli } from "@specter-security/cli";

function input(name: string, fallback = ""): string {
  const key = `INPUT_${name.toUpperCase().replaceAll("-", "_")}`;
  return (process.env[key] ?? fallback).trim();
}

function commandEscape(value: string): string {
  return value.replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A");
}

async function main(): Promise<void> {
  const target = input("target", ".");
  const failOn = input("fail-on", "high");
  const maxScoreDrop = input("max-score-drop", "5");
  const baseline = input("baseline");
  const offline = input("offline", "false").toLowerCase() === "true";

  const args = ["scan", target, "--ci", "--fail-on", failOn, "--max-score-drop", maxScoreDrop, "--json"];
  if (baseline) args.push("--baseline", baseline);
  if (offline) args.push("--offline");

  const result = await runCli({ cwd: process.cwd(), args });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);

  const reportPath = `${process.cwd()}/.specter/report.json`;
  process.stdout.write(`::notice title=SPECTER report::${commandEscape(reportPath)}\n`);
  if (result.exitCode !== 0) {
    process.stdout.write(`::error title=SPECTER security gate::SPECTER exited with code ${result.exitCode}. Review the report and findings.\n`);
    process.exitCode = result.exitCode;
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "Unknown SPECTER Action failure";
  process.stdout.write(`::error title=SPECTER action failed::${commandEscape(message)}\n`);
  process.exitCode = 3;
});
