#!/usr/bin/env node
import { runCli } from "./index.js";

const controller = new AbortController();
const cancel = () => controller.abort();
process.once("SIGINT", cancel);

try {
  const result = await runCli({
    cwd: process.cwd(),
    args: process.argv.slice(2),
    signal: controller.signal,
  });
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  process.exitCode = result.exitCode;
} finally {
  process.removeListener("SIGINT", cancel);
}
