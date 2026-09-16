import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const cli = path.join(root, "packages", "cli", "dist", "bin.js");
const temp = await mkdtemp(path.join(os.tmpdir(), "specter-active-smoke-"));

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      NO_COLOR: "1",
      SPECTER_TEST_USERNAME: "specter-test",
      SPECTER_TEST_PASSWORD: "specter-password",
    },
    timeout: 45_000,
  });
}

function assert(condition, message, result) {
  if (condition) return;
  process.stderr.write(`${message}\n`);
  if (result?.stdout) process.stderr.write(result.stdout);
  if (result?.stderr) process.stderr.write(result.stderr);
  process.exitCode = 1;
  throw new Error(message);
}

try {
  const securePath = path.join(temp, "secure.json");
  const vulnerablePath = path.join(temp, "vulnerable.json");
  const regressionPath = path.join(temp, "regression.json");

  const secure = run([
    "pentest",
    "examples/active-secure",
    "--json",
    "--ci",
    "--output",
    securePath,
  ]);
  assert(secure.status === 0, "secure active fixture must pass the CI gate", secure);
  const secureReport = JSON.parse(await readFile(securePath, "utf8"));
  assert(
    secureReport.summary.high === 0 && secureReport.summary.critical === 0,
    "secure active fixture must have zero high/critical findings",
    secure,
  );
  assert(secureReport.score.value >= 90, "secure active fixture must score at least 90", secure);

  const vulnerable = run([
    "pentest",
    "examples/active-vulnerable",
    "--json",
    "--ci",
    "--output",
    vulnerablePath,
  ]);
  assert(
    vulnerable.status === 1,
    "vulnerable active fixture must be blocked by the CI gate",
    vulnerable,
  );
  const vulnerableReport = JSON.parse(await readFile(vulnerablePath, "utf8"));
  assert(
    vulnerableReport.findings.some((finding) => finding.ruleId === "SPECTER-ACTIVE-CORS-001"),
    "vulnerable fixture must confirm active CORS exposure",
    vulnerable,
  );
  assert(
    vulnerableReport.budget.used <= vulnerableReport.budget.max,
    "active scanner exceeded request budget",
    vulnerable,
  );

  const regression = run([
    "pentest",
    "examples/active-vulnerable",
    "--json",
    "--ci",
    "--baseline",
    securePath,
    "--output",
    regressionPath,
  ]);
  assert(
    regression.status === 1,
    "secure to vulnerable transition must fail the regression gate",
    regression,
  );
  const regressionReport = JSON.parse(await readFile(regressionPath, "utf8"));
  assert(
    regressionReport.regressionDelta < 0,
    "active regression delta must be negative",
    regression,
  );

  const refused = run(["pentest", "https://unverified.example", "--json"]);
  assert(
    refused.status === 3 &&
      refused.stderr.includes(
        "Active scanning requires verified ownership or explicit authorization",
      ),
    "unverified remote active scanning must be refused before network activity",
    refused,
  );

  process.stdout.write(
    [
      "SPECTER ACTIVE SMOKE PASS",
      `secure score: ${secureReport.score.value}/100`,
      `vulnerable score: ${vulnerableReport.score.value}/100`,
      `vulnerable requests: ${vulnerableReport.budget.used}/${vulnerableReport.budget.max}`,
      `regression delta: ${regressionReport.regressionDelta}`,
      "",
    ].join("\n"),
  );
} finally {
  await rm(temp, { recursive: true, force: true });
}
