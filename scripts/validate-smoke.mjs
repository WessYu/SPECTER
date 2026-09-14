import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createFinding, redactEvidence } from "../packages/core/dist/index.js";
import { parseConfigSource, validateConfig } from "../packages/config/dist/index.js";
import { serializeSarif } from "../packages/reporter/dist/index.js";
import { calculateRiskScore } from "../packages/risk-engine/dist/index.js";
import { scanDependencies, StaticAdvisoryProvider } from "../packages/scanner-dependencies/dist/index.js";
import { scanSecrets } from "../packages/scanner-secrets/dist/index.js";
import { scanSource } from "../packages/scanner-static/dist/index.js";
import { analyzeTls, resolvePublicTarget } from "../packages/scanner-web/dist/index.js";
import { runCli } from "../packages/cli/dist/index.js";

const root = path.resolve(new URL("..", import.meta.url).pathname);
const vulnerable = path.join(root, "examples", "vulnerable-next");
const secure = path.join(root, "examples", "secure-next");

const secureSource = await scanSource(secure);
assert.equal(secureSource.findings.length, 0, "secure example must not produce source findings");

const vulnerableSource = await scanSource(vulnerable);
const sourceRules = new Set(vulnerableSource.findings.map((finding) => finding.ruleId));
for (const rule of [
  "SPECTER-SOURCE-001",
  "SPECTER-SOURCE-003",
  "SPECTER-SOURCE-005",
  "SPECTER-SOURCE-007",
])
  assert(sourceRules.has(rule), `vulnerable example must trigger ${rule}`);

const secrets = await scanSecrets(vulnerable);
assert(secrets.findings.length >= 1, "vulnerable example must expose a synthetic secret");
assert(
  !JSON.stringify(secrets.findings).includes("spt_test_Q7m9Z2x8N4v6K1r5T3w0"),
  "secret evidence must be redacted",
);

const provider = new StaticAdvisoryProvider([
  {
    id: "SPECTER-FIXTURE-LODASH",
    package: "lodash",
    affectedVersion: "4.17.20",
    severity: "high",
    summary: "Deterministic fixture advisory",
    patchedVersion: "4.17.21",
  },
]);
const dependency = await scanDependencies(vulnerable, provider);
assert.equal(
  dependency.findings.length,
  1,
  "vulnerable dependency fixture must produce one deterministic advisory",
);
assert.equal(dependency.findings[0]?.directDependency, true);

const parsed = parseConfigSource(
  'export default { failOn: "high", scan: { runtime: false }, suppressions: [{ ruleId: "R", reason: "accepted risk" }] };',
);
assert.equal(validateConfig(parsed).failOn, "high");
assert.throws(() => parseConfigSource("export default { failOn: process.env.FAIL_ON };"));

const redacted = redactEvidence({
  authorization: "Bearer real-token",
  apiKey: "spt_test_Q7m9Z2x8N4v6K1r5T3w0",
});
assert.equal(redacted.authorization, "[REDACTED]");
assert.equal(redacted.apiKey, "[REDACTED]");

const finding = createFinding({
  metadata: {
    id: "SMOKE-1",
    title: "Smoke",
    description: "Smoke",
    category: "source",
    defaultSeverity: "high",
    defaultConfidence: "high",
    remediation: "Fix",
  },
  source: "static",
});
assert(calculateRiskScore([finding]).value < 100);

const scan = {
  schemaVersion: "1",
  scanId: "smoke-scan",
  target: { kind: "project", value: vulnerable },
  startedAt: "2026-01-01T00:00:00.000Z",
  completedAt: "2026-01-01T00:00:01.000Z",
  durationMs: 1000,
  status: "completed",
  score: calculateRiskScore([finding]),
  summary: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
  findings: [finding],
  modules: [],
  errors: [],
};
assert.equal(JSON.parse(serializeSarif(scan)).version, "2.1.0");

assert(
  analyzeTls("http://example.com", { applicable: false }).some(
    (item) => item.ruleId === "SPECTER-TLS-006",
  ),
);
await assert.rejects(resolvePublicTarget("http://127.0.0.1"), /Blocked target/);

const cli = await runCli({
  cwd: root,
  args: ["scan", "examples/vulnerable-next", "--offline", "--no-build", "--json"],
});
assert.equal(cli.exitCode, 0, cli.stderr);
const cliReport = JSON.parse(cli.stdout ?? "{}");
assert.equal(cliReport.schemaVersion, "1");
assert(cliReport.findings.length >= 5, "CLI vulnerable fixture should report multiple findings");

const temp = await mkdtemp(path.join(os.tmpdir(), "specter-smoke-"));
try {
  await writeFile(path.join(temp, "package.json"), '{"name":"safe","version":"1.0.0"}');
  await writeFile(path.join(temp, "app.ts"), "export const value = 1;\n");
  const safeCli = await runCli({
    cwd: temp,
    args: ["scan", ".", "--offline", "--no-build", "--json"],
  });
  assert.equal(safeCli.exitCode, 0, safeCli.stderr);
  const safeReport = JSON.parse(safeCli.stdout ?? "{}");
  assert.equal(safeReport.findings.length, 0, "minimal safe fixture should have no findings");
  const saved = JSON.parse(await readFile(path.join(temp, ".specter", "report.json"), "utf8"));
  assert.equal(saved.scanId, safeReport.scanId);
} finally {
  await rm(temp, { recursive: true, force: true });
}

process.stdout.write("SPECTER smoke validation passed.\n");
