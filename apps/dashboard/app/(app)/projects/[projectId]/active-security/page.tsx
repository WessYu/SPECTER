import Link from "next/link";
import { apiFetch } from "../../../../../lib/api";
import type {
  ActiveScanSummary,
  ActiveTargetSummary,
  FindingSummary,
} from "../../../../../lib/types";
import { formatDate } from "../../../../../lib/format";
import { ProjectTabs } from "../../../../../components/project-tabs";
import { Severity } from "../../../../../components/severity";
import { ActiveTargetForm } from "../../../../../components/active-target-form";
import { ActiveTargetControls } from "../../../../../components/active-target-controls";
import {
  cancelActiveScan,
  startActiveScan,
} from "../../../actions";

function authClass(status: string): string {
  return status === "verified"
    ? "state state-unchanged"
    : status === "expired"
      ? "state state-removed"
      : "state state-new";
}

export default async function ActiveSecurityPage({
  params,
}: {
  readonly params: Promise<{ readonly projectId: string }>;
}) {
  const { projectId } = await params;
  const [targets, scans, findings] = await Promise.all([
    apiFetch<readonly ActiveTargetSummary[]>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/active-targets`,
    ),
    apiFetch<readonly ActiveScanSummary[]>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/active-scans`,
    ),
    apiFetch<readonly FindingSummary[]>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/active-findings`,
    ),
  ]);
  const latest = scans[0];
  const latestTarget = latest
    ? targets.find((target) => target.id === latest.targetId)
    : undefined;
  const regression = latest?.resultScan?.regressionDelta ?? null;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Authorized runtime validation</div>
          <h1>Active Security</h1>
        </div>
        <div className="state">AUTHORIZED ACTIVE TEST</div>
      </div>
      <ProjectTabs projectId={projectId} />

      <section className="panel">
        <h2>Add target</h2>
        <p className="subtle">
          Remote active testing stays disabled until ownership is
          verified for the exact hostname. Redirects never transfer
          authorization to another hostname.
        </p>
        <ActiveTargetForm projectId={projectId} />
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Last active test</h2>
          <span className="eyebrow">
            {latest ? formatDate(latest.createdAt) : "Never"}
          </span>
        </div>
        {latest ? (
          <div className="active-metric-grid">
            <div className="metric">
              <div className="metric-label">Target</div>
              <div className="metric-value active-value">
                {latest.target.hostname}
              </div>
            </div>
            <div className="metric">
              <div className="metric-label">Authorization</div>
              <div className="metric-value active-value">
                {latestTarget?.authorizationStatus.toUpperCase() ??
                  latest.target.authorizationStatus.toUpperCase()}
              </div>
            </div>
            <div className="metric">
              <div className="metric-label">Endpoints tested</div>
              <div className="metric-value">{latest.endpointCount}</div>
            </div>
            <div className="metric">
              <div className="metric-label">Requests used</div>
              <div className="metric-value">
                {latest.requestCount}/{latest.requestBudget}
              </div>
            </div>
            <div className="metric">
              <div className="metric-label">Active findings</div>
              <div className="metric-value">{latest.findingCount}</div>
            </div>
            <div className="metric">
              <div className="metric-label">Confirmed</div>
              <div className="metric-value">{latest.confirmedCount}</div>
            </div>
            <div className="metric">
              <div className="metric-label">Regression delta</div>
              <div
                className={
                  regression !== null && regression < 0
                    ? "metric-value delta-negative"
                    : "metric-value"
                }
              >
                {regression === null
                  ? "NO BASELINE"
                  : `${regression >= 0 ? "+" : ""}${regression}`}
              </div>
            </div>
            <div className="metric">
              <div className="metric-label">Score</div>
              <div className="metric-value">
                {latest.score === null
                  ? "—"
                  : `${Math.round(latest.score)}/100`}
              </div>
            </div>
          </div>
        ) : (
          <div className="empty">
            <p className="subtle">
              No active security test has been queued for this project.
            </p>
          </div>
        )}
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Authorized targets</h2>
          <span className="eyebrow">{targets.length}</span>
        </div>
        {targets.length === 0 ? (
          <div className="empty">
            <p className="subtle">No active targets configured.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Authorization</th>
                  <th>Verified</th>
                  <th>Expires</th>
                  <th>Run</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((target) => (
                  <tr key={target.id}>
                    <td>
                      <strong className="mono">{target.hostname}</strong>
                      <div className="subtle mono">{target.url}</div>
                      <ActiveTargetControls
                        projectId={projectId}
                        targetId={target.id}
                        status={target.authorizationStatus}
                      />
                    </td>
                    <td>
                      <span className={authClass(target.authorizationStatus)}>
                        {target.authorizationStatus.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      {target.verifiedAt
                        ? formatDate(target.verifiedAt)
                        : "—"}
                    </td>
                    <td>
                      {target.authorizationExpiresAt
                        ? formatDate(target.authorizationExpiresAt)
                        : "—"}
                    </td>
                    <td>
                      {target.authorizationStatus === "verified" ? (
                        <form action={startActiveScan} className="form-row">
                          <input
                            type="hidden"
                            name="projectId"
                            value={projectId}
                          />
                          <input
                            type="hidden"
                            name="targetId"
                            value={target.id}
                          />
                          <select
                            name="profile"
                            className="select"
                            defaultValue="safe"
                            aria-label="Active profile"
                          >
                            <option value="safe">SAFE</option>
                            <option value="standard">STANDARD</option>
                          </select>
                          <button className="button" type="submit">
                            Start active test
                          </button>
                        </form>
                      ) : (
                        <span className="subtle">
                          Verification required
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Active scan history</h2>
          <span className="eyebrow">{scans.length}</span>
        </div>
        {scans.length === 0 ? (
          <div className="empty">
            <p className="subtle">No active scan jobs persisted.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Target</th>
                  <th>Profile</th>
                  <th>Status</th>
                  <th>Budget</th>
                  <th>Score</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td>{formatDate(scan.startedAt ?? scan.createdAt)}</td>
                    <td className="mono">{scan.target.hostname}</td>
                    <td>{scan.profile.toUpperCase()}</td>
                    <td>
                      <span
                        className={
                          scan.status === "completed"
                            ? "state state-unchanged"
                            : scan.status === "failed" ||
                                scan.status === "cancelled"
                              ? "state state-removed"
                              : "state state-new"
                        }
                      >
                        {scan.status.toUpperCase()}
                      </span>
                    </td>
                    <td className="mono">
                      {scan.requestCount}/{scan.requestBudget}
                    </td>
                    <td>
                      {scan.score === null
                        ? "—"
                        : Math.round(scan.score)}
                    </td>
                    <td className="right">
                      {scan.status === "queued" ||
                      scan.status === "running" ? (
                        <form action={cancelActiveScan}>
                          <input
                            type="hidden"
                            name="projectId"
                            value={projectId}
                          />
                          <input
                            type="hidden"
                            name="scanId"
                            value={scan.id}
                          />
                          <button
                            type="submit"
                            className="button button-danger"
                          >
                            Cancel
                          </button>
                        </form>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="section">
        <div className="section-head">
          <h2>Active findings</h2>
          <span className="eyebrow">{findings.length}</span>
        </div>
        {findings.length === 0 ? (
          <div className="empty">
            <p className="subtle">
              No active findings are persisted for this project.
            </p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Confidence</th>
                  <th>Phase</th>
                  <th>Route</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <Severity value={finding.severity} />
                    </td>
                    <td>
                      <Link
                        href={`/projects/${projectId}/findings/${finding.id}`}
                      >
                        <strong>{finding.title}</strong>
                      </Link>
                      <div className="eyebrow">
                        {finding.ruleId}
                      </div>
                    </td>
                    <td>{finding.confidence}</td>
                    <td>{finding.phase ?? "—"}</td>
                    <td className="mono">{finding.route ?? "—"}</td>
                    <td>
                      {finding.validationStatus ??
                        finding.status}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
