import Link from "next/link";
import { notFound } from "next/navigation";
import { apiFetch, ApiError } from "../../../../lib/api";
import type { ProjectOverviewResponse } from "../../../../lib/types";
import { formatDate, scoreDelta } from "../../../../lib/format";
import { Severity } from "../../../../components/severity";
import { ProjectTabs } from "../../../../components/project-tabs";

export default async function ProjectPage({
  params,
}: {
  readonly params: Promise<{ readonly projectId: string }>;
}) {
  const { projectId } = await params;
  let data: ProjectOverviewResponse;
  try {
    data = await apiFetch<ProjectOverviewResponse>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/overview`,
    );
  } catch (error: unknown) {
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }
  const current = data.scans[0];
  const previous = data.scans[1];
  const delta = scoreDelta(current?.score, previous?.score);
  const metrics = [
    ["Code Security", data.metrics.codeSecurity],
    ["Dependencies", data.metrics.dependencies],
    ["Client Exposure", data.metrics.clientExposure],
    ["Runtime Configuration", data.metrics.runtimeConfiguration],
    ["Attack Surface", data.metrics.attackSurface],
  ] as const;
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Project / {data.project.slug}</div>
          <h1>{data.project.name}</h1>
        </div>
        <div className="page-actions">
          <Link className="button button-quiet" href={`/projects/${projectId}/scans`}>
            All scans
          </Link>
        </div>
      </div>
      <ProjectTabs projectId={projectId} />
      {current ? (
        <>
          <section className="score-line" aria-label="Current security score">
            <div>
              <div className="eyebrow">Production security score</div>
              <div className="score-value">
                {Math.round(current.score)}
                <span className="score-denominator">/100</span>
              </div>
            </div>
            <div className="score-meta">
              <span>Last scan {formatDate(current.completedAt)}</span>
              <span className={delta.className}>
                Regression{" "}
                {previous
                  ? `${Math.round(previous.score)} → ${Math.round(current.score)} (${delta.text})`
                  : "No baseline"}
              </span>
              <span className="mono">{current.status.toUpperCase()}</span>
            </div>
          </section>
          <div className="metric-grid">
            {metrics.map(([label, value]) => (
              <div className="metric" key={label}>
                <div className="metric-label">{label}</div>
                <div className="metric-value">
                  {value === null ? <span className="metric-na">NOT MEASURED</span> : value}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : (
        <section className="empty">
          <h2>No persisted scans</h2>
          <p className="subtle">
            Run SPECTER through the CLI or CI and submit the resulting scan to this project. Metrics
            are never fabricated.
          </p>
        </section>
      )}
      <section className="section">
        <div className="section-head">
          <h2>Security layers</h2>
        </div>
        <div className="layer-grid">
          <div className="panel">
            <div className="eyebrow">STATIC</div>
            <h2>Source + build</h2>
            <p className="subtle">
              {data.scans.some((scan) => scan.scanType !== "active" && scan.targetKind !== "url")
                ? "Measured"
                : "Not measured"}
            </p>
          </div>
          <div className="panel">
            <div className="eyebrow">PASSIVE</div>
            <h2>Published runtime</h2>
            <p className="subtle">
              {data.scans.some((scan) => scan.scanType !== "active" && scan.targetKind === "url")
                ? "Measured"
                : "Not measured"}
            </p>
          </div>
          <Link href={`/projects/${projectId}/active-security`} className="panel layer-link">
            <div className="eyebrow">ACTIVE</div>
            <h2>Authorized validation</h2>
            <p className="subtle">
              {data.scans.some((scan) => scan.scanType === "active") ? "Measured" : "Not measured"}
            </p>
          </Link>
        </div>
      </section>
      <section className="section">
        <div className="section-head">
          <h2>Latest findings</h2>
          <Link className="subtle" href={`/projects/${projectId}/findings`}>
            View all
          </Link>
        </div>
        {data.latestFindings.length === 0 ? (
          <div className="empty">
            <p className="subtle">No findings are associated with the latest scan.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Category</th>
                  <th>Source</th>
                  <th>Last detected</th>
                </tr>
              </thead>
              <tbody>
                {data.latestFindings.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <Severity value={finding.severity} />
                    </td>
                    <td>
                      <Link href={`/projects/${projectId}/findings/${finding.id}`}>
                        <strong>{finding.title}</strong>
                      </Link>
                      <div className="eyebrow" style={{ marginTop: 5 }}>
                        {finding.ruleId}
                      </div>
                    </td>
                    <td>{finding.category}</td>
                    <td className="mono">{finding.source}</td>
                    <td>{formatDate(finding.lastDetectedAt)}</td>
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
