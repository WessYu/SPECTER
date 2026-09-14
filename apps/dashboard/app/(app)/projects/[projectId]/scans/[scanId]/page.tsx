import Link from "next/link";
import { notFound } from "next/navigation";
import { apiFetch, ApiError } from "../../../../../../lib/api";
import type { ScanDetail } from "../../../../../../lib/types";
import { formatDate, formatDuration, shortId } from "../../../../../../lib/format";
import { Severity } from "../../../../../../components/severity";
import { ProjectTabs } from "../../../../../../components/project-tabs";

export default async function ScanDetailPage({
  params,
}: {
  readonly params: Promise<{ readonly projectId: string; readonly scanId: string }>;
}) {
  const { projectId, scanId } = await params;
  let scan: ScanDetail;
  try {
    scan = await apiFetch<ScanDetail>(`/api/v1/scans/${encodeURIComponent(scanId)}`);
  } catch (error: unknown) {
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Scan / {shortId(scan.id)}</div>
          <h1>{scan.targetValue}</h1>
        </div>
        <div className="mono">{Math.round(scan.score)}/100</div>
      </div>
      <ProjectTabs projectId={projectId} />
      <dl className="detail-list">
        <dt>Status</dt>
        <dd>{scan.status}</dd>
        <dt>Target</dt>
        <dd className="mono">
          {scan.targetKind} · {scan.targetValue}
        </dd>
        <dt>Completed</dt>
        <dd>{formatDate(scan.completedAt)}</dd>
        <dt>Duration</dt>
        <dd className="mono">{formatDuration(scan.durationMs)}</dd>
        <dt>Schema</dt>
        <dd className="mono">v{scan.schemaVersion}</dd>
      </dl>
      <section className="section">
        <div className="section-head">
          <h2>Findings in this scan</h2>
          <span className="eyebrow">{scan.occurrences.length}</span>
        </div>
        {scan.occurrences.length === 0 ? (
          <div className="empty">
            <p className="subtle">No persisted findings for this scan.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Location</th>
                  <th>Observed</th>
                </tr>
              </thead>
              <tbody>
                {scan.occurrences.map((occurrence) => (
                  <tr key={occurrence.id}>
                    <td>
                      <Severity value={occurrence.severity} />
                    </td>
                    <td>
                      <Link href={`/projects/${projectId}/findings/${occurrence.finding.id}`}>
                        <strong>{occurrence.finding.title}</strong>
                      </Link>
                      <div className="eyebrow" style={{ marginTop: 5 }}>
                        {occurrence.finding.ruleId}
                      </div>
                    </td>
                    <td className="mono">
                      {occurrence.file
                        ? `${occurrence.file}${occurrence.line ? `:${occurrence.line}` : ""}`
                        : (occurrence.url ?? "—")}
                    </td>
                    <td>{formatDate(occurrence.observedAt)}</td>
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
