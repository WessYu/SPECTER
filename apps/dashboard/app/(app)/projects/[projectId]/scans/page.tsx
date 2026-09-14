import Link from "next/link";
import { notFound } from "next/navigation";
import { apiFetch, ApiError } from "../../../../../lib/api";
import type { ProjectOverviewResponse, ScanSummary } from "../../../../../lib/types";
import { formatDate, formatDuration, shortId } from "../../../../../lib/format";
import { ProjectTabs } from "../../../../../components/project-tabs";

export default async function ScansPage({
  params,
}: {
  readonly params: Promise<{ readonly projectId: string }>;
}) {
  const { projectId } = await params;
  let overview: ProjectOverviewResponse;
  try {
    overview = await apiFetch<ProjectOverviewResponse>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/overview`,
    );
  } catch (error: unknown) {
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }
  const scans = await apiFetch<readonly ScanSummary[]>(
    `/api/v1/projects/${encodeURIComponent(projectId)}/scans`,
  );
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">{overview.project.name}</div>
          <h1>Scans</h1>
        </div>
      </div>
      <ProjectTabs projectId={projectId} />
      {scans.length === 0 ? (
        <section className="empty">
          <h2>No scans yet</h2>
          <p className="subtle">Completed scans submitted by the CLI or CI will appear here.</p>
        </section>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Target</th>
                <th>Status</th>
                <th>Score</th>
                <th>Findings</th>
                <th>Duration</th>
                <th>Completed</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td className="mono">
                    <Link href={`/projects/${projectId}/scans/${scan.id}`}>{shortId(scan.id)}</Link>
                  </td>
                  <td className="mono">{scan.targetValue}</td>
                  <td>{scan.status}</td>
                  <td className="mono">{Math.round(scan.score)}/100</td>
                  <td className="mono">
                    {scan.summaryJson
                      ? Object.values(scan.summaryJson).reduce(
                          (sum, value) => sum + Number(value),
                          0,
                        )
                      : "—"}
                  </td>
                  <td className="mono">{formatDuration(scan.durationMs)}</td>
                  <td>{formatDate(scan.completedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
