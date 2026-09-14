import Link from "next/link";
import { apiFetch } from "../../../../../lib/api";
import type { FindingSummary } from "../../../../../lib/types";
import { formatDate } from "../../../../../lib/format";
import { Severity } from "../../../../../components/severity";
import { ProjectTabs } from "../../../../../components/project-tabs";

export default async function FindingsPage({
  params,
  searchParams,
}: {
  readonly params: Promise<{ readonly projectId: string }>;
  readonly searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { projectId } = await params;
  const q = await searchParams;
  const query = new URLSearchParams();
  for (const key of ["severity", "category", "source", "status"] as const) {
    const value = q[key];
    if (typeof value === "string" && value) query.set(key, value);
  }
  const data = await apiFetch<{ readonly findings: readonly FindingSummary[] }>(
    `/api/v1/projects/${encodeURIComponent(projectId)}/findings${query.size ? `?${query.toString()}` : ""}`,
  );
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Project findings</div>
          <h1>Findings</h1>
        </div>
      </div>
      <ProjectTabs projectId={projectId} />
      <form className="filter-bar" method="get">
        <select
          className="select"
          name="severity"
          defaultValue={typeof q.severity === "string" ? q.severity : ""}
        >
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        <select
          className="select"
          name="status"
          defaultValue={typeof q.status === "string" ? q.status : ""}
        >
          <option value="">All statuses</option>
          {["open", "resolved", "suppressed"].map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        <select
          className="select"
          name="source"
          defaultValue={typeof q.source === "string" ? q.source : ""}
        >
          <option value="">All sources</option>
          {["static", "build", "dependency", "remote", "runtime"].map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        <button className="button" type="submit">
          Apply
        </button>
        <Link className="button button-quiet" href={`/projects/${projectId}/findings`}>
          Clear
        </Link>
      </form>
      {data.findings.length === 0 ? (
        <section className="empty">
          <h2>No matching findings</h2>
          <p className="subtle">The persisted project findings do not match this filter.</p>
        </section>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th>Category</th>
                <th>Source</th>
                <th>Status</th>
                <th>Last detected</th>
              </tr>
            </thead>
            <tbody>
              {data.findings.map((f) => (
                <tr key={f.id}>
                  <td>
                    <Severity value={f.severity} />
                  </td>
                  <td>
                    <Link href={`/projects/${projectId}/findings/${f.id}`}>
                      <strong>{f.title}</strong>
                    </Link>
                    <div className="eyebrow" style={{ marginTop: 5 }}>
                      {f.ruleId}
                    </div>
                  </td>
                  <td>{f.category}</td>
                  <td className="mono">{f.source}</td>
                  <td>{f.status}</td>
                  <td>{formatDate(f.lastDetectedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
