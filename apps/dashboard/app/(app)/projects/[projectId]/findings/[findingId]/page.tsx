import { notFound } from "next/navigation";
import { apiFetch, ApiError } from "../../../../../../lib/api";
import type { FindingSummary } from "../../../../../../lib/types";
import { formatDate } from "../../../../../../lib/format";
import { Severity } from "../../../../../../components/severity";
import { ProjectTabs } from "../../../../../../components/project-tabs";

function evidence(value: unknown): string {
  if (value === undefined || value === null) return "No evidence persisted.";
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return "Evidence could not be rendered.";
  }
}
export default async function FindingDetailPage({
  params,
}: {
  readonly params: Promise<{ readonly projectId: string; readonly findingId: string }>;
}) {
  const { projectId, findingId } = await params;
  let finding: FindingSummary;
  try {
    finding = await apiFetch<FindingSummary>(`/api/v1/findings/${encodeURIComponent(findingId)}`);
  } catch (error: unknown) {
    if (error instanceof ApiError && error.status === 404) notFound();
    throw error;
  }
  const latest = finding.occurrences?.[0];
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Finding / {finding.ruleId}</div>
          <h1>{finding.title}</h1>
        </div>
        <Severity value={finding.severity} />
      </div>
      <ProjectTabs projectId={projectId} />
      <div className="detail-grid">
        <section>
          <h2>Assessment</h2>
          <p className="subtle" style={{ fontSize: 14 }}>
            {finding.description ?? "No description persisted."}
          </p>
          <section className="section">
            <h2>Evidence</h2>
            <p className="subtle">Evidence is displayed only after server-side redaction.</p>
            <pre className="evidence">{evidence(latest?.evidenceJson)}</pre>
          </section>
          <section className="section">
            <h2>Remediation</h2>
            <p className="subtle">
              {finding.remediation ?? "No remediation guidance persisted for this rule."}
            </p>
          </section>
        </section>
        <aside>
          <dl className="detail-list">
            <dt>Severity</dt>
            <dd>
              <Severity value={finding.severity} />
            </dd>
            <dt>Confidence</dt>
            <dd>{finding.confidence}</dd>
            <dt>Category</dt>
            <dd>{finding.category}</dd>
            <dt>Source</dt>
            <dd className="mono">{finding.source}</dd>
            <dt>Status</dt>
            <dd>{finding.status}</dd>
            <dt>First detected</dt>
            <dd>{formatDate(finding.firstDetectedAt)}</dd>
            <dt>Last detected</dt>
            <dd>{formatDate(finding.lastDetectedAt)}</dd>
            <dt>Location</dt>
            <dd className="mono">
              {latest?.file
                ? `${latest.file}${latest.line ? `:${latest.line}` : ""}`
                : (latest?.url ?? "—")}
            </dd>
            <dt>Fingerprint</dt>
            <dd className="mono">{finding.fingerprint ?? "—"}</dd>
          </dl>
        </aside>
      </div>
    </>
  );
}
