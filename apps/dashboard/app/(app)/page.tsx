import Link from "next/link";
import { apiFetch } from "../../lib/api";
import type { OverviewResponse } from "../../lib/types";
import { formatDate, scoreDelta } from "../../lib/format";

export default async function OverviewPage() {
  const data = await apiFetch<OverviewResponse>("/api/v1/overview");
  return <>
    <div className="page-head"><div><div className="eyebrow">Portfolio security state</div><h1>Overview</h1></div><Link className="button" href="/projects">Projects</Link></div>
    {data.projects.length === 0 ? <section className="empty"><h2>No projects yet</h2><p className="subtle">Create a project, run a real SPECTER scan, then this view will reflect persisted security state.</p><Link className="button" href="/projects">Create project</Link></section> :
      <section className="section"><div className="section-head"><h2>Projects</h2><span className="eyebrow">{data.projects.length} tracked</span></div><div className="table-wrap"><table><thead><tr><th>Project</th><th>Target</th><th>Current</th><th>Regression</th><th>High / critical</th><th>Last scan</th></tr></thead><tbody>
        {data.projects.map((project) => { const current=project.scans[0]; const previous=project.scans[1]; const delta=scoreDelta(current?.score, previous?.score); return <tr key={project.id}>
          <td><Link href={`/projects/${project.id}`}><strong>{project.name}</strong></Link><div className="eyebrow" style={{marginTop:5}}>{project.slug}</div></td>
          <td className="mono">{project.domains[0]?.hostname ?? current?.targetValue ?? "—"}</td>
          <td className="mono">{current ? `${Math.round(current.score)}/100` : "Not scanned"}</td>
          <td className={`mono ${delta.className}`}>{delta.text}</td>
          <td className="mono">{project.findings.length}</td>
          <td>{current ? formatDate(current.completedAt) : formatDate(project.updatedAt)}</td>
        </tr>; })}
      </tbody></table></div></section>}
  </>;
}
