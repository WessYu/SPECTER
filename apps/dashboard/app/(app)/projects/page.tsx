import Link from "next/link";
import { apiFetch } from "../../../lib/api";
import type { OverviewResponse } from "../../../lib/types";
import { createProject } from "../actions";
import { formatDate } from "../../../lib/format";

export default async function ProjectsPage() {
  const data = await apiFetch<OverviewResponse>("/api/v1/overview");
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Inventory</div>
          <h1>Projects</h1>
        </div>
      </div>
      <section className="panel" aria-labelledby="create-project">
        <h2 id="create-project">Add project</h2>
        <p className="subtle">
          Project records organize scans and enforce organization ownership. A scan must still be
          submitted by the CLI or CI.
        </p>
        <form action={createProject} className="form-row">
          <input
            className="input"
            name="name"
            required
            maxLength={120}
            placeholder="Project name"
          />
          <input
            className="input mono"
            name="slug"
            required
            maxLength={80}
            pattern="[a-z0-9]+(?:-[a-z0-9]+)*"
            placeholder="project-slug"
          />
          <button className="button" type="submit">
            Create
          </button>
        </form>
      </section>
      <section className="section">
        <div className="section-head">
          <h2>Tracked projects</h2>
          <span className="eyebrow">{data.projects.length}</span>
        </div>
        {data.projects.length === 0 ? (
          <div className="empty">
            <p className="subtle">No project records in this organization.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Domain</th>
                  <th>Score</th>
                  <th>Scans</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {data.projects.map((project) => (
                  <tr key={project.id}>
                    <td>
                      <Link href={`/projects/${project.id}`}>
                        <strong>{project.name}</strong>
                      </Link>
                    </td>
                    <td className="mono">{project.domains[0]?.hostname ?? "—"}</td>
                    <td className="mono">
                      {project.scans[0] ? Math.round(project.scans[0].score) : "—"}
                    </td>
                    <td className="mono">
                      {project.scans.length}
                      {project.scans.length === 2 ? "+" : ""}
                    </td>
                    <td>{formatDate(project.updatedAt)}</td>
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
