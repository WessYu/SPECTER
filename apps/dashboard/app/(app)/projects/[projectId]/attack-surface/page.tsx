import Link from "next/link";
import { apiFetch } from "../../../../../lib/api";
import type { AttackSurfaceResponse, SurfaceRoute } from "../../../../../lib/types";
import { formatDate, shortId } from "../../../../../lib/format";
import { ProjectTabs } from "../../../../../components/project-tabs";

function routePath(route: SurfaceRoute): string {
  try {
    return new URL(route.url, "https://specter.invalid").pathname;
  } catch {
    return route.url;
  }
}
export default async function AttackSurfacePage({
  params,
}: {
  readonly params: Promise<{ readonly projectId: string }>;
}) {
  const { projectId } = await params;
  const data = await apiFetch<AttackSurfaceResponse>(
    `/api/v1/projects/${encodeURIComponent(projectId)}/attack-surface`,
  );
  const api = data.routes.filter((route) => routePath(route).startsWith("/api/"));
  const pages = data.routes.filter((route) => !routePath(route).startsWith("/api/"));
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Observed, not brute-forced</div>
          <h1>Attack surface</h1>
        </div>
        {data.observedAt ? (
          <div className="subtle">
            Observed {formatDate(data.observedAt)} ·{" "}
            <span className="mono">{data.currentScanId ? shortId(data.currentScanId) : "—"}</span>
          </div>
        ) : null}
      </div>
      <ProjectTabs projectId={projectId} />
      {!data.currentScanId ? (
        <section className="empty">
          <h2>No observed surface</h2>
          <p className="subtle">
            Run a remote scan with surface discovery. SPECTER will not fabricate routes or enumerate
            directories with aggressive wordlists.
          </p>
        </section>
      ) : (
        <>
          <SurfaceGroup title="Pages & observed routes" routes={pages} />
          <SurfaceGroup title="API" routes={api} />
          <section className="section">
            <div className="section-head">
              <h2>Domain trust</h2>
              <span className="eyebrow">Browser supply chain</span>
            </div>
            {data.domains.length === 0 ? (
              <div className="empty">
                <p className="subtle">No third-party domains observed.</p>
              </div>
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Domain</th>
                      <th>State</th>
                      <th>Classification</th>
                      <th>Resources</th>
                      <th>Page</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.domains.map((domain) => (
                      <tr key={`${domain.state}:${domain.domain}`}>
                        <td className="mono">{domain.domain}</td>
                        <td>
                          <span className={`state state-${domain.state}`}>{domain.state}</span>
                        </td>
                        <td>{domain.classification}</td>
                        <td>{domain.resourceTypes.join(", ") || "—"}</td>
                        <td className="mono">{domain.page ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      )}
    </>
  );
}
function SurfaceGroup({
  title,
  routes,
}: {
  readonly title: string;
  readonly routes: readonly SurfaceRoute[];
}) {
  return (
    <section className="section">
      <div className="section-head">
        <h2>{title}</h2>
        <span className="eyebrow">{routes.length} observed</span>
      </div>
      {routes.length === 0 ? (
        <div className="empty">
          <p className="subtle">No routes in this group.</p>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Method</th>
                <th>Route</th>
                <th>Status</th>
                <th>Content type</th>
                <th>CORS</th>
              </tr>
            </thead>
            <tbody>
              {routes.map((route, index) => (
                <tr key={`${route.method}:${route.url}:${index}`}>
                  <td className="mono">{route.method}</td>
                  <td className="mono">{route.url}</td>
                  <td className="mono">{route.status ?? "—"}</td>
                  <td>{route.contentType ?? "—"}</td>
                  <td className="mono">{route.cors ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
