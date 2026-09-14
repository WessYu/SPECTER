import { apiFetch, ApiError } from "../../../lib/api";
import type { ApiKeySummary } from "../../../lib/types";
import { formatDate } from "../../../lib/format";
import { ApiKeyForm } from "../../../components/api-key-form";
import { revokeApiKey } from "../actions";

export default async function SettingsPage() {
  let keys: readonly ApiKeySummary[] = [];
  let forbidden = false;
  try {
    keys = await apiFetch<readonly ApiKeySummary[]>("/api/v1/api-keys");
  } catch (error: unknown) {
    if (error instanceof ApiError && error.status === 403) forbidden = true;
    else throw error;
  }
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Organization security</div>
          <h1>Settings</h1>
        </div>
      </div>
      <section className="panel">
        <h2>CI API keys</h2>
        <p className="subtle">
          Keys are stored as hashes. The full credential is returned only at creation and is never
          listed again.
        </p>
        {forbidden ? (
          <p className="subtle">Owner or admin role is required to manage API keys.</p>
        ) : (
          <ApiKeyForm />
        )}
      </section>
      {!forbidden ? (
        <section className="section">
          <div className="section-head">
            <h2>Issued keys</h2>
            <span className="eyebrow">{keys.length}</span>
          </div>
          {keys.length === 0 ? (
            <div className="empty">
              <p className="subtle">No API keys have been issued.</p>
            </div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Prefix</th>
                    <th>Created</th>
                    <th>Last used</th>
                    <th>Status</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {keys.map((key) => (
                    <tr key={key.id}>
                      <td>{key.name}</td>
                      <td className="mono">sp_live_{key.prefix}_…</td>
                      <td>{formatDate(key.createdAt)}</td>
                      <td>{key.lastUsedAt ? formatDate(key.lastUsedAt) : "Never"}</td>
                      <td>{key.revokedAt ? "Revoked" : "Active"}</td>
                      <td className="right">
                        {!key.revokedAt ? (
                          <form action={revokeApiKey}>
                            <input type="hidden" name="id" value={key.id} />
                            <button className="button button-danger" type="submit">
                              Revoke
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
      ) : null}
    </>
  );
}
