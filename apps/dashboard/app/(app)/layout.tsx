import type { ReactNode } from "react";
import { redirect } from "next/navigation";
import { apiFetch, ApiError } from "../../lib/api";
import type { SessionMe } from "../../lib/types";
import { Sidebar } from "../../components/sidebar";
import { logout } from "./actions";

export default async function AppLayout({ children }: { readonly children: ReactNode }) {
  let me: SessionMe;
  try { me = await apiFetch<SessionMe>("/api/v1/auth/me"); }
  catch (error: unknown) { if (error instanceof ApiError && error.status === 401) redirect("/login"); throw error; }
  if (me.kind !== "session") redirect("/login");
  return <div className="shell">
    <Sidebar />
    <div className="content">
      <header className="topbar">
        <div className="topbar-org"><span className="eyebrow">Organization</span><span>{me.organization.name}</span><span className="mono">/{me.role}</span></div>
        <div className="topbar-org">
          {me.user.avatarUrl ? <img className="avatar" src={me.user.avatarUrl} alt="" /> : <span className="avatar" aria-hidden="true" />}
          <span>{me.user.name ?? "GitHub user"}</span>
          <form action={logout}><button className="button button-quiet" type="submit">Sign out</button></form>
        </div>
      </header>
      <main className="main">{children}</main>
    </div>
  </div>;
}
