import Link from "next/link";
import { Brand } from "./brand";

const items = [
  ["/", "01", "Overview"],
  ["/projects", "02", "Projects"],
  ["/settings", "03", "Settings"],
] as const;

export function Sidebar() {
  return <aside className="sidebar">
    <Brand />
    <nav className="nav" aria-label="Primary navigation">
      {items.map(([href, code, label]) => <Link key={href} href={href}><b className="mono">{code}</b><span>{label}</span></Link>)}
    </nav>
    <div className="sidebar-foot"><div className="eyebrow">Security state</div><div style={{marginTop: 8}}>Source → Production</div></div>
  </aside>;
}
