import Link from "next/link";
export function ProjectTabs({ projectId }: { readonly projectId: string }) {
  const base = `/projects/${projectId}`;
  return (
    <nav className="project-tabs" aria-label="Project navigation">
      <Link href={base}>Overview</Link>
      <Link href={`${base}/scans`}>Scans</Link>
      <Link href={`${base}/findings`}>Findings</Link>
      <Link href={`${base}/history`}>History</Link>
      <Link href={`${base}/attack-surface`}>Attack surface</Link>
      <Link href={`${base}/domains`}>Domains</Link>
    </nav>
  );
}
