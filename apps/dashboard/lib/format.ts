export function formatDate(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "—"
    : new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(date);
}
export function formatDuration(ms: number): string {
  if (!Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`;
}
export function scoreDelta(
  current?: number,
  previous?: number,
): { readonly text: string; readonly className: string } {
  if (current === undefined || previous === undefined)
    return { text: "No baseline", className: "" };
  const delta = current - previous;
  if (delta === 0) return { text: "No change", className: "" };
  return {
    text: `${delta > 0 ? "+" : ""}${delta}`,
    className: delta < 0 ? "delta-negative" : "delta-positive",
  };
}
export function severityClass(value: string): string {
  return `severity severity-${value.toLowerCase()}`;
}
export function shortId(value: string): string {
  return value.length <= 12 ? value : `${value.slice(0, 8)}…`;
}
