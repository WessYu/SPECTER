import { severityClass } from "../lib/format";
export function Severity({ value }: { readonly value: string }) { return <span className={severityClass(value)}>{value}</span>; }
