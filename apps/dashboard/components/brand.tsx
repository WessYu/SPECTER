import Link from "next/link";
export function Brand() {
  return (
    <Link className="brand" href="/">
      <i className="brand-mark" aria-hidden="true" />
      <span>SPECTER</span>
    </Link>
  );
}
