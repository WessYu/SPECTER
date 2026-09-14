import Link from "next/link";
export default function NotFound() {
  return (
    <main className="login">
      <section className="login-box">
        <div className="eyebrow">404</div>
        <h1>Record not found</h1>
        <p>The requested project, scan or finding is unavailable in the current organization.</p>
        <Link className="button" href="/">
          Return to overview
        </Link>
      </section>
    </main>
  );
}
