export default async function LoginPage({
  searchParams,
}: {
  readonly searchParams: Promise<{ readonly error?: string }>;
}) {
  const params = await searchParams;
  const base = (process.env.NEXT_PUBLIC_SPECTER_API_URL ?? "http://127.0.0.1:3001").replace(
    /\/$/,
    "",
  );
  return (
    <main className="login">
      <section className="login-box" aria-labelledby="login-title">
        <div className="eyebrow">Application security from source to production</div>
        <h1 id="login-title">SPECTER</h1>
        <p>
          Inspect security state, regression history and observed attack surface without turning the
          scanner into an exploitation tool.
        </p>
        {params.error ? (
          <p role="alert" className="delta-negative">
            Authentication was not completed. Try GitHub again.
          </p>
        ) : null}
        <a className="button" href={`${base}/api/v1/auth/github/start`}>
          Continue with GitHub
        </a>
      </section>
    </main>
  );
}
