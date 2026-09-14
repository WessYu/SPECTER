"use client";
export default function ErrorPage({
  reset,
}: {
  readonly error: Error & { digest?: string };
  readonly reset: () => void;
}) {
  return (
    <section className="empty" role="alert">
      <div className="eyebrow">Request failure</div>
      <h1>Security data could not be loaded</h1>
      <p className="subtle">
        The dashboard did not substitute mock data. Check the API connection and try the request
        again.
      </p>
      <button className="button" onClick={reset}>
        Retry
      </button>
    </section>
  );
}
