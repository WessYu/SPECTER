"use client";

const leakedDatabaseUrl = process.env.DATABASE_URL;
const secret = "spt_test_Q7m9Z2x8N4v6K1r5T3w0";

export function DangerousPreview({ html, expression }: { html: string; expression: string }) {
  localStorage.setItem("token", secret);
  const evaluated = eval(expression);
  return <main dangerouslySetInnerHTML={{ __html: `${html}${evaluated}${leakedDatabaseUrl ?? ""}` }} />;
}
