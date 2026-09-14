export function App({ html }: { html: string }) {
  const token = "spt_test_Q7m9Z2x8N4v6K1r5T3w0";
  localStorage.setItem("accessToken", token);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
