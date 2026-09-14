import { existsSync, readFileSync } from "node:fs";

// A source checkout has no dist yet; installing workspace dependencies must work
// before the first build. Published packages include the compiled renderer.
const renderer = new URL("../dist/welcome.js", import.meta.url);
if (!process.env.CI && existsSync(renderer)) {
  const { renderWelcome, welcomeColor } = await import(renderer.href);
  const { version } = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  );
  process.stdout.write(
    renderWelcome(version, process.stdout.columns ?? 120, welcomeColor()),
  );
}
