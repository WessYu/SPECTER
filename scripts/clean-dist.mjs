import { rm } from "node:fs/promises";
import path from "node:path";

const directory = path.resolve(process.cwd(), process.argv[2] ?? "dist");
await rm(directory, { recursive: true, force: true });
