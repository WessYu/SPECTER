import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

const SOURCE_EXTENSIONS = new Set([".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]);
const DEFAULT_IGNORES = new Set([
  "node_modules",
  ".git",
  ".next",
  ".turbo",
  "coverage",
  "dist",
  "build",
  ".cache",
]);

export interface SourceFile {
  readonly path: string;
  readonly absolutePath: string;
  readonly content: string;
  readonly size: number;
}

export interface WalkOptions {
  readonly maxFileBytes?: number;
  readonly ignores?: readonly string[];
  readonly includeBuildDirectories?: boolean;
}

export interface WalkResult {
  readonly files: readonly SourceFile[];
  readonly skippedLargeFiles: readonly string[];
  readonly unreadableFiles: readonly string[];
}

export async function walkSourceFiles(
  root: string,
  options: WalkOptions = {},
): Promise<WalkResult> {
  const absoluteRoot = path.resolve(root);
  const maxFileBytes = options.maxFileBytes ?? 1_000_000;
  const ignores = new Set(DEFAULT_IGNORES);
  if (options.includeBuildDirectories) {
    ignores.delete("dist");
    ignores.delete("build");
    ignores.delete(".next");
  }
  for (const entry of options.ignores ?? []) ignores.add(entry);

  const files: SourceFile[] = [];
  const skippedLargeFiles: string[] = [];
  const unreadableFiles: string[] = [];

  async function visit(directory: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      unreadableFiles.push(path.relative(absoluteRoot, directory) || ".");
      return;
    }

    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (ignores.has(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        await visit(absolute);
        continue;
      }
      if (!entry.isFile() || !SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase()))
        continue;

      try {
        const metadata = await stat(absolute);
        const relative = path.relative(absoluteRoot, absolute).replaceAll(path.sep, "/");
        if (metadata.size > maxFileBytes) {
          skippedLargeFiles.push(relative);
          continue;
        }
        files.push({
          path: relative,
          absolutePath: absolute,
          content: await readFile(absolute, "utf8"),
          size: metadata.size,
        });
      } catch {
        unreadableFiles.push(path.relative(absoluteRoot, absolute).replaceAll(path.sep, "/"));
      }
    }
  }

  await visit(absoluteRoot);
  return { files, skippedLargeFiles, unreadableFiles };
}
