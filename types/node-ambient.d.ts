declare module "node:crypto" {
  export function createHash(algorithm: string): { update(data: string): { digest(encoding: "hex"): string } };
  export function randomUUID(): string;
}
declare module "node:fs/promises" {
  export interface Dirent { name: string; isDirectory(): boolean; isFile(): boolean; }
  export function readdir(path: string, options: { withFileTypes: true }): Promise<Dirent[]>;
  export function readFile(path: string, encoding: "utf8"): Promise<string>;
  export function stat(path: string): Promise<{ size: number; isFile(): boolean; isDirectory(): boolean }>;
  export function access(path: string): Promise<void>;
  export function mkdir(path: string, options?: { recursive?: boolean }): Promise<string | undefined>;
  export function writeFile(path: string, data: string, encoding?: "utf8"): Promise<void>;
}
declare module "node:path" {
  const path: {
    join(...parts: string[]): string;
    resolve(...parts: string[]): string;
    relative(from: string, to: string): string;
    extname(path: string): string;
    basename(path: string): string;
    dirname(path: string): string;
    sep: string;
  };
  export default path;
}
