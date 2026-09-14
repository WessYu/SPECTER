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
declare const process: {
  argv: string[];
  cwd(): string;
  exitCode?: number;
  version: string;
  env: Record<string, string | undefined>;
  stdout: { write(value: string): boolean };
  stderr: { write(value: string): boolean };
  on(event: "SIGINT", listener: () => void): void;
};
declare module "node:process" { const process: typeof globalThis.process; export default process; }
declare module "node:dns/promises" {
  export function lookup(hostname: string, options: { all: true; verbatim: true }): Promise<Array<{ address: string; family: 4 | 6 }>>;
}
declare module "node:net" {
  export function isIP(input: string): 0 | 4 | 6;
}
declare module "node:http" {
  export interface IncomingHttpHeaders { [key: string]: string | string[] | undefined; location?: string; }
  export interface IncomingMessage {
    statusCode?: number;
    headers: IncomingHttpHeaders;
    on(event: "data", listener: (chunk: Uint8Array) => void): void;
    on(event: "end", listener: () => void): void;
    on(event: "error", listener: (error: Error) => void): void;
    destroy(error?: Error): void;
  }
  export interface ClientRequest {
    end(): void;
    destroy(error?: Error): void;
    on(event: "error", listener: (error: Error) => void): void;
    setTimeout(ms: number, listener: () => void): void;
  }
  export interface RequestOptions {
    protocol?: string; hostname?: string; port?: string | number; path?: string; method?: string;
    headers?: Record<string, string>; servername?: string;
    lookup?: (hostname: string, options: unknown, callback: (error: Error | null, address: string, family: number) => void) => void;
  }
  export function request(options: RequestOptions, callback: (response: IncomingMessage) => void): ClientRequest;
}
declare module "node:https" {
  import type { RequestOptions, ClientRequest, IncomingMessage } from "node:http";
  export function request(options: RequestOptions, callback: (response: IncomingMessage) => void): ClientRequest;
}
declare const Buffer: {
  concat(chunks: readonly Uint8Array[]): { toString(encoding: "utf8"): string; readonly byteLength: number };
  from(value: string): Uint8Array;
};
declare module "node:tls" {
  export interface PeerCertificate { subject?: { CN?: string }; issuer?: { CN?: string }; valid_from?: string; valid_to?: string; fingerprint256?: string; }
  export interface TLSSocket {
    authorized: boolean;
    authorizationError?: Error;
    getPeerCertificate(detailed?: boolean): PeerCertificate;
    getProtocol(): string | null;
    end(): void;
    destroy(error?: Error): void;
    setTimeout(ms: number, listener: () => void): void;
    once(event: "secureConnect", listener: () => void): void;
    once(event: "error", listener: (error: Error) => void): void;
  }
  export interface ConnectionOptions { host: string; port: number; servername: string; rejectUnauthorized: boolean; }
  export function connect(options: ConnectionOptions): TLSSocket;
  export function checkServerIdentity(hostname: string, cert: PeerCertificate): Error | undefined;
}
declare module "node:child_process" {
  export interface ChildProcess {
    stdout?: { on(event: "data", listener: (chunk: Uint8Array) => void): void };
    stderr?: { on(event: "data", listener: (chunk: Uint8Array) => void): void };
    on(event: "error", listener: (error: Error) => void): void;
    on(event: "close", listener: (code: number | null, signal: string | null) => void): void;
    kill(signal?: string): boolean;
  }
  export function spawn(command: string, args?: readonly string[], options?: {
    cwd?: string; shell?: boolean; env?: Record<string, string | undefined>; stdio?: readonly string[];
  }): ChildProcess;
}
declare function setTimeout(listener: () => void, ms: number): unknown;
declare function clearTimeout(handle: unknown): void;
declare module "node:crypto" {
  export function createHash(algorithm: string): { update(data: string): { digest(encoding: "hex"): string } };
  export function randomUUID(): string;
  export function randomBytes(size: number): { toString(encoding: "hex" | "base64url"): string };
  export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean;
}
declare module "node:dns/promises" {
  export function lookup(hostname: string, options: { all: true; verbatim: true }): Promise<Array<{ address: string; family: 4 | 6 }>>;
  export function resolveTxt(hostname: string): Promise<string[][]>;
}
