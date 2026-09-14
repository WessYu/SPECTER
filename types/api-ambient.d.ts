declare module "fastify" {
  export interface FastifyRequest<T = unknown> { readonly params: T extends { Params: infer P } ? P : Record<string, string>; readonly body: T extends { Body: infer B } ? B : unknown; readonly headers: Record<string, string | string[] | undefined>; readonly id: string; }
  export interface FastifyReply { code(statusCode: number): FastifyReply; send(payload?: unknown): unknown; header(name: string, value: string): FastifyReply; }
  export interface FastifyInstance {
    register(plugin: unknown, options?: unknown): Promise<void>;
    addHook(name: string, hook: (request: FastifyRequest, reply: FastifyReply) => Promise<void> | void): void;
    decorateRequest(name: string, value: unknown): void;
    get<T = unknown>(path: string, options: unknown, handler: (request: FastifyRequest<T>, reply: FastifyReply) => Promise<unknown> | unknown): void;
    post<T = unknown>(path: string, options: unknown, handler: (request: FastifyRequest<T>, reply: FastifyReply) => Promise<unknown> | unknown): void;
    listen(options: { port: number; host: string }): Promise<string>;
    close(): Promise<void>;
    log: { info(value: unknown, message?: string): void; error(value: unknown, message?: string): void; };
  }
  export default function fastify(options?: unknown): FastifyInstance;
}
declare module "@fastify/rate-limit" { const plugin: unknown; export default plugin; }
declare module "@prisma/client" {
  export class PrismaClient {
    project: { findFirst(args: unknown): Promise<unknown>; findMany(args: unknown): Promise<unknown[]>; create(args: unknown): Promise<unknown> };
    scan: { create(args: unknown): Promise<unknown>; findFirst(args: unknown): Promise<unknown>; findMany(args: unknown): Promise<unknown[]> };
    finding: { upsert(args: unknown): Promise<unknown>; findFirst(args: unknown): Promise<unknown> };
    findingOccurrence: { upsert(args: unknown): Promise<unknown> };
    suppression: { create(args: unknown): Promise<unknown> };
    domain: { findFirst(args: unknown): Promise<unknown>; update(args: unknown): Promise<unknown> };
    domainVerification: { create(args: unknown): Promise<unknown>; findFirst(args: unknown): Promise<unknown>; update(args: unknown): Promise<unknown> };
    apiKey: { findUnique(args: unknown): Promise<unknown>; update(args: unknown): Promise<unknown> };
    $transaction<T>(callback: (client: PrismaClient) => Promise<T>): Promise<T>;
    $disconnect(): Promise<void>;
  }
}
