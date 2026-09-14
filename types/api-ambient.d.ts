declare module "fastify" {
  export interface FastifyRequest<T = unknown> {
    readonly params: T extends { Params: infer P } ? P : Record<string, string>;
    readonly body: T extends { Body: infer B } ? B : unknown;
    readonly query: T extends { Querystring: infer Q } ? Q : Record<string, string | undefined>;
    readonly headers: Record<string, string | string[] | undefined>;
    readonly id: string;
    readonly url: string;
    readonly ip: string;
  }
  export interface FastifyReply {
    code(statusCode: number): FastifyReply;
    send(payload?: unknown): unknown;
    header(name: string, value: string | readonly string[]): FastifyReply;
  }
  export interface FastifyInstance {
    register(plugin: unknown, options?: unknown): Promise<void>;
    addHook(
      name: string,
      hook: (
        request: FastifyRequest,
        reply: FastifyReply,
        payload?: unknown,
      ) => Promise<unknown> | unknown,
    ): void;
    decorateRequest(name: string, value: unknown): void;
    get<T = unknown>(
      path: string,
      options: unknown,
      handler: (request: FastifyRequest<T>, reply: FastifyReply) => Promise<unknown> | unknown,
    ): void;
    post<T = unknown>(
      path: string,
      options: unknown,
      handler: (request: FastifyRequest<T>, reply: FastifyReply) => Promise<unknown> | unknown,
    ): void;
    listen(options: { port: number; host: string }): Promise<string>;
    close(): Promise<void>;
    log: {
      info(value: unknown, message?: string): void;
      error(value: unknown, message?: string): void;
    };
  }
  export default function fastify(options?: unknown): FastifyInstance;
}
declare module "@fastify/rate-limit" {
  const plugin: unknown;
  export default plugin;
}
declare module "@prisma/client" {
  export class PrismaClient {
    user: {
      upsert(args: unknown): Promise<unknown>;
      findUnique(args: unknown): Promise<unknown>;
      findFirst(args: unknown): Promise<unknown>;
    };
    organization: {
      create(args: unknown): Promise<unknown>;
      findFirst(args: unknown): Promise<unknown>;
      findMany(args: unknown): Promise<unknown[]>;
    };
    organizationMember: {
      create(args: unknown): Promise<unknown>;
      findFirst(args: unknown): Promise<unknown>;
      findMany(args: unknown): Promise<unknown[]>;
    };
    session: {
      create(args: unknown): Promise<unknown>;
      findUnique(args: unknown): Promise<unknown>;
      update(args: unknown): Promise<unknown>;
      updateMany(args: unknown): Promise<{ count: number }>;
    };
    project: {
      findFirst(args: unknown): Promise<unknown>;
      findMany(args: unknown): Promise<unknown[]>;
      create(args: unknown): Promise<unknown>;
    };
    scan: {
      create(args: unknown): Promise<unknown>;
      findFirst(args: unknown): Promise<unknown>;
      findMany(args: unknown): Promise<unknown[]>;
    };
    finding: {
      upsert(args: unknown): Promise<unknown>;
      findFirst(args: unknown): Promise<unknown>;
      findMany(args: unknown): Promise<unknown[]>;
      updateMany(args: unknown): Promise<{ count: number }>;
    };
    findingOccurrence: { upsert(args: unknown): Promise<unknown> };
    suppression: {
      create(args: unknown): Promise<unknown>;
      findMany(args: unknown): Promise<unknown[]>;
    };
    domain: {
      findFirst(args: unknown): Promise<unknown>;
      findMany(args: unknown): Promise<unknown[]>;
      create(args: unknown): Promise<unknown>;
      update(args: unknown): Promise<unknown>;
    };
    domainVerification: {
      create(args: unknown): Promise<unknown>;
      findFirst(args: unknown): Promise<unknown>;
      update(args: unknown): Promise<unknown>;
    };
    externalDomain: {
      findMany(args: unknown): Promise<unknown[]>;
      upsert(args: unknown): Promise<unknown>;
    };
    route: { findMany(args: unknown): Promise<unknown[]>; upsert(args: unknown): Promise<unknown> };
    apiKey: {
      findUnique(args: unknown): Promise<unknown>;
      findMany(args: unknown): Promise<unknown[]>;
      create(args: unknown): Promise<unknown>;
      update(args: unknown): Promise<unknown>;
      updateMany(args: unknown): Promise<{ count: number }>;
    };
    $transaction<T>(callback: (client: PrismaClient) => Promise<T>): Promise<T>;
    $disconnect(): Promise<void>;
  }
}
