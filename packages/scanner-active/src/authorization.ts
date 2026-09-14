import { randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { safeGet } from "@specter/scanner-web";
import type { ActiveAuthorization } from "@specter/types";

interface StoredAuthorization {
  readonly hostname: string;
  readonly origin: string;
  readonly token: string;
  readonly tokenExpiresAt: string;
  readonly verifiedAt?: string;
  readonly authorizationExpiresAt?: string;
}

interface AuthorizationStore {
  readonly version: 1;
  readonly records: Readonly<Record<string, StoredAuthorization>>;
}

const EMPTY_STORE: AuthorizationStore = { version: 1, records: {} };
const VERIFICATION_TTL_MS = 24 * 60 * 60 * 1_000;
const AUTHORIZATION_TTL_MS = 30 * 24 * 60 * 60 * 1_000;

export class ActiveAuthorizationError extends Error {
  constructor(message = "Active scanning requires verified ownership or explicit authorization.") {
    super(message);
    this.name = "ActiveAuthorizationError";
  }
}

export function defaultAuthorizationStore(cwd: string): string {
  return path.join(path.resolve(cwd), ".specter", "active-authorizations.json");
}

function normalized(input: string): URL {
  const url = new URL(input);
  if (url.protocol !== "http:" && url.protocol !== "https:")
    throw new ActiveAuthorizationError("Only HTTP and HTTPS targets can be authorized.");
  if (url.username || url.password)
    throw new ActiveAuthorizationError("Credentials embedded in target URLs are not allowed.");
  url.hash = "";
  return url;
}

function hostnameOf(url: URL): string {
  return url.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

export function isLocalActiveTarget(input: string): boolean {
  const hostname = hostnameOf(normalized(input));
  return hostname === "localhost" || hostname === "::1" || /^127(?:\.\d{1,3}){3}$/.test(hostname);
}

async function readStore(file: string): Promise<AuthorizationStore> {
  try {
    const parsed = JSON.parse(await readFile(file, "utf8")) as Partial<AuthorizationStore>;
    if (parsed.version !== 1 || !parsed.records || typeof parsed.records !== "object")
      return EMPTY_STORE;
    return { version: 1, records: parsed.records };
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return EMPTY_STORE;
    throw error;
  }
}

async function writeStore(file: string, store: AuthorizationStore): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, `${JSON.stringify(store, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

export async function generateDomainAuthorization(
  target: string,
  storePath: string,
  now = Date.now(),
): Promise<{
  readonly authorization: ActiveAuthorization;
  readonly token: string;
  readonly content: string;
  readonly path: string;
}> {
  const url = normalized(target);
  const hostname = hostnameOf(url);
  if (isLocalActiveTarget(url.toString()))
    return {
      authorization: { status: "local", mode: "local", hostname },
      token: "",
      content: "",
      path: "/.well-known/specter-verification.txt",
    };

  const token = randomBytes(24).toString("hex");
  const record: StoredAuthorization = {
    hostname,
    origin: url.origin,
    token,
    tokenExpiresAt: new Date(now + VERIFICATION_TTL_MS).toISOString(),
  };
  const store = await readStore(storePath);
  await writeStore(storePath, {
    version: 1,
    records: { ...store.records, [hostname]: record },
  });

  return {
    authorization: {
      status: "unverified",
      mode: "domain-verification",
      hostname,
      expiresAt: record.tokenExpiresAt,
    },
    token,
    content: `specter-verification=${token}`,
    path: "/.well-known/specter-verification.txt",
  };
}

export async function verifyDomainAuthorization(
  target: string,
  storePath: string,
  now = Date.now(),
): Promise<ActiveAuthorization> {
  const url = normalized(target);
  const hostname = hostnameOf(url);
  const store = await readStore(storePath);
  const record = store.records[hostname];
  if (!record)
    throw new ActiveAuthorizationError("No SPECTER verification token exists for this hostname.");
  if (Date.parse(record.tokenExpiresAt) <= now)
    return {
      status: "expired",
      mode: "domain-verification",
      hostname,
      expiresAt: record.tokenExpiresAt,
    };

  const verificationUrl = new URL("/.well-known/specter-verification.txt", record.origin);
  const response = await safeGet(verificationUrl.toString(), {
    followRedirects: false,
    maxRedirects: 0,
    requireSameHostname: true,
    requestTimeoutMs: 5_000,
    totalTimeoutMs: 8_000,
    maxResponseBytes: 8_192,
  });

  if (
    response.status !== 200 ||
    hostnameOf(new URL(response.url)) !== hostname ||
    response.body.trim() !== `specter-verification=${record.token}`
  )
    throw new ActiveAuthorizationError(
      "Domain verification failed. The verification file did not match.",
    );

  const verifiedAt = new Date(now).toISOString();
  const authorizationExpiresAt = new Date(now + AUTHORIZATION_TTL_MS).toISOString();
  const updated: StoredAuthorization = { ...record, verifiedAt, authorizationExpiresAt };
  await writeStore(storePath, {
    version: 1,
    records: { ...store.records, [hostname]: updated },
  });

  return {
    status: "verified",
    mode: "domain-verification",
    hostname,
    verifiedAt,
    expiresAt: authorizationExpiresAt,
  };
}

export async function resolveActiveAuthorization(
  target: string,
  storePath: string,
  previewHosts: readonly string[],
  now = Date.now(),
): Promise<ActiveAuthorization> {
  const url = normalized(target);
  const hostname = hostnameOf(url);

  if (isLocalActiveTarget(url.toString()))
    return { status: "local", mode: "local", hostname };

  if (previewHosts.some((item) => item.toLowerCase().replace(/\.$/, "") === hostname))
    return { status: "preview", mode: "preview", hostname };

  const store = await readStore(storePath);
  const record = store.records[hostname];
  if (!record || !record.verifiedAt || !record.authorizationExpiresAt)
    throw new ActiveAuthorizationError();

  if (Date.parse(record.authorizationExpiresAt) <= now)
    throw new ActiveAuthorizationError(
      "Active scanning authorization has expired. Verify the hostname again.",
    );

  return {
    status: "verified",
    mode: "domain-verification",
    hostname,
    verifiedAt: record.verifiedAt,
    expiresAt: record.authorizationExpiresAt,
  };
}
