import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

const PREFIX_BYTES = 5;
const SECRET_BYTES = 32;

export interface GeneratedApiKey { readonly value: string; readonly prefix: string; readonly hash: string; }

export function hashApiKey(value: string): string { return createHash("sha256").update(value).digest("hex"); }

export function generateApiKey(): GeneratedApiKey {
  const prefix = randomBytes(PREFIX_BYTES).toString("hex");
  const secret = randomBytes(SECRET_BYTES).toString("base64url");
  const value = `sp_live_${prefix}_${secret}`;
  return { value, prefix, hash: hashApiKey(value) };
}

export function parseApiKeyPrefix(value: string): string | undefined {
  const match = value.match(/^sp_live_([0-9a-f]{10})_[A-Za-z0-9_-]{30,}$/);
  return match?.[1];
}

export function constantTimeHashMatch(value: string, expectedHash: string): boolean {
  const actual = hashApiKey(value);
  if (actual.length !== expectedHash.length) return false;
  return timingSafeEqual(Buffer.from(actual), Buffer.from(expectedHash));
}
