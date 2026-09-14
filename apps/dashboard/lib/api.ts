import "server-only";
import { cookies } from "next/headers";

export class ApiError extends Error {
  constructor(readonly status: number, readonly payload: unknown) {
    super(`SPECTER API request failed (${status}).`);
    this.name = "ApiError";
  }
}

function apiBase(): string {
  const value = process.env.SPECTER_API_URL?.trim() || process.env.NEXT_PUBLIC_SPECTER_API_URL?.trim();
  if (!value) throw new Error("SPECTER_API_URL is not configured.");
  return value.replace(/\/$/, "");
}

async function sessionCookie(): Promise<string> {
  return (await cookies()).toString();
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const cookie = await sessionCookie();
  if (cookie) headers.set("cookie", cookie);
  headers.set("accept", "application/json");
  const response = await fetch(`${apiBase()}${path}`, { ...init, headers, cache: "no-store", signal: AbortSignal.timeout(12_000) });
  if (!response.ok) {
    let payload: unknown;
    try { payload = await response.json(); } catch { payload = { error: "invalid_api_response" }; }
    throw new ApiError(response.status, payload);
  }
  if (response.status === 204) return undefined as T;
  return await response.json() as T;
}

export async function apiJson<T>(path: string, method: "POST" | "PUT" | "PATCH", body: unknown): Promise<T> {
  return apiFetch<T>(path, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
}
