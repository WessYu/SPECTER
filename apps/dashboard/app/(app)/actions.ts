"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { apiFetch, apiJson, ApiError } from "../../lib/api";

function text(formData: FormData, key: string): string { const value = formData.get(key); return typeof value === "string" ? value.trim() : ""; }

export async function createProject(formData: FormData): Promise<void> {
  const name = text(formData, "name");
  const slug = text(formData, "slug");
  if (!name || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) return;
  const project = await apiJson<{ readonly id: string }>("/api/v1/projects", "POST", { name, slug });
  revalidatePath("/projects");
  redirect(`/projects/${project.id}`);
}

export async function logout(): Promise<void> {
  try { await apiJson<void>("/api/v1/auth/logout", "POST", {}); } catch (error: unknown) { if (!(error instanceof ApiError && error.status === 401)) throw error; }
  redirect("/login");
}

export interface ApiKeyState { readonly key?: string; readonly error?: string; }
export async function createApiKey(_previous: ApiKeyState, formData: FormData): Promise<ApiKeyState> {
  const name = text(formData, "name");
  if (!name) return { error: "A key name is required." };
  try {
    const created = await apiJson<{ readonly key: string }>("/api/v1/api-keys", "POST", { name });
    revalidatePath("/settings");
    return { key: created.key };
  } catch (error: unknown) {
    return { error: error instanceof ApiError && error.status === 403 ? "Only organization owners and admins can create API keys." : "API key creation failed." };
  }
}

export async function revokeApiKey(formData: FormData): Promise<void> {
  const id = text(formData, "id");
  if (!id) return;
  await apiJson<void>(`/api/v1/api-keys/${encodeURIComponent(id)}/revoke`, "POST", {});
  revalidatePath("/settings");
}
