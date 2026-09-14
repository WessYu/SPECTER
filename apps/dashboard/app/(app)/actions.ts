"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { apiJson, ApiError } from "../../lib/api";

function text(formData: FormData, key: string): string {
  const value = formData.get(key);
  return typeof value === "string" ? value.trim() : "";
}

export async function createProject(formData: FormData): Promise<void> {
  const name = text(formData, "name");
  const slug = text(formData, "slug");
  if (!name || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) return;
  const project = await apiJson<{ readonly id: string }>("/api/v1/projects", "POST", {
    name,
    slug,
  });
  revalidatePath("/projects");
  redirect(`/projects/${project.id}`);
}

export async function logout(): Promise<void> {
  try {
    await apiJson<void>("/api/v1/auth/logout", "POST", {});
  } catch (error: unknown) {
    if (!(error instanceof ApiError && error.status === 401)) throw error;
  }
  redirect("/login");
}

export interface ApiKeyState {
  readonly key?: string;
  readonly error?: string;
}
export async function createApiKey(
  _previous: ApiKeyState,
  formData: FormData,
): Promise<ApiKeyState> {
  const name = text(formData, "name");
  if (!name) return { error: "A key name is required." };
  try {
    const created = await apiJson<{ readonly key: string }>("/api/v1/api-keys", "POST", { name });
    revalidatePath("/settings");
    return { key: created.key };
  } catch (error: unknown) {
    return {
      error:
        error instanceof ApiError && error.status === 403
          ? "Only organization owners and admins can create API keys."
          : "API key creation failed.",
    };
  }
}

export interface DomainVerificationState {
  readonly token?: string;
  readonly dns?: string;
  readonly httpPath?: string;
  readonly domainId?: string;
  readonly error?: string;
}
export async function createDomain(
  _previous: DomainVerificationState,
  formData: FormData,
): Promise<DomainVerificationState> {
  const projectId = text(formData, "projectId");
  const hostname = text(formData, "hostname");
  if (!projectId || !hostname) return { error: "A valid hostname is required." };
  try {
    const domain = await apiJson<{ readonly id: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/domains`,
      "POST",
      { hostname },
    );
    const verification = await apiJson<{
      readonly token: string;
      readonly dns: string;
      readonly httpPath: string;
    }>(`/api/v1/domains/${encodeURIComponent(domain.id)}/verify`, "POST", { action: "create" });
    revalidatePath(`/projects/${projectId}/domains`);
    return { ...verification, domainId: domain.id };
  } catch (error: unknown) {
    if (error instanceof ApiError && error.status === 409)
      return { error: "That domain is already registered in this project." };
    return { error: "Domain registration could not be completed." };
  }
}

export async function checkDomain(formData: FormData): Promise<void> {
  const projectId = text(formData, "projectId");
  const domainId = text(formData, "domainId");
  if (!projectId || !domainId) return;
  await apiJson(`/api/v1/domains/${encodeURIComponent(domainId)}/verify`, "POST", {
    action: "check",
  });
  revalidatePath(`/projects/${projectId}/domains`);
}

export async function revokeApiKey(formData: FormData): Promise<void> {
  const id = text(formData, "id");
  if (!id) return;
  await apiJson<void>(`/api/v1/api-keys/${encodeURIComponent(id)}/revoke`, "POST", {});
  revalidatePath("/settings");
}

export interface ActiveVerificationState {
  readonly targetId?: string;
  readonly token?: string;
  readonly content?: string;
  readonly httpPath?: string;
  readonly verified?: boolean;
  readonly error?: string;
}

async function createActiveVerification(
  targetId: string,
): Promise<{
  readonly token: string;
  readonly content: string;
  readonly httpPath: string;
}> {
  return apiJson(
    `/api/v1/active-targets/${encodeURIComponent(targetId)}/verification`,
    "POST",
    { action: "create" },
  );
}

export async function createActiveTarget(
  _previous: ActiveVerificationState,
  formData: FormData,
): Promise<ActiveVerificationState> {
  const projectId = text(formData, "projectId");
  const url = text(formData, "url");
  if (!projectId || !/^https?:\/\//i.test(url))
    return { error: "Enter a complete HTTP(S) target URL." };
  try {
    const target = await apiJson<{ readonly id: string }>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/active-targets`,
      "POST",
      { url },
    );
    const verification = await createActiveVerification(target.id);
    revalidatePath(`/projects/${projectId}/active-security`);
    return {
      targetId: target.id,
      ...verification,
    };
  } catch (error: unknown) {
    return {
      error:
        error instanceof ApiError && error.status === 403
          ? "You do not have permission to add an active target."
          : "The active target could not be created.",
    };
  }
}

export async function generateActiveVerification(
  _previous: ActiveVerificationState,
  formData: FormData,
): Promise<ActiveVerificationState> {
  const projectId = text(formData, "projectId");
  const targetId = text(formData, "targetId");
  if (!projectId || !targetId)
    return { error: "Target information is missing." };
  try {
    const verification = await createActiveVerification(targetId);
    revalidatePath(`/projects/${projectId}/active-security`);
    return {
      targetId,
      ...verification,
    };
  } catch (error: unknown) {
    return {
      error:
        error instanceof ApiError && error.status === 403
          ? "Only owners and admins can generate verification tokens."
          : "Verification token generation failed.",
    };
  }
}

export async function verifyActiveTarget(
  _previous: ActiveVerificationState,
  formData: FormData,
): Promise<ActiveVerificationState> {
  const projectId = text(formData, "projectId");
  const targetId = text(formData, "targetId");
  if (!projectId || !targetId)
    return { error: "Target information is missing." };
  try {
    await apiJson(
      `/api/v1/active-targets/${encodeURIComponent(targetId)}/verification`,
      "POST",
      { action: "check" },
    );
    revalidatePath(`/projects/${projectId}/active-security`);
    return { targetId, verified: true };
  } catch (error: unknown) {
    return {
      error:
        error instanceof ApiError && error.status === 409
          ? "Verification file was not found or did not match."
          : error instanceof ApiError && error.status === 400
            ? "The verification challenge expired. Generate a new token."
            : "Target verification failed.",
    };
  }
}

export async function startActiveScan(
  formData: FormData,
): Promise<void> {
  const projectId = text(formData, "projectId");
  const targetId = text(formData, "targetId");
  const profile = text(formData, "profile");
  if (!projectId || !targetId) return;
  await apiJson(
    "/api/v1/active-scans",
    "POST",
    {
      targetId,
      profile: profile === "standard" ? "standard" : "safe",
    },
  );
  revalidatePath(`/projects/${projectId}/active-security`);
}

export async function cancelActiveScan(
  formData: FormData,
): Promise<void> {
  const projectId = text(formData, "projectId");
  const scanId = text(formData, "scanId");
  if (!projectId || !scanId) return;
  await apiJson(
    `/api/v1/active-scans/${encodeURIComponent(scanId)}/cancel`,
    "POST",
    {},
  );
  revalidatePath(`/projects/${projectId}/active-security`);
}
