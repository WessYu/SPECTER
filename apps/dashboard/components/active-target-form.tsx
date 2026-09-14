"use client";
import { useActionState } from "react";
import {
  createActiveTarget,
  type ActiveVerificationState,
} from "../app/(app)/actions";

const initial: ActiveVerificationState = {};

export function ActiveTargetForm({
  projectId,
}: {
  readonly projectId: string;
}) {
  const [state, action, pending] = useActionState(
    createActiveTarget,
    initial,
  );
  return (
    <div>
      <form action={action} className="form-row">
        <input
          type="hidden"
          name="projectId"
          value={projectId}
        />
        <label>
          <span
            className="eyebrow"
            style={{ display: "block", marginBottom: 7 }}
          >
            Target URL
          </span>
          <input
            className="input mono"
            name="url"
            type="url"
            required
            maxLength={4096}
            placeholder="https://preview.example.com"
          />
        </label>
        <button
          className="button"
          type="submit"
          disabled={pending}
        >
          {pending ? "Creating…" : "Add target & generate token"}
        </button>
      </form>
      {state.error ? (
        <p className="subtle delta-negative" role="alert">
          {state.error}
        </p>
      ) : null}
      {state.content ? (
        <div className="key-reveal" role="status">
          <strong>Verification challenge created.</strong>
          <p className="subtle">
            Publish this exact content on the target hostname. The
            token is shown here once and is only stored as a hash.
          </p>
          <code>{state.httpPath}</code>
          <code>{state.content}</code>
        </div>
      ) : null}
    </div>
  );
}
