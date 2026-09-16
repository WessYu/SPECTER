"use client";
import { useActionState } from "react";
import {
  generateActiveVerification,
  verifyActiveTarget,
  type ActiveVerificationState,
} from "../app/(app)/actions";

const initial: ActiveVerificationState = {};

export function ActiveTargetControls({
  projectId,
  targetId,
  status,
}: {
  readonly projectId: string;
  readonly targetId: string;
  readonly status: string;
}) {
  const [generation, generateAction, generating] = useActionState(
    generateActiveVerification,
    initial,
  );
  const [verification, verifyAction, verifying] = useActionState(verifyActiveTarget, initial);

  return (
    <div>
      <div className="form-row">
        {status !== "verified" ? (
          <form action={generateAction}>
            <input type="hidden" name="projectId" value={projectId} />
            <input type="hidden" name="targetId" value={targetId} />
            <button className="button button-quiet" type="submit" disabled={generating}>
              {generating ? "Generating…" : "Generate verification token"}
            </button>
          </form>
        ) : null}
        {status !== "verified" ? (
          <form action={verifyAction}>
            <input type="hidden" name="projectId" value={projectId} />
            <input type="hidden" name="targetId" value={targetId} />
            <button className="button" type="submit" disabled={verifying}>
              {verifying ? "VERIFYING" : "Verify"}
            </button>
          </form>
        ) : null}
      </div>
      {generation.content ? (
        <div className="key-reveal" role="status">
          <strong>Publish the well-known verification file.</strong>
          <code>{generation.httpPath}</code>
          <code>{generation.content}</code>
        </div>
      ) : null}
      {generation.error ? (
        <p className="subtle delta-negative" role="alert">
          {generation.error}
        </p>
      ) : null}
      {verification.verified ? (
        <p className="subtle delta-positive" role="status">
          VERIFIED
        </p>
      ) : null}
      {verification.error ? (
        <p className="subtle delta-negative" role="alert">
          {verification.error}
        </p>
      ) : null}
    </div>
  );
}
