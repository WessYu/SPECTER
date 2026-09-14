"use client";
import { useActionState } from "react";
import { createApiKey, type ApiKeyState } from "../app/(app)/actions";

const initial: ApiKeyState = {};
export function ApiKeyForm() {
  const [state, action, pending] = useActionState(createApiKey, initial);
  return <div>
    <form action={action} className="form-row">
      <label><span className="eyebrow" style={{display: "block", marginBottom: 7}}>Key name</span><input className="input" name="name" required maxLength={80} placeholder="CI production" /></label>
      <button className="button" type="submit" disabled={pending}>{pending ? "Creating…" : "Create API key"}</button>
    </form>
    {state.error ? <p role="alert" className="delta-negative subtle">{state.error}</p> : null}
    {state.key ? <div className="key-reveal" role="status"><strong>Copy this key now. It will not be shown again.</strong><code>{state.key}</code></div> : null}
  </div>;
}
