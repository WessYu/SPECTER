"use client";
import { useActionState } from "react";
import { createDomain, type DomainVerificationState } from "../app/(app)/actions";

const initial: DomainVerificationState = {};
export function DomainForm({ projectId }: { readonly projectId: string }) {
  const [state, action, pending] = useActionState(createDomain, initial);
  return <div>
    <form action={action} className="form-row">
      <input type="hidden" name="projectId" value={projectId}/>
      <label><span className="eyebrow" style={{display:"block",marginBottom:7}}>Hostname</span><input className="input mono" name="hostname" required maxLength={253} placeholder="example.com"/></label>
      <button className="button" type="submit" disabled={pending}>{pending?"Registering…":"Add domain"}</button>
    </form>
    {state.error?<p className="subtle delta-negative" role="alert">{state.error}</p>:null}
    {state.token?<div className="key-reveal" role="status"><strong>Verification challenge created.</strong><p className="subtle">Publish either DNS TXT or the well-known file, then run verification. The token is shown here once.</p><code>{state.dns}</code><code>{state.httpPath} → {state.token}</code></div>:null}
  </div>;
}
