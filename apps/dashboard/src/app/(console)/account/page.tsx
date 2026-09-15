"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState, type FormEvent } from "react";
import { PageHeader } from "@/components/shell/page-header";
import { Button, Field, Input, KeyValue, Panel } from "@/components/ui/primitives";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import { timestamp } from "@/lib/format";
import { useSession } from "@/lib/session";

function Account() {
  const { user, reload } = useSession();
  const toast = useToast();
  const router = useRouter();
  const required = useSearchParams().get("required") === "1" || user?.must_change_password;
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    if (next !== confirm) {
      setError("The new passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      // The response starts a fresh session for this browser; every other session ends.
      await api("/auth/change-password", { method: "POST", json: { current_password: current, new_password: next } });
      toast("success", "Password changed", "You stay signed in here. Every other session for this account was signed out.");
      setCurrent("");
      setNext("");
      setConfirm("");
      await reload();
      if (required) router.replace("/");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not change the password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Your account" />
      {required && (
        <p className="mb-4 max-w-2xl rounded-md border border-sev-medium/40 bg-sev-medium/10 px-4 py-3 text-sm text-sev-medium" role="alert">
          Your password was generated or reset by an administrator. Choose a new one to continue.
        </p>
      )}
      <div className="grid max-w-4xl gap-4 lg:grid-cols-2">
        <Panel title="Profile">
          <KeyValue items={[["Username", user?.username], ["Role", user?.role], ["Last sign-in", timestamp(user?.last_login_at)], ["Created", timestamp(user?.created_at)]]} />
        </Panel>
        <Panel title="Change password">
          <form onSubmit={submit} className="flex flex-col gap-3">
            <Field label="Current password" htmlFor="current"><Input id="current" type="password" autoComplete="current-password" required value={current} onChange={(event) => setCurrent(event.target.value)} /></Field>
            <Field label="New password" htmlFor="new" hint="At least 12 characters. A long passphrase is stronger than a short complex password."><Input id="new" type="password" autoComplete="new-password" required minLength={12} value={next} onChange={(event) => setNext(event.target.value)} /></Field>
            <Field label="Confirm new password" htmlFor="confirm" error={error}><Input id="confirm" type="password" autoComplete="new-password" required value={confirm} onChange={(event) => setConfirm(event.target.value)} /></Field>
            <Button type="submit" variant="primary" loading={busy} className="self-start">Change password</Button>
          </form>
        </Panel>
      </div>
    </>
  );
}

export default function AccountPage() {
  return <Suspense><Account /></Suspense>;
}
