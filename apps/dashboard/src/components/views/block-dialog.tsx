"use client";

import { ShieldAlert, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { Button, Dialog, Field, Input, Select } from "@/components/ui/primitives";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import type { BlockRequest, ResponseAction } from "@/lib/types";

interface SafetyReport { target: string; allowed: boolean; network: string | null; reason: string; dry_run: boolean }

const DURATIONS = [
  { label: "15 minutes", seconds: 900 },
  { label: "1 hour", seconds: 3600 },
  { label: "24 hours", seconds: 86_400 },
  { label: "Until removed", seconds: 0 },
];

/**
 * Confirmation for a destructive firewall action. It previews the safety guard's
 * verdict and says plainly whether DRY_RUN will stop the change from being applied,
 * before the operator commits.
 */
export function BlockDialog(props: { open: boolean; onClose: () => void; initialTarget?: string; initialReason?: string; onDone?: () => void }) {
  const { open, onClose } = props;
  // The form mounts only while open, so each opening starts from the latest
  // initial values without copying props into state from an effect.
  return (
    <Dialog open={open} onClose={onClose} title="Block or rate limit a source">
      {open && <BlockForm {...props} />}
    </Dialog>
  );
}

function BlockForm({ onClose, initialTarget = "", initialReason = "", onDone }: { onClose: () => void; initialTarget?: string; initialReason?: string; onDone?: () => void }) {
  const toast = useToast();
  const [target, setTarget] = useState(initialTarget);
  const [reason, setReason] = useState(initialReason);
  const [duration, setDuration] = useState(900);
  const [rateLimit, setRateLimit] = useState(false);
  const [checked, setChecked] = useState<SafetyReport | null>(null);
  // Why the safety check could not run (rate limited, API unreachable). Blocking stays
  // disabled until it succeeds, so the operator must be told why instead of guessing.
  const [checkError, setCheckError] = useState<{ target: string; message: string } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const trimmed = target.trim();
  const report = checked && checked.target === trimmed ? checked : null;

  useEffect(() => {
    if (trimmed.length < 2) return;
    const handle = setTimeout(() => {
      api<SafetyReport>("/firewall/check", { method: "POST", json: { target: trimmed } })
        .then((result) => {
          setChecked({ ...result, target: trimmed });
          setCheckError(null);
        })
        .catch((error: unknown) => {
          setChecked(null);
          setCheckError({ target: trimmed, message: error instanceof Error ? error.message : "request failed" });
        });
    }, 250);
    return () => clearTimeout(handle);
  }, [trimmed, attempt]);

  async function submit() {
    setBusy(true);
    try {
      const decision = await api<ResponseAction>("/firewall/block", {
        method: "POST",
        json: { target: target.trim(), reason: reason.trim(), duration_seconds: duration || null, rate_limit: rateLimit } satisfies BlockRequest,
      });
      if (decision.outcome === "failed") toast("error", `${target} was not blocked`, decision.error ?? undefined);
      else if (decision.outcome === "simulated") toast("info", `Block of ${target} simulated`, "DRY_RUN is on, so the firewall was not changed. The decision is in the audit log.");
      else toast("success", `${target} ${rateLimit ? "rate limited" : "blocked"}`, decision.reason);
      onDone?.();
      onClose();
    } catch (error) {
      toast("error", "The block request failed", error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(false);
    }
  }

  const canSubmit = reason.trim().length >= 3 && report?.allowed === true;
  return (
    <>
      <div className="flex flex-col gap-4">
        <Field label="Address or network" htmlFor="block-target" hint="A single address, or a small CIDR prefix">
          <Input id="block-target" value={target} onChange={(event) => setTarget(event.target.value)} className="font-mono" placeholder="203.0.113.45" maxLength={64} />
        </Field>
        {!report && checkError?.target === trimmed && (
          <div className="flex items-center justify-between gap-3 rounded-md border border-sev-medium/40 bg-sev-medium/10 px-3 py-2 text-sm text-sev-medium" role="alert">
            <span>Could not check this address with the safety guard ({checkError.message}). Blocking stays disabled until the check succeeds.</span>
            <Button size="sm" variant="secondary" onClick={() => setAttempt((value) => value + 1)}>Check again</Button>
          </div>
        )}
        {report && (
          <div className={`flex gap-2 rounded-md border px-3 py-2 text-sm ${report.allowed ? "border-ok/40 bg-ok/10 text-ok" : "border-sev-critical/40 bg-sev-critical/10 text-sev-critical"}`} role="status">
            {report.allowed ? <ShieldCheck className="mt-0.5 size-4 shrink-0" aria-hidden /> : <ShieldAlert className="mt-0.5 size-4 shrink-0" aria-hidden />}
            <span>{report.allowed ? `Safety guard permits acting on ${report.network}.` : `Safety guard will refuse this: ${report.reason}.`}</span>
          </div>
        )}
        <Field label="Reason" htmlFor="block-reason" hint="Recorded in the audit log with your name">
          <Input id="block-reason" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} />
        </Field>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Duration" htmlFor="block-duration">
            <Select id="block-duration" value={duration} onChange={(event) => setDuration(Number(event.target.value))}>
              {DURATIONS.map((option) => <option key={option.seconds} value={option.seconds}>{option.label}</option>)}
            </Select>
          </Field>
          <label className="flex items-end gap-2 pb-2 text-sm text-mist">
            <input type="checkbox" checked={rateLimit} onChange={(event) => setRateLimit(event.target.checked)} className="size-4 accent-[var(--color-iris)]" />
            Rate limit instead of blocking
          </label>
        </div>
        {report?.dry_run && (
          <p className="rounded-md border border-sev-medium/40 bg-sev-medium/10 px-3 py-2 text-xs text-sev-medium">
            DRY_RUN is enabled. This records the decision and shows it everywhere, but does not change the firewall.
          </p>
        )}
      </div>
      <div className="mt-5 flex justify-end gap-2 border-t border-line pt-3">
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="danger" loading={busy} disabled={!canSubmit} onClick={() => void submit()}>
          {report?.dry_run ? "Record simulated block" : rateLimit ? "Apply rate limit" : "Block source"}
        </Button>
      </div>
    </>
  );
}
