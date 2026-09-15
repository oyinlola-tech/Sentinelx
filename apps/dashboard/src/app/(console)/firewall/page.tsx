"use client";

import { Ban, Check, Plus, ShieldOff, X } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { SafetyChip } from "@/components/shell/app-shell";
import { BlockDialog } from "@/components/views/block-dialog";
import { Button, Dialog, EmptyState, ErrorState, Field, Input, Panel, StaleNotice, TableSkeleton, Tabs, Textarea } from "@/components/ui/primitives";
import { Mono, OutcomeBadge } from "@/components/ui/security";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { ago, humanise, timestamp } from "@/lib/format";
import { isTransientRateLimit } from "@/lib/rate-limit";
import { useSession } from "@/lib/session";
import type { FirewallOverview, PendingAction, ResponseAction, UnblockRequest } from "@/lib/types";

function remaining(seconds: number | null): string {
  if (seconds == null) return "permanent";
  if (seconds < 60) return `${Math.round(seconds)}s left`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m left`;
  return `${(seconds / 3600).toFixed(1)}h left`;
}

export default function FirewallPage() {
  const { can } = useSession();
  const toast = useToast();
  const { data, error, mutate } = useSWR<FirewallOverview>("/firewall", { refreshInterval: 10_000 });
  const [tab, setTab] = useState<"active" | "approvals" | "history" | "actions" | "allowlist">("active");
  const [blockOpen, setBlockOpen] = useState(false);
  const [unblock, setUnblock] = useState<string | null>(null);
  useEventRefresh(["ip.blocked", "ip.unblocked", "response.decided", "response.pending_approval", "config.changed"], () => void mutate());

  const rateLimited = isTransientRateLimit(error, data);
  if (error && !rateLimited) return <div className="panel"><ErrorState error={error} onRetry={() => void mutate()} /></div>;
  const status = data?.status;
  const banner = status ? (status.prevention_active ? "PREVENTION ACTIVE" : status.dry_run && status.mode !== "detect_only" ? "DRY RUN" : "DETECTION ONLY") : "";

  return (
    <>
      <PageHeader
        title="Firewall"
        description="Addresses SentinelX blocks or rate limits, decisions awaiting approval, and every response it has recorded."
        actions={can("admin") && <Button variant="danger" icon={<Ban className="size-4" />} onClick={() => setBlockOpen(true)}>Block an address</Button>}
      />

      {rateLimited && <StaleNotice error={error} className="mb-4" />}
      {status && (
        <div className="panel mb-4 flex flex-wrap items-center gap-x-8 gap-y-3 px-4 py-3">
          <SafetyChip banner={banner} />
          <KeyValueInline label="Response mode" value={humanise(status.mode)} />
          <KeyValueInline label="Dry run" value={status.dry_run ? "on" : "off"} />
          <KeyValueInline label="Backend" value={`${data!.health.backend}${data!.health.ok ? "" : " (unhealthy)"}`} />
          <KeyValueInline label="Auto-block threshold" value={`risk ≥ ${status.auto_block_threshold}`} />
          <KeyValueInline label="Safety refusals" value={String(status.safety_refusals)} />
          {can("admin") && <Link href="/settings#response" className="ml-auto text-xs text-iris hover:underline">Change response settings</Link>}
        </div>
      )}
      {data?.health.error && <p className="mb-4 rounded-md border border-sev-high/40 bg-sev-high/10 px-3 py-2 text-sm text-sev-high">Firewall backend reports: {data.health.error}</p>}

      <Panel bodyClassName="p-0">
        <Tabs
          label="Firewall sections"
          value={tab}
          onChange={setTab}
          options={[
            { value: "active", label: "Active blocks", count: data?.active.length },
            { value: "approvals", label: "Awaiting approval", count: data?.pending_approvals.length },
            { value: "history", label: "Block history" },
            { value: "actions", label: "Response log" },
            { value: "allowlist", label: "Allowlist" },
          ]}
        />
        {!data ? <TableSkeleton /> : tab === "active" ? (
          data.active.length ? (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead><tr><th scope="col">Network</th><th scope="col">Type</th><th scope="col">Expires</th><th scope="col">Since</th><th scope="col">Reason</th>{can("admin") && <th scope="col"><span className="sr-only">Actions</span></th>}</tr></thead>
                <tbody>
                  {data.active.map((entry) => (
                    <tr key={entry.network}>
                      <td><Mono>{entry.network}</Mono></td>
                      <td>{entry.rate_limited ? "Rate limit" : entry.temporary ? "Temporary block" : "Block"}</td>
                      <td><Mono className={entry.temporary ? "text-sev-medium" : "text-mist"}>{remaining(entry.remaining_seconds)}</Mono></td>
                      <td><Mono className="text-mist">{ago(entry.created_at)}</Mono></td>
                      <td className="max-w-md truncate text-mist">{entry.comment || "—"}</td>
                      {can("admin") && <td className="text-right"><Button size="sm" variant="ghost" icon={<ShieldOff className="size-3.5" />} onClick={() => setUnblock(entry.network)}>Unblock</Button></td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <EmptyState title="Nothing is blocked">{status?.dry_run ? "DRY_RUN is on, so blocks are simulated and recorded in the response log instead." : "Blocks appear here as soon as the firewall applies them."}</EmptyState>
        ) : tab === "approvals" ? (
          <Approvals pending={data.pending_approvals} canApprove={can("admin")} dryRun={data.status.dry_run} backend={data.status.firewall_backend} onChanged={() => void mutate()} />
        ) : tab === "history" ? (
          data.history.length ? (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead><tr><th scope="col">Network</th><th scope="col">State</th><th scope="col">Created</th><th scope="col">Removed</th><th scope="col">Backend</th><th scope="col">Reason</th></tr></thead>
                <tbody>
                  {data.history.map((entry) => (
                    <tr key={entry.id}>
                      <td><Mono>{entry.network}</Mono></td>
                      <td>{entry.active ? <span className="text-sev-critical">Active</span> : <span className="text-mist">Removed</span>}</td>
                      <td><Mono className="text-mist">{timestamp(entry.created_at)}</Mono></td>
                      <td><Mono className="text-mist">{entry.removed_at ? timestamp(entry.removed_at) : "—"}</Mono></td>
                      <td className="text-mist">{entry.backend || "—"}</td>
                      <td className="max-w-md truncate text-mist">{entry.removal_reason ? `${entry.reason} · removed: ${entry.removal_reason}` : entry.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <EmptyState title="No blocks have been applied yet" />
        ) : tab === "actions" ? (
          <ActionLog actions={data.actions} />
        ) : (
          <Allowlist allowlist={status?.allowlist ?? []} canEdit={can("admin")} onSaved={() => { void mutate(); toast("success", "Allowlist saved"); }} />
        )}
      </Panel>

      <BlockDialog open={blockOpen} onClose={() => setBlockOpen(false)} onDone={() => void mutate()} />
      <UnblockDialog network={unblock} onClose={() => setUnblock(null)} onDone={() => void mutate()} />
    </>
  );
}

function KeyValueInline({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="eyebrow">{label}</p>
      <p className="font-mono text-sm text-frost">{value}</p>
    </div>
  );
}

function ActionLog({ actions }: { actions: ResponseAction[] }) {
  if (!actions.length) return <EmptyState title="No response decisions recorded">Decisions are recorded for every block, rate limit, refusal and simulation, whatever the response mode.</EmptyState>;
  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead><tr><th scope="col">When</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Outcome</th><th scope="col">Reason</th><th scope="col">Source</th></tr></thead>
        <tbody>
          {actions.map((action) => (
            <tr key={action.decision_id}>
              <td><Mono className="text-mist">{ago(action.decided_at)}</Mono></td>
              <td className="whitespace-nowrap">{humanise(action.action)}</td>
              <td><Mono>{action.target}</Mono></td>
              <td><OutcomeBadge outcome={action.outcome} action={action.action} /></td>
              <td className="max-w-lg truncate text-mist" title={action.error ?? action.reason}>{action.error ?? action.reason}</td>
              <td>{action.incident_id ? <Link href={`/incidents/${action.incident_id}`} className="text-xs text-iris hover:underline">Incident</Link> : action.detection_id ? <Link href={`/detections/${action.detection_id}`} className="text-xs text-iris hover:underline">Detection</Link> : <span className="text-xs text-fog">Manual</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function durationText(seconds: number): string {
  if (seconds < 60) return `${seconds} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86_400) return `${+(seconds / 3600).toFixed(1)} hours`;
  return `${+(seconds / 86_400).toFixed(1)} days`;
}

function Approvals({ pending, canApprove, dryRun, backend, onChanged }: { pending: PendingAction[]; canApprove: boolean; dryRun: boolean; backend: string; onChanged: () => void }) {
  const toast = useToast();
  const [approving, setApproving] = useState<PendingAction | null>(null);
  const [rejecting, setRejecting] = useState<PendingAction | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function approve(item: PendingAction) {
    setBusy(item.action_id);
    try {
      const decision = await api<ResponseAction>(`/firewall/approvals/${item.action_id}/approve`, { method: "POST" });
      toast(decision.outcome === "failed" ? "error" : "success", `${humanise(item.action)} ${item.target}: ${humanise(decision.outcome)}`, decision.error ?? undefined);
      setApproving(null);
      onChanged();
    } catch (error) {
      toast("error", "Approval failed", error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  async function reject() {
    if (!rejecting) return;
    setBusy(rejecting.action_id);
    try {
      await api(`/firewall/approvals/${rejecting.action_id}/reject`, { method: "POST", json: { reason } });
      toast("info", `Rejected ${humanise(rejecting.action)} of ${rejecting.target}`);
      setRejecting(null);
      setReason("");
      onChanged();
    } catch (error) {
      toast("error", "Rejection failed", error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  if (!pending.length) return <EmptyState title="Nothing awaiting approval">In manual approval mode, blocks the engine recommends wait here for an administrator.</EmptyState>;
  return (
    <>
      <ul className="divide-y divide-line">
        {pending.map((item) => (
          <li key={item.action_id} className="flex flex-wrap items-start justify-between gap-4 px-4 py-3">
            <div className="min-w-0">
              <p className="text-sm text-frost">{humanise(item.action)} <Mono>{item.target}</Mono> <span className="text-mist">· risk {Math.round(item.risk)} · {ago(item.created_at)}</span></p>
              <p className="mt-0.5 text-xs text-mist">{item.reason}</p>
              {item.evidence.length > 0 && <ul className="mt-1 list-inside list-disc text-xs text-fog">{item.evidence.slice(0, 3).map((line) => <li key={line}>{line}</li>)}</ul>}
            </div>
            {canApprove && (
              <div className="flex gap-2">
                <Button size="sm" variant="ghost" icon={<X className="size-3.5" />} onClick={() => setRejecting(item)} disabled={busy !== null}>Reject</Button>
                <Button size="sm" variant="danger" icon={<Check className="size-3.5" />} loading={busy === item.action_id} onClick={() => setApproving(item)} disabled={busy !== null}>Approve</Button>
              </div>
            )}
          </li>
        ))}
      </ul>
      <Dialog
        open={approving !== null}
        onClose={() => setApproving(null)}
        title="Approve recommended action"
        footer={<><Button variant="ghost" onClick={() => setApproving(null)}>Cancel</Button><Button variant="danger" icon={<Check className="size-4" />} loading={busy !== null} onClick={() => approving && void approve(approving)}>{dryRun ? "Approve and simulate" : "Approve and apply"}</Button></>}
      >
        {approving && (
          <div className="flex flex-col gap-3 text-sm text-mist">
            <p>
              Approving {dryRun ? "records" : "applies"} <span className="text-frost">{humanise(approving.action)}</span> {dryRun ? "against" : "to"} <Mono className="text-frost">{approving.target}</Mono>
              {approving.duration_seconds ? ` for ${durationText(approving.duration_seconds)}` : ""}
              {dryRun ? " as a simulated decision." : <> on the <Mono className="text-frost">{backend}</Mono> firewall now.{approving.action.includes("block") ? " Traffic from that address is dropped as soon as the rule is in place." : ""}</>}
            </p>
            {dryRun && <p className="rounded-md border border-sev-medium/40 bg-sev-medium/10 px-3 py-2 text-xs text-sev-medium">Dry run is on, so the decision is recorded as simulated and the firewall is not changed.</p>}
            <p>The approval is recorded in the audit log with your name.{dryRun ? "" : " You can reverse it later from Active blocks."}</p>
          </div>
        )}
      </Dialog>
      <Dialog open={rejecting !== null} onClose={() => setRejecting(null)} title="Reject recommended action" footer={<><Button variant="ghost" onClick={() => setRejecting(null)}>Cancel</Button><Button variant="primary" loading={busy !== null} onClick={() => void reject()}>Reject action</Button></>}>
        <Field label="Reason (recorded in the audit log)" htmlFor="reject-reason">
          <Input id="reject-reason" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} placeholder="Known scanner operated by the security team" />
        </Field>
      </Dialog>
    </>
  );
}

function UnblockDialog({ network, onClose, onDone }: { network: string | null; onClose: () => void; onDone: () => void }) {
  const toast = useToast();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit() {
    if (!network) return;
    setBusy(true);
    try {
      const decision = await api<ResponseAction>("/firewall/unblock", { method: "POST", json: { target: network, reason } satisfies UnblockRequest });
      toast(decision.outcome === "failed" ? "error" : "success", `${network}: ${humanise(decision.outcome)}`, decision.error ?? undefined);
      setReason("");
      onDone();
      onClose();
    } catch (error) {
      toast("error", "Unblock failed", error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog open={network !== null} onClose={onClose} title={`Unblock ${network ?? ""}`} footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={busy} disabled={reason.trim().length < 3} onClick={() => void submit()}>Unblock</Button></>}>
      <Field label="Reason (recorded in the audit log)" htmlFor="unblock-reason">
        <Input id="unblock-reason" value={reason} onChange={(event) => setReason(event.target.value)} maxLength={500} />
      </Field>
    </Dialog>
  );
}

const LOOPBACK = ["127.0.0.0/8", "::1/128"];

function Allowlist({ allowlist, canEdit, onSaved }: { allowlist: string[]; canEdit: boolean; onSaved: () => void }) {
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [problems, setProblems] = useState<string | null>(null);
  const networks = [...new Set(text.split(/[\s,]+/).map((line) => line.trim()).filter(Boolean))];
  const added = networks.filter((network) => !allowlist.includes(network));
  const removedAll = allowlist.filter((network) => !networks.includes(network));
  // The server always keeps loopback, so removing it is not a real change.
  const removed = removedAll.filter((network) => !LOOPBACK.includes(network));
  async function save() {
    setBusy(true);
    setProblems(null);
    try {
      await api("/firewall/allowlist", { method: "PUT", json: { networks } });
      setConfirming(false);
      setEditing(false);
      onSaved();
    } catch (error) {
      setProblems(error instanceof Error ? error.message : "Could not save the allowlist");
      setConfirming(false);
      toast("error", "Allowlist not saved");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="p-4">
      <p className="mb-3 max-w-2xl text-sm text-mist">
        Addresses and networks here are never blocked, by a detector or by a person. Loopback is always protected, and so is every address assigned to this host.
      </p>
      {editing ? (
        <div className="flex max-w-xl flex-col gap-3">
          <Field label="One address or CIDR per line" htmlFor="allowlist" error={problems}>
            <Textarea id="allowlist" rows={8} value={text} onChange={(event) => setText(event.target.value)} />
          </Field>
          <div className="flex gap-2">
            <Button variant="primary" loading={busy} disabled={!added.length && !removed.length} onClick={() => setConfirming(true)}>Review changes</Button>
            <Button variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>
          </div>
        </div>
      ) : (
        <>
          <ul className="flex flex-wrap gap-2">
            {allowlist.map((network) => <li key={network} className="rounded-sm border border-line-strong px-2 py-1 font-mono text-xs">{network}</li>)}
          </ul>
          {canEdit && <Button className="mt-4" size="sm" variant="secondary" icon={<Plus className="size-3.5" />} onClick={() => { setText(allowlist.join("\n")); setProblems(null); setEditing(true); }}>Edit allowlist</Button>}
        </>
      )}
      <Dialog
        open={confirming}
        onClose={() => setConfirming(false)}
        title="Save allowlist changes"
        footer={<><Button variant="ghost" onClick={() => setConfirming(false)}>Keep editing</Button><Button variant={removed.length ? "danger" : "primary"} loading={busy} onClick={() => void save()}>Save allowlist</Button></>}
      >
        <div className="flex flex-col gap-4 text-sm text-mist">
          {removed.length > 0 && (
            <div>
              <p className="text-frost">Removed ({removed.length})</p>
              <p className="mt-0.5 text-xs">These lose their allowlist protection immediately, so a detector or a person can block them after you save (this host&apos;s own addresses and management addresses stay protected).</p>
              <ul className="mt-2 flex flex-wrap gap-2">{removed.map((network) => <li key={network} className="rounded-sm border border-sev-critical/50 px-2 py-1 font-mono text-xs text-sev-critical line-through">{network}</li>)}</ul>
            </div>
          )}
          {added.length > 0 && (
            <div>
              <p className="text-frost">Added ({added.length})</p>
              <p className="mt-0.5 text-xs">Addresses in these networks can no longer be blocked by a detector or a person.</p>
              <ul className="mt-2 flex flex-wrap gap-2">{added.map((network) => <li key={network} className="rounded-sm border border-ok/40 px-2 py-1 font-mono text-xs text-ok">{network}</li>)}</ul>
            </div>
          )}
          {removedAll.length > removed.length && <p className="text-xs">Loopback stays protected even though you removed it from the list.</p>}
          <p className="text-xs">The change applies immediately and is recorded in the audit log.</p>
        </div>
      </Dialog>
    </div>
  );
}


