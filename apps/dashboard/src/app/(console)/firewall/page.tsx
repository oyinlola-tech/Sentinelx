"use client";

import { Ban, Check, Plus, ShieldOff, X } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { SafetyChip } from "@/components/shell/app-shell";
import { BlockDialog } from "@/components/views/block-dialog";
import { Button, Dialog, EmptyState, ErrorState, Field, Input, Panel, TableSkeleton, Tabs, Textarea } from "@/components/ui/primitives";
import { Mono, OutcomeBadge } from "@/components/ui/security";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { ago, humanise, timestamp } from "@/lib/format";
import { useSession } from "@/lib/session";
import type { FirewallOverview, PendingAction, ResponseAction } from "@/lib/types";

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

  if (error) return <div className="panel"><ErrorState error={error} onRetry={() => void mutate()} /></div>;
  const status = data?.status;
  const banner = status ? (status.prevention_active ? "PREVENTION ACTIVE" : status.dry_run && status.mode !== "detect_only" ? "DRY RUN" : "DETECTION ONLY") : "";

  return (
    <>
      <PageHeader
        title="Firewall"
        description="Addresses SentinelX blocks or rate limits, decisions awaiting approval, and every response it has recorded."
        actions={can("admin") && <Button variant="danger" icon={<Ban className="size-4" />} onClick={() => setBlockOpen(true)}>Block an address</Button>}
      />

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
          ) : <EmptyState title="Nothing is blocked">{status?.dry_run ? "DRY_RUN is on, so blocks are simulated and recorded in the response log instead." : "Blocks appear here as soon as the firewall applies them."}</EmptyState>
        ) : tab === "approvals" ? (
          <Approvals pending={data.pending_approvals} canApprove={can("admin")} onChanged={() => void mutate()} />
        ) : tab === "history" ? (
          data.history.length ? (
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
              <td><OutcomeBadge outcome={action.outcome} /></td>
              <td className="max-w-lg truncate text-mist" title={action.error ?? action.reason}>{action.error ?? action.reason}</td>
              <td>{action.incident_id ? <Link href={`/incidents/${action.incident_id}`} className="text-xs text-iris hover:underline">Incident</Link> : action.detection_id ? <Link href={`/detections/${action.detection_id}`} className="text-xs text-iris hover:underline">Detection</Link> : <span className="text-xs text-fog">Manual</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Approvals({ pending, canApprove, onChanged }: { pending: PendingAction[]; canApprove: boolean; onChanged: () => void }) {
  const toast = useToast();
  const [rejecting, setRejecting] = useState<PendingAction | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  async function approve(item: PendingAction) {
    setBusy(item.action_id);
    try {
      const decision = await api<ResponseAction>(`/firewall/approvals/${item.action_id}/approve`, { method: "POST" });
      toast(decision.outcome === "failed" ? "error" : "success", `${humanise(item.action)} ${item.target}: ${humanise(decision.outcome)}`, decision.error ?? undefined);
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
                <Button size="sm" variant="danger" icon={<Check className="size-3.5" />} loading={busy === item.action_id} onClick={() => void approve(item)}>Approve</Button>
              </div>
            )}
          </li>
        ))}
      </ul>
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
      const decision = await api<ResponseAction>("/firewall/unblock", { method: "POST", json: { target: network, reason } });
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

function Allowlist({ allowlist, canEdit, onSaved }: { allowlist: string[]; canEdit: boolean; onSaved: () => void }) {
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [problems, setProblems] = useState<string | null>(null);
  async function save() {
    setBusy(true);
    setProblems(null);
    try {
      const networks = text.split(/[\s,]+/).map((line) => line.trim()).filter(Boolean);
      await api("/firewall/allowlist", { method: "PUT", json: { networks } });
      setEditing(false);
      onSaved();
    } catch (error) {
      setProblems(error instanceof Error ? error.message : "Could not save the allowlist");
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
            <Button variant="primary" loading={busy} onClick={() => void save()}>Save allowlist</Button>
            <Button variant="ghost" onClick={() => setEditing(false)}>Cancel</Button>
          </div>
        </div>
      ) : (
        <>
          <ul className="flex flex-wrap gap-2">
            {allowlist.map((network) => <li key={network} className="rounded-sm border border-line-strong px-2 py-1 font-mono text-xs">{network}</li>)}
          </ul>
          {canEdit && <Button className="mt-4" size="sm" variant="secondary" icon={<Plus className="size-3.5" />} onClick={() => { setText(allowlist.join("\n")); setEditing(true); }}>Edit allowlist</Button>}
        </>
      )}
    </div>
  );
}


