"use client";

import { ArrowLeft, Ban } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { BlockDialog } from "@/components/views/block-dialog";
import { DetectionTable } from "@/components/views/detection-table";
import { Button, Dialog, ErrorState, Field, KeyValue, Panel, Select, Skeleton, StaleNotice, Textarea } from "@/components/ui/primitives";
import { Mono, OutcomeBadge, RiskBreakdown, SeverityBadge, StatusBadge } from "@/components/ui/security";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { ago, clock, humanise, severityColor, timestamp } from "@/lib/format";
import { isTransientRateLimit } from "@/lib/rate-limit";
import { useSession } from "@/lib/session";
import type { Incident, IncidentStatus } from "@/lib/types";

const STATUSES: IncidentStatus[] = ["open", "investigating", "contained", "resolved", "false_positive"];
/** Statuses that close an incident, so they ask for confirmation first. */
const CLOSING: IncidentStatus[] = ["resolved", "false_positive"];

export default function IncidentPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { can, user } = useSession();
  const toast = useToast();
  // Events keep the page current; the interval covers a dropped or reconnecting stream.
  const { data, error, mutate } = useSWR<Incident>(`/incidents/${id}`, { refreshInterval: 30_000 });
  useEventRefresh(["incident.updated", "severity.changed", "response.decided", "ip.blocked"], () => void mutate());
  const [blockTarget, setBlockTarget] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [closing, setClosing] = useState<IncidentStatus | null>(null);

  if (error instanceof ApiError && error.status === 404) return <div className="panel"><ErrorState error={new Error("This incident no longer exists.")} /></div>;
  const rateLimited = isTransientRateLimit(error, data);
  if (error && !rateLimited) return <div className="panel"><ErrorState error={error} onRetry={() => void mutate()} /></div>;
  if (!data) return <div className="flex flex-col gap-4"><Skeleton className="h-10 w-1/2" /><Skeleton className="h-72" /></div>;

  async function update(changes: Partial<Pick<Incident, "status" | "assigned_to" | "notes">>, message: string): Promise<boolean> {
    setSaving(true);
    try {
      await mutate(api<Incident>(`/incidents/${id}`, { method: "PATCH", json: changes }).then((updated) => ({ ...data!, ...updated })), { revalidate: true });
      toast("success", message);
      return true;
    } catch (caught) {
      toast("error", "Could not update the incident", caught instanceof Error ? caught.message : undefined);
      return false;
    } finally {
      setSaving(false);
    }
  }

  function chooseStatus(status: IncidentStatus) {
    if (CLOSING.includes(status)) setClosing(status);
    else void update({ status }, `Status set to ${humanise(status)}`);
  }

  const detections = data.detections ?? [];
  return (
    <>
      <button onClick={() => router.back()} className="mb-3 inline-flex items-center gap-1 text-xs text-mist hover:text-frost">
        <ArrowLeft className="size-3.5" aria-hidden /> Back
      </button>
      {rateLimited && <StaleNotice error={error} className="mb-4" />}
      <PageHeader
        eyebrow={`Incident · ${humanise(data.correlation_rule)}`}
        title={data.title}
        description={data.summary}
        actions={
          <>
            {can("analyst") && (
              <Select aria-label="Incident status" value={data.status} disabled={saving} onChange={(event) => chooseStatus(event.target.value as IncidentStatus)} className="w-44">
                {STATUSES.map((status) => <option key={status} value={status}>{humanise(status)}</option>)}
              </Select>
            )}
            {can("analyst") && data.assigned_to !== user?.username && (
              <Button size="sm" variant="secondary" loading={saving} onClick={() => void update({ assigned_to: user?.username }, "Assigned to you")}>Assign to me</Button>
            )}
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="flex min-w-0 flex-col gap-4">
          <Panel title="Timeline" eyebrow={`${data.timeline.length} events over ${Math.max(1, Math.round((new Date(data.last_seen).getTime() - new Date(data.first_seen).getTime()) / 1000))}s`}>
            <ol className="relative ml-2 border-l border-line-strong">
              {data.timeline.map((entry) => (
                <li key={entry.detection_id} className="relative pb-4 pl-5 last:pb-0">
                  <span className="absolute top-1.5 -left-[5px] size-2.5 rounded-full border-2 border-panel" style={{ background: severityColor[entry.severity] }} aria-hidden />
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                    <Mono className="text-fog">{clock(entry.timestamp)}</Mono>
                    <SeverityBadge severity={entry.severity} compact />
                    <Link href={`/detections/${entry.detection_id}`} className="text-sm text-frost hover:text-iris">{entry.title}</Link>
                    <Mono className="text-mist">risk {Math.round(entry.risk)}</Mono>
                    {entry.destination_port != null && <Mono className="text-fog">port {entry.destination_port}</Mono>}
                  </div>
                </li>
              ))}
            </ol>
          </Panel>
          <Panel title="Correlated detections" eyebrow={`${detections.length} detections`} bodyClassName="p-0">
            <DetectionTable detections={detections} emptyTitle="Detections were removed by retention" />
          </Panel>
          <Panel title="Actions taken" eyebrow="Response" bodyClassName="p-0">
            {data.actions?.length ? (
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead><tr><th scope="col">When</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Outcome</th><th scope="col">Detail</th></tr></thead>
                  <tbody>
                    {data.actions.map((action) => (
                      <tr key={action.decision_id}>
                        <td><Mono className="text-mist">{ago(action.decided_at)}</Mono></td>
                        <td className="whitespace-nowrap">{humanise(action.action)}</td>
                        <td><Mono>{action.target}</Mono></td>
                        <td><OutcomeBadge outcome={action.outcome} action={action.action} /></td>
                        <td className="text-mist">{action.error ?? action.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="px-4 py-3 text-sm text-mist">No response has been applied. Recommended action: <span className="font-mono text-frost">{humanise(data.recommended_action)}</span>.</p>
            )}
          </Panel>
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <Panel title="Risk assessment" eyebrow={data.risk.band}>
            <RiskBreakdown risk={data.risk} />
          </Panel>
          <Panel title="Affected systems">
            <KeyValue
              items={[
                ["Severity", <SeverityBadge key="s" severity={data.severity} />],
                ["Status", <StatusBadge key="st" status={data.status} />],
                ["Sources", <span key="src" className="flex flex-col gap-1">{data.affected_sources.map((source) => (
                  <span key={source} className="flex items-center justify-between gap-2">
                    <Mono>{source}</Mono>
                    {can("admin") && <button onClick={() => setBlockTarget(source)} className="inline-flex items-center gap-1 text-2xs text-sev-critical hover:underline"><Ban className="size-3" aria-hidden />Block</button>}
                  </span>
                ))}</span>],
                ["Targets", <Mono key="dst" className="break-all">{data.affected_destinations.join(", ") || "—"}</Mono>],
                ["Services", <Mono key="svc">{data.affected_services.join(", ") || "—"}</Mono>],
                ["Categories", data.categories.map(humanise).join(", ")],
                ["First seen", timestamp(data.first_seen)],
                ["Last seen", timestamp(data.last_seen)],
                ["Assigned", data.assigned_to ?? "Unassigned"],
              ]}
            />
          </Panel>
          <Panel title="Analyst notes">
            {/* Keyed by the saved notes: a fresh editor mounts whenever the stored value changes. */}
            <NotesEditor key={`${data.incident_id}:${data.notes ?? ""}`} initial={data.notes ?? ""} editable={can("analyst")} saving={saving} onSave={(notes) => void update({ notes }, "Notes saved")} />
          </Panel>
        </div>
      </div>
      <BlockDialog open={blockTarget !== null} onClose={() => setBlockTarget(null)} initialTarget={blockTarget ?? ""} initialReason={`Incident: ${data.title}`} onDone={() => void mutate()} />
      <Dialog
        open={closing !== null}
        onClose={() => setClosing(null)}
        title={closing === "false_positive" ? "Mark incident as false positive" : "Resolve incident"}
        footer={<><Button variant="ghost" onClick={() => setClosing(null)}>Keep {humanise(data.status)}</Button><Button variant="primary" loading={saving} onClick={async () => { if (closing && (await update({ status: closing }, `Status set to ${humanise(closing)}`))) setClosing(null); }}>{closing === "false_positive" ? "Mark as false positive" : "Resolve incident"}</Button></>}
      >
        <div className="flex flex-col gap-2 text-sm text-mist">
          <p>
            <span className="text-frost">{data.title}</span> changes from <span className="text-frost">{humanise(data.status)}</span> to <span className="text-frost">{humanise(closing)}</span> and moves to the Closed list on the Incidents page.
            {closing === "false_positive" ? " Use this when the detections were not an attack, so the record shows the alert was wrong." : " Use this when the activity has been dealt with."}
          </p>
          <p>The change is visible to everyone and can be reversed by setting the status again.</p>
        </div>
      </Dialog>
    </>
  );
}

function NotesEditor({ initial, editable, saving, onSave }: { initial: string; editable: boolean; saving: boolean; onSave: (notes: string) => void }) {
  const [notes, setNotes] = useState(initial);
  return (
    <>
      <Field label="Notes" htmlFor="notes" hint="Visible to everyone with access to this incident">
        <Textarea id="notes" rows={5} value={notes} onChange={(event) => setNotes(event.target.value)} disabled={!editable} maxLength={10_000} className="font-sans text-sm" />
      </Field>
      {editable && (
        <div className="mt-2 flex justify-end">
          <Button size="sm" variant="secondary" loading={saving} disabled={notes === initial} onClick={() => onSave(notes)}>Save notes</Button>
        </div>
      )}
    </>
  );
}
