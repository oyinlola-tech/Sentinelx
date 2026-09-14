"use client";

import { ArrowLeft, Ban } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { BlockDialog } from "@/components/views/block-dialog";
import { DetectionTable } from "@/components/views/detection-table";
import { Button, ErrorState, Field, KeyValue, Panel, Select, Skeleton, Textarea } from "@/components/ui/primitives";
import { Mono, OutcomeBadge, RiskBreakdown, SeverityBadge, StatusBadge } from "@/components/ui/security";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { ago, clock, humanise, severityColor, timestamp } from "@/lib/format";
import { useSession } from "@/lib/session";
import type { Incident, IncidentStatus } from "@/lib/types";

const STATUSES: IncidentStatus[] = ["open", "investigating", "contained", "resolved", "false_positive"];

export default function IncidentPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { can, user } = useSession();
  const toast = useToast();
  const { data, error, mutate } = useSWR<Incident>(`/incidents/${id}`);
  useEventRefresh(["incident.updated", "severity.changed", "response.decided", "ip.blocked"], () => void mutate());
  const [blockTarget, setBlockTarget] = useState<string | null>(null);
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  useEffect(() => setNotes(data?.notes ?? ""), [data?.notes]);

  if (error instanceof ApiError && error.status === 404) return <div className="panel"><ErrorState error={new Error("This incident no longer exists.")} /></div>;
  if (error) return <div className="panel"><ErrorState error={error} onRetry={() => void mutate()} /></div>;
  if (!data) return <div className="flex flex-col gap-4"><Skeleton className="h-10 w-1/2" /><Skeleton className="h-72" /></div>;

  async function update(changes: Partial<Pick<Incident, "status" | "assigned_to" | "notes">>, message: string) {
    setSaving(true);
    try {
      await mutate(api<Incident>(`/incidents/${id}`, { method: "PATCH", json: changes }).then((updated) => ({ ...data!, ...updated })), { revalidate: true });
      toast("success", message);
    } catch (caught) {
      toast("error", "Could not update the incident", caught instanceof Error ? caught.message : undefined);
    } finally {
      setSaving(false);
    }
  }

  const detections = data.detections ?? [];
  return (
    <>
      <button onClick={() => router.back()} className="mb-3 inline-flex items-center gap-1 text-xs text-mist hover:text-frost">
        <ArrowLeft className="size-3.5" aria-hidden /> Back
      </button>
      <PageHeader
        eyebrow={`Incident · ${humanise(data.correlation_rule)}`}
        title={data.title}
        description={data.summary}
        actions={
          <>
            {can("analyst") && (
              <Select aria-label="Incident status" value={data.status} disabled={saving} onChange={(event) => void update({ status: event.target.value as IncidentStatus }, `Status set to ${humanise(event.target.value)}`)} className="w-44">
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
              <table className="data-table">
                <thead><tr><th scope="col">When</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Outcome</th><th scope="col">Detail</th></tr></thead>
                <tbody>
                  {data.actions.map((action) => (
                    <tr key={action.decision_id}>
                      <td><Mono className="text-mist">{ago(action.decided_at)}</Mono></td>
                      <td>{humanise(action.action)}</td>
                      <td><Mono>{action.target}</Mono></td>
                      <td><OutcomeBadge outcome={action.outcome} /></td>
                      <td className="text-mist">{action.error ?? action.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
            <Field label="Notes" htmlFor="notes" hint="Visible to everyone with access to this incident">
              <Textarea id="notes" rows={5} value={notes} onChange={(event) => setNotes(event.target.value)} disabled={!can("analyst")} maxLength={10_000} className="font-sans text-sm" />
            </Field>
            {can("analyst") && (
              <div className="mt-2 flex justify-end">
                <Button size="sm" variant="secondary" loading={saving} disabled={notes === (data.notes ?? "")} onClick={() => void update({ notes }, "Notes saved")}>Save notes</Button>
              </div>
            )}
          </Panel>
        </div>
      </div>
      <BlockDialog open={blockTarget !== null} onClose={() => setBlockTarget(null)} initialTarget={blockTarget ?? ""} initialReason={`Incident: ${data.title}`} onDone={() => void mutate()} />
    </>
  );
}
