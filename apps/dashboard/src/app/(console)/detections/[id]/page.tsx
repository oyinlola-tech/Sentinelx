"use client";

import { ArrowLeft, Ban, CheckCheck, CircleSlash, Eye } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { BlockDialog } from "@/components/views/block-dialog";
import { Button, ErrorState, KeyValue, Panel, Skeleton } from "@/components/ui/primitives";
import { EvidenceList, Mono, OutcomeBadge, RiskBreakdown, SeverityBadge, StatusBadge } from "@/components/ui/security";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api";
import { ago, endpoint, humanise, num, timestamp } from "@/lib/format";
import { useSession } from "@/lib/session";
import type { Detection, DetectionStatus } from "@/lib/types";

export default function DetectionPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const { can } = useSession();
  const toast = useToast();
  const { data, error, mutate } = useSWR<Detection>(`/detections/${id}`);
  const [blockOpen, setBlockOpen] = useState(false);
  const [busy, setBusy] = useState<DetectionStatus | null>(null);

  if (error instanceof ApiError && error.status === 404) {
    return <div className="panel"><ErrorState error={new Error("This detection no longer exists. It may have been removed by the retention policy.")} /></div>;
  }
  if (error) return <div className="panel"><ErrorState error={error} onRetry={() => void mutate()} /></div>;
  if (!data) return <div className="flex flex-col gap-4"><Skeleton className="h-10 w-2/3" /><Skeleton className="h-64" /></div>;

  async function triage(status: DetectionStatus) {
    setBusy(status);
    try {
      await mutate(api<Detection>(`/detections/${id}`, { method: "PATCH", json: { status } }), { revalidate: false });
      toast("success", `Marked as ${humanise(status)}`);
    } catch (caught) {
      toast("error", "Could not update the detection", caught instanceof Error ? caught.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <button onClick={() => router.back()} className="mb-3 inline-flex items-center gap-1 text-xs text-mist hover:text-frost">
        <ArrowLeft className="size-3.5" aria-hidden /> Back
      </button>
      <PageHeader
        eyebrow={`Detection · ${humanise(data.category)}`}
        title={data.title}
        description={data.description}
        actions={
          <>
            {can("analyst") && (
              <>
                <Button size="sm" variant="ghost" icon={<Eye className="size-3.5" />} loading={busy === "acknowledged"} onClick={() => void triage("acknowledged")} disabled={data.status === "acknowledged"}>Acknowledge</Button>
                <Button size="sm" variant="ghost" icon={<CircleSlash className="size-3.5" />} loading={busy === "false_positive"} onClick={() => void triage("false_positive")} disabled={data.status === "false_positive"}>False positive</Button>
                <Button size="sm" variant="ghost" icon={<CheckCheck className="size-3.5" />} loading={busy === "resolved"} onClick={() => void triage("resolved")} disabled={data.status === "resolved"}>Resolve</Button>
              </>
            )}
            {can("admin") && <Button size="sm" variant="danger" icon={<Ban className="size-3.5" />} onClick={() => setBlockOpen(true)}>Block source</Button>}
          </>
        }
      />

      <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="flex min-w-0 flex-col gap-4">
          <Panel title="Evidence" eyebrow={`${data.evidence.length} observations`}>
            <EvidenceList evidence={data.evidence} />
          </Panel>
          <Panel title="Response decisions" eyebrow="What SentinelX did" bodyClassName="p-0">
            {data.actions?.length ? (
              <table className="data-table">
                <thead><tr><th scope="col">When</th><th scope="col">Action</th><th scope="col">Outcome</th><th scope="col">Reason</th></tr></thead>
                <tbody>
                  {data.actions.map((action) => (
                    <tr key={action.decision_id}>
                      <td><Mono className="text-mist">{ago(action.decided_at)}</Mono></td>
                      <td className="whitespace-nowrap">{humanise(action.action)}</td>
                      <td><OutcomeBadge outcome={action.outcome} /></td>
                      <td className="text-mist">{action.error ?? action.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <p className="px-4 py-3 text-sm text-mist">
                No preventive action was recorded. Recommended action: <span className="font-mono text-frost">{humanise(data.recommended_action)}</span>.
              </p>
            )}
          </Panel>
        </div>
        <div className="flex min-w-0 flex-col gap-4">
          <Panel title="Risk assessment" eyebrow={data.risk.band}>
            <RiskBreakdown risk={data.risk} />
          </Panel>
          <Panel title="Context">
            <KeyValue
              items={[
                ["Severity", <SeverityBadge key="s" severity={data.severity} />],
                ["Confidence", `${Math.round(data.confidence * 100)}%`],
                ["Status", data.status ? <StatusBadge key="st" status={data.status} /> : "—"],
                ["Source", <Mono key="src">{endpoint(data.source_ip, data.source_port)}</Mono>],
                ["Target", <Mono key="dst">{endpoint(data.destination_ip, data.destination_port)}</Mono>],
                ["Protocol", data.protocol?.toUpperCase() ?? "—"],
                ["Detector", <span key="d" className="font-mono text-xs">{data.detector}</span>],
                ["Rule", data.rule_name ?? "built-in"],
                ["Window", data.observation_window_seconds != null ? `${num(data.observation_window_seconds)} s` : "—"],
                ["Packets", num(data.packet_count)],
                ["Detected", timestamp(data.timestamp)],
                ["Incident", data.incident_id ? <Link key="i" href={`/incidents/${data.incident_id}`} className="text-iris hover:underline">View incident</Link> : "Not correlated"],
                ["Reviewed", data.reviewed_by ? `by ${data.reviewed_by}` : "Not yet"],
                ...(data.replay_id ? [["Replay", <Link key="r" href={`/lab?replay=${data.replay_id}`} className="text-iris hover:underline">From a PCAP replay</Link>] as [string, React.ReactNode]] : []),
              ]}
            />
          </Panel>
        </div>
      </div>
      <BlockDialog open={blockOpen} onClose={() => setBlockOpen(false)} initialTarget={data.source_ip} initialReason={`${data.title} (risk ${Math.round(data.risk.score)})`} onDone={() => void mutate()} />
    </>
  );
}
