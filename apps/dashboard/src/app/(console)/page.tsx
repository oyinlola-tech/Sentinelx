"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import useSWR from "swr";
import { SeverityTimeline, ShareBar, type TimelineBucket } from "@/components/charts/charts";
import { PageHeader } from "@/components/shell/page-header";
import { DetectionTable } from "@/components/views/detection-table";
import { SensorControl } from "@/components/views/sensor-control";
import { EmptyState, ErrorState, Panel, TableSkeleton } from "@/components/ui/primitives";
import { RiskScore, SeverityBadge } from "@/components/ui/security";
import { useEventRefresh, useEvents } from "@/lib/events";
import { ago, bandColor, bandFor, bytes, compact } from "@/lib/format";
import type { Analytics, Overview } from "@/lib/types";

export default function OverviewPage() {
  const { data, error, mutate, isLoading } = useSWR<Overview>("/stats/overview", { refreshInterval: 15_000 });
  const { data: analytics, mutate: mutateAnalytics } = useSWR<Analytics>("/stats/analytics?hours=6", { refreshInterval: 60_000 });
  const { subscribe } = useEvents();
  useEventRefresh(["detection.created", "incident.opened", "incident.updated", "ip.blocked", "ip.unblocked", "response.pending_approval"], () => {
    void mutate();
    void mutateAnalytics();
  });
  const live = useLiveStat(subscribe);

  if (error) return <div className="panel"><ErrorState error={error} onRetry={() => void mutate()} /></div>;

  return (
    <>
      <PageHeader title="Overview" description="What the sensor is seeing now, and what needs a decision." />
      <InstrumentStrip overview={data} livePps={live} loading={isLoading} />

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Detections, last 6 hours" eyebrow="Timeline" actions={<Link href="/analytics" className="text-xs text-iris hover:underline">Analytics</Link>}>
          {analytics ? (
            analytics.timeline.length ? <SeverityTimeline buckets={analytics.timeline as TimelineBucket[]} /> : <EmptyState title="Nothing detected in the last 6 hours">Replay a capture in the PCAP Lab to see the pipeline work end to end.</EmptyState>
          ) : (
            <TableSkeleton rows={4} columns={1} />
          )}
        </Panel>
        <Panel title="Sensor" eyebrow="Capture">
          <SensorControl />
          <div className="mt-4 border-t border-line pt-3">
            <p className="eyebrow mb-2">Protocol mix</p>
            <ShareBar shares={data?.protocols ?? {}} />
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Latest detections" eyebrow="Live" bodyClassName="p-0" actions={<Link href="/monitor" className="text-xs text-iris hover:underline">Live monitor</Link>}>
          {data ? (
            <DetectionTable compact detections={data.recent_detections} emptyTitle="No detections yet" emptyBody="When the sensor or a replay produces a detection, it appears here within a second." />
          ) : (
            <TableSkeleton />
          )}
        </Panel>
        <Panel title="Open incidents" eyebrow="Needs attention" bodyClassName="p-0" actions={<Link href="/incidents" className="text-xs text-iris hover:underline">All incidents</Link>}>
          {data?.top_incidents.length ? (
            <ul className="divide-y divide-line">
              {data.top_incidents.map((incident) => (
                <li key={incident.incident_id}>
                  <Link href={`/incidents/${incident.incident_id}`} className="flex items-start justify-between gap-3 px-4 py-3 hover:bg-raised">
                    <div className="min-w-0">
                      <p className="truncate text-sm text-frost">{incident.title}</p>
                      <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-mist">
                        <SeverityBadge severity={incident.severity} compact />
                        <span className="font-mono">{incident.affected_sources.slice(0, 2).join(", ")}</span>
                        <span>{incident.detection_count} detections, {ago(incident.last_seen)}</span>
                      </p>
                    </div>
                    <RiskScore score={incident.risk.score} />
                  </Link>
                </li>
              ))}
            </ul>
          ) : data ? (
            <EmptyState title="No open incidents">Incidents open when several related detections from one source arrive within the correlation window.</EmptyState>
          ) : (
            <TableSkeleton rows={3} columns={2} />
          )}
        </Panel>
      </div>
    </>
  );
}

/** Packets per second from live capture stats on the event stream (replays excluded). */
function useLiveStat(subscribe: ReturnType<typeof useEvents>["subscribe"]): number | null {
  const [pps, setPps] = useState<number | null>(null);
  useEffect(
    () =>
      subscribe(["packet.stats"], (event) => {
        const payload = event.payload as { kind?: string; packets_per_second?: number };
        if (payload.kind === "live") setPps(payload.packets_per_second ?? null);
      }),
    [subscribe],
  );
  return pps;
}

function InstrumentStrip({ overview, livePps, loading }: { overview?: Overview; livePps: number | null; loading: boolean }) {
  const risk = overview?.current_risk ?? 0;
  const readouts: { label: string; value: string; detail?: string; href?: string; tone?: string }[] = [
    { label: "Packets", value: compact(overview?.packets_processed), detail: bytes(overview?.bytes_processed) },
    { label: "Packets/s", value: livePps != null ? compact(livePps) : "—", detail: livePps != null ? "live capture" : "no live capture" },
    { label: "Connections", value: compact(overview?.active_flows), detail: `${compact(overview?.tracked_sources)} sources` },
    { label: "Detections", value: compact(overview?.detections_24h), detail: "last 24 hours", href: "/threats" },
    { label: "Critical", value: compact(overview?.critical_incidents), detail: `${compact(overview?.open_incidents)} incidents open`, href: "/incidents", tone: overview?.critical_incidents ? "text-sev-critical" : undefined },
    { label: "Blocked", value: compact(overview?.blocked_sources), detail: overview?.pending_approvals ? `${overview.pending_approvals} awaiting approval` : "sources", href: "/firewall" },
    { label: "Health", value: overview?.health ?? "—", tone: overview?.health === "ok" ? "text-ok" : overview?.health === "degraded" ? "text-sev-medium" : overview?.health ? "text-sev-critical" : undefined, href: "/settings#health" },
  ];
  return (
    <div className="panel grid grid-cols-2 divide-line sm:grid-cols-4 xl:grid-cols-8 xl:divide-x" aria-busy={loading}>
      <div className="col-span-2 flex items-center gap-4 border-b border-line px-4 py-3 sm:col-span-4 xl:col-span-1 xl:flex-col xl:items-start xl:justify-center xl:border-b-0">
        <p className="eyebrow">Current risk</p>
        <p className="font-display text-3xl font-semibold tabular" style={{ color: bandColor[bandFor(risk)] }}>{Math.round(risk)}</p>
        <p className="font-mono text-2xs text-fog">highest open incident</p>
      </div>
      {readouts.map((readout) => {
        const body = (
          <>
            <p className="eyebrow">{readout.label}</p>
            <p className={`mt-1 font-mono text-xl tabular ${readout.tone ?? "text-frost"}`}>{loading && !overview ? "…" : readout.value}</p>
            {readout.detail && <p className="mt-0.5 truncate text-2xs text-fog">{readout.detail}</p>}
          </>
        );
        return readout.href ? (
          <Link key={readout.label} href={readout.href} className="border-b border-line px-4 py-3 hover:bg-raised xl:border-b-0">{body}</Link>
        ) : (
          <div key={readout.label} className="border-b border-line px-4 py-3 xl:border-b-0">{body}</div>
        );
      })}
    </div>
  );
}
