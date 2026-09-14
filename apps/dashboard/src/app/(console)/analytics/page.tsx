"use client";

import { useState } from "react";
import useSWR from "swr";
import { BarList, LineSeries, SeverityTimeline, type TimelineBucket } from "@/components/charts/charts";
import { PageHeader } from "@/components/shell/page-header";
import { EmptyState, ErrorState, Panel, Select, TableSkeleton } from "@/components/ui/primitives";
import { Mono } from "@/components/ui/security";
import { useEventRefresh } from "@/lib/events";
import { bytes, humanise, num } from "@/lib/format";
import type { Analytics } from "@/lib/types";

const RANGES = [{ label: "6 hours", hours: 6 }, { label: "24 hours", hours: 24 }, { label: "7 days", hours: 168 }, { label: "30 days", hours: 720 }];

export default function AnalyticsPage() {
  const [hours, setHours] = useState(24);
  const { data, error, mutate } = useSWR<Analytics>(`/stats/analytics?hours=${hours}`, { refreshInterval: 60_000 });
  useEventRefresh(["detection.created"], () => void mutate(), 10_000);

  if (error) return <div className="panel"><ErrorState error={error} onRetry={() => void mutate()} /></div>;
  const reviewed = data?.reviewed ?? 0;

  return (
    <>
      <PageHeader
        title="Analytics"
        description="Trends in live detections. Replays are excluded so lab work never skews these numbers."
        actions={
          <Select aria-label="Time range" value={hours} onChange={(event) => setHours(Number(event.target.value))} className="w-36">
            {RANGES.map((range) => <option key={range.hours} value={range.hours}>Last {range.label}</option>)}
          </Select>
        }
      />
      <div className="panel mb-4 grid grid-cols-2 gap-px overflow-hidden bg-line sm:grid-cols-4">
        {[
          ["Detections", num(data?.detections)],
          ["Mean risk", data?.mean_risk != null ? num(data.mean_risk) : "—"],
          ["Reviewed", num(reviewed)],
          ["False positive rate", data?.false_positive_rate != null ? `${(data.false_positive_rate * 100).toFixed(1)}%` : "—"],
        ].map(([label, value]) => (
          <div key={label} className="bg-panel px-4 py-3">
            <p className="eyebrow">{label}</p>
            <p className="mt-1 font-mono text-lg tabular text-frost">{data ? value : "…"}</p>
          </div>
        ))}
      </div>
      {data && data.false_positive_rate == null && (
        <p className="mb-4 text-xs text-fog">The false positive rate needs reviewed detections. Mark detections as acknowledged, resolved or false positive to start measuring it; unreviewed alerts are never counted as correct.</p>
      )}

      <Panel title="Detection trend" eyebrow={data ? `${data.bucket_minutes}-minute intervals, by severity` : "Loading"}>
        {!data ? <TableSkeleton rows={4} columns={1} /> : data.timeline.length ? <SeverityTimeline buckets={data.timeline as TimelineBucket[]} height={220} /> : <EmptyState title="No live detections in this period" />}
      </Panel>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Panel title="Threat categories">
          {data ? <BarList items={data.by_category.map((row) => ({ key: row.key ?? "unknown", value: row.count, label: humanise(row.key) }))} /> : <TableSkeleton rows={4} columns={2} />}
        </Panel>
        <Panel title="Severity distribution">
          {data ? <BarList items={["critical", "high", "medium", "low", "info"].map((severity) => ({ key: severity, value: data.by_severity.find((row) => row.key === severity)?.count ?? 0, label: <span className="capitalize">{severity}</span> })).filter((item) => item.value > 0)} /> : <TableSkeleton rows={4} columns={2} />}
        </Panel>
        <Panel title="Protocols">
          {data ? <BarList items={data.by_protocol.map((row) => ({ key: row.key ?? "unknown", value: row.count, label: (row.key ?? "unknown").toUpperCase() }))} /> : <TableSkeleton rows={4} columns={2} />}
        </Panel>
        <Panel title="Top sources">
          {data ? <BarList items={data.top_sources.map((row) => ({ key: row.key ?? "unknown", value: row.count, label: <span className="font-mono text-xs">{row.key}</span> }))} /> : <TableSkeleton rows={4} columns={2} />}
        </Panel>
        <Panel title="Top destinations">
          {data ? <BarList items={data.top_destinations.filter((row) => row.key).map((row) => ({ key: row.key!, value: row.count, label: <span className="font-mono text-xs">{row.key}</span> }))} /> : <TableSkeleton rows={4} columns={2} />}
        </Panel>
        <Panel title="Detections by detector">
          {data ? <BarList items={data.by_detector.map((row) => ({ key: row.key ?? "unknown", value: row.count, label: humanise(row.key) }))} /> : <TableSkeleton rows={4} columns={2} />}
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Panel title="Detector performance" eyebrow="Since the server started" bodyClassName="p-0">
          {!data ? <TableSkeleton /> : (
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead><tr><th scope="col">Detector</th><th scope="col">Enabled</th><th scope="col">Evaluations</th><th scope="col">Hits</th><th scope="col">Hit rate</th><th scope="col">Mean eval</th></tr></thead>
                <tbody>
                  {data.detector_performance.map((row) => (
                    <tr key={row.name}>
                      <td>{humanise(row.name)}</td>
                      <td>{row.enabled ? <span className="text-ok">yes</span> : <span className="text-fog">no</span>}</td>
                      <td><Mono>{num(row.evaluations)}</Mono></td>
                      <td><Mono>{num(row.hits)}</Mono></td>
                      <td><Mono className="text-mist">{row.evaluations ? `${((row.hits / row.evaluations) * 100).toFixed(2)}%` : "—"}</Mono></td>
                      <td><Mono className="text-mist">{row.mean_eval_microseconds != null ? `${num(row.mean_eval_microseconds)} µs` : "—"}</Mono></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <Panel title="Sensor memory" eyebrow="Measured per minute during live capture">
          {data ? <LineSeries label="Resident memory" format={bytes} points={data.system.map((row) => ({ t: row.timestamp, v: row.memory_bytes }))} /> : <TableSkeleton rows={3} columns={1} />}
        </Panel>
      </div>
    </>
  );
}
