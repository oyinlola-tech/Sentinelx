"use client";

import useSWR from "swr";
import { BarList, LineSeries, ShareBar } from "@/components/charts/charts";
import { PageHeader } from "@/components/shell/page-header";
import { SensorControl } from "@/components/views/sensor-control";
import { EmptyState, ErrorState, Panel, TableSkeleton } from "@/components/ui/primitives";
import { Mono } from "@/components/ui/security";
import { useEventRefresh } from "@/lib/events";
import { bytes, compact, num } from "@/lib/format";
import type { NetworkStats } from "@/lib/types";

export default function NetworkPage() {
  const { data, error, mutate } = useSWR<NetworkStats>("/stats/network", { refreshInterval: 10_000 });
  useEventRefresh(["sensor.status"], () => void mutate(), 5000);
  if (error) return <div className="panel"><ErrorState error={error} onRetry={() => void mutate()} /></div>;

  const state = data?.state;
  return (
    <>
      <PageHeader title="Network" description="Interfaces, the traffic the sensor has processed, and the hosts generating most of it." />
      <div className="panel mb-4 grid grid-cols-2 gap-px overflow-hidden bg-line sm:grid-cols-4">
        {[
          ["Packets processed", compact(state?.packets)],
          ["Bytes processed", bytes(state?.bytes)],
          ["Active flows", compact(state?.active_flows)],
          ["Tracked sources", compact(state?.tracked_sources)],
        ].map(([label, value]) => (
          <div key={label} className="bg-panel px-4 py-3">
            <p className="eyebrow">{label}</p>
            <p className="mt-1 font-mono text-lg tabular text-frost">{data ? value : "…"}</p>
          </div>
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Panel title="Traffic rate" eyebrow="Per-minute summaries, last 24 hours">
          {data ? (
            <LineSeries label="Packets per second" format={(value) => `${num(value)} pkt/s`} points={data.traffic.map((row) => ({ t: row.bucket_start, v: row.packets_per_second }))} />
          ) : <TableSkeleton rows={3} columns={1} />}
          <p className="mt-2 text-xs text-fog">Summaries are recorded while live capture runs. Replays do not add to traffic history.</p>
        </Panel>
        <Panel title="Capture" eyebrow="Sensor">
          <SensorControl />
          <div className="mt-4 border-t border-line pt-3">
            <p className="eyebrow mb-2">Protocol distribution</p>
            <ShareBar shares={data?.protocols ?? {}} />
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Panel title="Top sources" eyebrow="By packets in the detection window">
          {data ? <BarList items={data.top_sources.map((row) => ({ key: row.source_ip, value: row.packets, label: <span className="font-mono text-xs">{row.source_ip} <span className="text-fog">· {row.unique_dst_ports} ports · {row.unique_dst_ips} hosts</span></span> }))} empty="No traffic tracked yet." /> : <TableSkeleton rows={5} columns={2} />}
        </Panel>
        <Panel title="Top destinations" eyebrow="By packets across active flows">
          {data ? <BarList items={data.top_destinations.map((row) => ({ key: row.destination_ip, value: row.packets, label: <span className="font-mono text-xs">{row.destination_ip} <span className="text-fog">· {row.flows} flows</span></span> }))} empty="No traffic tracked yet." /> : <TableSkeleton rows={5} columns={2} />}
        </Panel>
      </div>

      <Panel title="Interfaces" className="mt-4" bodyClassName="p-0">
        {!data ? <TableSkeleton /> : !data.interfaces.length ? <EmptyState title="No interfaces reported">Interface enumeration reads /sys/class/net, which is only available on Linux.</EmptyState> : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead><tr><th scope="col">Name</th><th scope="col">State</th><th scope="col">Addresses</th><th scope="col">MAC</th><th scope="col">MTU</th><th scope="col">RX packets</th><th scope="col">TX packets</th><th scope="col">RX bytes</th><th scope="col">RX dropped</th></tr></thead>
              <tbody>
                {data.interfaces.map((entry) => (
                  <tr key={entry.name}>
                    <td><Mono>{entry.name}</Mono>{entry.is_loopback && <span className="ml-2 text-2xs text-fog">loopback</span>}</td>
                    <td><span className={entry.state === "up" ? "text-ok" : "text-mist"}>{entry.state}</span></td>
                    <td><Mono className="text-mist">{entry.addresses.join(", ") || "—"}</Mono></td>
                    <td><Mono className="text-fog">{entry.mac ?? "—"}</Mono></td>
                    <td><Mono>{entry.mtu}</Mono></td>
                    <td><Mono>{compact(entry.statistics.rx_packets)}</Mono></td>
                    <td><Mono>{compact(entry.statistics.tx_packets)}</Mono></td>
                    <td><Mono>{bytes(entry.statistics.rx_bytes)}</Mono></td>
                    <td><Mono className={entry.statistics.rx_dropped ? "text-sev-medium" : ""}>{compact(entry.statistics.rx_dropped)}</Mono></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
