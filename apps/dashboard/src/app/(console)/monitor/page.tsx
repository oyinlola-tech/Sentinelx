"use client";

import { Pause, Play, Trash2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { PageHeader } from "@/components/shell/page-header";
import { Button, EmptyState, Field, Input, Panel, Select } from "@/components/ui/primitives";
import { Mono, OutcomeBadge, RiskScore, SeverityBadge } from "@/components/ui/security";
import { useEvents } from "@/lib/events";
import { SEVERITIES, clock, compact, endpoint, humanise } from "@/lib/format";
import type { Detection, EventType, Incident, ResponseAction, Severity, StreamEvent } from "@/lib/types";

const FEED_TYPES: EventType[] = ["detection.created", "incident.opened", "incident.updated", "severity.changed", "ip.blocked", "ip.unblocked", "response.decided", "response.pending_approval", "sensor.status"];
const WINDOWS = [{ label: "Last 5 minutes", minutes: 5 }, { label: "Last 15 minutes", minutes: 15 }, { label: "Last hour", minutes: 60 }, { label: "Everything received", minutes: 0 }];

interface Filters { severity: Severity | ""; protocol: string; source: string; destination: string; detector: string; minutes: number; includeReplays: boolean }

export default function MonitorPage() {
  const { recent, subscribe, state } = useEvents();
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<StreamEvent[] | null>(null);
  const [cleared, setCleared] = useState<string | null>(null);
  const [stats, setStats] = useState<Record<string, number | string> | null>(null);
  const [filters, setFilters] = useState<Filters>({ severity: "", protocol: "", source: "", destination: "", detector: "", minutes: 15, includeReplays: true });
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => subscribe(["packet.stats"], (event) => setStats(event.payload as Record<string, number | string>)), [subscribe]);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(timer);
  }, []);

  const source = paused ? (frozen ?? recent) : recent;
  const cutoff = cleared ? new Date(cleared).getTime() : 0;
  const events = useMemo(() => {
    const since = filters.minutes ? now - filters.minutes * 60_000 : 0;
    return source.filter((event) => {
      if (!FEED_TYPES.includes(event.type)) return false;
      const time = new Date(event.timestamp).getTime();
      if (time < Math.max(since, cutoff)) return false;
      const payload = event.payload as Partial<Detection & Incident & ResponseAction & { network: string }>;
      if (!filters.includeReplays && payload.replay_id) return false;
      const sourceIp = payload.source_ip ?? payload.affected_sources?.join(" ") ?? payload.target ?? payload.network ?? "";
      if (filters.source && !sourceIp.includes(filters.source)) return false;
      if (filters.destination && !(payload.destination_ip ?? payload.affected_destinations?.join(" ") ?? "").includes(filters.destination)) return false;
      if (filters.severity && payload.severity !== filters.severity) return false;
      if (filters.protocol && payload.protocol !== filters.protocol) return false;
      if (filters.detector && !(payload.detector ?? "").includes(filters.detector)) return false;
      return true;
    });
  }, [source, filters, now, cutoff]);

  const set = <K extends keyof Filters>(key: K, value: Filters[K]) => setFilters((current) => ({ ...current, [key]: value }));
  const togglePause = () => {
    setFrozen(paused ? null : recent);
    setPaused(!paused);
  };

  return (
    <>
      <PageHeader
        title="Live monitor"
        description="Detections, incidents and response decisions as the pipeline produces them."
        actions={
          <>
            <Button size="sm" variant="secondary" icon={paused ? <Play className="size-3.5" /> : <Pause className="size-3.5" />} onClick={togglePause} aria-pressed={paused}>
              {paused ? "Resume feed" : "Pause feed"}
            </Button>
            <Button size="sm" variant="ghost" icon={<Trash2 className="size-3.5" />} onClick={() => setCleared(new Date().toISOString())}>
              Clear view
            </Button>
          </>
        }
      />

      <div className="panel mb-4 grid grid-cols-2 gap-px overflow-hidden bg-line sm:grid-cols-4 lg:grid-cols-6" aria-label="Pipeline statistics">
        {[
          ["Source", stats ? String(stats.source ?? "—") : "—"],
          ["Packets", compact(Number(stats?.frames ?? 0))],
          ["Packets / s", compact(Number(stats?.packets_per_second ?? 0))],
          ["Active flows", compact(Number(stats?.active_flows ?? 0))],
          ["Detections", compact(Number(stats?.detections ?? 0))],
          ["Stream", state],
        ].map(([label, value]) => (
          <div key={label} className="bg-panel px-4 py-2.5">
            <p className="eyebrow">{label}</p>
            <p className="truncate font-mono text-sm tabular text-frost">{value}</p>
          </div>
        ))}
      </div>

      <Panel bodyClassName="p-0">
        <form className="grid gap-3 border-b border-line p-3 sm:grid-cols-3 lg:grid-cols-7" onSubmit={(event) => event.preventDefault()} aria-label="Feed filters">
          <Field label="Severity" htmlFor="f-sev">
            <Select id="f-sev" value={filters.severity} onChange={(event) => set("severity", event.target.value as Severity | "")}>
              <option value="">Any</option>
              {SEVERITIES.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
            </Select>
          </Field>
          <Field label="Protocol" htmlFor="f-proto">
            <Select id="f-proto" value={filters.protocol} onChange={(event) => set("protocol", event.target.value)}>
              <option value="">Any</option>
              {["tcp", "udp", "icmp", "icmpv6", "arp"].map((protocol) => <option key={protocol} value={protocol}>{protocol.toUpperCase()}</option>)}
            </Select>
          </Field>
          <Field label="Source" htmlFor="f-src"><Input id="f-src" value={filters.source} onChange={(event) => set("source", event.target.value)} placeholder="203.0.113." className="font-mono" /></Field>
          <Field label="Destination" htmlFor="f-dst"><Input id="f-dst" value={filters.destination} onChange={(event) => set("destination", event.target.value)} placeholder="192.168." className="font-mono" /></Field>
          <Field label="Detector" htmlFor="f-det"><Input id="f-det" value={filters.detector} onChange={(event) => set("detector", event.target.value)} placeholder="port_scan" /></Field>
          <Field label="Time" htmlFor="f-time">
            <Select id="f-time" value={filters.minutes} onChange={(event) => set("minutes", Number(event.target.value))}>
              {WINDOWS.map((window) => <option key={window.minutes} value={window.minutes}>{window.label}</option>)}
            </Select>
          </Field>
          <label className="flex items-end gap-2 pb-2 text-sm text-mist">
            <input type="checkbox" checked={filters.includeReplays} onChange={(event) => set("includeReplays", event.target.checked)} className="size-4 accent-[var(--color-iris)]" />
            Include replays
          </label>
        </form>

        {events.length === 0 ? (
          <EmptyState title={paused ? "Feed paused" : "Waiting for events"}>
            {state === "open" ? (
              <>Nothing matches these filters yet. Start capture on the <Link className="text-iris hover:underline" href="/">Overview</Link>, or replay a capture in the <Link className="text-iris hover:underline" href="/lab">PCAP Lab</Link>.</>
            ) : (
              "The event stream is not connected. The view resumes automatically when it reconnects."
            )}
          </EmptyState>
        ) : (
          <ol className="divide-y divide-line" aria-live={paused ? "off" : "polite"} aria-relevant="additions">
            {events.slice(0, 200).map((event) => <FeedRow key={event.id} event={event} />)}
          </ol>
        )}
      </Panel>
    </>
  );
}

function FeedRow({ event }: { event: StreamEvent }) {
  const time = <Mono className="w-16 shrink-0 text-fog">{clock(event.timestamp)}</Mono>;
  const replay = (event.payload as { replay_id?: string | null }).replay_id ? <span className="rounded-sm border border-line-strong px-1 font-mono text-2xs text-fog">replay</span> : null;
  if (event.type === "detection.created") {
    const detection = event.payload as unknown as Detection;
    return (
      <li className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2 hover:bg-raised">
        {time}
        <SeverityBadge severity={detection.severity} />
        <RiskScore score={detection.risk.score} />
        <Link href={`/detections/${detection.detection_id}`} className="min-w-0 flex-1 truncate text-sm text-frost hover:text-iris">{detection.title}</Link>
        <Mono>{detection.source_ip}</Mono>
        <span className="text-fog" aria-hidden>→</span>
        <Mono className="text-mist">{endpoint(detection.destination_ip, detection.destination_port)}</Mono>
        <span className="w-full truncate pl-[4.75rem] text-xs text-mist sm:w-auto sm:pl-0">{detection.evidence[0]?.description}</span>
        {replay}
      </li>
    );
  }
  if (event.type === "incident.opened" || event.type === "incident.updated") {
    const incident = event.payload as unknown as Incident;
    return (
      <li className="flex flex-wrap items-center gap-3 border-l-2 border-iris bg-iris/5 px-4 py-2">
        {time}
        <span className="font-mono text-2xs uppercase text-iris">{event.type === "incident.opened" ? "Incident opened" : "Incident updated"}</span>
        <Link href={`/incidents/${incident.incident_id}`} className="min-w-0 flex-1 truncate text-sm font-medium text-frost hover:text-iris">{incident.title}</Link>
        <RiskScore score={incident.risk.score} />
        <span className="text-xs text-mist">{incident.detection_count} detections</span>
        {replay}
      </li>
    );
  }
  if (event.type === "response.decided" || event.type === "response.pending_approval") {
    const action = event.payload as unknown as ResponseAction & { risk?: number };
    return (
      <li className="flex flex-wrap items-center gap-3 px-4 py-2">
        {time}
        <OutcomeBadge outcome={event.type === "response.pending_approval" ? "pending_approval" : action.outcome} />
        <span className="text-sm text-frost">{humanise(action.action)} <Mono>{action.target}</Mono></span>
        <span className="min-w-0 flex-1 truncate text-xs text-mist">{action.reason}</span>
      </li>
    );
  }
  const payload = event.payload as { network?: string; reason?: string; state?: string; interface?: string };
  return (
    <li className="flex flex-wrap items-center gap-3 px-4 py-2 text-sm">
      {time}
      <span className="font-mono text-2xs uppercase text-mist">{event.type.replace(".", " ")}</span>
      <span className="text-frost">{payload.network ?? payload.interface ?? payload.state}</span>
      <span className="truncate text-xs text-mist">{payload.reason}</span>
    </li>
  );
}
