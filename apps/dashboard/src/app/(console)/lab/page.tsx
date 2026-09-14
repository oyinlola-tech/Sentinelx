"use client";

import { FilePlus2, Play, Upload, X } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { DetectionTable } from "@/components/views/detection-table";
import { Button, EmptyState, ErrorState, Field, KeyValue, Panel, Select, TableSkeleton } from "@/components/ui/primitives";
import { Mono, OutcomeBadge, RiskScore, SeverityBadge } from "@/components/ui/security";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import { useEvents } from "@/lib/events";
import { ago, bytes, humanise, num } from "@/lib/format";
import { useSession } from "@/lib/session";
import type { PcapFile, ReplayRequest, ReplayRun } from "@/lib/types";

interface ScenarioInfo { name: string; description: string }
interface Progress { replay_id: string; frames: number; packets_per_second: number; detections: number; incidents: number; elapsed_seconds: number }

export default function LabPage() {
  return (
    <Suspense fallback={<TableSkeleton />}>
      <Lab />
    </Suspense>
  );
}

function Lab() {
  const { can } = useSession();
  const toast = useToast();
  const router = useRouter();
  const params = useSearchParams();
  const selected = params.get("replay");
  const { subscribe } = useEvents();
  const { data: files, mutate: mutateFiles } = useSWR<PcapFile[]>("/replay/files");
  const { data: scenarios } = useSWR<ScenarioInfo[]>("/replay/scenarios");
  const { data: runs, mutate: mutateRuns, error: runsError } = useSWR<ReplayRun[]>("/replay?limit=20");
  const [chosenPath, setPath] = useState("");
  const path = chosenPath || files?.[0]?.path || "";
  const [scenario, setScenario] = useState("mixed_intrusion");
  const [speed, setSpeed] = useState(0);
  const [busy, setBusy] = useState<"upload" | "generate" | "start" | null>(null);
  const [progress, setProgress] = useState<Record<string, Progress>>({});
  const fileInput = useRef<HTMLInputElement>(null);

  useEffect(
    () =>
      subscribe(["replay.progress", "replay.completed"], (event) => {
        const payload = event.payload as unknown as Progress & { status?: string };
        if (event.type === "replay.progress") setProgress((current) => ({ ...current, [payload.replay_id]: payload }));
        else void mutateRuns();
      }),
    [subscribe, mutateRuns],
  );

  async function upload(file: File) {
    setBusy("upload");
    try {
      const form = new FormData();
      form.append("file", file);
      const csrf = document.cookie.split("; ").find((part) => part.startsWith("sx_csrf="))?.slice(8) ?? "";
      const response = await fetch("/api/v1/replay/upload", { method: "POST", body: form, headers: { "X-CSRF-Token": decodeURIComponent(csrf), "X-SentinelX-Client": "dashboard" }, credentials: "same-origin" });
      const body = (await response.json()) as { path?: string; packet_count?: number; detail?: string };
      if (!response.ok) throw new Error(body.detail ?? `Upload failed (${response.status})`);
      toast("success", `Uploaded ${file.name}`, `${num(body.packet_count)} packets`);
      await mutateFiles();
      if (body.path) setPath(body.path);
    } catch (error) {
      toast("error", "Upload rejected", error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(null);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  async function generate() {
    setBusy("generate");
    try {
      const result = await api<{ path: string; packets: number; expected_detectors: string[] }>(`/replay/scenarios/${scenario}`, { method: "POST", json: {} });
      toast("success", `Generated ${result.path}`, `${num(result.packets)} packets · a correct engine should report: ${result.expected_detectors.map(humanise).join(", ") || "nothing (benign traffic)"}`);
      await mutateFiles();
      setPath(result.path);
    } catch (error) {
      toast("error", "Could not generate the capture", error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  async function start() {
    setBusy("start");
    try {
      const run = await api<{ replay_id: string }>("/replay", { method: "POST", json: { path, speed } satisfies ReplayRequest });
      await mutateRuns();
      router.replace(`/lab?replay=${run.replay_id}`);
    } catch (error) {
      toast("error", "Replay did not start", error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <PageHeader title="PCAP Lab" description="Replay a capture through exactly the pipeline that watches live traffic. Responses are always simulated here; a replay never changes the firewall." />
      <div className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
        <div className="flex min-w-0 flex-col gap-4">
          <Panel title="Choose a capture" eyebrow="Input">
            <div className="flex flex-col gap-4">
              <Field label="Capture file" htmlFor="lab-file" hint={files && !files.length ? "No captures yet: upload one or generate a test fixture below." : undefined}>
                <Select id="lab-file" value={path} onChange={(event) => setPath(event.target.value)} disabled={!files?.length}>
                  {files?.map((file) => <option key={file.path} value={file.path}>{file.path} · {bytes(file.size_bytes)}</option>)}
                </Select>
              </Field>
              <Field label="Replay speed" htmlFor="lab-speed" hint="Unpaced is fastest and what benchmarks use. Original timing lets you watch detections arrive.">
                <Select id="lab-speed" value={speed} onChange={(event) => setSpeed(Number(event.target.value))}>
                  <option value={0}>Unpaced</option>
                  <option value={1}>Original timing</option>
                  <option value={5}>5× original</option>
                </Select>
              </Field>
              {can("analyst") && (
                <Button variant="primary" icon={<Play className="size-4" />} loading={busy === "start"} disabled={!path} onClick={() => void start()}>Replay capture</Button>
              )}
            </div>
          </Panel>
          {can("analyst") && (
            <Panel title="Add a capture" eyebrow="Sources">
              <div className="flex flex-col gap-4">
                <div>
                  <input ref={fileInput} type="file" accept=".pcap,.pcapng,.cap" className="sr-only" id="lab-upload" onChange={(event) => { const file = event.target.files?.[0]; if (file) void upload(file); }} />
                  <Button variant="secondary" icon={<Upload className="size-4" />} loading={busy === "upload"} onClick={() => fileInput.current?.click()}>Upload pcap or pcapng</Button>
                  <p className="mt-1.5 text-xs text-fog">Files are checked for a capture signature and stored under a random name.</p>
                </div>
                <div className="border-t border-line pt-4">
                  <Field label="Generate a synthetic test fixture" htmlFor="lab-scenario" hint="Built in memory and written to a file. Nothing is sent on the network.">
                    <Select id="lab-scenario" value={scenario} onChange={(event) => setScenario(event.target.value)}>
                      {scenarios?.map((item) => <option key={item.name} value={item.name}>{humanise(item.name)}</option>)}
                    </Select>
                  </Field>
                  <p className="mt-1 text-xs text-mist">{scenarios?.find((item) => item.name === scenario)?.description}</p>
                  <Button className="mt-2" variant="secondary" icon={<FilePlus2 className="size-4" />} loading={busy === "generate"} onClick={() => void generate()}>Generate fixture</Button>
                </div>
              </div>
            </Panel>
          )}
          <Panel title="Recent replays" bodyClassName="p-0">
            {runsError ? <ErrorState error={runsError} /> : !runs ? <TableSkeleton rows={3} columns={3} /> : !runs.length ? <EmptyState title="No replays yet" /> : (
              <ul className="divide-y divide-line">
                {runs.map((run) => {
                  const live = progress[run.replay_id];
                  return (
                    <li key={run.replay_id}>
                      <Link href={`/lab?replay=${run.replay_id}`} aria-current={selected === run.replay_id ? "true" : undefined} className={`flex items-center justify-between gap-3 px-4 py-2.5 hover:bg-raised ${selected === run.replay_id ? "bg-raised" : ""}`}>
                        <span className="min-w-0">
                          <span className="block truncate text-sm text-frost">{run.filename}</span>
                          <span className="block text-xs text-mist">{ago(run.created_at)} · {run.created_by}{run.summary?.detection_count != null ? ` · ${run.summary.detection_count} detections` : ""}</span>
                        </span>
                        <RunStatus status={run.status} live={live} />
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </Panel>
        </div>
        <div className="min-w-0">{selected ? <ReplayReportView id={selected} live={progress[selected]} onClose={() => router.replace("/lab")} /> : (
          <Panel><EmptyState title="Choose or start a replay">The report shows packets processed, measured throughput and latency, resource use, and every detection, incident and simulated response.</EmptyState></Panel>
        )}</div>
      </div>
    </>
  );
}

function RunStatus({ status, live }: { status: ReplayRun["status"]; live?: Progress }) {
  const tone = { queued: "text-mist", running: "text-iris", completed: "text-ok", failed: "text-sev-high", cancelled: "text-fog" }[status];
  return <span className={`shrink-0 font-mono text-2xs uppercase ${tone}`}>{status === "running" && live ? `${num(live.frames)} pkts` : status}</span>;
}

function ReplayReportView({ id, live, onClose }: { id: string; live?: Progress; onClose: () => void }) {
  const toast = useToast();
  const { can } = useSession();
  const { data: run, error, mutate } = useSWR<ReplayRun>(`/replay/${id}`, { refreshInterval: (latest) => (latest && ["queued", "running"].includes(latest.status) ? 1000 : 0) });
  useEffect(() => {
    if (live && run?.status === "running") void mutate();
  }, [live, run?.status, mutate]);
  if (error) return <Panel><ErrorState error={error} onRetry={() => void mutate()} /></Panel>;
  if (!run) return <Panel><TableSkeleton /></Panel>;

  const report = run.report;
  const running = run.status === "running" || run.status === "queued";
  async function cancel() {
    try {
      await api(`/replay/${id}/cancel`, { method: "POST" });
      toast("info", "Cancelling replay");
      await mutate();
    } catch (caught) {
      toast("error", "Could not cancel", caught instanceof Error ? caught.message : undefined);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Panel
        eyebrow={`Replay · ${run.status}`}
        title={run.filename}
        actions={
          <>
            {running && can("analyst") && <Button size="sm" variant="ghost" onClick={() => void cancel()}>Cancel</Button>}
            <Button size="sm" variant="ghost" icon={<X className="size-3.5" />} onClick={onClose} aria-label="Close report" />
          </>
        }
      >
        {running ? (
          <div role="status" aria-live="polite">
            <p className="text-sm text-mist">Replaying… {live ? `${num(live.frames)} packets · ${num(live.packets_per_second)} packets/s · ${live.detections} detections · ${live.incidents} incidents` : "starting"}</p>
            <div className="mt-3 h-1 overflow-hidden rounded-full bg-line"><div className="h-full w-1/3 animate-pulse rounded-full bg-iris" /></div>
          </div>
        ) : run.status === "failed" ? (
          <p className="rounded-md border border-sev-high/40 bg-sev-high/10 px-3 py-2 text-sm text-sev-high">{run.error ?? "The replay failed."}</p>
        ) : report && report.frames != null ? (
          <div className="grid gap-4 sm:grid-cols-2">
            <KeyValue items={[
              ["Packets processed", num(report.frames)],
              ["Throughput", `${num(report.packets_per_second)} packets/s`],
              ["Wall time", `${num(report.wall_seconds)} s`],
              ["Capture span", `${num(report.capture_span_seconds)} s`],
              ["Decode failures", num(report.decode_failures)],
            ]} />
            <KeyValue items={[
              ["Detections", num(report.detection_count)],
              ["Incidents", num(report.incident_count)],
              ["Per-packet latency", `p50 ${report.latency.per_packet_p50_ms} ms · p99 ${report.latency.per_packet_p99_ms} ms`],
              ["Detection latency", `${report.latency.detection_mean_ms} ms mean · ${report.latency.detection_max_ms} ms max`],
              ["CPU / memory", `${report.resources.cpu_percent_mean}% mean · ${report.resources.memory_peak_mb} MB peak`],
            ]} />
            <p className="text-xs text-fog sm:col-span-2">All figures were measured during this run on this server. {report.safety_note}</p>
          </div>
        ) : <p className="text-sm text-mist">No report was recorded.</p>}
      </Panel>

      {report?.incidents?.length ? (
        <Panel title="Incidents" bodyClassName="p-0">
          <ul className="divide-y divide-line">
            {report.incidents.map((incident) => (
              <li key={incident.incident_id}>
                <Link href={`/incidents/${incident.incident_id}`} className="flex items-center justify-between gap-3 px-4 py-3 hover:bg-raised">
                  <span className="min-w-0">
                    <span className="block text-sm text-frost">{incident.title}</span>
                    <span className="mt-1 flex items-center gap-2 text-xs text-mist"><SeverityBadge severity={incident.severity} compact />{incident.detection_count} detections · {incident.affected_sources.join(", ")}</span>
                  </span>
                  <RiskScore score={incident.risk.score} />
                </Link>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}

      {report?.decisions?.length ? (
        <Panel title="Response decisions" eyebrow="Simulated" bodyClassName="p-0">
          <table className="data-table">
            <thead><tr><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Outcome</th><th scope="col">Reason</th></tr></thead>
            <tbody>
              {report.decisions.map((decision) => (
                <tr key={decision.decision_id}>
                  <td className="whitespace-nowrap">{humanise(decision.action)}</td>
                  <td><Mono>{decision.target}</Mono></td>
                  <td><OutcomeBadge outcome={decision.outcome} /></td>
                  <td className="max-w-md truncate text-mist">{decision.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      ) : null}

      {report?.detections && (
        <Panel title="Detections" eyebrow={`${report.detections.length} shown`} bodyClassName="p-0">
          <DetectionTable detections={report.detections} showStatus={false} emptyTitle="No detections" emptyBody="The engine found nothing suspicious in this capture." />
        </Panel>
      )}
    </div>
  );
}
