"use client";

import { Play, Square } from "lucide-react";
import { useState } from "react";
import useSWR from "swr";
import { Button, Dialog, Field, Input, Select } from "@/components/ui/primitives";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { ago, compact } from "@/lib/format";
import { useSession } from "@/lib/session";
import type { NetworkInterface, SensorStatus } from "@/lib/types";

export function SensorControl() {
  const { can } = useSession();
  const toast = useToast();
  const { data: sensors, mutate } = useSWR<SensorStatus[]>("/sensors", { refreshInterval: 5000 });
  const { data: interfaces } = useSWR<NetworkInterface[]>(can("admin") ? "/interfaces" : null);
  const [open, setOpen] = useState(false);
  const [iface, setIface] = useState("any");
  const [bpf, setBpf] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmStop, setConfirmStop] = useState(false);
  useEventRefresh(["sensor.status"], () => void mutate());
  const sensor = sensors?.[0];

  async function start() {
    setBusy(true);
    try {
      await api("/sensors/start", { method: "POST", json: { interface: iface, bpf_filter: bpf || null } });
      toast("success", `Capture started on ${iface}`);
      setOpen(false);
      await mutate();
    } catch (error) {
      toast("error", "Capture did not start", error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(false);
    }
  }

  async function stop() {
    setBusy(true);
    try {
      await api("/sensors/stop", { method: "POST" });
      setConfirmStop(false);
      toast("info", "Capture stopped");
      await mutate();
    } catch (error) {
      toast("error", "Capture did not stop", error instanceof Error ? error.message : undefined);
    } finally {
      setBusy(false);
    }
  }

  if (!sensor) return <p className="text-sm text-mist">Loading sensor…</p>;
  const tone = sensor.state === "running" ? "text-ok" : sensor.state === "error" ? "text-sev-high" : "text-mist";
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className={`font-mono text-xs uppercase tracking-wide ${tone}`}>{sensor.state}</p>
          <p className="text-sm text-frost">
            {sensor.running ? `Capturing on ${sensor.interface}` : "Not capturing"}
            {sensor.running && sensor.started_at && <span className="text-mist"> · since {ago(sensor.started_at)}</span>}
          </p>
        </div>
        {can("admin") &&
          (sensor.running ? (
            <Button size="sm" variant="secondary" icon={<Square className="size-3.5" />} loading={busy} onClick={() => setConfirmStop(true)}>
              Stop capture
            </Button>
          ) : (
            <Button size="sm" variant="primary" icon={<Play className="size-3.5" />} onClick={() => setOpen(true)}>
              Start capture
            </Button>
          ))}
      </div>
      {sensor.error && <p className="rounded-md border border-sev-high/40 bg-sev-high/10 px-3 py-2 text-xs text-sev-high">{sensor.error}</p>}
      {!sensor.capture_capabilities.available && !sensor.running && (
        <div className="rounded-md border border-line bg-ground/60 px-3 py-2 text-xs text-mist">
          <p><span className="font-mono uppercase text-sev-medium">Live capture unavailable</span> · {sensor.capture_capabilities.reason}. PCAP replay still works.</p>
          {sensor.capture_capabilities.remedy && <p className="mt-1 text-fog">To enable it: {sensor.capture_capabilities.remedy}</p>}
        </div>
      )}
      {sensor.capture && (
        <dl className="grid grid-cols-3 gap-2 font-mono text-xs">
          <div><dt className="text-fog">received</dt><dd className="tabular">{compact(sensor.capture.received)}</dd></div>
          <div><dt className="text-fog">kernel drops</dt><dd className="tabular">{compact(sensor.capture.dropped_kernel)}</dd></div>
          <div><dt className="text-fog">queue drops</dt><dd className="tabular">{compact(sensor.capture.dropped_queue)}</dd></div>
        </dl>
      )}
      <Dialog
        open={confirmStop}
        onClose={() => setConfirmStop(false)}
        title="Stop live capture?"
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmStop(false)}>Keep capturing</Button>
            <Button variant="danger" loading={busy} onClick={() => void stop()}>Stop capture</Button>
          </>
        }
      >
        <p className="text-sm text-mist">Detection of live traffic on {sensor.interface} stops until capture is started again. Detections already recorded are kept.</p>
      </Dialog>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        title="Start live capture"
        footer={
          <>
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="primary" loading={busy} onClick={() => void start()}>Start capture</Button>
          </>
        }
      >
        <div className="flex flex-col gap-4">
          <Field label="Interface" htmlFor="iface">
            <Select id="iface" value={iface} onChange={(event) => setIface(event.target.value)}>
              <option value="any">any (every interface)</option>
              {interfaces?.map((entry) => (
                <option key={entry.name} value={entry.name}>
                  {entry.name} — {entry.state}{entry.addresses.length ? ` · ${entry.addresses[0]}` : ""}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="BPF filter (optional)" htmlFor="bpf" hint="Applied in the kernel before SentinelX sees a packet, e.g. tcp or udp port 53">
            <Input id="bpf" value={bpf} onChange={(event) => setBpf(event.target.value)} placeholder="tcp or udp" className="font-mono" maxLength={512} />
          </Field>
        </div>
      </Dialog>
    </div>
  );
}
