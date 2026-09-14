"use client";

import { AlertOctagon, KeyRound, ShieldAlert, UserPlus } from "lucide-react";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { Button, Dialog, EmptyState, ErrorState, Field, Input, Panel, Select, TableSkeleton, Textarea } from "@/components/ui/primitives";
import { Mono } from "@/components/ui/security";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { ago, humanise } from "@/lib/format";
import { useSession } from "@/lib/session";
import type { ConfigView, Role, User } from "@/lib/types";

type Kind = "number" | "text" | "list" | "bool" | "select";
interface Spec { key: string; label: string; hint?: string; kind: Kind; options?: string[] }

const SECTIONS: { id: string; section: string; title: string; description: string; fields: Spec[] }[] = [
  {
    id: "detection", section: "detection", title: "Detection thresholds",
    description: "When built-in detectors fire. Tune against your own normal traffic; the PCAP Lab shows the effect before you commit.",
    fields: [
      { key: "mode", label: "Detection mode", kind: "select", options: ["disabled", "signature_only", "balanced", "aggressive"], hint: "signature_only runs only denylist and protocol-anomaly checks" },
      { key: "port_scan_unique_ports", label: "Port scan: distinct ports", kind: "number" },
      { key: "port_scan_window_seconds", label: "Port scan: window (s)", kind: "number", hint: "Changing a window resets in-flight traffic state" },
      { key: "port_scan_min_syn_ratio", label: "Port scan: minimum SYN ratio", kind: "number", hint: "0-1. Keeps busy clients that complete handshakes from matching" },
      { key: "horizontal_scan_unique_hosts", label: "Sweep: distinct hosts", kind: "number" },
      { key: "brute_force_attempts", label: "Brute force: short sessions", kind: "number" },
      { key: "brute_force_window_seconds", label: "Brute force: window (s)", kind: "number" },
      { key: "connection_rate_threshold", label: "Connection rate: attempts per window", kind: "number" },
      { key: "syn_flood_threshold", label: "SYN flood: SYNs per window", kind: "number" },
      { key: "icmp_flood_threshold", label: "ICMP flood: packets per window", kind: "number" },
      { key: "http_flood_threshold", label: "HTTP flood: requests per window", kind: "number" },
      { key: "dns_query_threshold", label: "DNS: queries per window", kind: "number" },
      { key: "detection_cooldown_seconds", label: "Repeat suppression (s)", kind: "number", hint: "One detection per source per detector in this period, unless it escalates" },
      { key: "allowlist_networks", label: "Never report these sources", kind: "list" },
      { key: "denylist_networks", label: "Always report these addresses", kind: "list" },
    ],
  },
  {
    id: "scoring", section: "scoring", title: "Risk scoring",
    description: "How much each factor adds to a score. Every score shows this breakdown, so changes stay explainable.",
    fields: [
      { key: "severity_weight", label: "Severity weight", kind: "number" },
      { key: "confidence_weight", label: "Confidence weight", kind: "number" },
      { key: "frequency_weight", label: "Repetition weight", kind: "number" },
      { key: "history_weight", label: "Source history weight", kind: "number" },
      { key: "intel_weight", label: "Threat intelligence weight", kind: "number" },
      { key: "correlation_weight", label: "Correlation weight", kind: "number" },
      { key: "sensitive_target_weight", label: "Sensitive target weight", kind: "number" },
      { key: "auto_block_threshold", label: "Automatic response threshold", kind: "number", hint: "Risk at or above which prevention may act" },
    ],
  },
  {
    id: "notifications", section: "response", title: "Notifications",
    description: "Send detections above a risk level to a webhook (Slack-compatible JSON body).",
    fields: [
      { key: "webhook_url", label: "Webhook URL", kind: "text", hint: "Leave empty to disable" },
      { key: "webhook_min_risk", label: "Minimum risk to notify", kind: "number" },
    ],
  },
  {
    id: "limits", section: "response", title: "Blocking limits",
    description: "Guard rails the safety layer enforces on every block, automatic or manual.",
    fields: [
      { key: "default_block_seconds", label: "Default temporary block (s)", kind: "number" },
      { key: "max_block_seconds", label: "Longest allowed block (s)", kind: "number" },
      { key: "max_block_prefix_hosts", label: "Widest prefix (addresses)", kind: "number", hint: "256 permits up to a /24" },
      { key: "max_blocked_addresses", label: "Concurrent block limit", kind: "number" },
      { key: "management_addresses", label: "Management addresses (never blocked)", kind: "list" },
    ],
  },
  {
    id: "retention", section: "storage", title: "Retention",
    description: "How long history is kept. Raw packets are never stored in the database.",
    fields: [
      { key: "retention_days", label: "Detections and incidents (days)", kind: "number" },
      { key: "audit_retention_days", label: "Audit log (days)", kind: "number" },
      { key: "metrics_retention_days", label: "Traffic summaries and metrics (days)", kind: "number" },
    ],
  },
  {
    id: "sensor", section: "capture", title: "Sensor",
    description: "Defaults for live capture. Changes apply the next time capture starts.",
    fields: [
      { key: "interface", label: "Default interface", kind: "text" },
      { key: "bpf_filter", label: "Default BPF filter", kind: "text" },
      { key: "home_networks", label: "Home networks", kind: "list", hint: "Used to label traffic as inbound, outbound or internal" },
    ],
  },
];

export default function SettingsPage() {
  const { can } = useSession();
  const { data, error, mutate } = useSWR<ConfigView>(can("analyst") ? "/config" : null);
  useEventRefresh(["config.changed"], () => void mutate());
  if (!can("analyst")) return <><PageHeader title="Settings" /><Panel><EmptyState title="Analysts and administrators only" /></Panel></>;
  if (error) return <div className="panel"><ErrorState error={error} onRetry={() => void mutate()} /></div>;
  const readOnly = !can("admin");

  return (
    <>
      <PageHeader title="Settings" description={readOnly ? "You can view settings. Only administrators can change them." : "Changes apply immediately, are saved across restarts, and are recorded in the audit log."} />
      <div className="grid gap-6 lg:grid-cols-[12rem_minmax(0,1fr)]">
        <nav aria-label="Settings sections" className="lg:sticky lg:top-20 lg:self-start">
          <ul className="flex flex-wrap gap-1 lg:flex-col">
            {[["health", "Health"], ["response", "Response mode"], ...SECTIONS.map((s) => [s.id, s.title]), ...(can("admin") ? [["users", "Users"]] : [])].map(([id, title]) => (
              <li key={id}><a href={`#${id}`} className="block rounded-md px-2 py-1 text-sm text-mist hover:bg-raised hover:text-frost">{title}</a></li>
            ))}
          </ul>
        </nav>
        <div className="flex min-w-0 flex-col gap-4">
          <HealthPanel />
          {data ? <ResponsePanel key={`${String(data.settings.response?.mode)}:${String(data.settings.response?.dry_run)}`} view={data} readOnly={readOnly} onSaved={() => void mutate()} /> : <Panel><TableSkeleton rows={3} /></Panel>}
          {data ? SECTIONS.map((spec) => <SectionForm key={`${spec.id}:${JSON.stringify(spec.fields.map((field) => data.settings[spec.section]?.[field.key]))}`} spec={spec} view={data} readOnly={readOnly} onSaved={() => void mutate()} />) : null}
          {can("admin") && <UsersPanel />}
        </div>
      </div>
    </>
  );
}

function toText(value: unknown, kind: Kind): string {
  if (kind === "list") return Array.isArray(value) ? value.join("\n") : "";
  if (value === null || value === undefined) return "";
  return String(value);
}

function fromText(text: string, kind: Kind): unknown {
  if (kind === "list") return text.split(/[\n,]+/).map((line) => line.trim()).filter(Boolean);
  if (kind === "number") return text.trim() === "" ? null : Number(text);
  if (kind === "bool") return text === "true";
  return text;
}

function SectionForm({ spec, view, readOnly, onSaved }: { spec: (typeof SECTIONS)[number]; view: ConfigView; readOnly: boolean; onSaved: () => void }) {
  const toast = useToast();
  const editable = new Set(view.editable[spec.section] ?? []);
  const current = view.settings[spec.section] ?? {};
  // The parent keys this component by the stored values, so initial state is always current.
  const [initial] = useState(() => Object.fromEntries(spec.fields.map((field) => [field.key, toText(current[field.key], field.kind)])));
  const [values, setValues] = useState(initial);
  const [problem, setProblem] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const changed = spec.fields.filter((field) => values[field.key] !== initial[field.key]);

  async function save() {
    setBusy(true);
    setProblem(null);
    try {
      const changes = Object.fromEntries(changed.map((field) => [field.key, fromText(values[field.key] ?? "", field.kind)]));
      await api(`/config/${spec.section}`, { method: "PATCH", json: { changes } });
      toast("success", `${spec.title} saved`);
      onSaved();
    } catch (caught) {
      setProblem(caught instanceof Error ? caught.message : "Not saved");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel id={spec.id} title={spec.title} bodyClassName="p-4">
      <p className="mb-4 max-w-2xl text-sm text-mist">{spec.description}</p>
      <div className="grid gap-4 sm:grid-cols-2">
        {spec.fields.map((field) => {
          const id = `${spec.id}-${field.key}`;
          const disabled = readOnly || !editable.has(field.key);
          const value = values[field.key] ?? "";
          const set = (next: string) => setValues((all) => ({ ...all, [field.key]: next }));
          return (
            <div key={field.key} className={field.kind === "list" ? "sm:col-span-2" : ""}>
              <Field label={field.label} htmlFor={id} hint={field.hint}>
                {field.kind === "select" ? (
                  <Select id={id} value={value} disabled={disabled} onChange={(event) => set(event.target.value)}>
                    {field.options?.map((option) => <option key={option} value={option}>{humanise(option)}</option>)}
                  </Select>
                ) : field.kind === "list" ? (
                  <Textarea id={id} rows={3} value={value} disabled={disabled} onChange={(event) => set(event.target.value)} placeholder="One address or CIDR per line" />
                ) : (
                  <Input id={id} type={field.kind === "number" ? "number" : "text"} step="any" value={value} disabled={disabled} onChange={(event) => set(event.target.value)} className={field.kind === "number" ? "font-mono" : ""} />
                )}
              </Field>
            </div>
          );
        })}
      </div>
      {problem && <p className="mt-3 rounded-md border border-sev-high/40 bg-sev-high/10 px-3 py-2 text-sm text-sev-high" role="alert">{problem}</p>}
      {!readOnly && (
        <div className="mt-4 flex items-center gap-3">
          <Button variant="primary" size="sm" disabled={!changed.length} loading={busy} onClick={() => void save()}>Save {spec.title.toLowerCase()}</Button>
          {changed.length > 0 && <Button variant="ghost" size="sm" onClick={() => setValues(initial)}>Discard changes</Button>}
        </div>
      )}
    </Panel>
  );
}

function ResponsePanel({ view, readOnly, onSaved }: { view: ConfigView; readOnly: boolean; onSaved: () => void }) {
  const toast = useToast();
  const response = view.settings.response ?? {};
  const [mode, setMode] = useState(String(response.mode));
  const [dryRun, setDryRun] = useState(Boolean(response.dry_run));
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [phrase, setPhrase] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);

  const wouldEnable = mode === "automatic" && !dryRun && !view.safety.prevention_active;
  const changed = mode !== response.mode || dryRun !== response.dry_run;
  const backend = view.safety.firewall_backend;

  async function apply(confirmation?: string) {
    setBusy(true);
    setProblem(null);
    try {
      await api("/config/response", { method: "PATCH", json: { changes: { mode, dry_run: dryRun }, confirmation } });
      toast(wouldEnable ? "info" : "success", wouldEnable ? "Prevention enabled" : "Response settings saved", wouldEnable ? `SentinelX may now change the ${backend} firewall automatically.` : undefined);
      setConfirmOpen(false);
      setPhrase("");
      onSaved();
    } catch (caught) {
      setProblem(caught instanceof ApiError ? caught.message : "Not saved");
    } finally {
      setBusy(false);
    }
  }

  const modes = [
    { value: "detect_only", title: "Detection only", body: "Detect, score and explain. Recommended blocks are recorded as not applied." },
    { value: "manual_approval", title: "Manual approval", body: "Recommended blocks wait in the Firewall page for an administrator." },
    { value: "automatic", title: "Automatic", body: "Blocks above the risk threshold are applied without waiting, subject to dry run and the safety guard." },
  ];

  return (
    <Panel id="response" title="Response mode">
      <p className="mb-4 max-w-2xl text-sm text-mist">{view.safety.banner}. Firewall backend: <Mono>{backend}</Mono>{backend === "null" ? " (records decisions only; set FIREWALL_BACKEND on the server to enforce)" : ""}.</p>
      <fieldset disabled={readOnly} className="grid gap-2 sm:grid-cols-3">
        <legend className="sr-only">Response mode</legend>
        {modes.map((option) => (
          <label key={option.value} className={`cursor-pointer rounded-md border p-3 transition-colors ${mode === option.value ? "border-iris bg-iris/10" : "border-line-strong hover:border-mist"} ${readOnly ? "cursor-default opacity-80" : ""}`}>
            <input type="radio" name="response-mode" value={option.value} checked={mode === option.value} onChange={() => setMode(option.value)} className="sr-only" />
            <span className="block text-sm font-medium text-frost">{option.title}</span>
            <span className="mt-1 block text-xs text-mist">{option.body}</span>
          </label>
        ))}
      </fieldset>
      <label className="mt-4 flex items-start gap-3 text-sm">
        <input type="checkbox" checked={dryRun} disabled={readOnly} onChange={(event) => setDryRun(event.target.checked)} className="mt-0.5 size-4 accent-[var(--color-iris)]" />
        <span><span className="text-frost">Dry run</span><span className="block text-xs text-mist">Decide and record every response, but never change the firewall. Leave on until you trust the thresholds.</span></span>
      </label>
      {problem && <p className="mt-3 rounded-md border border-sev-high/40 bg-sev-high/10 px-3 py-2 text-sm text-sev-high" role="alert">{problem}</p>}
      {!readOnly && (
        <div className="mt-4 flex gap-3">
          {wouldEnable ? (
            <Button variant="danger" icon={<ShieldAlert className="size-4" />} disabled={!changed} onClick={() => setConfirmOpen(true)}>Enable prevention…</Button>
          ) : (
            <Button variant="primary" size="sm" disabled={!changed} loading={busy} onClick={() => void apply()}>Save response mode</Button>
          )}
        </div>
      )}
      <Dialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="Enable automatic prevention"
        footer={<><Button variant="ghost" onClick={() => setConfirmOpen(false)}>Keep detection only</Button><Button variant="danger" loading={busy} disabled={phrase !== view.safety.confirmation_phrase} onClick={() => void apply(phrase)}>Enable prevention</Button></>}
      >
        <div className="flex flex-col gap-4 text-sm">
          <div className="flex gap-3 rounded-md border border-sev-critical/50 bg-sev-critical/10 p-3 text-sev-critical">
            <AlertOctagon className="mt-0.5 size-5 shrink-0" aria-hidden />
            <p>SentinelX will modify the <strong>{backend}</strong> firewall on this host without asking, for any source whose risk reaches <strong>{String(view.settings.scoring?.auto_block_threshold)}</strong>. A misconfigured threshold can block legitimate users.</p>
          </div>
          <ul className="list-inside list-disc text-mist">
            <li>Loopback, this host&apos;s addresses, management addresses and the allowlist are never blocked.</li>
            <li>No prefix wider than {String(view.settings.response?.max_block_prefix_hosts)} addresses can be blocked.</li>
            <li>Every action is recorded in the audit log and can be reversed from the Firewall page.</li>
          </ul>
          <Field label={`Type ${view.safety.confirmation_phrase} to confirm`} htmlFor="prevention-phrase">
            <Input id="prevention-phrase" value={phrase} onChange={(event) => setPhrase(event.target.value)} autoComplete="off" className="font-mono" />
          </Field>
        </div>
      </Dialog>
    </Panel>
  );
}

interface StatusReport { status: string; version: string; safety: string; components: Record<string, Record<string, unknown> & { ok?: boolean }>; process: { cpu_percent: number; memory_bytes: number; uptime_seconds: number } }

function HealthPanel() {
  const { data, error, mutate } = useSWR<StatusReport>("/system/status", { refreshInterval: 15_000 });
  useEventRefresh(["system.health"], () => void mutate(), 10_000);
  return (
    <Panel id="health" title="Health" bodyClassName="p-0">
      {error ? <ErrorState error={error} onRetry={() => void mutate()} /> : !data ? <TableSkeleton rows={4} columns={3} /> : (
        <table className="data-table">
          <thead><tr><th scope="col">Component</th><th scope="col">State</th><th scope="col">Detail</th></tr></thead>
          <tbody>
            {Object.entries(data.components).filter(([name]) => name !== "sensor").map(([name, component]) => {
              const degraded = component.degraded === true;
              const ok = component.ok !== false && !degraded;
              const detail = name === "event_bus" ? `${component.published} published · ${component.dropped} dropped · ${component.subscribers} subscribers`
                : name === "rules" ? ((component.problems as string[] | undefined)?.join("; ") || "all rules valid")
                : name === "redis" ? (degraded ? "unreachable: rate limits and tickets are per-process" : "connected")
                : name === "persister" ? `${component.written} events written · ${component.failed_batches} failed batches`
                : name === "firewall" ? `${component.backend}${component.enforcing ? " · enforcing" : " · not enforcing"}${component.error ? ` · ${component.error}` : ""}`
                : String(component.url ?? component.dialect ?? "");
              return (
                <tr key={name}>
                  <td className="capitalize">{humanise(name)}</td>
                  <td className={ok ? "text-ok" : degraded ? "text-sev-medium" : "text-sev-high"}>{ok ? "ok" : degraded ? "degraded" : "failing"}</td>
                  <td className="max-w-lg truncate font-mono text-xs text-mist" title={detail}>{detail}</td>
                </tr>
              );
            })}
            <tr>
              <td>Process</td>
              <td className="text-ok">v{data.version}</td>
              <td className="font-mono text-xs text-mist">{data.process.cpu_percent.toFixed(1)}% CPU · {(data.process.memory_bytes / 1_048_576).toFixed(0)} MB · up {Math.round(data.process.uptime_seconds / 60)} min</td>
            </tr>
          </tbody>
        </table>
      )}
    </Panel>
  );
}

function UsersPanel() {
  const toast = useToast();
  const { user: me } = useSession();
  const { data, error, mutate } = useSWR<User[]>("/users");
  const [creating, setCreating] = useState(false);
  const [resetting, setResetting] = useState<User | null>(null);
  const [form, setForm] = useState({ username: "", password: "", role: "viewer" as Role });
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  async function act(run: () => Promise<unknown>, success: string) {
    setBusy(true);
    try {
      await run();
      toast("success", success);
      await mutate();
      return true;
    } catch (caught) {
      toast("error", "Change not saved", caught instanceof Error ? caught.message : undefined);
      return false;
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel id="users" title="Users" bodyClassName="p-0" actions={<Button size="sm" variant="secondary" icon={<UserPlus className="size-3.5" />} onClick={() => setCreating(true)}>Add user</Button>}>
      {error ? <ErrorState error={error} onRetry={() => void mutate()} /> : !data ? <TableSkeleton rows={3} /> : (
        <table className="data-table">
          <thead><tr><th scope="col">User</th><th scope="col">Role</th><th scope="col">Active</th><th scope="col">Last sign-in</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {data.map((user) => (
              <tr key={user.id}>
                <td>{user.username}{user.id === me?.id && <span className="ml-2 text-2xs text-fog">you</span>}{user.must_change_password && <span className="ml-2 text-2xs text-sev-medium">must change password</span>}</td>
                <td>
                  <Select aria-label={`Role for ${user.username}`} value={user.role} disabled={busy || user.id === me?.id} onChange={(event) => void act(() => api(`/users/${user.id}`, { method: "PATCH", json: { role: event.target.value } }), `${user.username} is now ${event.target.value}`)} className="h-7 w-28 text-xs">
                    {(["viewer", "analyst", "admin"] as Role[]).map((role) => <option key={role} value={role}>{role}</option>)}
                  </Select>
                </td>
                <td>
                  <input type="checkbox" aria-label={`${user.is_active ? "Deactivate" : "Activate"} ${user.username}`} checked={user.is_active} disabled={busy || user.id === me?.id} onChange={(event) => void act(() => api(`/users/${user.id}`, { method: "PATCH", json: { is_active: event.target.checked } }), `${user.username} ${event.target.checked ? "activated" : "deactivated"}`)} className="size-4 accent-[var(--color-iris)]" />
                </td>
                <td><Mono className="text-mist">{ago(user.last_login_at)}</Mono></td>
                <td className="text-right"><Button size="sm" variant="ghost" icon={<KeyRound className="size-3.5" />} onClick={() => setResetting(user)}>Reset password</Button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <Dialog open={creating} onClose={() => setCreating(false)} title="Add user" footer={<><Button variant="ghost" onClick={() => setCreating(false)}>Cancel</Button><Button variant="primary" loading={busy} onClick={async () => { if (await act(() => api("/users", { method: "POST", json: form }), `Created ${form.username}`)) { setCreating(false); setForm({ username: "", password: "", role: "viewer" }); } }}>Create user</Button></>}>
        <div className="flex flex-col gap-3">
          <Field label="Username" htmlFor="new-username"><Input id="new-username" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} autoComplete="off" /></Field>
          <Field label="Initial password" htmlFor="new-password" hint="At least 12 characters. Share it out of band."><Input id="new-password" type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} autoComplete="new-password" /></Field>
          <Field label="Role" htmlFor="new-role" hint="Viewers read; analysts triage, test rules and replay captures; administrators change rules, firewall and settings.">
            <Select id="new-role" value={form.role} onChange={(event) => setForm({ ...form, role: event.target.value as Role })}>
              <option value="viewer">viewer</option><option value="analyst">analyst</option><option value="admin">admin</option>
            </Select>
          </Field>
        </div>
      </Dialog>
      <Dialog open={resetting !== null} onClose={() => setResetting(null)} title={`Reset password for ${resetting?.username ?? ""}`} footer={<><Button variant="ghost" onClick={() => setResetting(null)}>Cancel</Button><Button variant="primary" loading={busy} onClick={async () => { if (resetting && (await act(() => api(`/users/${resetting.id}/reset-password`, { method: "POST", json: { new_password: password } }), `Password reset for ${resetting.username}`))) { setResetting(null); setPassword(""); } }}>Reset password</Button></>}>
        <Field label="Temporary password" htmlFor="reset-password" hint="They must choose a new password at next sign-in. All their sessions are signed out."><Input id="reset-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" /></Field>
      </Dialog>
    </Panel>
  );
}
