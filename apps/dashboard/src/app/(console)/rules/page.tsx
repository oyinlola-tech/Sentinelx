"use client";

import { CheckCircle2, FileCode2, FlaskConical, Plus, Trash2, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { Button, Dialog, EmptyState, ErrorState, Field, Panel, Select, TableSkeleton, Textarea } from "@/components/ui/primitives";
import { EvidenceList, Mono, SeverityBadge } from "@/components/ui/security";
import { useToast } from "@/components/ui/toast";
import { ApiError, api } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { humanise, num } from "@/lib/format";
import { useSession } from "@/lib/session";
import type { PcapFile, RuleSummary, RuleTestResult } from "@/lib/types";

interface RulesResponse { rules: RuleSummary[]; load_problems: string[] }
interface FieldsResponse { fields: { name: string; kind: string; description: string }[]; operators: string[]; scenarios: string[] }

const TEMPLATE = `rule:
  name: SSH Brute Force Strict
  description: Short-lived SSH sessions from one source, tuned for a quiet network.
  condition: protocol == TCP and destination_port == 22 and short_sessions >= 10
  within: 60s
  severity: high
  category: brute_force
  confidence: 0.85
  action: alert
  tests:
    - scenario: ssh_brute_force
      expect: match
    - scenario: normal_traffic
      expect: no_match
`;

export default function RulesPage() {
  const { can } = useSession();
  const toast = useToast();
  const { data, error, mutate } = useSWR<RulesResponse>("/rules");
  const [editing, setEditing] = useState<{ mode: "create" | "edit" | "view"; rule?: RuleSummary } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<RuleSummary | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  useEventRefresh(["rule.changed"], () => void mutate());

  async function toggle(rule: RuleSummary) {
    setBusy(rule.rule_id);
    try {
      await api(`/rules/${rule.rule_id}/enabled`, { method: "PATCH", json: { enabled: !rule.enabled } });
      toast("success", `${rule.name} ${rule.enabled ? "disabled" : "enabled"}`);
      await mutate();
    } catch (caught) {
      toast("error", "Could not change the rule", caught instanceof Error ? caught.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  async function remove() {
    if (!confirmDelete) return;
    setBusy(confirmDelete.rule_id);
    try {
      await api(`/rules/${confirmDelete.rule_id}`, { method: "DELETE" });
      toast("success", `Deleted ${confirmDelete.name}`);
      setConfirmDelete(null);
      await mutate();
    } catch (caught) {
      toast("error", "Could not delete the rule", caught instanceof Error ? caught.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <PageHeader
        title="Rules"
        description="Custom detections in a small, safe condition language. Rules from files are version-controlled; rules created here live in the database."
        actions={can("analyst") && <Button variant="primary" icon={<Plus className="size-4" />} onClick={() => setEditing({ mode: "create" })}>{can("admin") ? "New rule" : "Write and test a rule"}</Button>}
      />
      {data?.load_problems.length ? (
        <div className="mb-4 rounded-md border border-sev-high/40 bg-sev-high/10 px-4 py-3 text-sm text-sev-high" role="alert">
          <p className="font-medium">Some rule files were rejected and are not running:</p>
          <ul className="mt-1 list-inside list-disc font-mono text-xs">{data.load_problems.map((problem) => <li key={problem}>{problem}</li>)}</ul>
        </div>
      ) : null}
      <Panel bodyClassName="p-0">
        {error ? <ErrorState error={error} onRetry={() => void mutate()} /> : !data ? <TableSkeleton /> : !data.rules.length ? (
          <EmptyState title="No rules yet" action={can("admin") && <Button variant="primary" onClick={() => setEditing({ mode: "create" })}>Create the first rule</Button>}>
            Built-in detectors are already running. Rules add site-specific detections on top of them.
          </EmptyState>
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead><tr><th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Action</th><th scope="col">Window</th><th scope="col">Condition</th><th scope="col">Hits</th><th scope="col">Origin</th><th scope="col">Enabled</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {data.rules.map((rule) => (
                  <tr key={rule.rule_id}>
                    <td className="max-w-64">
                      <button onClick={() => setEditing({ mode: rule.origin === "api" && can("admin") ? "edit" : "view", rule })} className="block truncate text-left text-frost hover:text-iris">{rule.name}</button>
                      <Mono className="text-fog">{rule.rule_id}</Mono>
                      {!rule.valid && <span className="ml-2 text-2xs text-sev-high">invalid</span>}
                    </td>
                    <td>{rule.severity && <SeverityBadge severity={rule.severity} />}</td>
                    <td className="whitespace-nowrap text-mist">{humanise(rule.action)}</td>
                    <td><Mono className="text-mist">{rule.within_seconds != null ? `${rule.within_seconds}s` : "—"}</Mono></td>
                    <td className="max-w-md"><code className="line-clamp-2 font-mono text-xs text-mist">{rule.condition}</code></td>
                    <td><Mono>{rule.stats ? num(rule.stats.hits) : "—"}</Mono></td>
                    <td>
                      <span className="inline-flex items-center gap-1 text-xs text-mist" title={rule.source_path ?? undefined}>
                        <FileCode2 className="size-3" aria-hidden />{rule.origin === "file" ? "file" : `dashboard · ${rule.updated_by}`}
                      </span>
                    </td>
                    <td>
                      <label className="inline-flex cursor-pointer items-center gap-2">
                        <input type="checkbox" role="switch" checked={rule.enabled} disabled={!can("admin") || busy === rule.rule_id} onChange={() => void toggle(rule)} className="peer sr-only" aria-label={`${rule.enabled ? "Disable" : "Enable"} ${rule.name}`} />
                        <span className="relative h-4 w-7 rounded-full bg-line-strong transition-colors peer-checked:bg-iris peer-focus-visible:outline-2 peer-focus-visible:outline-iris after:absolute after:top-0.5 after:left-0.5 after:size-3 after:rounded-full after:bg-frost after:transition-transform peer-checked:after:translate-x-3" aria-hidden />
                      </label>
                    </td>
                    <td className="text-right">
                      {can("admin") && rule.origin === "api" && (
                        <Button size="sm" variant="ghost" icon={<Trash2 className="size-3.5" />} onClick={() => setConfirmDelete(rule)} aria-label={`Delete ${rule.name}`} />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {editing && <RuleEditor state={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); void mutate(); }} />}
      <Dialog open={confirmDelete !== null} onClose={() => setConfirmDelete(null)} title="Delete rule" footer={<><Button variant="ghost" onClick={() => setConfirmDelete(null)}>Cancel</Button><Button variant="danger" loading={busy !== null} onClick={() => void remove()}>Delete rule</Button></>}>
        <p className="text-sm text-mist">Delete <span className="text-frost">{confirmDelete?.name}</span>? It stops matching immediately. Past detections it produced are kept.</p>
      </Dialog>
    </>
  );
}

function RuleEditor({ state, onClose, onSaved }: { state: { mode: "create" | "edit" | "view"; rule?: RuleSummary }; onClose: () => void; onSaved: () => void }) {
  const { can } = useSession();
  const toast = useToast();
  const { data: meta } = useSWR<FieldsResponse>("/rules/fields");
  const { data: files } = useSWR<PcapFile[]>(can("analyst") ? "/replay/files" : null);
  const [definition, setDefinition] = useState(state.rule?.definition ?? TEMPLATE);
  const [validation, setValidation] = useState<{ valid: boolean; problems: string[] } | null>(null);
  const [target, setTarget] = useState("tests");
  const [result, setResult] = useState<RuleTestResult | null>(null);
  const [busy, setBusy] = useState<"test" | "save" | null>(null);
  const readOnly = state.mode === "view" || !can("admin");
  // Validating and testing are analyst actions; viewers see the definition only.
  const canTest = can("analyst");

  useEffect(() => {
    if (!canTest) return;
    const handle = setTimeout(() => {
      api<{ valid: boolean; problems: string[] }>("/rules/validate", { method: "POST", json: { definition } }).then(setValidation).catch(() => setValidation(null));
    }, 400);
    return () => clearTimeout(handle);
  }, [definition, canTest]);

  const targets = useMemo(() => [
    { value: "tests", label: "Embedded tests (positive and negative)" },
    ...(meta?.scenarios ?? []).map((scenario) => ({ value: `scenario:${scenario}`, label: `Scenario · ${humanise(scenario)}` })),
    ...(files ?? []).map((file) => ({ value: `pcap:${file.path}`, label: `Capture · ${file.path}` })),
  ], [meta, files]);

  async function test() {
    setBusy("test");
    setResult(null);
    try {
      const body = target === "tests" ? {} : target.startsWith("scenario:") ? { scenario: target.slice(9) } : { pcap_path: target.slice(5) };
      setResult(await api<RuleTestResult>("/rules/test", { method: "POST", json: { definition, ...body } }));
    } catch (caught) {
      toast("error", "Test could not run", caught instanceof ApiError && caught.problems.length ? caught.problems.join("; ") : caught instanceof Error ? caught.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  async function save() {
    setBusy("save");
    try {
      if (state.mode === "edit" && state.rule) await api(`/rules/${state.rule.rule_id}`, { method: "PUT", json: { definition } });
      else await api("/rules", { method: "POST", json: { definition } });
      toast("success", state.mode === "edit" ? "Rule updated and applied" : "Rule created and applied");
      onSaved();
    } catch (caught) {
      toast("error", "Rule not saved", caught instanceof ApiError && caught.problems.length ? caught.problems.join("; ") : caught instanceof Error ? caught.message : undefined);
    } finally {
      setBusy(null);
    }
  }

  const title = state.mode === "create" ? "New rule" : state.mode === "edit" ? `Edit ${state.rule?.name}` : state.rule?.name ?? "Rule";
  return (
    <Dialog
      open
      wide
      onClose={onClose}
      title={title}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>{readOnly ? "Close" : "Cancel"}</Button>
          {!readOnly && <Button variant="primary" loading={busy === "save"} disabled={!validation?.valid} onClick={() => void save()}>{state.mode === "edit" ? "Save and apply" : "Create and apply"}</Button>}
        </>
      }
    >
      <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <div className="flex flex-col gap-2">
          {state.rule?.origin === "file" && <p className="rounded-md border border-line-strong px-3 py-2 text-xs text-mist">Defined in <span className="font-mono">{state.rule.source_path}</span>. Edit that file to change it{can("analyst") ? "; you can test changes here without saving" : ""}.</p>}
          <Field label="Rule (YAML)" htmlFor="rule-yaml">
            <Textarea id="rule-yaml" rows={18} value={definition} readOnly={!canTest} onChange={(event) => setDefinition(event.target.value)} aria-describedby="rule-validation" />
          </Field>
          <div id="rule-validation" role="status" aria-live="polite">
            {validation?.valid && <p className="flex items-center gap-1.5 text-xs text-ok"><CheckCircle2 className="size-3.5" aria-hidden />Valid rule</p>}
            {validation && !validation.valid && (
              <ul className="flex flex-col gap-1 text-xs text-sev-high">
                {validation.problems.map((problem) => <li key={problem} className="flex gap-1.5"><XCircle className="mt-0.5 size-3.5 shrink-0" aria-hidden />{problem}</li>)}
              </ul>
            )}
          </div>
        </div>
        <div className="flex min-w-0 flex-col gap-4">
          {canTest ? (
            <div className="flex flex-col gap-2">
              <Field label="Test against" htmlFor="rule-target">
                <Select id="rule-target" value={target} onChange={(event) => setTarget(event.target.value)}>
                  {targets.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
                </Select>
              </Field>
              <Button variant="secondary" icon={<FlaskConical className="size-4" />} loading={busy === "test"} disabled={validation?.valid === false} onClick={() => void test()}>Run test</Button>
            </div>
          ) : (
            <p className="rounded-md border border-line-strong px-3 py-2 text-xs text-mist">You have read-only access to rules. Analysts and administrators can validate this definition and test it against scenarios and captures.</p>
          )}
          {result && <TestResult result={result} />}
          <details className="text-xs text-mist">
            <summary className="cursor-pointer text-frost">Fields and operators</summary>
            <p className="mt-2 font-mono">{meta?.operators.join("  ")}</p>
            <ul className="mt-2 max-h-56 overflow-y-auto">
              {meta?.fields.map((field) => <li key={field.name} className="py-0.5"><span className="font-mono text-frost">{field.name}</span> <span className="text-fog">{field.kind}</span> — {field.description}</li>)}
            </ul>
          </details>
        </div>
      </div>
    </Dialog>
  );
}

function TestResult({ result }: { result: RuleTestResult }) {
  if (result.tests) {
    return (
      <div className="rounded-md border border-line p-3">
        <p className={`mb-2 text-sm font-medium ${result.passed ? "text-ok" : "text-sev-high"}`}>{result.count ? (result.passed ? "All embedded tests pass" : "Some embedded tests fail") : "This rule has no embedded tests"}</p>
        <ul className="flex flex-col gap-1 text-xs">
          {result.tests.map((test, index) => (
            <li key={`${test.scenario}-${index}`} className="flex items-center justify-between gap-2">
              <span className="text-mist">{humanise(test.scenario)} · expect {humanise(test.expected)}</span>
              <span className={test.passed ? "text-ok" : "text-sev-high"}>{test.passed ? "pass" : `got ${humanise(test.actual)}`}</span>
            </li>
          ))}
        </ul>
      </div>
    );
  }
  return (
    <div className="rounded-md border border-line p-3">
      <p className={`text-sm font-medium ${result.matched ? "text-sev-medium" : "text-mist"}`}>{result.matched ? `Matched ${result.detection_count} time(s)` : "No match"}</p>
      <p className="mt-1 font-mono text-2xs text-fog">{num(result.packets)} packets from {result.target} in {num((result.elapsed_seconds ?? 0) * 1000)} ms · sources {Object.keys(result.sources ?? {}).join(", ") || "none"}</p>
      {result.evidence && result.evidence.length > 0 && <div className="mt-2 border-t border-line pt-2"><EvidenceList evidence={result.evidence} /></div>}
    </div>
  );
}


