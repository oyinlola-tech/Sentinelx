"use client";

import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { EmptyState, ErrorState, Input, Pagination, Panel, TableSkeleton } from "@/components/ui/primitives";
import { Mono } from "@/components/ui/security";
import { query } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { humanise, timestamp } from "@/lib/format";
import { useSession } from "@/lib/session";
import { useDebouncedValue } from "@/lib/use-debounced-value";
import type { AuditEvent, Page } from "@/lib/types";

export default function AuditPage() {
  const { can } = useSession();
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [target, setTarget] = useState("");
  const [offset, setOffset] = useState(0);
  const [expanded, setExpanded] = useState<number | null>(null);
  // The filters are exact matches on the server; wait for a pause in typing before fetching.
  const actorFilter = useDebouncedValue(actor.trim(), 300);
  const actionFilter = useDebouncedValue(action.trim(), 300);
  const targetFilter = useDebouncedValue(target.trim(), 300);
  const key = can("analyst") ? `/audit${query({ actor: actorFilter || null, action: actionFilter || null, target: targetFilter || null, limit: 50, offset })}` : null;
  const { data, error, mutate } = useSWR<Page<AuditEvent>>(key);
  useEventRefresh(["audit.event"], () => void mutate(), 2000);

  if (!can("analyst")) {
    return <><PageHeader title="Audit log" /><Panel><EmptyState title="Analysts and administrators only">Ask an administrator for access if you need the audit trail.</EmptyState></Panel></>;
  }
  return (
    <>
      <PageHeader title="Audit log" description="Every administrative and response action: who did it, from where, to what, and whether it succeeded. Entries cannot be edited." />
      <Panel bodyClassName="p-0">
        <div className="grid gap-2 border-b border-line p-3 sm:grid-cols-3">
          <Input aria-label="Filter by actor" placeholder="Actor (exact match), e.g. admin" value={actor} onChange={(event) => { setActor(event.target.value); setOffset(0); }} />
          <Input aria-label="Filter by action" placeholder="Action (exact match), e.g. BLOCK_IP" value={action} onChange={(event) => { setAction(event.target.value); setOffset(0); }} className="font-mono uppercase placeholder:font-sans placeholder:normal-case" />
          <Input aria-label="Filter by target" placeholder="Target (exact match), e.g. 203.0.113.45" value={target} onChange={(event) => { setTarget(event.target.value); setOffset(0); }} className="font-mono placeholder:font-sans" />
        </div>
        {error ? <ErrorState error={error} onRetry={() => void mutate()} /> : !data ? <TableSkeleton /> : !data.items.length ? <EmptyState title="No audit events match" /> : (
          <>
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead><tr><th scope="col">Time</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Outcome</th><th scope="col">Source</th><th scope="col">Reason</th></tr></thead>
                <tbody>
                  {data.items.map((event) => (
                    <FragmentRow key={event.id} event={event} expanded={expanded === event.id} onToggle={() => setExpanded(expanded === event.id ? null : event.id)} />
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination total={data.total} limit={data.limit} offset={data.offset} onChange={setOffset} />
          </>
        )}
      </Panel>
    </>
  );
}

function FragmentRow({ event, expanded, onToggle }: { event: AuditEvent; expanded: boolean; onToggle: () => void }) {
  const outcomeTone = event.outcome === "success" || event.outcome === "executed" ? "text-ok" : event.outcome === "simulated" ? "text-sev-medium" : event.outcome === "skipped" ? "text-mist" : "text-sev-high";
  const hasDetails = Object.keys(event.details ?? {}).length > 0;
  return (
    <>
      <tr>
        <td className="whitespace-nowrap"><Mono className="text-mist">{timestamp(event.timestamp)}</Mono></td>
        <td><Mono>{event.actor}</Mono></td>
        <td>
          {hasDetails ? (
            <button onClick={onToggle} aria-expanded={expanded} className="font-mono text-xs text-frost underline decoration-line-strong underline-offset-4 hover:text-iris">{event.action}</button>
          ) : <Mono>{event.action}</Mono>}
        </td>
        <td><Mono className="text-mist">{event.target ?? "—"}</Mono></td>
        <td className={`text-xs ${outcomeTone}`}>{humanise(event.outcome)}</td>
        <td className="text-xs text-mist">{event.source}{event.client_ip ? <Mono className="ml-1 text-fog">{event.client_ip}</Mono> : null}</td>
        <td className="max-w-md truncate text-mist" title={event.reason}>{event.reason || "—"}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={7} className="bg-ground">
            <pre className="max-h-64 overflow-auto font-mono text-2xs text-mist">{JSON.stringify(event.details, null, 2)}</pre>
          </td>
        </tr>
      )}
    </>
  );
}
