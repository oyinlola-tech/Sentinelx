"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { EmptyState, ErrorState, Pagination, Panel, StaleNotice, TableSkeleton, Tabs } from "@/components/ui/primitives";
import { Mono, RiskScore, SeverityBadge, StatusBadge } from "@/components/ui/security";
import { query } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { ago, humanise } from "@/lib/format";
import { isTransientRateLimit } from "@/lib/rate-limit";
import type { Incident, Page } from "@/lib/types";

const VIEWS = { active: ["open", "investigating", "contained"], closed: ["resolved", "false_positive"], all: [] as string[] };

export default function IncidentsPage() {
  const router = useRouter();
  const [view, setView] = useState<keyof typeof VIEWS>("active");
  const [offset, setOffset] = useState(0);
  const { data, error, mutate } = useSWR<Page<Incident>>(`/incidents${query({ status: VIEWS[view], limit: 50, offset })}`, { refreshInterval: 30_000 });
  useEventRefresh(["incident.opened", "incident.updated", "severity.changed"], () => void mutate());
  const rateLimited = isTransientRateLimit(error, data);

  return (
    <>
      <PageHeader title="Incidents" description="Related detections grouped into one story per source, named for the attack pattern they match." />
      <Panel bodyClassName="p-0">
        <Tabs label="Incident status" value={view} onChange={(value) => { setView(value); setOffset(0); }} options={[{ value: "active", label: "Active" }, { value: "closed", label: "Closed" }, { value: "all", label: "All" }]} />
        {rateLimited && <StaleNotice error={error} className="m-3" />}
        {error && !rateLimited ? <ErrorState error={error} onRetry={() => void mutate()} /> : !data ? <TableSkeleton /> : !data.items.length ? (
          <EmptyState title={view === "active" ? "No active incidents" : "No incidents"}>
            An incident opens when separate detectors agree about one source within the correlation window, or a single detection is critical enough on its own.
          </EmptyState>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="data-table">
                <thead>
                  <tr><th scope="col">Risk</th><th scope="col">Severity</th><th scope="col">Incident</th><th scope="col">Sources</th><th scope="col">Detections</th><th scope="col">Services</th><th scope="col">Status</th><th scope="col">Assigned</th><th scope="col">Last activity</th></tr>
                </thead>
                <tbody>
                  {data.items.map((incident) => {
                    const href = `/incidents/${incident.incident_id}`;
                    return (
                      <tr key={incident.incident_id} data-href={href} onClick={() => router.push(href)}>
                        <td><RiskScore score={incident.risk.score} /></td>
                        <td><SeverityBadge severity={incident.severity} /></td>
                        <td className="max-w-80">
                          <Link href={href} className="block truncate text-frost hover:text-iris">{incident.title}</Link>
                          <span className="font-mono text-2xs text-fog">{humanise(incident.correlation_rule)}</span>
                        </td>
                        <td><Mono>{incident.affected_sources.slice(0, 2).join(", ")}{incident.affected_sources.length > 2 ? ` +${incident.affected_sources.length - 2}` : ""}</Mono></td>
                        <td><Mono>{incident.detection_count}</Mono></td>
                        <td><Mono className="text-mist">{incident.affected_services.slice(0, 4).join(", ") || "—"}</Mono></td>
                        <td><StatusBadge status={incident.status} /></td>
                        <td className="text-mist">{incident.assigned_to ?? "—"}</td>
                        <td><Mono className="text-mist">{ago(incident.last_seen)}</Mono></td>
                      </tr>
                    );
                  })}
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
