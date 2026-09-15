"use client";

import { Search } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";
import useSWR from "swr";
import { PageHeader } from "@/components/shell/page-header";
import { DetectionTable } from "@/components/views/detection-table";
import { EmptyState, ErrorState, Input, Pagination, Panel, Select, StaleNotice, TableSkeleton, Tabs } from "@/components/ui/primitives";
import { Mono, RiskScore, SeverityBadge } from "@/components/ui/security";
import { query } from "@/lib/api";
import { useEventRefresh } from "@/lib/events";
import { isTransientRateLimit } from "@/lib/rate-limit";
import { useDebouncedValue } from "@/lib/use-debounced-value";
import { useNow } from "@/lib/use-now";
import { SEVERITIES, ago, humanise } from "@/lib/format";
import type { Detection, Page, Severity, Threat } from "@/lib/types";

const RANGES = [{ label: "1 hour", hours: 1 }, { label: "24 hours", hours: 24 }, { label: "7 days", hours: 168 }, { label: "30 days", hours: 720 }];

export default function ThreatsPage() {
  return (
    <Suspense fallback={<TableSkeleton />}>
      <Threats />
    </Suspense>
  );
}

function Threats() {
  const params = useSearchParams();
  const initialSource = params.get("source") ?? "";
  const [view, setView] = useState<"sources" | "detections">(initialSource ? "detections" : "sources");
  const [hours, setHours] = useState(initialSource ? 720 : 24);
  return (
    <>
      <PageHeader
        title="Threats"
        description="Who is acting against the network, how dangerous it is, and the detections behind each assessment."
        actions={
          <Select aria-label="Time range" value={hours} onChange={(event) => setHours(Number(event.target.value))} className="w-36">
            {RANGES.map((range) => <option key={range.hours} value={range.hours}>Last {range.label}</option>)}
          </Select>
        }
      />
      <Panel bodyClassName="p-0">
        <Tabs label="Threat views" value={view} onChange={setView} options={[{ value: "sources", label: "By source" }, { value: "detections", label: "All detections" }]} />
        {view === "sources" ? <SourceView hours={hours} /> : <DetectionView hours={hours} initialSource={initialSource} />}
      </Panel>
    </>
  );
}

function SourceView({ hours }: { hours: number }) {
  const router = useRouter();
  const { data, error, mutate } = useSWR<Threat[]>(`/threats${query({ hours, limit: 200 })}`, { refreshInterval: 30_000 });
  useEventRefresh(["detection.created", "ip.blocked", "ip.unblocked"], () => void mutate(), 3000);
  const rateLimited = isTransientRateLimit(error, data);
  if (error && !rateLimited) return <ErrorState error={error} onRetry={() => void mutate()} />;
  if (!data) return <TableSkeleton />;
  if (!data.length) return <EmptyState title={`No threat sources in the last ${hours === 1 ? "hour" : `${hours} hours`}`}>Detections are grouped here by the address that caused them.</EmptyState>;
  return (
    <>
      {rateLimited && <StaleNotice error={error} className="m-3" />}
      <div className="overflow-x-auto">
        <table className="data-table">
          <thead>
            <tr>
              <th scope="col">Source</th><th scope="col">Max risk</th><th scope="col">Worst</th><th scope="col">Top threat</th>
              <th scope="col">Detections</th><th scope="col">Categories</th><th scope="col">Targets</th><th scope="col">Last seen</th><th scope="col">Status</th>
            </tr>
          </thead>
          <tbody>
            {data.map((threat) => {
              const worst = (SEVERITIES.find((severity) => threat.severities[severity]) ?? "info") as Severity;
              const href = `/detections/${threat.top_detection.detection_id}`;
              return (
                <tr key={threat.source_ip} data-href={href} onClick={() => router.push(href)}>
                  <td><Link href={href} className="font-mono text-xs text-frost hover:text-iris">{threat.source_ip}</Link></td>
                  <td><RiskScore score={threat.max_risk} /></td>
                  <td><SeverityBadge severity={worst} /></td>
                  <td className="max-w-64 truncate">{threat.top_detection.title}</td>
                  <td><Mono>{threat.detections}</Mono></td>
                  <td className="max-w-48 truncate text-mist">{threat.categories.map(humanise).join(", ")}</td>
                  <td><Mono className="text-mist">{threat.destinations.length}</Mono></td>
                  <td><Mono className="text-mist">{ago(threat.last_seen)}</Mono></td>
                  <td>
                    {threat.blocked ? (
                      <span className="font-mono text-2xs uppercase text-sev-critical">Blocked</span>
                    ) : threat.incident_ids.length ? (
                      <Link href={`/incidents/${threat.incident_ids[0]}`} onClick={(event) => event.stopPropagation()} className="font-mono text-2xs uppercase text-iris hover:underline">In incident</Link>
                    ) : (
                      <span className="font-mono text-2xs uppercase text-fog">Observed</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function DetectionView({ hours, initialSource }: { hours: number; initialSource: string }) {
  const [source, setSource] = useState(initialSource);
  const [severity, setSeverity] = useState<Severity | "">("");
  const [status, setStatus] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const now = useNow(60_000);
  const since = new Date(now - hours * 3_600_000).toISOString();
  // Typed filters wait for a pause in typing before they become part of the request.
  const debouncedSource = useDebouncedValue(source.trim(), 300);
  const debouncedSearch = useDebouncedValue(search.trim(), 300);
  const key = `/detections${query({ since, source_ip: debouncedSource || null, severity: severity || null, status: status || null, q: debouncedSearch || null, limit: 50, offset })}`;
  const { data, error, mutate } = useSWR<Page<Detection>>(key, { refreshInterval: 30_000 });
  const rateLimited = isTransientRateLimit(error, data);
  useEventRefresh(["detection.created"], () => void mutate(), 3000);
  return (
    <>
      <div className="flex flex-wrap gap-2 border-b border-line p-3">
        <div className="relative min-w-56 flex-1">
          <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-fog" aria-hidden />
          <Input aria-label="Search detections" placeholder="Search title, source or detector" value={search} onChange={(event) => { setSearch(event.target.value); setOffset(0); }} className="pl-8" />
        </div>
        <Input aria-label="Source address" placeholder="Source IP (exact match)" value={source} onChange={(event) => { setSource(event.target.value); setOffset(0); }} className="w-44 font-mono" />
        <Select aria-label="Severity" value={severity} onChange={(event) => { setSeverity(event.target.value as Severity | ""); setOffset(0); }} className="w-40">
          <option value="">Any severity</option>
          {SEVERITIES.map((item) => <option key={item} value={item}>{item}</option>)}
        </Select>
        <Select aria-label="Status" value={status} onChange={(event) => { setStatus(event.target.value); setOffset(0); }} className="w-44">
          <option value="">Any status</option>
          {["new", "acknowledged", "false_positive", "resolved"].map((item) => <option key={item} value={item}>{humanise(item)}</option>)}
        </Select>
      </div>
      {error && !rateLimited ? <ErrorState error={error} onRetry={() => void mutate()} /> : data ? (
        <>
          {rateLimited && <StaleNotice error={error} className="m-3" />}
          <DetectionTable detections={data.items} emptyTitle="No detections match" emptyBody="Try a wider time range or clear the filters." />
          <Pagination total={data.total} limit={data.limit} offset={data.offset} onChange={setOffset} />
        </>
      ) : <TableSkeleton />}
    </>
  );
}
