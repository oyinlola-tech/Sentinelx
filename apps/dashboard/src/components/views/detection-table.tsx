"use client";

import { useRouter } from "next/navigation";
import { EmptyState } from "@/components/ui/primitives";
import { Mono, RiskScore, SeverityBadge, StatusBadge } from "@/components/ui/security";
import { ago, endpoint, humanise } from "@/lib/format";
import type { Detection } from "@/lib/types";

export function DetectionTable({ detections, emptyTitle = "No detections", emptyBody, showStatus = true, compact = false }: { detections: Detection[]; emptyTitle?: string; emptyBody?: string; showStatus?: boolean; compact?: boolean }) {
  const router = useRouter();
  if (!detections.length) return <EmptyState title={emptyTitle}>{emptyBody}</EmptyState>;
  return (
    <div className="overflow-x-auto">
      <table className="data-table">
        <thead>
          <tr>
            <th scope="col">When</th>
            <th scope="col">Severity</th>
            <th scope="col">Risk</th>
            <th scope="col">Threat</th>
            <th scope="col">Source</th>
            {!compact && <th scope="col">Target</th>}
            <th scope="col">Detector</th>
            {showStatus && !compact && <th scope="col">Status</th>}
          </tr>
        </thead>
        <tbody>
          {detections.map((detection) => {
            const href = `/detections/${detection.detection_id}`;
            return (
              <tr key={detection.detection_id} data-href={href} onClick={() => router.push(href)}>
                <td className="whitespace-nowrap"><Mono className="text-mist" >{ago(detection.timestamp)}</Mono></td>
                <td><SeverityBadge severity={detection.severity} /></td>
                <td><RiskScore score={detection.risk?.score ?? 0} /></td>
                <td className="max-w-72">
                  {/* A real link keeps the row keyboard- and screen-reader-reachable. */}
                  <a href={href} onClick={(event) => { event.preventDefault(); router.push(href); }} className="block truncate text-frost hover:text-iris">
                    {detection.title}
                  </a>
                </td>
                <td><Mono>{detection.source_ip}</Mono></td>
                {!compact && <td><Mono className="text-mist">{endpoint(detection.destination_ip, detection.destination_port)}</Mono></td>}
                <td className="whitespace-nowrap text-mist">{humanise(detection.detector)}</td>
                {showStatus && !compact && <td>{detection.status ? <StatusBadge status={detection.status} /> : null}</td>}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
