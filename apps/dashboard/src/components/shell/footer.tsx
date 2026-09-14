"use client";

import Link from "next/link";
import useSWR from "swr";

interface Health { status: "ok" | "degraded" | "error"; version: string }

/**
 * Slim console footer: honest system status, the running version, and the places an
 * operator goes next (API reference, detection performance, audit log), and the author credit. The health dot reads the same
 * unauthenticated endpoint load balancers use.
 */
export function ConsoleFooter({ minimal = false, sensor }: { minimal?: boolean; sensor?: string }) {
  const { data, error } = useSWR<Health>("/system/health", { refreshInterval: 30_000 });
  const status = error ? "unreachable" : data?.status ?? "checking";
  const tone = { ok: "bg-ok", degraded: "bg-sev-medium", error: "bg-sev-critical", unreachable: "bg-sev-critical", checking: "bg-fog" }[status];
  const label = { ok: "All systems operational", degraded: "Degraded — see Settings › Health", error: "Platform error", unreachable: "API unreachable", checking: "Checking status" }[status];
  return (
    <footer className="border-t border-line px-4 py-3 lg:px-6">
      <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 font-mono text-2xs text-fog">
        <p className="flex items-center gap-2" role="status">
          <span className={`size-1.5 rounded-full ${tone}`} aria-hidden />
          <span className="text-mist">{label}</span>
          {sensor && <span>· sensor {sensor}</span>}
          {data?.version && <span>· v{data.version}</span>}
        </p>
        {!minimal && (
          <nav aria-label="Footer" className="flex flex-wrap gap-x-4 gap-y-1">
            <a href="/api/docs" target="_blank" rel="noreferrer" className="hover:text-frost">API reference</a>
            <Link href="/analytics" className="hover:text-frost">Detection performance</Link>
            <Link href="/audit" className="hover:text-frost">Audit log</Link>
          </nav>
        )}
        <p>
          Apache-2.0 · defensive use only · built by{" "}
          <a href="https://oyinlola1.vercel.app" target="_blank" rel="noreferrer" className="text-mist hover:text-frost">
            Oluwayemi Oyinlola Michael
          </a>
        </p>
      </div>
    </footer>
  );
}
