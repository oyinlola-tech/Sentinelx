"use client";

import { ArrowUpRight } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import useSWR from "swr";
import { NAV, type NavItem } from "@/components/shell/nav";
import { Wordmark } from "@/components/shell/wordmark";
import { useSession } from "@/lib/session";
import type { Overview } from "@/lib/types";

interface Health {
  status: "ok" | "degraded" | "error";
  version: string;
}

type Status = "ok" | "degraded" | "error" | "unreachable" | "checking";

const STATUS: Record<Status, { tone: string; label: string }> = {
  ok: { tone: "bg-ok", label: "All systems operational" },
  degraded: { tone: "bg-sev-medium", label: "Degraded, see Settings › Health" },
  error: { tone: "bg-sev-critical", label: "Platform error" },
  unreachable: { tone: "bg-sev-critical", label: "API unreachable" },
  checking: { tone: "bg-fog", label: "Checking status" },
};

const AUTHOR = { name: "Oluwayemi Oyinlola Michael", url: "https://oyinlola1.vercel.app" };
const GROUPS: NavItem["group"][] = ["Watch", "Investigate", "Respond", "Administer"];

/**
 * The console footer, laid out like the rating plate on a piece of network hardware:
 * what this instrument is, which build it runs, whether it is healthy, and what it is
 * allowed to do to traffic. Every value is live; nothing here is decorative copy.
 */
export function ConsoleFooter({ minimal = false }: { minimal?: boolean }) {
  const { data: health, error } = useSWR<Health>("/system/health", { refreshInterval: 30_000 });
  const status: Status = error ? "unreachable" : (health?.status ?? "checking");

  if (minimal) {
    return (
      <footer className="border-t border-line px-4 py-4 lg:px-6">
        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 font-mono text-2xs text-fog">
          <StatusLine status={status} version={health?.version} />
          <Credit />
        </div>
      </footer>
    );
  }
  return <FullFooter status={status} version={health?.version} />;
}

function FullFooter({ status, version }: { status: Status; version?: string }) {
  const { can } = useSession();
  // Shares the SWR key the sidebar already polls, so this costs no extra request.
  const { data: overview } = useSWR<Overview>("/stats/overview", { refreshInterval: 30_000 });
  const visible = NAV.filter((item) => can(item.minRole));
  // The footer is on every page: a malformed overview must not take the page down with it.
  const posture = (typeof overview?.safety === "string" ? overview.safety.split(" - ")[0] : undefined) ?? "Unknown";
  const enforcing = posture.startsWith("PREVENTION");
  const plate: [string, ReactNode][] = [
    ["Sensor", typeof overview?.sensor?.sensor === "string" ? overview.sensor.sensor : "…"],
    ["Build", `v${overview?.version ?? version ?? "…"}`],
    ["Status", <StatusLine key="status" status={status} />],
    [
      "Posture",
      <span key="posture" className={enforcing ? "text-sev-high" : "text-frost"}>
        {posture.toLowerCase()}
      </span>,
    ],
  ];

  return (
    <footer className="relative mt-10 overflow-hidden border-t border-line bg-panel/40" aria-labelledby="footer-heading">
      <h2 id="footer-heading" className="sr-only">
        Site footer
      </h2>
      <div className="relative z-10 grid gap-10 px-4 pt-10 pb-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,2fr)] lg:px-6">
        <div className="max-w-sm">
          <Wordmark />
          <p className="mt-3 text-sm text-mist">
            Explainable network intrusion detection. Every alert shows its evidence, its score and what was done about it.
          </p>
          <dl className="mt-5 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 rounded border border-line bg-ground/60 px-3 py-2.5 font-mono text-2xs">
            {plate.map(([label, value]) => (
              <div key={label} className="contents">
                <dt className="uppercase tracking-[0.14em] text-fog">{label}</dt>
                <dd className="min-w-0 truncate text-mist">{value}</dd>
              </div>
            ))}
          </dl>
        </div>

        <nav aria-label="Footer" className="grid grid-cols-2 gap-x-6 gap-y-8 sm:grid-cols-4">
          {GROUPS.map((group) => {
            const items = visible.filter((item) => item.group === group);
            if (items.length === 0) return null;
            return (
              <div key={group}>
                <p className="eyebrow">{group}</p>
                <ul className="mt-3 space-y-2 text-sm">
                  {items.map((item) => (
                    <li key={item.href}>
                      <Link href={item.href} className="text-mist transition-colors hover:text-frost">
                        {item.label}
                      </Link>
                    </li>
                  ))}
                  {group === "Administer" && overview?.api_docs && (
                    <li>
                      <a href="/api/docs" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-mist transition-colors hover:text-frost">
                        API reference
                        <ArrowUpRight className="size-3" aria-hidden />
                        <span className="sr-only">(opens in a new tab)</span>
                      </a>
                    </li>
                  )}
                </ul>
              </div>
            );
          })}
        </nav>
      </div>

      <div className="relative z-10 mx-4 flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-t border-line py-4 font-mono text-2xs text-fog lg:mx-6">
        <p>Apache-2.0 · For defensive use on networks you are authorised to monitor</p>
        <Credit />
      </div>

      <Signature />
    </footer>
  );
}

function StatusLine({ status, version }: { status: Status; version?: string }) {
  const { tone, label } = STATUS[status];
  return (
    <span className="inline-flex items-center gap-2" role="status">
      <span className={`relative flex size-1.5 rounded-full ${tone}`} aria-hidden>
        {status === "ok" && <span className={`absolute inset-0 rounded-full ${tone} motion-safe:animate-ping opacity-60`} />}
      </span>
      <span className="text-mist">{label}</span>
      {version && <span>· v{version}</span>}
    </span>
  );
}

function Credit() {
  return (
    <p>
      Designed and built by{" "}
      <a href={AUTHOR.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-mist underline decoration-line underline-offset-4 transition-colors hover:text-frost hover:decoration-iris">
        {AUTHOR.name}
        <ArrowUpRight className="size-3" aria-hidden />
        <span className="sr-only">(opens in a new tab)</span>
      </a>
    </p>
  );
}

/**
 * The oversized wordmark, cropped by the bottom edge, with the SentinelX trace
 * running through it. Decorative only, so it is hidden from assistive technology.
 */
function Signature() {
  return (
    <div className="pointer-events-none relative -mt-2 h-[clamp(4.5rem,13vw,11rem)] select-none" aria-hidden>
      <p className="absolute inset-x-0 bottom-0 translate-y-[28%] px-3 text-center font-display text-[clamp(5rem,17vw,15rem)] leading-none font-extrabold tracking-[-0.045em] whitespace-nowrap text-transparent [-webkit-text-stroke:1px_var(--color-line-strong)]">
        Sentinel<span className="[-webkit-text-stroke:1px_color-mix(in_oklab,var(--color-iris)_55%,transparent)]">X</span>
      </p>
      <svg className="absolute inset-x-0 bottom-[38%] h-10 w-full" viewBox="0 0 1200 40" preserveAspectRatio="none">
        <path
          d="M0 20 H470 l8 -6 8 12 10 -18 12 26 10 -14 H1200"
          fill="none"
          stroke="var(--color-iris)"
          strokeOpacity="0.55"
          strokeWidth="1.5"
          vectorEffect="non-scaling-stroke"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}
