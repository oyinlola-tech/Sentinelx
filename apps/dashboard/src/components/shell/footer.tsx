"use client";

import { ArrowUpRight } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";
import useSWR from "swr";
import { NAV, type NavItem } from "@/components/shell/nav";
import { ScopeMark } from "@/components/shell/wordmark";
import { useSession } from "@/lib/session";
import type { Overview } from "@/lib/types";

interface Health {
  status: "ok" | "degraded" | "error";
  version: string;
}

type Status = "ok" | "degraded" | "error" | "unreachable" | "checking";

const STATUS: Record<Status, { tone: string; label: string }> = {
  ok: { tone: "bg-ok", label: "All systems operational" },
  degraded: { tone: "bg-signal", label: "Degraded, see Settings › Health" },
  error: { tone: "bg-sev-critical", label: "Platform error" },
  unreachable: { tone: "bg-sev-critical", label: "API unreachable" },
  checking: { tone: "bg-fog", label: "Checking status" },
};

const AUTHOR = { name: "Oluwayemi Oyinlola Michael", url: "https://oyinlola1.vercel.app" };
const GROUPS: NavItem["group"][] = ["Watch", "Investigate", "Respond", "Administer"];

/**
 * The console footer, built like the sign-off of a well-made site: a live rating plate
 * (what this instrument is, which build, whether it is healthy, what it may do to
 * traffic), the map of the console by task, and the name set large enough to be the
 * last thing on the page. Every value on the plate is live.
 */
export function ConsoleFooter({ minimal = false }: { minimal?: boolean }) {
  const { data: health, error } = useSWR<Health>("/system/health", { refreshInterval: 30_000 });
  const status: Status = error ? "unreachable" : (health?.status ?? "checking");

  if (minimal) {
    return (
      <footer className="border-t border-line px-4 py-4 lg:px-8">
        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 font-mono text-[10px] tracking-wide text-fog">
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
  // Shares the SWR key the navigation already polls, so this costs no extra request.
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
      <span key="posture" className={enforcing ? "text-sev-critical" : "text-frost"}>
        {posture.toLowerCase()}
      </span>,
    ],
  ];

  return (
    <footer className="relative mt-16 overflow-hidden border-t border-line" aria-labelledby="footer-heading">
      <h2 id="footer-heading" className="sr-only">
        Site footer
      </h2>
      <div className="relative z-10 mx-auto grid max-w-[1680px] gap-10 px-4 pt-12 pb-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:px-8">
        <div>
          <p className="heading-display max-w-md text-4xl text-frost sm:text-5xl">
            Every alert shows its&nbsp;work.
          </p>
          <p className="mt-4 max-w-sm text-sm text-mist">
            Explainable intrusion detection for networks you are responsible for: the evidence, the score and what was done about it.
          </p>
          <dl className="mt-7 grid max-w-md grid-cols-[auto_1fr] border border-line-strong font-mono text-[11px]">
            {plate.map(([label, value], index) => (
              <div key={label} className={`contents ${index > 0 ? "[&>*]:border-t [&>*]:border-line" : ""}`}>
                <dt className="border-r border-line bg-panel px-3 py-2 tracking-[0.14em] text-fog uppercase">{label}</dt>
                <dd className="min-w-0 truncate px-3 py-2 text-mist">{value}</dd>
              </div>
            ))}
          </dl>
        </div>

        <nav aria-label="Footer" className="grid grid-cols-2 gap-x-6 gap-y-10 sm:grid-cols-4 lg:pt-3">
          {GROUPS.map((group) => {
            const items = visible.filter((item) => item.group === group);
            if (items.length === 0) return null;
            return (
              <div key={group}>
                <p className="eyebrow border-b border-line pb-2">{group}</p>
                <ul className="mt-4 space-y-2.5 text-sm">
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

      <div className="relative z-10 mx-auto flex max-w-[1680px] flex-wrap items-center justify-between gap-x-6 gap-y-2 border-t border-line px-4 py-4 font-mono text-[10px] tracking-wide text-fog lg:px-8">
        <p className="flex items-center gap-2">
          <ScopeMark className="size-3.5" />
          Apache-2.0 · For defensive use on networks you are authorised to monitor
        </p>
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
        {status === "ok" && <span className={`absolute inset-0 rounded-full ${tone} opacity-60 motion-safe:animate-ping`} />}
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
      <a href={AUTHOR.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-0.5 text-mist underline decoration-line-strong underline-offset-4 transition-colors hover:text-frost hover:decoration-signal">
        {AUTHOR.name}
        <ArrowUpRight className="size-3" aria-hidden />
        <span className="sr-only">(opens in a new tab)</span>
      </a>
    </p>
  );
}

/**
 * The name in stencil letters wide enough to fill the page, cropped by its bottom edge,
 * with a single contact on the X. Decorative only, so hidden from assistive technology.
 */
function Signature() {
  return (
    <div className="pointer-events-none relative h-[clamp(5rem,15vw,15rem)] select-none" aria-hidden>
      <p className="absolute inset-x-0 bottom-0 translate-y-[24%] text-center font-stencil text-[clamp(6rem,21.5vw,26rem)] leading-[0.8] font-black tracking-[0.01em] whitespace-nowrap text-raised uppercase">
        Sentinel<span className="relative text-line-strong">X<span className="absolute top-[18%] right-[8%] size-[0.07em] rounded-full bg-signal shadow-[0_0_0.1em_var(--color-signal)]" /></span>
      </p>
    </div>
  );
}
