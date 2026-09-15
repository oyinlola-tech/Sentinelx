"use client";

import { ChevronDown, LogOut, Menu, Search, UserRound, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import useSWR from "swr";
import { ThreatTape } from "@/components/charts/charts";
import { CommandMenu } from "@/components/shell/command-menu";
import { ConsoleFooter } from "@/components/shell/footer";
import { NAV, type NavItem } from "@/components/shell/nav";
import { Wordmark } from "@/components/shell/wordmark";
import { query } from "@/lib/api";
import { EventsProvider, useEvents, type StreamState } from "@/lib/events";
import { useSession } from "@/lib/session";
import { useNow } from "@/lib/use-now";
import type { Detection, Overview, Page, Severity } from "@/lib/types";

const GROUPS: { name: NavItem["group"]; blurb: string }[] = [
  { name: "Watch", blurb: "What the sensor sees right now" },
  { name: "Investigate", blurb: "Sources, incidents and traffic" },
  { name: "Respond", blurb: "Blocks, rules and replays" },
  { name: "Administer", blurb: "Accountability and configuration" },
];

export function AppShell({ children }: { children: ReactNode }) {
  const { user, loading } = useSession();
  if (loading || !user) {
    return (
      <div className="graticule grid min-h-dvh place-items-center" role="status">
        <p className="eyebrow">Checking session…</p>
      </div>
    );
  }
  return (
    <EventsProvider enabled>
      <Chrome>{children}</Chrome>
    </EventsProvider>
  );
}

function Chrome({ children }: { children: ReactNode }) {
  const { can } = useSession();
  const visible = NAV.filter((item) => can(item.minRole));
  return (
    <div className="flex min-h-dvh flex-col">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-sm focus:bg-signal focus:px-3 focus:py-1.5 focus:text-ground">
        Skip to content
      </a>
      <TopNav />
      <main id="main" className="mx-auto w-full max-w-[1680px] min-w-0 flex-1 px-4 py-6 lg:px-8">
        {children}
      </main>
      <ConsoleFooter />
      <CommandMenu pages={visible.map((item) => ({ id: item.href, label: item.label, hint: item.hint, href: item.href }))} />
    </div>
  );
}

function useCounts() {
  const { data: overview } = useSWR<Overview>("/stats/overview", { refreshInterval: 30_000 });
  return {
    overview,
    counts: {
      incidents: typeof overview?.open_incidents === "number" ? overview.open_incidents : 0,
      approvals: typeof overview?.pending_approvals === "number" ? overview.pending_approvals : 0,
    },
  };
}

function isActive(pathname: string, href: string): boolean {
  return href === "/" ? pathname === "/" : pathname.startsWith(href);
}

/**
 * Top navigation: four task groups, each a panel of destinations with what they are
 * for, in the manner of a product mega menu. Everything an operator glances at between
 * tasks (posture, stream, search, account) sits on the right of the same bar.
 */
function TopNav() {
  const pathname = usePathname();
  const { can } = useSession();
  const { overview, counts } = useCounts();
  const [openGroup, setOpenGroup] = useState<NavItem["group"] | null>(null);
  const [sheetOpen, setSheetOpen] = useState(false);
  const [lastPath, setLastPath] = useState(pathname);
  const barRef = useRef<HTMLDivElement>(null);
  const visible = NAV.filter((item) => can(item.minRole));

  // Navigating closes any open menu (state adjusted during render, not in an effect).
  if (lastPath !== pathname) {
    setLastPath(pathname);
    setOpenGroup(null);
    setSheetOpen(false);
  }

  useEffect(() => {
    if (!openGroup) return;
    const close = (event: MouseEvent | KeyboardEvent) => {
      if (event instanceof KeyboardEvent ? event.key === "Escape" : !barRef.current?.contains(event.target as Node)) setOpenGroup(null);
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", close);
    };
  }, [openGroup]);

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-ground/92 backdrop-blur-md">
      <div ref={barRef} className="relative mx-auto flex h-14 max-w-[1680px] items-center gap-3 px-4 lg:gap-6 lg:px-8">
        <button className="-ml-1 rounded-sm p-1.5 text-mist hover:text-frost lg:hidden" onClick={() => setSheetOpen(true)} aria-label="Open navigation">
          <Menu className="size-5" />
        </button>
        <Link href="/" aria-label="SentinelX overview" className="shrink-0">
          <Wordmark size="sm" />
        </Link>

        <nav aria-label="Primary" className="hidden h-full items-stretch lg:flex">
          {GROUPS.map(({ name }) => {
            const items = visible.filter((item) => item.group === name);
            if (items.length === 0) return null;
            const active = items.some((item) => isActive(pathname, item.href));
            const expanded = openGroup === name;
            const attention = items.reduce((total, item) => total + (item.badge ? counts[item.badge] : 0), 0);
            return (
              <div key={name} className="relative flex">
                <button
                  type="button"
                  aria-expanded={expanded}
                  aria-controls={`menu-${name}`}
                  onClick={() => setOpenGroup(expanded ? null : name)}
                  className={`group relative flex items-center gap-1.5 px-3 text-sm transition-colors ${active || expanded ? "text-frost" : "text-mist hover:text-frost"}`}
                >
                  {name}
                  {attention > 0 && <span className="size-1.5 rounded-full bg-signal" aria-label={`${attention} need attention`} />}
                  <ChevronDown className={`size-3.5 text-fog transition-transform ${expanded ? "rotate-180" : ""}`} aria-hidden />
                  <span className={`absolute inset-x-3 bottom-0 h-0.5 ${active ? "bg-signal" : "bg-transparent"}`} aria-hidden />
                </button>
              </div>
            );
          })}
        </nav>

        {openGroup && (
          <MegaMenu
            id={`menu-${openGroup}`}
            group={GROUPS.find((group) => group.name === openGroup)!}
            items={visible.filter((item) => item.group === openGroup)}
            pathname={pathname}
            counts={counts}
            onNavigate={() => setOpenGroup(null)}
          />
        )}

        <div className="ml-auto flex shrink-0 items-center gap-2 sm:gap-3">
          <button
            onClick={() => window.dispatchEvent(new Event("sentinelx:command"))}
            className="flex h-8 items-center gap-2 rounded-sm border border-line-strong px-2.5 text-xs text-mist transition-colors hover:border-mist hover:text-frost"
            aria-label="Open command menu"
          >
            <Search className="size-3.5" aria-hidden />
            <span className="hidden xl:inline">Search</span>
            <kbd className="hidden rounded-sm border border-line px-1 font-mono text-[10px] text-fog xl:inline">Ctrl K</kbd>
          </button>
          {typeof overview?.safety === "string" && <SafetyChip banner={overview.safety} />}
          <StreamIndicator />
          <UserMenu />
        </div>
      </div>
      <StreamProblem />
      <ScopeStrip overview={overview} />
      {sheetOpen && <MobileSheet visible={visible} pathname={pathname} counts={counts} onClose={() => setSheetOpen(false)} />}
    </header>
  );
}

function MegaMenu({ id, group, items, pathname, counts, onNavigate }: {
  id: string;
  group: { name: string; blurb: string };
  items: NavItem[];
  pathname: string;
  counts: Record<"incidents" | "approvals", number>;
  onNavigate: () => void;
}) {
  return (
    <div id={id} className="absolute inset-x-4 top-[calc(100%+1px)] z-40 hidden motion-safe:animate-[menu-in_140ms_ease-out] lg:inset-x-8 lg:block">
      <div className="grid grid-cols-[14rem_1fr] overflow-hidden rounded-b-sm border border-t-0 border-line-strong bg-panel shadow-[0_24px_60px_-20px_rgba(0,0,0,0.7)]">
        <div className="graticule flex flex-col justify-between border-r border-line p-5">
          <p className="heading-display text-3xl text-frost">{group.name}</p>
          <p className="mt-6 text-sm text-mist">{group.blurb}</p>
        </div>
        <ul className={`grid ${items.length > 2 ? "grid-cols-2" : "grid-cols-1"} ${items.length > 3 ? "xl:grid-cols-4" : ""} [&>li]:border-r [&>li]:border-b [&>li]:border-line`}>
          {items.map((item) => {
            const active = isActive(pathname, item.href);
            const count = item.badge ? counts[item.badge] : 0;
            return (
              <li key={item.href} className="bg-panel">
                <Link
                  href={item.href}
                  onClick={onNavigate}
                  aria-current={active ? "page" : undefined}
                  className={`group flex h-full gap-3 p-4 transition-colors hover:bg-raised ${active ? "bg-raised" : ""}`}
                >
                  <span className={`mt-0.5 [&_svg]:size-4 ${active ? "text-signal" : "text-fog group-hover:text-frost"}`} aria-hidden>{item.icon}</span>
                  <span className="min-w-0">
                    <span className="flex items-center gap-2 text-sm font-medium text-frost">
                      {item.label}
                      {count > 0 && (
                        <span className={`rounded-sm px-1.5 font-mono text-[10px] tabular ${item.badge === "approvals" ? "bg-signal/15 text-signal" : "bg-sev-high/15 text-sev-high"}`}>
                          {count}
                          <span className="sr-only"> {item.badge === "approvals" ? "awaiting approval" : "open"}</span>
                        </span>
                      )}
                    </span>
                    <span className="mt-1 block text-xs text-mist">{item.hint}</span>
                  </span>
                </Link>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}

function MobileSheet({ visible, pathname, counts, onClose }: {
  visible: NavItem[];
  pathname: string;
  counts: Record<"incidents" | "approvals", number>;
  onClose: () => void;
}) {
  useEffect(() => {
    const close = (event: KeyboardEvent) => event.key === "Escape" && onClose();
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-ground lg:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
      <div className="flex h-14 items-center justify-between border-b border-line px-4">
        <Wordmark size="sm" />
        <button onClick={onClose} className="rounded-sm p-1.5 text-mist hover:text-frost" aria-label="Close navigation">
          <X className="size-5" />
        </button>
      </div>
      <nav aria-label="Primary" className="flex-1 overflow-y-auto px-4 py-4">
        {GROUPS.map(({ name }) => {
          const items = visible.filter((item) => item.group === name);
          if (items.length === 0) return null;
          return (
            <div key={name} className="mb-6">
              <p className="eyebrow mb-2">{name}</p>
              <ul className="divide-y divide-line border-y border-line">
                {items.map((item) => {
                  const active = isActive(pathname, item.href);
                  const count = item.badge ? counts[item.badge] : 0;
                  return (
                    <li key={item.href}>
                      <Link href={item.href} onClick={onClose} aria-current={active ? "page" : undefined} className="flex items-center gap-3 py-3">
                        <span className={`[&_svg]:size-4 ${active ? "text-signal" : "text-fog"}`} aria-hidden>{item.icon}</span>
                        <span className="heading-display text-2xl text-frost">{item.label}</span>
                        {count > 0 && <span className="ml-auto font-mono text-xs text-sev-high tabular">{count}</span>}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          );
        })}
      </nav>
    </div>
  );
}

function UserMenu() {
  const { user, logout } = useSession();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent | KeyboardEvent) => {
      if (event instanceof KeyboardEvent ? event.key === "Escape" : !ref.current?.contains(event.target as Node)) setOpen(false);
    };
    window.addEventListener("mousedown", close);
    window.addEventListener("keydown", close);
    return () => {
      window.removeEventListener("mousedown", close);
      window.removeEventListener("keydown", close);
    };
  }, [open]);
  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        aria-label={`Account: ${user?.username ?? ""}`}
        className="flex h-8 items-center gap-2 rounded-sm border border-line-strong pr-2.5 pl-1.5 text-xs text-mist transition-colors hover:border-mist hover:text-frost"
      >
        <span className="grid size-5 place-items-center rounded-sm bg-raised font-mono text-[10px] text-frost uppercase">{user?.username.slice(0, 1)}</span>
        <span className="hidden max-w-24 truncate sm:inline">{user?.username}</span>
      </button>
      {open && (
        <div className="absolute top-[calc(100%+6px)] right-0 z-40 w-56 rounded-sm border border-line-strong bg-panel p-1 shadow-2xl motion-safe:animate-[menu-in_140ms_ease-out]">
          <div className="border-b border-line px-3 py-2.5">
            <p className="truncate text-sm text-frost">{user?.username}</p>
            <p className="eyebrow mt-0.5">{user?.role}</p>
          </div>
          <Link href="/account" onClick={() => setOpen(false)} className="flex items-center gap-2 rounded-sm px-3 py-2 text-sm text-mist hover:bg-raised hover:text-frost">
            <UserRound className="size-4" aria-hidden /> Account
          </Link>
          <button onClick={() => void logout()} className="flex w-full items-center gap-2 rounded-sm px-3 py-2 text-left text-sm text-mist hover:bg-raised hover:text-frost">
            <LogOut className="size-4" aria-hidden /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

/**
 * The scope strip under the navigation, on every page: live packets per second from
 * this session's capture statistics as an amber trace, and the last hour's detections
 * as ticks (height and colour by severity, label on hover). Both are real data; with no
 * live capture the trace stays flat and says so.
 */
function ScopeStrip({ overview }: { overview?: Overview }) {
  const { recent, subscribe } = useEvents();
  const now = useNow(60_000);
  const since = new Date(now - 3_600_000).toISOString();
  const { data } = useSWR<Page<Detection>>(`/detections${query({ since, limit: 500 })}`, { refreshInterval: 60_000 });
  const [samples, setSamples] = useState<{ t: number; pps: number }[]>([]);

  useEffect(
    () =>
      subscribe(["packet.stats"], (event) => {
        const payload = event.payload as { kind?: string; packets_per_second?: number };
        if (payload.kind !== "live" || typeof payload.packets_per_second !== "number") return;
        const sample = { t: Date.now(), pps: payload.packets_per_second };
        setSamples((previous) => [...previous.filter((item) => sample.t - item.t < 3_600_000), sample].slice(-720));
      }),
    [subscribe],
  );

  const tapeEvents = useMemo(() => {
    const seen = new Set<string>();
    const merged: { timestamp: string; severity: Severity; title: string; source: string }[] = [];
    for (const event of recent) {
      if (event.type !== "detection.created") continue;
      const payload = event.payload as unknown as Detection;
      if (payload.replay_id || seen.has(payload.detection_id)) continue;
      seen.add(payload.detection_id);
      merged.push({ timestamp: payload.timestamp, severity: payload.severity, title: payload.title, source: payload.source_ip });
    }
    for (const detection of Array.isArray(data?.items) ? data.items : []) {
      if (seen.has(detection.detection_id)) continue;
      seen.add(detection.detection_id);
      merged.push({ timestamp: detection.timestamp, severity: detection.severity, title: detection.title, source: detection.source_ip });
    }
    return merged;
  }, [recent, data]);

  const latest = samples.at(-1)?.pps;
  const capturing = overview?.sensor?.running === true;
  return (
    <div className="border-t border-line/70 bg-panel/40">
      <div className="mx-auto flex h-9 max-w-[1680px] items-center gap-4 px-4 lg:px-8">
        <div className="hidden w-36 shrink-0 items-baseline gap-2 sm:flex">
          <span className="eyebrow">Signal</span>
          <span className="font-mono text-xs text-frost tabular">
            {latest != null ? `${compactNumber(latest)} pkt/s` : capturing ? "waiting…" : "no capture"}
          </span>
        </div>
        <div className="relative min-w-0 flex-1">
          <PacketTrace samples={samples} now={now} />
          <ThreatTape events={tapeEvents} />
        </div>
      </div>
    </div>
  );
}

function PacketTrace({ samples, now }: { samples: { t: number; pps: number }[]; now: number }) {
  const span = 3_600_000;
  const end = Math.max(now, samples.at(-1)?.t ?? now);
  const max = Math.max(1, ...samples.map((sample) => sample.pps));
  const points = samples.map((sample) => `${Math.max(0, 1000 - ((end - sample.t) / span) * 1000).toFixed(1)},${(26 - (sample.pps / max) * 22).toFixed(1)}`);
  const path = points.length > 1 ? `M${points.join(" L")}` : "M0,26 L1000,26";
  return (
    <svg className="pointer-events-none absolute inset-0 h-7 w-full" viewBox="0 0 1000 28" preserveAspectRatio="none" aria-hidden>
      <path d={path} fill="none" stroke="var(--color-signal)" strokeOpacity={points.length > 1 ? 0.9 : 0.25} strokeWidth="1.25" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
    </svg>
  );
}

function compactNumber(value: number): string {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

export function SafetyChip({ banner }: { banner: string }) {
  const mode = banner.startsWith("PREVENTION ACTIVE") ? "active" : banner.startsWith("DRY RUN") ? "dry" : "detect";
  const styles = {
    active: "border-sev-critical/70 bg-sev-critical/15 text-sev-critical",
    dry: "border-signal/60 bg-signal/10 text-signal",
    detect: "border-line-strong text-mist",
  }[mode];
  const label = { active: "Prevention active", dry: "Dry run", detect: "Detection only" }[mode];
  return (
    <Link href="/settings#response" title={banner} aria-label={`Safety posture: ${label}`} className={`inline-flex h-8 items-center gap-2 rounded-sm border px-2.5 font-mono text-[10px] font-medium tracking-[0.12em] uppercase transition-colors hover:text-frost ${styles}`}>
      <span className={`size-1.5 rounded-full ${mode === "active" ? "motion-safe:animate-pulse" : ""}`} style={{ background: "currentColor" }} aria-hidden />
      <span className="sm:hidden">{{ active: "Prevent", dry: "Dry run", detect: "Detect" }[mode]}</span>
      <span className="hidden sm:inline">{label}</span>
    </Link>
  );
}

/** Tells the operator why the live stream is refused, and what to change, instead of spinning. */
function StreamProblem() {
  const { state, problem } = useEvents();
  if (!problem || state === "open") return null;
  const origin = typeof window !== "undefined" ? window.location.origin : "";
  const originRefused = /origin/i.test(problem);
  return (
    <div role="alert" className="border-t border-signal/40 bg-signal/10">
      <p className="mx-auto max-w-[1680px] px-4 py-2 text-xs text-signal lg:px-8">
        <span className="font-mono tracking-[0.1em] uppercase">Live stream refused</span> · {problem}.{" "}
        {originRefused ? (
          <>The API does not allow this dashboard address. Add <code className="font-mono text-frost">{origin}</code> to <code className="font-mono text-frost">CORS_ORIGINS</code> on the server and restart it.</>
        ) : (
          <>Retrying automatically.</>
        )}
      </p>
    </div>
  );
}

function StreamIndicator() {
  const { state } = useEvents();
  const meta: Record<StreamState, { label: string; className: string; dot: string }> = {
    open: { label: "Live", className: "text-ok", dot: "bg-ok" },
    connecting: { label: "Connecting", className: "text-mist", dot: "bg-mist motion-safe:animate-pulse" },
    reconnecting: { label: "Reconnecting", className: "text-signal", dot: "bg-signal motion-safe:animate-pulse" },
    offline: { label: "Stream offline", className: "text-sev-high", dot: "bg-sev-high" },
  };
  const current = meta[state];
  return (
    <span className={`hidden items-center gap-1.5 font-mono text-[10px] tracking-[0.12em] uppercase md:flex ${current.className}`} role="status" aria-live="polite">
      <span className="relative flex size-2" aria-hidden>
        {state === "open" && <span className={`absolute inset-0 rounded-full ${current.dot} opacity-60 motion-safe:animate-ping`} />}
        <span className={`relative size-2 rounded-full ${current.dot}`} />
      </span>
      {current.label}
    </span>
  );
}
