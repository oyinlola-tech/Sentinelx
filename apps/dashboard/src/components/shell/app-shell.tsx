"use client";

import { LogOut, Menu, Search, X } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useMemo, useState, type ReactNode } from "react";
import useSWR from "swr";
import { ThreatTape } from "@/components/charts/charts";
import { CommandMenu } from "@/components/shell/command-menu";
import { ConsoleFooter } from "@/components/shell/footer";
import { NAV } from "@/components/shell/nav";
import { Wordmark } from "@/components/shell/wordmark";
import { query } from "@/lib/api";
import { EventsProvider, useEvents, type StreamState } from "@/lib/events";
import { useSession } from "@/lib/session";
import { useMediaQuery } from "@/lib/use-media-query";
import { useNow } from "@/lib/use-now";
import type { Detection, Overview, Page, Severity } from "@/lib/types";



export function AppShell({ children }: { children: ReactNode }) {
  const { user, loading } = useSession();
  if (loading || !user) {
    return (
      <div className="grid min-h-dvh place-items-center" role="status">
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
  const [menuOpen, setMenuOpen] = useState(false);
  const { can } = useSession();
  const visible = NAV.filter((item) => can(item.minRole));
  return (
    <div className="flex min-h-dvh">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-iris focus:px-3 focus:py-1.5 focus:text-ground">
        Skip to content
      </a>
      <Sidebar open={menuOpen} onClose={() => setMenuOpen(false)} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onMenu={() => setMenuOpen(true)} />
        <main id="main" className="min-w-0 flex-1 px-4 py-5 lg:px-6">
          {children}
        </main>
        <ConsoleFooter />
      </div>
      <CommandMenu pages={visible.map((item) => ({ id: item.href, label: item.label, hint: item.hint, href: item.href }))} />
    </div>
  );
}

function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  const pathname = usePathname();
  const { user, logout, can } = useSession();
  const visible = NAV.filter((item) => can(item.minRole));
  const groups = [...new Set(visible.map((item) => item.group))];
  const { data: overview } = useSWR<Overview>("/stats/overview", { refreshInterval: 30_000 });
  const counts = { incidents: overview?.open_incidents ?? 0, approvals: overview?.pending_approvals ?? 0 };
  // Below lg the closed sidebar sits off-screen; inert keeps its links out of the tab order.
  const desktop = useMediaQuery("(min-width: 64rem)");
  return (
    <>
      {open && <button className="fixed inset-0 z-30 bg-black/50 lg:hidden" aria-label="Close navigation" onClick={onClose} />}
      <nav
        aria-label="Primary"
        inert={!open && !desktop}
        className={`fixed inset-y-0 left-0 z-40 flex w-56 flex-col border-r border-line bg-panel transition-transform lg:sticky lg:top-0 lg:h-dvh lg:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}
      >
        <div className="flex h-14 items-center justify-between border-b border-line px-4">
          <Link href="/" className="flex items-center gap-2">
            <Wordmark />
          </Link>
          <button className="text-mist lg:hidden" onClick={onClose} aria-label="Close navigation">
            <X className="size-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-2 py-3">
          {groups.map((group) => (
            <div key={group} className="mb-4">
              <p className="eyebrow px-2 pb-1">{group}</p>
              <ul>
                {visible.filter((item) => item.group === group).map((item) => {
                  const active = item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
                  return (
                    <li key={item.href}>
                      <Link
                        href={item.href}
                        aria-current={active ? "page" : undefined}
                        onClick={onClose}
                        className={`flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors [&_svg]:size-4 ${active ? "bg-raised text-frost shadow-[inset_2px_0_0_var(--color-iris)]" : "text-mist hover:bg-raised hover:text-frost"}`}
                      >
                        <span aria-hidden className={active ? "text-iris" : ""}>{item.icon}</span>
                        {item.label}
                        {item.badge && counts[item.badge] > 0 && (
                          <span className={`ml-auto rounded-full px-1.5 font-mono text-2xs tabular ${item.badge === "approvals" ? "bg-iris/20 text-iris" : "bg-sev-high/15 text-sev-high"}`}>
                            {counts[item.badge]}
                            <span className="sr-only"> {item.badge === "approvals" ? "awaiting approval" : "open"}</span>
                          </span>
                        )}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </div>
        <div className="border-t border-line p-3">
          <div className="flex items-center justify-between gap-2">
            <Link href="/account" className="min-w-0 rounded px-1 hover:bg-raised">
              <p className="truncate text-sm text-frost">{user?.username}</p>
              <p className="font-mono text-2xs uppercase tracking-wide text-fog">{user?.role}</p>
            </Link>
            <button onClick={() => void logout()} className="rounded p-1.5 text-mist hover:bg-raised hover:text-frost" aria-label="Sign out" title="Sign out">
              <LogOut className="size-4" />
            </button>
          </div>
        </div>
      </nav>
    </>
  );
}


function TopBar({ onMenu }: { onMenu: () => void }) {
  const { state, recent } = useEvents();
  const now = useNow(60_000);
  const since = new Date(now - 3_600_000).toISOString();
  const { data } = useSWR<Page<Detection>>(`/detections${query({ since, limit: 500 })}`, { refreshInterval: 60_000 });
  const { data: overview } = useSWR<{ safety: string }>("/stats/overview", { refreshInterval: 30_000 });

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
    for (const detection of data?.items ?? []) {
      if (seen.has(detection.detection_id)) continue;
      seen.add(detection.detection_id);
      merged.push({ timestamp: detection.timestamp, severity: detection.severity, title: detection.title, source: detection.source_ip });
    }
    return merged;
  }, [recent, data]);

  return (
    <header className="sticky top-0 z-20 border-b border-line bg-ground/90 backdrop-blur">
      <div className="flex h-14 items-center gap-4 px-4 lg:px-6">
        <button className="text-mist lg:hidden" onClick={onMenu} aria-label="Open navigation">
          <Menu className="size-5" />
        </button>
        <div className="hidden min-w-0 flex-1 sm:block">
          <ThreatTape events={tapeEvents} />
        </div>
        <div className="ml-auto flex shrink-0 items-center gap-3">
          <button
            onClick={() => window.dispatchEvent(new Event("sentinelx:command"))}
            className="flex h-8 items-center gap-2 rounded-md border border-line-strong px-2.5 text-xs text-mist hover:border-mist hover:text-frost"
            aria-label="Open command menu"
          >
            <Search className="size-3.5" aria-hidden />
            <span className="hidden lg:inline">Search</span>
            <kbd className="hidden rounded border border-line px-1 font-mono text-2xs text-fog lg:inline">Ctrl K</kbd>
          </button>
          {overview?.safety && <SafetyChip banner={overview.safety} />}
          <StreamIndicator state={state} />
        </div>
      </div>
    </header>
  );
}

export function SafetyChip({ banner }: { banner: string }) {
  const mode = banner.startsWith("PREVENTION ACTIVE") ? "active" : banner.startsWith("DRY RUN") ? "dry" : "detect";
  const styles = {
    active: "border-sev-critical/60 bg-sev-critical/15 text-sev-critical",
    dry: "border-sev-medium/50 bg-sev-medium/10 text-sev-medium",
    detect: "border-ok/40 bg-ok/10 text-ok",
  }[mode];
  const label = { active: "Prevention active", dry: "Dry run", detect: "Detection only" }[mode];
  return (
    <Link href="/settings#response" title={banner} aria-label={`Safety posture: ${label}`} className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-1 font-mono text-2xs font-medium tracking-wide uppercase sm:px-2.5 ${styles}`}>
      <span className={`size-1.5 rounded-full ${mode === "active" ? "animate-pulse" : ""}`} style={{ background: "currentColor" }} aria-hidden />
      <span className="sm:hidden">{{ active: "Prevent", dry: "Dry run", detect: "Detect" }[mode]}</span>
      <span className="hidden sm:inline">{label}</span>
    </Link>
  );
}

function StreamIndicator({ state }: { state: StreamState }) {
  const meta = {
    open: { label: "Live", className: "text-ok", dot: "bg-ok" },
    connecting: { label: "Connecting", className: "text-mist", dot: "bg-mist animate-pulse" },
    reconnecting: { label: "Reconnecting", className: "text-sev-medium", dot: "bg-sev-medium animate-pulse" },
    offline: { label: "Stream offline", className: "text-sev-high", dot: "bg-sev-high" },
  }[state];
  return (
    <span className={`flex items-center gap-1.5 font-mono text-2xs tracking-wide uppercase ${meta.className}`} role="status" aria-live="polite">
      <span className={`size-2 rounded-full ${meta.dot}`} aria-hidden />
      {meta.label}
    </span>
  );
}
