"use client";

import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { clock, compact, num } from "@/lib/format";
import type { Severity } from "@/lib/types";

const RAMP: Record<Severity, string> = {
  info: "var(--color-ramp-info)",
  low: "var(--color-ramp-low)",
  medium: "var(--color-ramp-medium)",
  high: "var(--color-ramp-high)",
  critical: "var(--color-ramp-critical)",
};
const STACK_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

function useWidth<T extends HTMLElement>(): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => entry && setWidth(entry.contentRect.width));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  return [ref, width];
}

function Tooltip({ x, y, children, containerWidth }: { x: number; y: number; children: ReactNode; containerWidth: number }) {
  const flip = x > containerWidth - 180;
  return (
    <div
      role="tooltip"
      className="pointer-events-none absolute z-10 min-w-36 rounded-md border border-line-strong bg-ground/95 px-2.5 py-2 text-xs shadow-xl"
      style={{ left: flip ? undefined : x + 12, right: flip ? containerWidth - x + 12 : undefined, top: Math.max(0, y - 8) }}
    >
      {children}
    </div>
  );
}

export function SeverityLegend({ present }: { present?: Severity[] }) {
  const items = (present ?? STACK_ORDER).slice().reverse();
  return (
    <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-mist" aria-label="Severity legend">
      {items.map((severity) => (
        <li key={severity} className="flex items-center gap-1.5 capitalize">
          <span className="size-2.5 rounded-sm" style={{ background: RAMP[severity] }} aria-hidden />
          {severity}
        </li>
      ))}
    </ul>
  );
}

/**
 * The threat tape: the last hour of detections as severity ticks on a strip, drawn
 * like a seismograph trace. Tick height and ramp step both encode severity, so the
 * strip still reads in grayscale.
 */
export function ThreatTape({ events, minutes = 60 }: { events: { timestamp: string; severity: Severity; title: string; source: string }[]; minutes?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [now, setNow] = useState(() => Date.now());
  const [hover, setHover] = useState<{ x: number; event: (typeof events)[number] } | null>(null);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(timer);
  }, []);
  const height = 28;
  const span = minutes * 60_000;
  const heights: Record<Severity, number> = { info: 6, low: 10, medium: 15, high: 20, critical: 26 };
  const ticks = events
    .map((event) => ({ event, x: width - ((now - new Date(event.timestamp).getTime()) / span) * width }))
    .filter((tick) => tick.x >= 0 && tick.x <= width);
  const counts = ticks.reduce<Record<string, number>>((acc, tick) => ({ ...acc, [tick.event.severity]: (acc[tick.event.severity] ?? 0) + 1 }), {});
  const label = `Threat tape, last ${minutes} minutes: ${ticks.length} detections${ticks.length ? ` (${STACK_ORDER.slice().reverse().filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(", ")})` : ""}`;

  return (
    <div ref={ref} className="relative h-7 w-full" onMouseLeave={() => setHover(null)}>
      <svg width={width} height={height} role="img" aria-label={label} className="block">
        {Array.from({ length: 7 }, (_, index) => (
          <line key={index} x1={(width / 6) * index} x2={(width / 6) * index} y1={height - 4} y2={height} stroke="var(--color-line-strong)" strokeWidth={1} />
        ))}
        <line x1={0} x2={width} y1={height - 0.5} y2={height - 0.5} stroke="var(--color-line)" />
        {ticks.map(({ event, x }, index) => (
          <rect
            key={`${event.timestamp}-${index}`}
            x={x - 1}
            y={height - heights[event.severity]}
            width={2}
            height={heights[event.severity]}
            rx={1}
            fill={RAMP[event.severity]}
            className="origin-bottom animate-tape"
          />
        ))}
        {ticks.map(({ event, x }, index) => (
          <rect key={`hit-${index}`} x={x - 5} y={0} width={10} height={height} fill="transparent" onMouseEnter={() => setHover({ x, event })} />
        ))}
      </svg>
      <span className="pointer-events-none absolute top-0 left-0 font-mono text-2xs text-fog">−{minutes}m</span>
      <span className="pointer-events-none absolute top-0 right-0 font-mono text-2xs text-fog">now</span>
      {hover && (
        <Tooltip x={hover.x} y={height} containerWidth={width}>
          <p className="font-medium text-frost">{hover.event.title}</p>
          <p className="font-mono text-mist">{hover.event.source} · {hover.event.severity} · {clock(hover.event.timestamp)}</p>
        </Tooltip>
      )}
    </div>
  );
}

export interface TimelineBucket { bucket_start: string; total: number; critical?: number; high?: number; medium?: number; low?: number; info?: number }

/** Detections per time bucket, stacked by severity on the validated ordinal ramp. */
export function SeverityTimeline({ buckets, height = 180 }: { buckets: TimelineBucket[]; height?: number }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const padding = { top: 8, right: 8, bottom: 22, left: 36 };
  const plotWidth = Math.max(0, width - padding.left - padding.right);
  const plotHeight = height - padding.top - padding.bottom;
  const max = Math.max(1, ...buckets.map((bucket) => bucket.total));
  const niceMax = Math.ceil(max / 5) * 5 || 5;
  const barWidth = buckets.length ? Math.max(2, plotWidth / buckets.length - 2) : 0;
  const y = (value: number) => padding.top + plotHeight - (value / niceMax) * plotHeight;
  const present = STACK_ORDER.filter((severity) => buckets.some((bucket) => (bucket[severity] ?? 0) > 0));

  return (
    <div className="flex flex-col gap-2">
      <div ref={ref} className="relative w-full" style={{ height }} onMouseLeave={() => setHover(null)}>
        <svg width={width} height={height} role="img" aria-label={`Detections over time, ${buckets.length} intervals, peak ${max}`}>
          {[0, 0.5, 1].map((fraction) => (
            <g key={fraction}>
              <line x1={padding.left} x2={width - padding.right} y1={y(niceMax * fraction)} y2={y(niceMax * fraction)} stroke="var(--color-line)" strokeDasharray={fraction === 0 ? undefined : "2 4"} />
              <text x={padding.left - 6} y={y(niceMax * fraction) + 3} textAnchor="end" className="fill-fog font-mono text-[10px]">{compact(niceMax * fraction)}</text>
            </g>
          ))}
          {buckets.map((bucket, index) => {
            const x = padding.left + index * (plotWidth / buckets.length) + 1;
            let offset = 0;
            return (
              <g key={bucket.bucket_start} opacity={hover === null || hover === index ? 1 : 0.45}>
                {STACK_ORDER.map((severity) => {
                  const value = bucket[severity] ?? 0;
                  if (!value) return null;
                  const top = y(offset + value);
                  const bottom = y(offset);
                  offset += value;
                  return <rect key={severity} x={x} y={top} width={barWidth} height={Math.max(1, bottom - top - 2)} rx={1.5} fill={RAMP[severity]} />;
                })}
                <rect x={x - 1} y={padding.top} width={barWidth + 2} height={plotHeight} fill="transparent" onMouseEnter={() => setHover(index)} />
              </g>
            );
          })}
          {buckets.length > 0 &&
            [0, Math.floor(buckets.length / 2), buckets.length - 1].map((index) => (
              <text key={index} x={padding.left + index * (plotWidth / buckets.length) + barWidth / 2} y={height - 6} textAnchor="middle" className="fill-fog font-mono text-[10px]">
                {new Date(buckets[index]!.bucket_start).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}
              </text>
            ))}
        </svg>
        {hover !== null && buckets[hover] && (
          <Tooltip x={padding.left + hover * (plotWidth / buckets.length)} y={padding.top} containerWidth={width}>
            <p className="mb-1 font-mono text-mist">{new Date(buckets[hover]!.bucket_start).toLocaleString("en-GB", { dateStyle: "short", timeStyle: "short" })}</p>
            {STACK_ORDER.slice().reverse().map((severity) =>
              buckets[hover]![severity] ? (
                <p key={severity} className="flex justify-between gap-4 capitalize text-frost">
                  <span className="flex items-center gap-1.5"><span className="size-2 rounded-sm" style={{ background: RAMP[severity] }} />{severity}</span>
                  <span className="font-mono tabular">{buckets[hover]![severity]}</span>
                </p>
              ) : null,
            )}
            <p className="mt-1 flex justify-between border-t border-line pt-1 text-mist"><span>Total</span><span className="font-mono tabular">{buckets[hover]!.total}</span></p>
          </Tooltip>
        )}
      </div>
      {present.length > 1 && <SeverityLegend present={present} />}
    </div>
  );
}

/**
 * Ranked horizontal bars with direct labels: one series, so no legend is needed.
 * Label and value share a line above a thin bar on a full-width track, so text is
 * never clipped by, or overhanging, a short bar.
 */
export function BarList({ items, format = num, empty = "No data in this period." }: { items: { label: ReactNode; value: number; key: string }[]; format?: (value: number) => string; empty?: string }) {
  const max = Math.max(1, ...items.map((item) => item.value));
  if (!items.length) return <p className="py-6 text-center text-sm text-mist">{empty}</p>;
  return (
    <ul className="flex flex-col gap-2.5">
      {items.map((item) => (
        <li key={item.key} className="group" title={`${item.key}: ${format(item.value)}`}>
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className="min-w-0 truncate text-frost">{item.label}</span>
            <span className="shrink-0 font-mono text-xs tabular text-mist">{format(item.value)}</span>
          </div>
          <div className="mt-1 h-1 rounded-full bg-line" aria-hidden>
            <div className="h-full rounded-full bg-iris/70 transition-colors group-hover:bg-iris" style={{ width: `${Math.max(2, (item.value / max) * 100)}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

/** A single measured series over time, with a crosshair tooltip. */
export function LineSeries({ points, height = 140, format = num, label }: { points: { t: string; v: number }[]; height?: number; format?: (value: number) => string; label: string }) {
  const [ref, width] = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const padding = { top: 10, right: 8, bottom: 20, left: 44 };
  const plotWidth = Math.max(0, width - padding.left - padding.right);
  const plotHeight = height - padding.top - padding.bottom;
  const max = Math.max(1, ...points.map((point) => point.v));
  const x = (index: number) => padding.left + (points.length <= 1 ? plotWidth / 2 : (index / (points.length - 1)) * plotWidth);
  const y = (value: number) => padding.top + plotHeight - (value / max) * plotHeight;
  const path = useMemo(() => points.map((point, index) => `${index ? "L" : "M"}${x(index).toFixed(1)},${y(point.v).toFixed(1)}`).join(""), [points, width]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!points.length) return <p className="py-8 text-center text-sm text-mist">No measurements recorded yet.</p>;
  return (
    <div
      ref={ref}
      className="relative w-full"
      style={{ height }}
      onMouseMove={(event) => {
        const box = event.currentTarget.getBoundingClientRect();
        const ratio = (event.clientX - box.left - padding.left) / Math.max(1, plotWidth);
        setHover(Math.min(points.length - 1, Math.max(0, Math.round(ratio * (points.length - 1)))));
      }}
      onMouseLeave={() => setHover(null)}
    >
      <svg width={width} height={height} role="img" aria-label={`${label}: ${points.length} measurements, peak ${format(max)}`}>
        {[0, 0.5, 1].map((fraction) => (
          <g key={fraction}>
            <line x1={padding.left} x2={width - padding.right} y1={y(max * fraction)} y2={y(max * fraction)} stroke="var(--color-line)" strokeDasharray={fraction === 0 ? undefined : "2 4"} />
            <text x={padding.left - 6} y={y(max * fraction) + 3} textAnchor="end" className="fill-fog font-mono text-[10px]">{format(max * fraction)}</text>
          </g>
        ))}
        <path d={path} fill="none" stroke="var(--color-iris)" strokeWidth={2} strokeLinejoin="round" />
        {hover !== null && points[hover] && (
          <>
            <line x1={x(hover)} x2={x(hover)} y1={padding.top} y2={padding.top + plotHeight} stroke="var(--color-mist)" strokeDasharray="3 3" />
            <circle cx={x(hover)} cy={y(points[hover]!.v)} r={4} fill="var(--color-iris)" stroke="var(--color-panel)" strokeWidth={2} />
          </>
        )}
      </svg>
      {hover !== null && points[hover] && (
        <Tooltip x={x(hover)} y={padding.top} containerWidth={width}>
          <p className="font-mono text-mist">{new Date(points[hover]!.t).toLocaleString("en-GB", { dateStyle: "short", timeStyle: "short" })}</p>
          <p className="font-mono tabular text-frost">{format(points[hover]!.v)}</p>
        </Tooltip>
      )}
    </div>
  );
}

/**
 * Protocol identity colours. Each protocol keeps its colour whatever its share (colour
 * follows the entity, not its rank). Four validated slots on the dark panel surface
 * (dataviz validator: lightness band, chroma, CVD >= 8, normal-vision >= 15), chosen
 * outside the reserved status hues (amber attention, flare danger, lichen healthy);
 * anything else folds into a neutral "other".
 */
const PROTOCOL_COLORS: Record<string, string> = { tcp: "#3987e5", udp: "#d55181", icmp: "#9085e9", arp: "#2a9cb0" };

function protocolColor(key: string): string {
  return PROTOCOL_COLORS[key.toLowerCase()] ?? "var(--color-line-strong)";
}

/** Share of a whole as one segmented bar, direct-labelled (used for protocol mix). */
export function ShareBar({ shares }: { shares: Record<string, number> }) {
  const entries = Object.entries(shares).filter(([, value]) => value > 0).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return <p className="text-sm text-mist">No traffic observed yet.</p>;
  return (
    <div className="flex flex-col gap-2">
      <div className="flex h-2.5 w-full gap-[2px] overflow-hidden rounded-sm" role="img" aria-label={entries.map(([k, v]) => `${k} ${(v * 100).toFixed(1)}%`).join(", ")}>
        {entries.map(([key, value], index) => (
          <span key={key} style={{ width: `${value * 100}%`, background: protocolColor(key) }} />
        ))}
      </div>
      <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {entries.map(([key, value], index) => (
          <li key={key} className="flex items-center gap-1.5 text-mist">
            <span className="size-2 rounded-sm" style={{ background: protocolColor(key) }} aria-hidden />
            <span className="uppercase">{key}</span>
            <span className="font-mono tabular text-frost">{(value * 100).toFixed(1)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
