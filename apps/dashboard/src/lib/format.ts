import type { RiskBand, Severity } from "./types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function bandFor(score: number): RiskBand {
  if (score <= 20) return "informational";
  if (score <= 40) return "low";
  if (score <= 60) return "medium";
  if (score <= 80) return "high";
  return "critical";
}

export const bandColor: Record<RiskBand, string> = {
  informational: "var(--color-sev-info)",
  low: "var(--color-sev-low)",
  medium: "var(--color-sev-medium)",
  high: "var(--color-sev-high)",
  critical: "var(--color-sev-critical)",
};

export const severityColor: Record<Severity, string> = {
  critical: "var(--color-sev-critical)",
  high: "var(--color-sev-high)",
  medium: "var(--color-sev-medium)",
  low: "var(--color-sev-low)",
  info: "var(--color-sev-info)",
};

const numberFormat = new Intl.NumberFormat("en", { maximumFractionDigits: 1 });
const compactFormat = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });

export const num = (value: number | null | undefined): string => (value == null ? "—" : numberFormat.format(value));
export const compact = (value: number | null | undefined): string => (value == null ? "—" : compactFormat.format(value));

export function bytes(value: number | null | undefined): string {
  if (value == null) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${numberFormat.format(size)} ${units[unit]}`;
}

export function ago(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "—";
  const seconds = Math.max(0, (now - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${Math.floor(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function timestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-GB", { dateStyle: "short", timeStyle: "medium" });
}

export function clock(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleTimeString("en-GB", { hour12: false });
}

export const humanise = (value: string | null | undefined): string =>
  value ? value.replaceAll("_", " ").replace(/^rule:/, "rule · ") : "—";

export function endpoint(ip: string | null | undefined, port: number | null | undefined): string {
  if (!ip) return "—";
  if (port == null) return ip;
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}
