import { Ban, CheckCircle2, CircleDashed, Clock3, FlaskConical, ShieldAlert, XCircle } from "lucide-react";
import type { ReactNode } from "react";
import { bandColor, bandFor, humanise, severityColor } from "@/lib/format";
import type { Evidence, ResponseAction, Risk, Severity } from "@/lib/types";

/** Severity is always text + colour, never colour alone. */
export function SeverityBadge({ severity, compact = false }: { severity: Severity; compact?: boolean }) {
  const color = severityColor[severity] ?? "var(--color-sev-info)";
  return (
    <span
      className={`inline-flex items-center rounded-sm border py-px font-mono text-2xs font-medium uppercase tracking-wide ${compact ? "gap-1 px-1" : "gap-1.5 px-1.5"}`}
      style={{ color, borderColor: `color-mix(in oklab, ${color} 45%, transparent)`, background: `color-mix(in oklab, ${color} 10%, transparent)` }}
    >
      <span className="size-1.5 rounded-full" style={{ background: color }} aria-hidden />
      {severity}
    </span>
  );
}

export function RiskScore({ score, size = "sm" }: { score: number; size?: "sm" | "lg" }) {
  const band = bandFor(score);
  const color = bandColor[band];
  if (size === "lg") {
    return (
      <div className="flex items-baseline gap-2">
        <span className="font-display text-4xl font-semibold tabular" style={{ color }}>{Math.round(score)}</span>
        <span className="font-mono text-xs text-fog">/100 · {band}</span>
      </div>
    );
  }
  return (
    <span className="inline-flex items-center gap-2" title={`Risk ${score.toFixed(1)} of 100 (${band})`}>
      <span className="relative h-1.5 w-10 overflow-hidden rounded-full bg-line" aria-hidden>
        <span className="absolute inset-y-0 left-0 rounded-full" style={{ width: `${Math.max(3, score)}%`, background: color }} />
      </span>
      <span className="font-mono text-xs tabular text-frost">{Math.round(score)}</span>
    </span>
  );
}

const FACTOR_LABELS: Record<string, string> = {
  severity: "Severity",
  confidence: "Detector confidence",
  frequency: "Repetition",
  history: "Source history",
  correlation: "Correlated detectors",
  threat_intel: "Threat intelligence",
  sensitive_target: "Sensitive target",
  previous_responses: "Previous responses",
  allowlist: "Allowlisted source",
  highest_detection: "Highest detection",
  corroboration: "Corroboration",
  category_breadth: "Category breadth",
  pattern: "Attack pattern",
};

/**
 * The explainability view of a score: each factor's contribution as a segment of
 * one bar, labelled, followed by the engine's own rationale sentences. Segments use
 * a 2px surface gap and iris steps rather than severity colours - they identify
 * factors, not severity.
 */
export function RiskBreakdown({ risk }: { risk: Risk }) {
  const positive = Object.entries(risk.contributions).filter(([, value]) => value > 0);
  const negative = Object.entries(risk.contributions).filter(([, value]) => value < 0);
  const total = positive.reduce((sum, [, value]) => sum + value, 0) || 1;
  const scale = Math.max(total, 100);
  const shades = ["#8c9eff", "#7486ec", "#5f71d6", "#a6b3ff", "#4d5fbf", "#bcc6ff", "#3f4fa8"];
  return (
    <div className="flex flex-col gap-3">
      <RiskScore score={risk.score} size="lg" />
      <div className="relative flex h-3 w-full gap-[2px] overflow-hidden rounded-sm bg-line" role="img" aria-label={`Score composition: ${positive.map(([k, v]) => `${FACTOR_LABELS[k] ?? k} ${v.toFixed(1)}`).join(", ")}`}>
        {positive.map(([key, value], index) => (
          <span key={key} className="h-full first:rounded-l-sm" style={{ width: `${(value / scale) * 100}%`, background: shades[index % shades.length] }} title={`${FACTOR_LABELS[key] ?? key}: +${value.toFixed(1)}`} />
        ))}
        {total > 100 && <span className="absolute inset-y-0 border-l-2 border-dashed border-frost" style={{ left: `${(100 / scale) * 100}%` }} title="Score is capped at 100" />}
      </div>
      <ul className="grid gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
        {positive.map(([key, value], index) => (
          <li key={key} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-2 text-mist">
              <span className="size-2 rounded-sm" style={{ background: shades[index % shades.length] }} aria-hidden />
              {FACTOR_LABELS[key] ?? humanise(key)}
            </span>
            <span className="font-mono tabular text-frost">+{value.toFixed(1)}</span>
          </li>
        ))}
        {negative.map(([key, value]) => (
          <li key={key} className="flex items-center justify-between gap-3">
            <span className="text-mist">{FACTOR_LABELS[key] ?? humanise(key)}</span>
            <span className="font-mono tabular text-ok">{value.toFixed(1)}</span>
          </li>
        ))}
      </ul>
      <div>
        <p className="eyebrow mb-1">Why this score</p>
        <ul className="flex flex-col gap-0.5 font-mono text-xs text-mist">
          {risk.rationale.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "number") return Number.isInteger(value) ? value.toLocaleString("en") : value.toFixed(3);
  if (Array.isArray(value)) return value.slice(0, 8).join(", ") + (value.length > 8 ? " …" : "");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function EvidenceList({ evidence }: { evidence: Evidence[] }) {
  if (!evidence.length) return <p className="text-sm text-mist">No evidence recorded.</p>;
  return (
    <ol className="flex flex-col divide-y divide-line">
      {evidence.map((item) => (
        <li key={`${item.key}-${String(item.value)}`} className="grid grid-cols-[1fr_auto] items-start gap-4 py-2">
          <div className="min-w-0">
            <p className="text-sm text-frost">{item.description}</p>
            <p className="mt-0.5 font-mono text-2xs text-fog">{item.key}</p>
          </div>
          <div className="text-right font-mono text-xs tabular">
            <span className="text-frost">{formatValue(item.value)}</span>
            {item.threshold !== null && item.threshold !== undefined && <span className="block text-fog">threshold {formatValue(item.threshold)}</span>}
          </div>
        </li>
      ))}
    </ol>
  );
}

const OUTCOMES: Record<ResponseAction["outcome"], { label: string; icon: ReactNode; className: string }> = {
  executed: { label: "Executed", icon: <Ban className="size-3" />, className: "text-sev-critical border-sev-critical/40" },
  simulated: { label: "Simulated", icon: <FlaskConical className="size-3" />, className: "text-sev-medium border-sev-medium/40" },
  skipped: { label: "Not applied", icon: <CircleDashed className="size-3" />, className: "text-mist border-line-strong" },
  failed: { label: "Refused", icon: <XCircle className="size-3" />, className: "text-sev-high border-sev-high/40" },
  pending_approval: { label: "Awaiting approval", icon: <Clock3 className="size-3" />, className: "text-iris border-iris/40" },
};

export function OutcomeBadge({ outcome }: { outcome: ResponseAction["outcome"] }) {
  const meta = OUTCOMES[outcome] ?? OUTCOMES.skipped;
  return (
    <span className={`inline-flex items-center gap-1 rounded-sm border px-1.5 py-px text-2xs font-medium ${meta.className}`}>
      <span aria-hidden>{meta.icon}</span>
      {meta.label}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const tone = status === "new" || status === "open" ? "text-iris border-iris/40" : status === "false_positive" ? "text-fog border-line-strong" : status === "resolved" ? "text-ok border-ok/40" : "text-sev-medium border-sev-medium/40";
  const icon = status === "resolved" ? <CheckCircle2 className="size-3" /> : status === "open" || status === "new" ? <ShieldAlert className="size-3" /> : null;
  return (
    <span className={`inline-flex items-center gap-1 rounded-sm border px-1.5 py-px text-2xs font-medium capitalize ${tone}`}>
      {icon && <span aria-hidden>{icon}</span>}
      {humanise(status)}
    </span>
  );
}

export function Mono({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`font-mono text-xs tabular ${className}`}>{children}</span>;
}
