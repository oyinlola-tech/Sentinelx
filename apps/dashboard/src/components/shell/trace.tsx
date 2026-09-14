/**
 * The SentinelX trace: a seismograph line. Used as the brand motif on the sign-in
 * hero (an active trace) and the 404 page (a flatline). Pure SVG, no animation
 * unless the viewer allows motion.
 */
export function Trace({ variant = "active", className = "" }: { variant?: "active" | "flatline" | "interrupted"; className?: string }) {
  const paths = {
    active: "M0 60 H300 l10 -8 10 16 12 -40 14 70 16 -90 14 64 12 -22 10 10 H620 l8 -6 8 10 10 -24 12 38 10 -18 H1200",
    flatline: "M0 60 H420 l10 -8 10 16 12 -40 14 58 12 -26 H1200",
    interrupted: "M0 60 H380 l12 -30 14 52 16 -70 14 40 M560 60 H1200",
  };
  return (
    <svg className={className} viewBox="0 0 1200 120" preserveAspectRatio="none" aria-hidden>
      <defs>
        <linearGradient id={`trace-fade-${variant}`} x1="0" x2="1">
          <stop offset="0" stopColor="var(--color-iris)" stopOpacity="0" />
          <stop offset="0.25" stopColor="var(--color-iris)" stopOpacity="0.9" />
          <stop offset="0.75" stopColor="var(--color-iris)" stopOpacity="0.9" />
          <stop offset="1" stopColor="var(--color-iris)" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={paths[variant]} fill="none" stroke={`url(#trace-fade-${variant})`} strokeWidth="2" vectorEffect="non-scaling-stroke" strokeLinejoin="round" className="motion-safe:[stroke-dasharray:2400] motion-safe:[stroke-dashoffset:2400] motion-safe:animate-[trace-draw_2.4s_ease-out_forwards]" />
    </svg>
  );
}
