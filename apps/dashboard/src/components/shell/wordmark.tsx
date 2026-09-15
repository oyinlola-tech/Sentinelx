/**
 * The SentinelX mark: a scope face with two range rings swept from its corner and one
 * contact. It says what the product does (watch a network, find the thing that moved)
 * and stays legible at favicon size. The wordmark is set in Big Shoulders Stencil, the
 * lettering of stencilled equipment plates.
 */
export function ScopeMark({ className = "size-6", contact = true }: { className?: string; contact?: boolean }) {
  return (
    <svg viewBox="0 0 24 24" className={className} aria-hidden>
      <rect x="2.25" y="2.25" width="19.5" height="19.5" rx="1.5" fill="none" stroke="var(--color-frost)" strokeWidth="1.5" />
      <path d="M2.25 14.25a7.5 7.5 0 0 1 7.5 7.5" fill="none" stroke="var(--color-frost)" strokeOpacity="0.55" strokeWidth="1.25" />
      <path d="M2.25 7.5a14.25 14.25 0 0 1 14.25 14.25" fill="none" stroke="var(--color-frost)" strokeOpacity="0.35" strokeWidth="1.25" />
      <path d="M2.25 21.75 17.5 6.5" stroke="var(--color-signal)" strokeOpacity="0.45" strokeWidth="1" />
      {contact && <circle cx="15.75" cy="8.25" r="2.1" fill="var(--color-signal)" />}
    </svg>
  );
}

export function Wordmark({ size = "md" }: { size?: "sm" | "md" | "lg" }) {
  const mark = { sm: "size-5", md: "size-6", lg: "size-9" }[size];
  const text = { sm: "text-[17px]", md: "text-[20px]", lg: "text-[30px]" }[size];
  return (
    <span className="flex items-center gap-2.5">
      <ScopeMark className={mark} />
      <span className={`font-stencil leading-none font-black tracking-[0.06em] text-frost uppercase ${text}`}>
        Sentinel<span className="text-signal">X</span>
      </span>
    </span>
  );
}
