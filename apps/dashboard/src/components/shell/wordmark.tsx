export function Wordmark() {
  return (
    <span className="flex items-center gap-2">
      <svg viewBox="0 0 24 24" className="size-5" aria-hidden>
        <path d="M2 14h4l2-6 3 10 3-14 2 10h6" fill="none" stroke="var(--color-iris)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span className="font-display text-[15px] font-bold tracking-tight text-frost">
        Sentinel<span className="text-iris">X</span>
      </span>
    </span>
  );
}
