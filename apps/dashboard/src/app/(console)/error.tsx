"use client";

import { RotateCcw } from "lucide-react";
import Link from "next/link";
import { useEffect } from "react";
import { Button } from "@/components/ui/primitives";

/** A view that failed to render: the trace breaks, the rest of the console keeps running. */
export default function ConsoleError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error("view crashed", error);
  }, [error]);
  return (
    <div className="panel relative overflow-hidden">
      <div className="graticule pointer-events-none absolute inset-0 opacity-60 [mask-image:linear-gradient(to_right,black,transparent_70%)]" aria-hidden />
      <svg className="pointer-events-none absolute inset-x-0 top-10 h-16 w-full" viewBox="0 0 1200 64" preserveAspectRatio="none" aria-hidden>
        <path d="M0 32 H330 l12 -22 14 40 16 -30 12 12 M520 32 H1200" fill="none" stroke="var(--color-signal)" strokeOpacity="0.7" strokeWidth="1.5" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
        <path d="M372 30 L520 32" fill="none" stroke="var(--color-sev-critical)" strokeOpacity="0.6" strokeWidth="1.5" strokeDasharray="4 6" vectorEffect="non-scaling-stroke" />
      </svg>
      <div className="relative max-w-2xl px-6 pt-32 pb-10 sm:px-10">
        <p className="eyebrow">Trace interrupted</p>
        <h1 className="heading-display mt-3 text-5xl text-frost">This view stopped responding</h1>
        <p className="mt-4 text-sm leading-relaxed text-mist">
          The page failed to render. Detection and the event stream are unaffected: this happened in your browser, not on the sensor.
        </p>
        <p className="mt-4 border border-line bg-ground px-3 py-2 font-mono text-xs break-words text-mist">
          {error.message || "Unknown error"}
          {error.digest && <span className="block text-fog">reference {error.digest}</span>}
        </p>
        <div className="mt-6 flex flex-wrap gap-2">
          <Button variant="primary" icon={<RotateCcw className="size-4" />} onClick={reset}>Try again</Button>
          <Link href="/" className="inline-flex h-9 items-center rounded-sm px-3.5 text-sm text-mist hover:bg-raised hover:text-frost">Go to the overview</Link>
        </div>
      </div>
    </div>
  );
}
