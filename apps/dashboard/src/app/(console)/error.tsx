"use client";

import { RotateCcw } from "lucide-react";
import Link from "next/link";
import { useEffect } from "react";
import { Trace } from "@/components/shell/trace";
import { Button } from "@/components/ui/primitives";

export default function ConsoleError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => {
    console.error("view crashed", error);
  }, [error]);
  return (
    <div className="panel relative overflow-hidden px-6 py-12">
      <Trace variant="interrupted" className="pointer-events-none absolute inset-x-0 top-6 h-16 w-full opacity-30" />
      <div className="relative max-w-lg">
        <p className="eyebrow">Trace interrupted</p>
        <h1 className="mt-2 font-display text-2xl font-semibold">This view stopped responding</h1>
        <p className="mt-2 text-sm text-mist">
          The page failed to render. Detection and the event stream are unaffected: this happened in your browser, not on the sensor.
        </p>
        <p className="mt-3 rounded-md border border-line bg-ground px-3 py-2 font-mono text-xs text-mist break-words">
          {error.message || "Unknown error"}
          {error.digest && <span className="block text-fog">reference {error.digest}</span>}
        </p>
        <div className="mt-5 flex gap-2">
          <Button variant="primary" icon={<RotateCcw className="size-4" />} onClick={reset}>Try again</Button>
          <Link href="/" className="inline-flex h-9 items-center rounded-md px-3.5 text-sm text-mist hover:bg-raised hover:text-frost">Go to the overview</Link>
        </div>
      </div>
    </div>
  );
}
