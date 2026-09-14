import { ArrowRight } from "lucide-react";
import Link from "next/link";
import { Trace } from "@/components/shell/trace";

export const metadata = { title: "Signal lost" };

const ROUTES = [
  { href: "/", label: "Overview", hint: "What the sensor sees now" },
  { href: "/incidents", label: "Incidents", hint: "Correlated attacks to investigate" },
  { href: "/lab", label: "PCAP Lab", hint: "Replay a capture through the engine" },
];

export default function NotFound() {
  return (
    <main className="relative grid min-h-dvh place-items-center overflow-hidden px-6 py-16">
      <Trace variant="flatline" className="pointer-events-none absolute inset-x-0 top-1/2 h-28 w-full -translate-y-1/2 opacity-30" />
      <div className="relative w-full max-w-xl">
        <p className="font-mono text-7xl font-medium tracking-tighter text-line-strong sm:text-8xl" aria-hidden>404</p>
        <h1 className="mt-4 font-display text-3xl font-semibold tracking-tight">Signal lost</h1>
        <p className="mt-2 max-w-md text-mist">
          There is nothing at this address. The link may be out of date, or the detection it pointed to was removed by the retention policy.
        </p>
        <ul className="mt-8 divide-y divide-line border-y border-line">
          {ROUTES.map((route) => (
            <li key={route.href}>
              <Link href={route.href} className="group flex items-center justify-between gap-4 py-3 hover:text-iris">
                <span>
                  <span className="block text-sm font-medium text-frost group-hover:text-iris">{route.label}</span>
                  <span className="block text-xs text-mist">{route.hint}</span>
                </span>
                <ArrowRight className="size-4 text-fog transition-transform group-hover:translate-x-0.5 group-hover:text-iris" aria-hidden />
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </main>
  );
}
