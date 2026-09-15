import { ArrowRight } from "lucide-react";
import Link from "next/link";
import { RequestedPath } from "@/components/shell/requested-path";
import { Wordmark } from "@/components/shell/wordmark";

export const metadata = { title: "Signal lost" };

const ROUTES = [
  { href: "/", label: "Overview", hint: "What the sensor sees now" },
  { href: "/incidents", label: "Incidents", hint: "Correlated attacks to investigate" },
  { href: "/lab", label: "PCAP Lab", hint: "Replay a capture through the engine" },
];

/**
 * 404: an empty scope. The range rings sweep, nothing answers, and the requested
 * address is read back like a bearing with no contact on it.
 */
export default function NotFound() {
  return (
    <main className="relative flex min-h-dvh flex-col overflow-hidden">
      <div className="range-rings pointer-events-none absolute top-1/2 left-1/2 size-[80rem] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-60 [mask-image:radial-gradient(circle,black_25%,transparent_68%)]" aria-hidden>
        <div className="absolute inset-0 rounded-full bg-[conic-gradient(from_0deg,transparent_0deg,color-mix(in_oklab,var(--color-signal)_7%,transparent)_30deg,transparent_31deg)] motion-safe:animate-[sweep_7s_linear_infinite]" />
        <div className="absolute top-1/2 left-0 h-px w-full bg-line-strong/60" />
        <div className="absolute top-0 left-1/2 h-full w-px bg-line-strong/60" />
      </div>

      <header className="relative flex items-center justify-between px-5 py-5 lg:px-10">
        <Link href="/" aria-label="SentinelX overview">
          <Wordmark size="sm" />
        </Link>
        <p className="font-mono text-[10px] tracking-[0.14em] text-fog uppercase">Error 404 · no route</p>
      </header>

      <div className="relative flex flex-1 flex-col items-center justify-center px-5 pb-16 text-center">
        <p className="font-stencil text-[clamp(9rem,30vw,22rem)] leading-[0.78] font-black tracking-[0.02em] text-line-strong select-none" aria-hidden>
          4<span className="relative">0<span className="absolute top-[30%] right-[22%] size-[0.06em] rounded-full bg-signal shadow-[0_0_0.12em_var(--color-signal)] motion-safe:animate-pulse" /></span>4
        </p>
        <h1 className="heading-display mt-6 text-5xl text-frost sm:text-6xl">Signal lost</h1>
        <p className="mt-4 max-w-md text-mist">
          Nothing answers at this address. The link may be out of date, or the record it pointed to was removed by the retention policy.
        </p>
        <RequestedPath />

        <ul className="mt-10 grid w-full max-w-3xl gap-px border border-line bg-line text-left sm:grid-cols-3">
          {ROUTES.map((route) => (
            <li key={route.href} className="bg-ground/90 backdrop-blur">
              <Link href={route.href} className="group flex h-full items-start justify-between gap-4 p-4 transition-colors hover:bg-raised">
                <span>
                  <span className="block font-display text-xl font-semibold text-frost">{route.label}</span>
                  <span className="mt-1 block text-xs text-mist">{route.hint}</span>
                </span>
                <ArrowRight className="mt-1 size-4 shrink-0 text-fog transition-transform group-hover:translate-x-0.5 group-hover:text-signal" aria-hidden />
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </main>
  );
}
