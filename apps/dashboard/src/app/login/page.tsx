"use client";

import { ArrowRight, Lock } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState, type FormEvent } from "react";
import { Wordmark } from "@/components/shell/wordmark";
import { ConsoleFooter } from "@/components/shell/footer";
import { Button, Field, Input } from "@/components/ui/primitives";
import { RiskScore } from "@/components/ui/security";
import { ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";

/**
 * Example shown in the hero, labelled as an example on screen: not live data and not a
 * performance claim. It is the engine's output copied verbatim - the highest-scoring
 * detection when the bundled tcp_port_scan fixture is replayed with default settings
 * (sentinelx fixtures generate; sentinelx replay tcp_port_scan.pcap). Update it if the
 * detector's wording changes.
 */
const EXAMPLE = {
  title: "TCP port scan",
  source: "203.0.113.45",
  score: 66.6,
  evidence: [
    "100 distinct destination ports contacted on 192.168.10.50 (threshold 20)",
    "observed over 1.1 seconds",
    "100% of this source's packets are bare SYNs - it opens connections but does not complete them",
    "only 2.0% of SYNs were answered with SYN-ACK, so most probed ports are closed",
    "100 connection attempts in the window",
    "97% of attempts were refused with RST",
  ],
  factors: [["Severity", 45], ["Detector confidence", 19.6], ["Repetition", 2]] as [string, number][],
  decision: "Temporary block: not applied: risk 67 is below the automatic response threshold of 85",
};

function LoginForm() {
  const { login, user } = useSession();
  const router = useRouter();
  const params = useSearchParams();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const next = params.get("next");
  const destination = safeDestination(next);

  useEffect(() => {
    document.title = "Sign in · SentinelX";
    if (user) router.replace(user.must_change_password ? "/account?required=1" : destination);
  }, [user, router, destination]);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 423) setError("This account is locked after repeated failed sign-ins. Try again in 15 minutes.");
      else if (caught instanceof ApiError && caught.status === 429) setError("Too many sign-in attempts from this address. Wait a few minutes, then try again.");
      else if (caught instanceof ApiError && caught.status === 401) setError("The username or password is incorrect.");
      else setError("Cannot reach the SentinelX API. Check that the server is running.");
      setPassword("");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="flex w-full flex-col gap-4" aria-describedby={error ? "login-error" : undefined}>
      <div className="mb-1">
        <p className="eyebrow">Console access</p>
        <h2 className="heading-display mt-2 text-4xl text-frost">Sign in</h2>
      </div>
      <Field label="Username" htmlFor="username">
        <Input id="username" autoComplete="username" autoFocus required value={username} onChange={(event) => setUsername(event.target.value)} maxLength={64} />
      </Field>
      <Field label="Password" htmlFor="password">
        <Input id="password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} maxLength={256} />
      </Field>
      {error && (
        <p id="login-error" role="alert" className="rounded-sm border border-sev-critical/50 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical">
          {error}
        </p>
      )}
      <Button type="submit" variant="primary" loading={busy} className="mt-1 h-11 justify-between">
        Sign in <ArrowRight className="size-4" aria-hidden />
      </Button>
      <p className="flex items-start gap-1.5 text-xs text-fog">
        <Lock className="mt-0.5 size-3 shrink-0" aria-hidden />
        First run? The administrator password is printed once in the server console, and you will be asked to change it.
      </p>
    </form>
  );
}

/** Plain statements of how SentinelX behaves out of the box; each is enforced in code. */
const FACTS = [
  ["Detection only", "by default: nothing touches traffic until you enable prevention"],
  ["Explained", "every detection lists its evidence and how its risk was scored"],
  ["Self-hosted", "runs on your own host, air-gapped if you need it"],
];

export default function LoginPage() {
  return (
    <div className="flex min-h-dvh flex-col">
      <main className="relative flex-1 overflow-hidden">
        {/* The scope: graticule fading out from the centre, range rings off to the right. */}
        <div className="graticule pointer-events-none absolute inset-0 [mask-image:radial-gradient(ellipse_at_40%_45%,black_20%,transparent_75%)]" aria-hidden />
        <div className="range-rings pointer-events-none absolute top-1/2 right-[-18rem] size-[64rem] -translate-y-1/2 rounded-full opacity-40 [mask-image:radial-gradient(circle,black_35%,transparent_70%)]" aria-hidden>
          <div className="absolute inset-0 origin-center rounded-full bg-[conic-gradient(from_0deg,transparent_0deg,color-mix(in_oklab,var(--color-signal)_18%,transparent)_40deg,transparent_42deg)] motion-safe:animate-[sweep_9s_linear_infinite]" />
        </div>

        <div className="relative mx-auto flex min-h-full max-w-[1400px] flex-col px-5 py-6 lg:px-10">
          <header className="flex items-center justify-between">
            <Wordmark size="md" />
            <p className="hidden font-mono text-[10px] tracking-[0.14em] text-fog uppercase sm:block">Network intrusion detection &amp; prevention</p>
          </header>

          <div className="grid flex-1 items-center gap-12 py-12 lg:grid-cols-[minmax(0,7fr)_minmax(22rem,4fr)] lg:gap-16 lg:py-16">
            <section aria-labelledby="hero-title">
              <p className="eyebrow flex items-center gap-2">
                <span className="size-1.5 rounded-full bg-signal" aria-hidden /> Console · sign in to continue
              </p>
              <h1 id="hero-title" className="heading-display mt-5 text-[clamp(3.6rem,8.4vw,8.25rem)] text-frost">
                Every alert
                <br />
                shows its <span className="text-signal">work.</span>
              </h1>
              <p className="mt-6 max-w-xl text-lg leading-relaxed text-mist">
                SentinelX watches the wire, correlates what it sees into incidents, and tells you exactly why it thinks a source is hostile, before anything is blocked.
              </p>
              <dl className="mt-9 grid max-w-2xl gap-px border border-line bg-line sm:grid-cols-3">
                {FACTS.map(([term, detail]) => (
                  <div key={term} className="bg-ground/80 px-4 py-3 backdrop-blur">
                    <dt className="font-display text-xl font-semibold text-frost">{term}</dt>
                    <dd className="mt-1 text-xs leading-relaxed text-mist">{detail}</dd>
                  </div>
                ))}
              </dl>

              <figure className="mt-10 hidden max-w-2xl border border-line-strong bg-panel/90 backdrop-blur md:block">
                <figcaption className="flex items-center justify-between border-b border-line px-4 py-2">
                  <span className="eyebrow">Example explanation · synthetic fixture</span>
                  <RiskScore score={EXAMPLE.score} />
                </figcaption>
                <div className="grid gap-4 p-4 sm:grid-cols-[minmax(0,1fr)_12rem]">
                  <div>
                    <p className="text-sm font-medium text-frost">
                      {EXAMPLE.title} <span className="font-mono text-xs text-mist">from {EXAMPLE.source}</span>
                    </p>
                    <ul className="mt-2 flex flex-col gap-1 text-xs text-mist">
                      {EXAMPLE.evidence.slice(0, 4).map((line) => (
                        <li key={line} className="flex gap-2"><span className="text-signal" aria-hidden>›</span>{line}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="border-line sm:border-l sm:pl-4">
                    <p className="eyebrow">Risk contributions</p>
                    <ul className="mt-2 space-y-1.5">
                      {EXAMPLE.factors.map(([label, value]) => (
                        <li key={label} className="text-xs">
                          <span className="flex justify-between text-mist"><span>{label}</span><span className="font-mono text-frost tabular">+{value}</span></span>
                          <span className="mt-1 block h-1 bg-line" aria-hidden><span className="block h-full bg-signal" style={{ width: `${Math.min(100, (value / 45) * 100)}%` }} /></span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
                <p className="border-t border-line px-4 py-2 font-mono text-[11px] text-fog">{EXAMPLE.decision}</p>
              </figure>
            </section>

            <section className="border border-line-strong bg-panel/95 p-6 shadow-[0_40px_120px_-40px_rgba(0,0,0,0.9)] backdrop-blur sm:p-8" aria-label="Sign in">
              <Suspense>
                <LoginForm />
              </Suspense>
            </section>
          </div>
        </div>
      </main>
      <ConsoleFooter minimal />
    </div>
  );
}

/**
 * Only same-origin paths may follow sign-in. Checking the prefix is not enough:
 * "/\\evil.example" is normalised by browsers to "//evil.example".
 */
function safeDestination(next: string | null): string {
  if (!next || !next.startsWith("/") || typeof window === "undefined") return "/";
  try {
    const url = new URL(next, window.location.origin);
    return url.origin === window.location.origin ? `${url.pathname}${url.search}${url.hash}` : "/";
  } catch {
    return "/";
  }
}
