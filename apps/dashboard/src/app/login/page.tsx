"use client";

import { ArrowRight, Lock } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useState, type FormEvent } from "react";
import { Wordmark } from "@/components/shell/wordmark";
import { ConsoleFooter } from "@/components/shell/footer";
import { Trace } from "@/components/shell/trace";
import { Button, Field, Input } from "@/components/ui/primitives";
import { RiskScore } from "@/components/ui/security";
import { ApiError } from "@/lib/api";
import { useSession } from "@/lib/session";

/**
 * Example shown in the hero: the explanation SentinelX produces for the bundled
 * tcp_port_scan fixture with default settings, copied from the engine's output
 * (critical escalation of the scan). Labelled as an example on screen - not live
 * data, and not a performance claim. Regenerate it if detector wording changes.
 */
const EXAMPLE = {
  title: "TCP port scan",
  source: "203.0.113.45",
  score: 66.6,
  evidence: [
    "100 distinct destination ports contacted on 192.168.10.50 (threshold 20)",
    "observed over 1.1 seconds",
    "100% of this source's packets are bare SYNs",
    "only 2.0% of SYNs were answered with SYN-ACK",
    "97% of attempts were refused with RST",
  ],
  factors: [["Severity", 45], ["Confidence", 19.6], ["Repetition", 2]] as [string, number][],
  decision: "Temporary block recommended · not applied (detection-only mode)",
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
  const destination = next && next.startsWith("/") && !next.startsWith("//") ? next : "/"; // no open redirects

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
    <form onSubmit={submit} className="flex w-full max-w-sm flex-col gap-4" aria-describedby={error ? "login-error" : undefined}>
      <div>
        <p className="eyebrow">Console access</p>
        <h2 className="mt-1 font-display text-xl font-semibold">Sign in</h2>
      </div>
      <Field label="Username" htmlFor="username">
        <Input id="username" autoComplete="username" autoFocus required value={username} onChange={(event) => setUsername(event.target.value)} maxLength={64} />
      </Field>
      <Field label="Password" htmlFor="password">
        <Input id="password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} maxLength={256} />
      </Field>
      {error && (
        <p id="login-error" role="alert" className="rounded-md border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-sm text-sev-critical">
          {error}
        </p>
      )}
      <Button type="submit" variant="primary" loading={busy} className="justify-between">
        Sign in <ArrowRight className="size-4" aria-hidden />
      </Button>
      <p className="flex items-start gap-1.5 text-xs text-fog">
        <Lock className="mt-0.5 size-3 shrink-0" aria-hidden />
        First run? The administrator password is printed once in the server console, and you will be asked to change it.
      </p>
    </form>
  );
}

export default function LoginPage() {
  return (
    <div className="flex min-h-dvh flex-col">
      <main className="grid flex-1 lg:grid-cols-[minmax(0,1.25fr)_minmax(24rem,1fr)]">
        {/* Hero: the thesis, shown with the product's own output rather than described. */}
        <section className="relative flex flex-col justify-between overflow-hidden border-b border-line px-6 py-8 lg:border-r lg:border-b-0 lg:px-12 lg:py-10" aria-labelledby="hero-title">
          <Wordmark />
          <div className="relative my-10 max-w-xl">
            <h1 id="hero-title" className="font-display text-4xl leading-[1.05] font-bold tracking-tight text-frost sm:text-5xl">
              Every alert shows its&nbsp;work.
            </h1>
            <p className="mt-4 max-w-md text-base text-mist">
              SentinelX watches the wire, correlates what it sees into incidents, and tells you exactly why it thinks a source is hostile before anything is blocked.
            </p>
          </div>
          <Trace className="pointer-events-none absolute inset-x-0 top-[46%] h-24 w-full opacity-40" />
          <figure className="relative max-w-lg rounded-lg border border-line-strong bg-panel/90 p-4 shadow-2xl backdrop-blur">
            <figcaption className="mb-3 flex items-center justify-between">
              <span className="eyebrow">Example explanation · synthetic fixture</span>
              <RiskScore score={EXAMPLE.score} />
            </figcaption>
            <p className="text-sm font-medium text-frost">
              {EXAMPLE.title} <span className="font-mono text-xs text-mist">from {EXAMPLE.source}</span>
            </p>
            <ul className="mt-2 flex flex-col gap-1 text-xs text-mist">
              {EXAMPLE.evidence.map((line) => (
                <li key={line} className="flex gap-2"><span className="text-iris" aria-hidden>›</span>{line}</li>
              ))}
            </ul>
            <div className="mt-3 flex h-1.5 gap-[2px] overflow-hidden rounded-sm bg-line" aria-hidden>
              {EXAMPLE.factors.map(([label, value], index) => (
                <span key={label} style={{ width: `${value}%`, background: ["#8c9eff", "#5f71d6", "#bcc6ff"][index] }} />
              ))}
            </div>
            <p className="mt-2 font-mono text-2xs text-fog">{EXAMPLE.factors.map(([label, value]) => `${label} +${value}`).join("  ·  ")}</p>
            <p className="mt-3 border-t border-line pt-2 text-xs text-mist">{EXAMPLE.decision}</p>
          </figure>
        </section>
        <section className="flex items-center justify-center px-6 py-10">
          <Suspense>
            <LoginForm />
          </Suspense>
        </section>
      </main>
      <ConsoleFooter minimal />
    </div>
  );
}
