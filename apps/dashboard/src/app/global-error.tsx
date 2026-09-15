"use client";

/**
 * Shown when the root layout itself fails, so it cannot rely on the stylesheet or the
 * fonts: everything is inline. A full page load is the dependable recovery here, so the
 * button reloads the page (the console-level error view offers reset() instead).
 */
export default function GlobalError() {
  const mono = "ui-monospace, SFMono-Regular, Menlo, monospace";
  return (
    <html lang="en">
      <body style={{ background: "#0d1110", color: "#e4ebe6", fontFamily: "ui-sans-serif, system-ui", display: "grid", placeItems: "center", minHeight: "100dvh", margin: 0, backgroundImage: "repeating-radial-gradient(circle at 50% 50%, transparent 0 63px, rgba(58,72,68,0.45) 63px 64px)" }}>
        <main style={{ maxWidth: 460, padding: 28, background: "#141a19", border: "1px solid #3a4844" }}>
          <p style={{ fontFamily: mono, fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase", color: "#7a8882", margin: 0 }}>Console unavailable</p>
          <h1 style={{ fontSize: 34, lineHeight: 1, margin: "12px 0", fontWeight: 800, letterSpacing: "-0.01em" }}>The dashboard failed to load</h1>
          <p style={{ color: "#9ba9a3", fontSize: 14, lineHeight: 1.6 }}>Reload the page. If it keeps happening, check that the SentinelX API is running and reachable from this server.</p>
          <button onClick={() => window.location.reload()} style={{ marginTop: 16, background: "#e4ebe6", color: "#0d1110", border: 0, borderRadius: 2, padding: "10px 16px", fontWeight: 600, cursor: "pointer" }}>Reload page</button>
        </main>
      </body>
    </html>
  );
}
