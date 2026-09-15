"use client";

/**
 * Shown when the root layout itself fails. A full page load is the dependable recovery
 * here, so the button reloads the page (the console-level error view offers reset()
 * as "Try again" instead).
 */
export default function GlobalError() {
  return (
    <html lang="en">
      <body style={{ background: "#0b1117", color: "#d7e1ea", fontFamily: "ui-sans-serif, system-ui", display: "grid", placeItems: "center", minHeight: "100dvh", margin: 0 }}>
        <main style={{ maxWidth: 420, padding: 24 }}>
          <p style={{ fontFamily: "ui-monospace, monospace", fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase", color: "#6b7f90" }}>Console unavailable</p>
          <h1 style={{ fontSize: 24, margin: "8px 0" }}>The dashboard failed to load</h1>
          <p style={{ color: "#95a7b7", fontSize: 14 }}>Reload the page. If it keeps happening, check that the SentinelX API is running and reachable from this server.</p>
          <button onClick={() => window.location.reload()} style={{ marginTop: 16, background: "#8c9eff", color: "#0b1117", border: 0, borderRadius: 6, padding: "8px 14px", fontWeight: 500, cursor: "pointer" }}>Reload page</button>
        </main>
      </body>
    </html>
  );
}
