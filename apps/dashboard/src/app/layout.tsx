import type { Metadata, Viewport } from "next";
import localFont from "next/font/local";
import type { ReactNode } from "react";
import { Providers } from "./providers";
import "./globals.css";

/*
 * Fonts are self-hosted from @fontsource packages rather than fetched from Google at
 * build time: SentinelX must build and run with no internet access (air-gapped
 * sensors are a normal deployment), and a console should not leak visits to a third
 * party. All faces are OFL-licensed.
 *
 * - Big Shoulders Stencil: the wordmark and oversized numerals, like the stencilled
 *   plates on field equipment.
 * - Big Shoulders (variable): headings and figures; condensed, so numbers stay large
 *   without crowding a panel.
 * - Public Sans: body copy.
 * - Martian Mono (variable, width axis): addresses, ports, labels and tables.
 */
const stencil = localFont({
  src: [
    { path: "../../node_modules/@fontsource/big-shoulders-stencil-display/files/big-shoulders-stencil-display-latin-800-normal.woff2", weight: "800" },
    { path: "../../node_modules/@fontsource/big-shoulders-stencil-display/files/big-shoulders-stencil-display-latin-900-normal.woff2", weight: "900" },
  ],
  variable: "--font-stencil-face",
  display: "swap",
});
const shoulders = localFont({
  src: "../../node_modules/@fontsource-variable/big-shoulders/files/big-shoulders-latin-standard-normal.woff2",
  weight: "100 900",
  variable: "--font-shoulders",
  display: "swap",
});
const publicSans = localFont({
  src: [
    { path: "../../node_modules/@fontsource/public-sans/files/public-sans-latin-400-normal.woff2", weight: "400" },
    { path: "../../node_modules/@fontsource/public-sans/files/public-sans-latin-500-normal.woff2", weight: "500" },
    { path: "../../node_modules/@fontsource/public-sans/files/public-sans-latin-600-normal.woff2", weight: "600" },
    { path: "../../node_modules/@fontsource/public-sans/files/public-sans-latin-700-normal.woff2", weight: "700" },
  ],
  variable: "--font-public-sans",
  display: "swap",
});
const martian = localFont({
  src: "../../node_modules/@fontsource-variable/martian-mono/files/martian-mono-latin-standard-normal.woff2",
  weight: "100 800",
  variable: "--font-martian",
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: "SentinelX", template: "%s · SentinelX" },
  description: "Network intrusion detection and prevention console",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { themeColor: "#0d1110", colorScheme: "dark" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${stencil.variable} ${shoulders.variable} ${publicSans.variable} ${martian.variable}`}>
      <body className="min-h-dvh font-sans">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
