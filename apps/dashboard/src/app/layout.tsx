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
 */
const plexSans = localFont({
  src: [
    { path: "../../node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-400-normal.woff2", weight: "400" },
    { path: "../../node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-500-normal.woff2", weight: "500" },
    { path: "../../node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-600-normal.woff2", weight: "600" },
  ],
  variable: "--font-plex-sans",
  display: "swap",
});
const plexMono = localFont({
  src: [
    { path: "../../node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-400-normal.woff2", weight: "400" },
    { path: "../../node_modules/@fontsource/ibm-plex-mono/files/ibm-plex-mono-latin-500-normal.woff2", weight: "500" },
  ],
  variable: "--font-plex-mono",
  display: "swap",
});
const archivo = localFont({
  src: [
    { path: "../../node_modules/@fontsource/archivo/files/archivo-latin-600-normal.woff2", weight: "600" },
    { path: "../../node_modules/@fontsource/archivo/files/archivo-latin-700-normal.woff2", weight: "700" },
  ],
  variable: "--font-archivo",
  display: "swap",
});

export const metadata: Metadata = {
  title: { default: "SentinelX", template: "%s · SentinelX" },
  description: "Network intrusion detection and prevention console",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { themeColor: "#0b1117", colorScheme: "dark" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable} ${archivo.variable}`}>
      <body className="min-h-dvh font-sans">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
