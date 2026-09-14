import type { NextConfig } from "next";

/**
 * The dashboard proxies /api/* to the SentinelX API so the browser sees one
 * origin. That is what lets the API's SameSite=Strict, httpOnly session cookies
 * work without CORS, and keeps CSRF protection meaningful.
 */
const apiOrigin = process.env.SENTINELX_API_URL ?? "http://127.0.0.1:8000";

const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiOrigin}/api/:path*` }];
  },
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;
