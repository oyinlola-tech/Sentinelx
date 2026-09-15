import type { NextConfig } from "next";

/**
 * The dashboard proxies /api/* to the SentinelX API so the browser sees one
 * origin. That is what lets the API's SameSite=Strict, httpOnly session cookies
 * work without CORS, and keeps CSRF protection meaningful.
 */
const apiOrigin = process.env.SENTINELX_API_URL ?? "http://127.0.0.1:8000";

/**
 * Everything the dashboard loads is same-origin (local fonts, the proxied API and the
 * event stream). Next.js hydration uses inline scripts, so scripts and styles allow
 * 'unsafe-inline'; the policy still blocks scripts and connections to other origins,
 * framing, plugins and <base> hijacking. Development needs eval for React Refresh,
 * so the policy is applied to production builds only.
 */
const contentSecurityPolicy = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join("; ");

const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
  ...(process.env.NODE_ENV === "production" ? [{ key: "Content-Security-Policy", value: contentSecurityPolicy }] : []),
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
