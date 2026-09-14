/**
 * Browser API client.
 *
 * Talks to same-origin /api/v1 (proxied to the backend by next.config.ts), so
 * session cookies are attached automatically. State-changing requests echo the
 * sx_csrf cookie in X-CSRF-Token (double-submit). A 401 triggers one silent
 * refresh, shared by concurrent requests, then a single retry.
 */

const BASE = "/api/v1";
const CLIENT_HEADER = { "X-SentinelX-Client": "dashboard" };

export class ApiError extends Error {
  readonly status: number;
  readonly problems: string[];
  readonly body: unknown;

  constructor(status: number, message: string, body: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
    const problems = (body as { problems?: unknown } | null)?.problems;
    this.problems = Array.isArray(problems) ? problems.map(String) : [];
  }
}

function csrfToken(): string {
  const match = document.cookie.split("; ").find((part) => part.startsWith("sx_csrf="));
  return match ? decodeURIComponent(match.slice("sx_csrf=".length)) : "";
}

let refreshing: Promise<boolean> | null = null;

async function refreshSession(): Promise<boolean> {
  refreshing ??= fetch(`${BASE}/auth/refresh`, { method: "POST", headers: CLIENT_HEADER, credentials: "same-origin" })
    .then((response) => response.ok)
    .catch(() => false)
    .finally(() => {
      setTimeout(() => (refreshing = null), 0);
    });
  return refreshing;
}

async function parse(response: Response): Promise<unknown> {
  if (response.status === 204) return null;
  const type = response.headers.get("content-type") ?? "";
  return type.includes("application/json") ? response.json() : response.text();
}

function messageFrom(body: unknown, status: number): string {
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      return detail
        .map((item) => (item && typeof item === "object" && "msg" in item ? `${(item as { loc?: unknown[] }).loc?.slice(1).join(".")}: ${(item as { msg: string }).msg}` : String(item)))
        .join("; ");
    }
  }
  return status === 429 ? "Too many requests. Wait a moment and try again." : `Request failed (${status})`;
}

export async function api<T>(path: string, init: RequestInit & { json?: unknown; retry?: boolean } = {}): Promise<T> {
  const { json, retry = true, headers, ...rest } = init;
  const method = (rest.method ?? "GET").toUpperCase();
  const finalHeaders: Record<string, string> = { ...CLIENT_HEADER, ...(headers as Record<string, string>) };
  if (json !== undefined) finalHeaders["Content-Type"] = "application/json";
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) finalHeaders["X-CSRF-Token"] = csrfToken();

  const response = await fetch(`${BASE}${path}`, {
    ...rest,
    method,
    headers: finalHeaders,
    body: json !== undefined ? JSON.stringify(json) : rest.body,
    credentials: "same-origin",
    cache: "no-store",
  });

  if (response.status === 401 && retry && !path.startsWith("/auth/login") && !path.startsWith("/auth/refresh")) {
    if (await refreshSession()) return api<T>(path, { ...init, retry: false });
  }
  const body = await parse(response);
  if (!response.ok) throw new ApiError(response.status, messageFrom(body, response.status), body);
  return body as T;
}

export const fetcher = <T,>(path: string): Promise<T> => api<T>(path);

export function query(params: Record<string, string | number | boolean | string[] | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === null || value === undefined || value === "") continue;
    if (Array.isArray(value)) value.forEach((item) => search.append(key, item));
    else search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}
