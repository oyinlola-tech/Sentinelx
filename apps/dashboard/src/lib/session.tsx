"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import useSWR from "swr";
import { ApiError, SESSION_EXPIRED_EVENT, api } from "./api";
import type { LoginRequest, Role, User } from "./types";

interface SessionValue {
  user: User | null;
  loading: boolean;
  can: (role: Role) => boolean;
  login: (username: string, password: string) => Promise<User>;
  logout: () => Promise<void>;
  reload: () => Promise<void>;
}

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };
const SessionContext = createContext<SessionValue | null>(null);

async function loadUser(): Promise<User | null> {
  try {
    return await api<User>("/auth/me");
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null; // signed out is a state, not an error
    throw error;
  }
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const { data, isLoading, mutate } = useSWR<User | null>("session", loadUser, { revalidateOnFocus: true, shouldRetryOnError: false });
  const user = data ?? null;
  const loading = isLoading && data === undefined;

  useEffect(() => {
    // A request failed with 401 and the session could not be refreshed: sign out now
    // rather than leaving pages showing "invalid token" errors.
    const expired = () => void mutate(null, { revalidate: false });
    window.addEventListener(SESSION_EXPIRED_EVENT, expired);
    return () => window.removeEventListener(SESSION_EXPIRED_EVENT, expired);
  }, [mutate]);

  useEffect(() => {
    if (loading) return;
    const here = `${pathname}${window.location.search}`;
    if (!user && pathname !== "/login") router.replace(`/login?next=${encodeURIComponent(here)}`);
    if (user?.must_change_password && pathname !== "/account") router.replace("/account?required=1");
  }, [loading, user, pathname, router]);

  const reload = useCallback(async () => {
    await mutate();
  }, [mutate]);

  const value = useMemo<SessionValue>(
    () => ({
      user,
      loading,
      can: (role) => (user ? RANK[user.role] >= RANK[role] : false),
      login: async (username, password) => {
        const result = await api<{ user: User }>("/auth/login", { method: "POST", json: { username, password } satisfies LoginRequest });
        await mutate();
        return result.user;
      },
      logout: async () => {
        try {
          await api("/auth/logout", { method: "POST" });
        } finally {
          await mutate(null, { revalidate: false });
          router.replace("/login");
        }
      },
      reload,
    }),
    [user, loading, mutate, reload, router],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession must be used inside SessionProvider");
  return value;
}
