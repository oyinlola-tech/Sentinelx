"use client";

import type { ReactNode } from "react";
import { SWRConfig } from "swr";
import { ToastProvider } from "@/components/ui/toast";
import { fetcher } from "@/lib/api";
import { SessionProvider } from "@/lib/session";

export function Providers({ children }: { children: ReactNode }) {
  return (
    <SWRConfig value={{ fetcher, revalidateOnFocus: true, shouldRetryOnError: false, keepPreviousData: true }}>
      <ToastProvider>
        <SessionProvider>{children}</SessionProvider>
      </ToastProvider>
    </SWRConfig>
  );
}
