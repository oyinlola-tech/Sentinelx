"use client";

import { CheckCircle2, CircleAlert, Info, X } from "lucide-react";
import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

type Tone = "success" | "error" | "info";
interface Toast { id: number; tone: Tone; title: string; detail?: string }

const ToastContext = createContext<(tone: Tone, title: string, detail?: string) => void>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const dismiss = useCallback((id: number) => setToasts((all) => all.filter((toast) => toast.id !== id)), []);
  const push = useCallback(
    (tone: Tone, title: string, detail?: string) => {
      const id = Date.now() + Math.random();
      setToasts((all) => [...all.slice(-3), { id, tone, title, detail }]);
      // Errors stay until dismissed: an operator must not miss a failed block.
      if (tone !== "error") setTimeout(() => dismiss(id), 5000);
    },
    [dismiss],
  );
  const icon = { success: <CheckCircle2 className="size-4 text-ok" />, error: <CircleAlert className="size-4 text-sev-critical" />, info: <Info className="size-4 text-iris" /> };
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="pointer-events-none fixed right-4 bottom-4 z-50 flex w-80 flex-col gap-2" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} role={toast.tone === "error" ? "alert" : "status"} className="panel pointer-events-auto flex gap-3 p-3 shadow-xl">
            <span aria-hidden className="mt-0.5">{icon[toast.tone]}</span>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">{toast.title}</p>
              {toast.detail && <p className="mt-0.5 break-words text-xs text-mist">{toast.detail}</p>}
            </div>
            <button onClick={() => dismiss(toast.id)} aria-label="Dismiss notification" className="self-start text-fog hover:text-frost">
              <X className="size-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);
