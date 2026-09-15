"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { mutate } from "swr";
import { api } from "./api";
import type { EventType, StreamEvent } from "./types";

type Listener = (event: StreamEvent) => void;
export type StreamState = "connecting" | "open" | "reconnecting" | "offline";

interface EventsValue {
  state: StreamState;
  subscribe: (types: EventType[] | "*", listener: Listener) => () => void;
  recent: StreamEvent[];
}

const EventsContext = createContext<EventsValue | null>(null);
const RECENT_LIMIT = 400;
/** Event types the live feed shows; others (progress, stats, audit) never evict them. */
const FEED_TYPES = new Set<string>([
  "detection.created",
  "incident.opened",
  "incident.updated",
  "severity.changed",
  "response.decided",
  "response.pending_approval",
  "ip.blocked",
  "ip.unblocked",
]);
const FEED_FLUSH_MS = 250;

async function socketUrl(ticket: string): Promise<string> {
  let base: string | null = null;
  try {
    const config = (await (await fetch("/runtime-config", { cache: "no-store" })).json()) as { wsUrl: string | null };
    base = config.wsUrl;
  } catch {
    base = null;
  }
  if (!base) {
    // Same origin: the dashboard server (development) or the front proxy (Docker) forwards
    // the upgrade to the API, so no separate public WebSocket address is needed.
    const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
    base = `${scheme}//${window.location.host}`;
  }
  return `${base.replace(/\/$/, "")}/api/v1/ws/events?ticket=${encodeURIComponent(ticket)}`;
}

/**
 * One WebSocket for the whole dashboard.
 *
 * Each connection uses a fresh single-use ticket from POST /auth/ws-ticket, so a
 * reconnect after a network blip or a server restart re-authenticates cleanly.
 * Backoff is exponential with jitter, capped at 30s, and resets after a stable
 * connection.
 */
export function EventsProvider({ enabled, children }: { enabled: boolean; children: ReactNode }) {
  const [state, setState] = useState<StreamState>("connecting");
  const [recent, setRecent] = useState<StreamEvent[]>([]);
  const listeners = useRef(new Set<{ types: Set<EventType> | null; listener: Listener }>());

  useEffect(() => {
    if (!enabled) return;
    let socket: WebSocket | null = null;
    let attempt = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let flushTimer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let everOpened = false;
    let pending: StreamEvent[] = [];

    const flush = () => {
      flushTimer = undefined;
      if (stopped || pending.length === 0) return;
      const batch = pending;
      pending = [];
      setRecent((previous) => [...batch.reverse(), ...previous].slice(0, RECENT_LIMIT));
    };

    const schedule = () => {
      if (stopped) return;
      const delay = Math.min(30_000, 1000 * 2 ** attempt) * (0.7 + Math.random() * 0.6);
      attempt += 1;
      setState(attempt > 5 ? "offline" : "reconnecting");
      timer = setTimeout(connect, delay);
    };

    const connect = async () => {
      if (stopped) return;
      let created: WebSocket;
      try {
        const { ticket } = await api<{ ticket: string }>("/auth/ws-ticket", { method: "POST" });
        const url = await socketUrl(ticket);
        if (stopped) return; // unmounted while fetching the ticket: never open a socket
        created = new WebSocket(url);
      } catch {
        schedule();
        return;
      }
      socket = created;
      let openedAt = 0;
      created.onopen = () => {
        if (stopped) {
          created.close();
          return;
        }
        openedAt = Date.now();
        setState("open");
        // After a reconnect, refetch everything: events sent while disconnected are gone.
        if (everOpened) void mutate(() => true);
        everOpened = true;
      };
      created.onmessage = (message) => {
        let event: StreamEvent;
        try {
          event = JSON.parse(String(message.data)) as StreamEvent;
        } catch {
          return;
        }
        if ((event.type as string) === "ping" || (event.type as string) === "hello") return;
        if (FEED_TYPES.has(event.type)) {
          // Batched: a burst of events renders once, not once per event.
          pending.push(event);
          flushTimer ??= setTimeout(flush, FEED_FLUSH_MS);
        }
        for (const entry of listeners.current) {
          if (!entry.types || entry.types.has(event.type)) entry.listener(event);
        }
      };
      created.onclose = (closed) => {
        if (openedAt && Date.now() - openedAt > 10_000) attempt = 0;
        // 4403: role changed; reconnect at once with a fresh ticket and permissions.
        if (closed.code === 4403) attempt = 0;
        schedule();
      };
      created.onerror = () => created.close();
    };

    void connect();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      if (flushTimer) clearTimeout(flushTimer);
      socket?.close();
    };
  }, [enabled]);

  // Stable identity: consumers resubscribe only if this function changes, and the
  // provider re-renders on every event.
  const subscribe = useCallback((types: EventType[] | "*", listener: Listener) => {
    const entry = { types: types === "*" ? null : new Set(types), listener };
    listeners.current.add(entry);
    return () => {
      listeners.current.delete(entry);
    };
  }, []);
  const value = useMemo<EventsValue>(() => ({ state, recent, subscribe }), [state, recent, subscribe]);
  return <EventsContext.Provider value={value}>{children}</EventsContext.Provider>;
}

export function useEvents(): EventsValue {
  const value = useContext(EventsContext);
  if (!value) throw new Error("useEvents must be used inside EventsProvider");
  return value;
}

/** Re-run `callback` whenever one of `types` arrives (typically an SWR mutate). */
export function useEventRefresh(types: EventType[], callback: () => void, throttleMs = 1500): void {
  const { subscribe } = useEvents();
  const saved = useRef(callback);
  useEffect(() => {
    saved.current = callback;
  }, [callback]);
  const key = types.join(",");
  useEffect(() => {
    let last = 0;
    let pending: ReturnType<typeof setTimeout> | undefined;
    const unsubscribe = subscribe(key.split(",") as EventType[], () => {
      const wait = throttleMs - (Date.now() - last);
      if (wait <= 0) {
        last = Date.now();
        saved.current();
      } else if (!pending) {
        pending = setTimeout(() => {
          pending = undefined;
          last = Date.now();
          saved.current();
        }, wait);
      }
    });
    return () => {
      unsubscribe();
      if (pending) clearTimeout(pending);
    };
  }, [subscribe, key, throttleMs]);
}
