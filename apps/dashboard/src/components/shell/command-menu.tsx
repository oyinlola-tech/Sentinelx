"use client";

import { CornerDownLeft, Search } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { Detection, Incident } from "@/lib/types";

export interface CommandItem { id: string; label: string; hint: string; href: string }

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const IPV6 = /^[0-9a-f:]+:[0-9a-f:]*$/i;
const HEX_ID = /^[0-9a-f]{32}$/i;

/**
 * Command menu (Ctrl/Cmd+K). Jumps to any page, and resolves what analysts paste:
 * an IP address opens its threat view, a 32-character id opens the detection or
 * incident it belongs to.
 */
export function CommandMenu({ pages }: { pages: CommandItem[] }) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [active, setActive] = useState(0);
  const [lookup, setLookup] = useState<CommandItem | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen((current) => !current);
      }
    };
    const onOpen = () => setOpen(true);
    window.addEventListener("keydown", onKey);
    window.addEventListener("sentinelx:command", onOpen);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("sentinelx:command", onOpen);
    };
  }, []);

  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    if (open && !element.open) {
      element.showModal();
      setText("");
      setActive(0);
    }
    if (!open && element.open) element.close();
  }, [open]);

  const value = text.trim();
  useEffect(() => {
    setLookup(null);
    if (!HEX_ID.test(value)) return;
    let cancelled = false;
    (async () => {
      try {
        const detection = await api<Detection>(`/detections/${value}`);
        if (!cancelled) setLookup({ id: "lookup", label: detection.title, hint: `Detection from ${detection.source_ip}`, href: `/detections/${value}` });
      } catch {
        try {
          const incident = await api<Incident>(`/incidents/${value}`);
          if (!cancelled) setLookup({ id: "lookup", label: incident.title, hint: "Incident", href: `/incidents/${value}` });
        } catch {
          if (!cancelled) setLookup({ id: "lookup", label: "No detection or incident with that id", hint: "Retention may have removed it", href: "" });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [value]);

  const items = useMemo(() => {
    const results: CommandItem[] = [];
    if (IPV4.test(value) || (value.includes(":") && IPV6.test(value))) {
      results.push({ id: "ip", label: `Investigate ${value}`, hint: "Detections from this source", href: `/threats?source=${encodeURIComponent(value)}` });
    }
    if (lookup) results.push(lookup);
    const needle = value.toLowerCase();
    results.push(...pages.filter((page) => !needle || page.label.toLowerCase().includes(needle) || page.hint.toLowerCase().includes(needle)));
    return results;
  }, [value, lookup, pages]);

  function go(item: CommandItem | undefined) {
    if (!item?.href) return;
    setOpen(false);
    router.push(item.href);
  }

  return (
    <dialog
      ref={dialog}
      aria-label="Command menu"
      onClose={() => setOpen(false)}
      onClick={(event) => event.target === dialog.current && setOpen(false)}
      className="mx-auto mt-[12vh] w-[calc(100%-2rem)] max-w-xl rounded-lg border border-line-strong bg-panel p-0 text-frost shadow-2xl backdrop:bg-black/60"
    >
      {open && (
        <div>
          <div className="flex items-center gap-2 border-b border-line px-3">
            <Search className="size-4 text-fog" aria-hidden />
            <input
              autoFocus
              value={text}
              onChange={(event) => { setText(event.target.value); setActive(0); }}
              onKeyDown={(event) => {
                if (event.key === "ArrowDown") { event.preventDefault(); setActive((index) => Math.min(items.length - 1, index + 1)); }
                if (event.key === "ArrowUp") { event.preventDefault(); setActive((index) => Math.max(0, index - 1)); }
                if (event.key === "Enter") { event.preventDefault(); go(items[active]); }
              }}
              placeholder="Jump to a page, or paste an IP or detection id"
              aria-label="Search pages, addresses and ids"
              aria-controls="command-results"
              aria-activedescendant={items[active] ? `command-${items[active]!.id}` : undefined}
              className="h-12 flex-1 bg-transparent text-sm outline-none placeholder:text-fog"
            />
            <kbd className="rounded border border-line-strong px-1.5 font-mono text-2xs text-fog">Esc</kbd>
          </div>
          <ul id="command-results" role="listbox" className="max-h-80 overflow-y-auto p-1.5">
            {items.length === 0 && <li className="px-3 py-6 text-center text-sm text-mist">Nothing matches “{value}”.</li>}
            {items.map((item, index) => (
              <li
                key={item.id}
                id={`command-${item.id}`}
                role="option"
                aria-selected={index === active}
                onMouseEnter={() => setActive(index)}
                onClick={() => go(item)}
                className={`flex cursor-pointer items-center justify-between gap-3 rounded-md px-3 py-2 ${index === active ? "bg-raised" : ""} ${item.href ? "" : "cursor-default opacity-70"}`}
              >
                <span className="min-w-0">
                  <span className="block truncate text-sm">{item.label}</span>
                  <span className="block truncate text-xs text-mist">{item.hint}</span>
                </span>
                {index === active && item.href && <CornerDownLeft className="size-3.5 shrink-0 text-fog" aria-hidden />}
              </li>
            ))}
          </ul>
        </div>
      )}
    </dialog>
  );
}
