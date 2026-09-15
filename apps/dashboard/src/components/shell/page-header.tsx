"use client";

import { usePathname } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { NAV } from "@/components/shell/nav";

/**
 * Page title set as signage: the task group as a small mono label, the page name in
 * condensed display type, and the page's purpose underneath.
 */
export function PageHeader({ title, description, actions, eyebrow }: { title: string; description?: ReactNode; actions?: ReactNode; eyebrow?: string }) {
  const pathname = usePathname();
  useEffect(() => {
    document.title = `${title} · SentinelX`;
  }, [title]);
  const section = NAV.find((item) => (item.href === "/" ? pathname === "/" : pathname.startsWith(item.href)));
  const label = eyebrow ?? (section ? `${section.group} / ${section.label}` : undefined);
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-x-6 gap-y-4 border-b border-line pb-5">
      <div className="min-w-0">
        {label && <p className="eyebrow mb-3">{label}</p>}
        <h1 className="heading-display text-[clamp(2.4rem,4.2vw,3.6rem)] text-frost">{title}</h1>
        {description && <p className="mt-3 max-w-3xl text-sm leading-relaxed text-mist">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}
