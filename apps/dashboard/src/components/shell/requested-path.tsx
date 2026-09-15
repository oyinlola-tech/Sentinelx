"use client";

import { usePathname } from "next/navigation";

/** The address that was not found, read back in mono like a bearing. */
export function RequestedPath() {
  const pathname = usePathname();
  if (!pathname || pathname === "/_not-found") return null;
  return (
    <p className="mt-5 max-w-full truncate border border-line bg-panel px-3 py-1.5 font-mono text-xs text-mist">
      <span className="text-fog">bearing </span>
      {pathname}
      <span className="text-fog"> · no contact</span>
    </p>
  );
}
