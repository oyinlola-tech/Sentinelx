"use client";

import { usePathname } from "next/navigation";
import { useSyncExternalStore } from "react";

const noop = () => () => {};

/**
 * The address that was not found, read back in mono like a bearing. The 404 page is
 * prerendered without the real address, so this renders only after hydration.
 */
export function RequestedPath() {
  const pathname = usePathname();
  const hydrated = useSyncExternalStore(noop, () => true, () => false);
  if (!hydrated || !pathname || pathname === "/_not-found") return null;
  return (
    <p className="mt-5 max-w-full truncate border border-line bg-panel px-3 py-1.5 font-mono text-xs text-mist">
      <span className="text-fog">bearing </span>
      {pathname}
      <span className="text-fog"> · no contact</span>
    </p>
  );
}
