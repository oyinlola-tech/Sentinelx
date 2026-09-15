"use client";

import { useEffect, useState } from "react";

/**
 * `value`, once it has stopped changing for `delayMs`. Used for text filters that
 * feed an SWR key, so typing an address fetches once instead of once per keystroke.
 */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}
