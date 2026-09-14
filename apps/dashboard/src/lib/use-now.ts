"use client";

import { useEffect, useState } from "react";

/**
 * Current time that updates on an interval. Reading Date.now() during render makes
 * a component impure (different output for the same props); this keeps render pure
 * and refreshes relative times and time-window queries on a steady cadence.
 * `granularityMs` rounds the value so dependent SWR keys stay stable between ticks.
 */
export function useNow(intervalMs = 60_000, granularityMs = intervalMs): number {
  const [now, setNow] = useState(() => roundTo(Date.now(), granularityMs));
  useEffect(() => {
    const timer = setInterval(() => setNow(roundTo(Date.now(), granularityMs)), intervalMs);
    return () => clearInterval(timer);
  }, [intervalMs, granularityMs]);
  return now;
}

function roundTo(value: number, step: number): number {
  return step > 0 ? Math.floor(value / step) * step : value;
}
