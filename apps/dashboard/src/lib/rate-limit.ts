import { ApiError } from "./api";

/**
 * True when a failed request was rate limited (429) but SWR still holds data from an
 * earlier response. Pages keep showing that data with a small notice instead of
 * replacing the view with an error state for a transient limit.
 */
export function isTransientRateLimit(error: unknown, data: unknown): error is ApiError {
  return data !== undefined && error instanceof ApiError && error.status === 429;
}
