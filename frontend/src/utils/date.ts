/**
 * Date utility functions for consistent timestamp handling.
 *
 * The backend stores and returns UTC. The UI shows every timestamp in the
 * user's local time and says which timezone that is.
 */

const HAS_TIMEZONE = /(Z|[+-]\d{2}:?\d{2})$/i;

/**
 * Parse UTC timestamp from backend.
 * Backend may return timestamps with or without 'Z' suffix.
 * This ensures consistent parsing as UTC.
 */
export function parseUTC(dateString: string): Date {
  if (dateString.includes('T') || dateString.includes(' ')) {
    if (!HAS_TIMEZONE.test(dateString)) {
      return new Date(dateString.replace(' ', 'T') + 'Z');
    }
  }
  return new Date(dateString);
}

/** Short name of the user's timezone at `date`, e.g. "PDT", "GMT+2", "UTC". */
export function timeZoneLabel(date: Date = new Date(), timeZone?: string): string {
  try {
    const parts = new Intl.DateTimeFormat('en-US', { timeZoneName: 'short', timeZone }).formatToParts(date);
    return parts.find((part) => part.type === 'timeZoneName')?.value ?? '';
  } catch {
    return '';
  }
}

interface FormatOptions {
  /** Include seconds (default: false). */
  seconds?: boolean;
  /** Include the year (default: true). */
  year?: boolean;
  /** Override the timezone (tests); defaults to the browser's. */
  timeZone?: string;
}

/**
 * Format a backend timestamp in the user's local time with a timezone label,
 * e.g. "Oct 10, 2026, 12:01 PM PDT". Returns "—" for missing/invalid values.
 */
export function formatDateTime(value: string | Date | null | undefined, options: FormatOptions = {}): string {
  if (!value) return '—';
  const date = typeof value === 'string' ? parseUTC(value) : value;
  if (Number.isNaN(date.getTime())) return '—';

  const { seconds = false, year = true, timeZone } = options;
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: year ? 'numeric' : undefined,
    hour: 'numeric',
    minute: '2-digit',
    second: seconds ? '2-digit' : undefined,
    timeZoneName: 'short',
    timeZone,
  }).format(date);
}

const BARE_UTC_TIMESTAMP = /\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?\b/g;

/**
 * Rewrite the bare UTC timestamps ("2026-10-10 19:01") inside backend-written
 * text as local time with a timezone label.
 */
export function localizeTimestamps(text: string, options: FormatOptions = {}): string {
  return text.replace(BARE_UTC_TIMESTAMP, (stamp) => formatDateTime(stamp, options));
}
