/**
 * Date utility functions for consistent timestamp handling.
 */

/**
 * Parse UTC timestamp from backend.
 * Backend may return timestamps with or without 'Z' suffix.
 * This ensures consistent parsing as UTC.
 */
export function parseUTC(dateString: string): Date {
  if (!dateString.endsWith('Z') && !dateString.includes('+')) {
    return new Date(dateString + 'Z');
  }
  return new Date(dateString);
}
