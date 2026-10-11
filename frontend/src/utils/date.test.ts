import { describe, it, expect } from 'vitest';
import { formatDateTime, parseUTC, timeZoneLabel } from './date';

describe('parseUTC', () => {
  it('treats timestamps without a timezone as UTC', () => {
    expect(parseUTC('2026-10-10T19:01:49.123456').toISOString()).toBe('2026-10-10T19:01:49.123Z');
    expect(parseUTC('2026-10-10 19:01:49').toISOString()).toBe('2026-10-10T19:01:49.000Z');
  });

  it('keeps an explicit timezone', () => {
    expect(parseUTC('2026-10-10T19:01:49Z').toISOString()).toBe('2026-10-10T19:01:49.000Z');
    expect(parseUTC('2026-10-10T19:01:49+02:00').toISOString()).toBe('2026-10-10T17:01:49.000Z');
    // A negative offset must not be mistaken for a missing timezone
    expect(parseUTC('2026-10-10T19:01:49-07:00').toISOString()).toBe('2026-10-11T02:01:49.000Z');
  });
});

describe('formatDateTime', () => {
  it('shows local time with a timezone label', () => {
    const text = formatDateTime('2026-10-10T19:01:49', { timeZone: 'America/Los_Angeles' });
    expect(text).toContain('Oct 10, 2026');
    expect(text).toContain('12:01');
    expect(text).toContain('PDT');
  });

  it('converts the same instant differently per timezone', () => {
    const utc = formatDateTime('2026-10-10T19:01:49', { timeZone: 'UTC' });
    expect(utc).toContain('7:01');
    expect(utc).toContain('UTC');
  });

  it('supports seconds and omitting the year', () => {
    const text = formatDateTime('2026-10-10T19:01:49', { timeZone: 'UTC', seconds: true, year: false });
    expect(text).toContain('7:01:49');
    expect(text).not.toContain('2026');
  });

  it('returns a dash for missing or invalid values', () => {
    expect(formatDateTime(null)).toBe('—');
    expect(formatDateTime(undefined)).toBe('—');
    expect(formatDateTime('not a date')).toBe('—');
  });
});

describe('timeZoneLabel', () => {
  it('names the timezone', () => {
    expect(timeZoneLabel(new Date('2026-10-10T19:01:49Z'), 'UTC')).toBe('UTC');
    expect(timeZoneLabel(new Date('2026-10-10T19:01:49Z'), 'America/Los_Angeles')).toBe('PDT');
  });
});
