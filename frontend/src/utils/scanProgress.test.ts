import { describe, it, expect } from 'vitest';
import { phaseLabel, phaseStep, progressPercent } from './scanProgress';

describe('progressPercent', () => {
  it('converts the backend fraction to a percentage', () => {
    // Regression: the scan list rendered the fraction itself, so every running scan showed "1%"
    expect(progressPercent(0.1)).toBe(10);
    expect(progressPercent(0.85)).toBe(85);
    expect(progressPercent(0.876)).toBe(88);
  });

  it('keeps a running scan between 1% and 99%', () => {
    expect(progressPercent(0.001)).toBe(1);
    expect(progressPercent(0.999)).toBe(99);
  });

  it('handles the ends and bad input', () => {
    expect(progressPercent(0)).toBe(0);
    expect(progressPercent(1)).toBe(100);
    expect(progressPercent(null)).toBe(0);
    expect(progressPercent(undefined)).toBe(0);
    expect(progressPercent(Number.NaN)).toBe(0);
  });
});

describe('phaseStep', () => {
  it('reports the step that is running', () => {
    expect(phaseStep('nuclei', { nuclei: { completed: 5, total: 37 } })).toEqual({ current: 6, total: 37 });
    expect(phaseStep('nuclei', { nuclei: { completed: 37, total: 37 } })).toEqual({ current: 37, total: 37 });
  });

  it('finds ssh-audit stats for the ssh_audit phase', () => {
    expect(phaseStep('ssh_audit', { 'ssh-audit': { completed: 0, total: 2 } })).toEqual({ current: 1, total: 2 });
  });

  it('is null for single-step phases and missing stats', () => {
    expect(phaseStep('nmap', { nmap: { completed: 0, total: 1 } })).toBeNull();
    expect(phaseStep('nmap', null)).toBeNull();
    expect(phaseStep('zap', { nmap: { completed: 0, total: 3 } })).toBeNull();
  });
});

describe('phaseLabel', () => {
  it('names known phases and passes unknown ones through', () => {
    expect(phaseLabel('nuclei_endpoints')).toBe('Nuclei Endpoint Scan');
    expect(phaseLabel('something_new')).toBe('something_new');
  });
});
