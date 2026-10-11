/**
 * Scan progress helpers shared by the scan list and the scan detail page.
 */

/** Human-readable name of each backend phase (Scan.current_phase). */
export const PHASE_LABELS: Record<string, string> = {
  pending: 'Initializing',
  nmap_discovery: 'Port Discovery',
  nmap: 'Service Enumeration',
  httpx: 'HTTP Probing',
  katana: 'Endpoint Discovery',
  ssh_audit: 'SSH Audit',
  nuclei: 'Nuclei Vulnerability Scan',
  nuclei_endpoints: 'Nuclei Endpoint Scan',
  nse: 'NSE Scripts',
  sslscan: 'SSL/TLS Analysis',
  testssl: 'Deep TLS Analysis',
  nikto: 'Nikto Web Scan',
  zap: 'OWASP ZAP',
};

export function phaseLabel(phase: string): string {
  return PHASE_LABELS[phase] || phase;
}

/**
 * The backend reports progress as a fraction (0..1); the UI shows a whole
 * percentage. A running scan never shows 100% and one that has started work
 * never shows 0%.
 */
export function progressPercent(fraction: number | null | undefined): number {
  const value = Number(fraction);
  if (!Number.isFinite(value) || value <= 0) return 0;
  if (value >= 1) return 100;
  return Math.min(99, Math.max(1, Math.round(value * 100)));
}

type PhaseStats = Record<string, { completed: number; total: number }> | null | undefined;

/** "step N of M" of the running phase, when it has more than one step. */
export function phaseStep(phase: string, phaseStats: PhaseStats): { current: number; total: number } | null {
  if (!phaseStats) return null;
  // The worker keys ssh-audit with a dash, the phase enum uses an underscore
  const stats = phaseStats[phase] ?? phaseStats[phase.replace(/_/g, '-')];
  if (!stats || stats.total <= 1) return null;
  return { current: Math.min(stats.completed + 1, stats.total), total: stats.total };
}
