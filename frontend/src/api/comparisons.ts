import { apiClient } from './client';

export interface ScanComparison {
  id: string;
  baseline_scan_id: string;
  current_scan_id: string;
  created_at: string;
  total_changes: number;
  new_ports: number;
  closed_ports: number;
  version_changes: number;
  new_vulnerabilities: number;
  fixed_vulnerabilities: number;
  critical_changes: number;
  high_changes: number;
  medium_changes: number;
  positive_changes: number;
  summary: string;
  changes: Change[];
}

export interface Change {
  type: string;
  severity: string;
  category: string;
  ip_address: string;
  device_name?: string;
  port?: number;
  protocol?: string;
  service_name?: string;
  version?: string;
  product?: string;
  old_version?: string;
  new_version?: string;
  template_id?: string;
  name?: string;
  vuln_severity?: string;
  matched_at?: string;
  vuln_description?: string;
  reference?: string;
  old_vuln_count?: number;
  new_vuln_count?: number;
  description: string;
  associated_vulnerabilities?: AssociatedVulnerability[];
  // NEW_VULNERABILITY triage classification (SOC hardening): distinguishes genuinely new
  // findings from ones already suppressed via triage (excluded from headline counts, but
  // may still appear in the changes array).
  classification?: 'GENUINELY_NEW' | 'SUPPRESSED';
  fingerprint?: string;
}

export interface AssociatedVulnerability {
  name: string;
  severity: string;
  template_id: string;
  matched_at: string;
}

interface ComparisonExport {
  /** Path below /api/reports/comparison/{id}/ */
  path: string;
  params?: Record<string, string>;
  /** Suffix and extension of the saved file. */
  fileSuffix: string;
}

// Mirrors the scan report exports: two PDFs, HTML, and CSVs.
export const COMPARISON_EXPORTS = {
  'pdf-executive': { path: 'pdf/executive', fileSuffix: 'executive_summary.pdf' },
  'pdf-detailed': { path: 'pdf/detailed', fileSuffix: 'report.pdf' },
  html: { path: 'html', fileSuffix: 'report.html' },
  'csv-changes': { path: 'csv/changes', fileSuffix: 'changes.csv' },
  'csv-vulnerabilities': {
    path: 'csv/changes',
    params: { category: 'vulnerability' },
    fileSuffix: 'vulnerability_changes.csv',
  },
  'csv-ports': { path: 'csv/changes', params: { category: 'port' }, fileSuffix: 'port_changes.csv' },
  'csv-summary': { path: 'csv/summary', fileSuffix: 'summary.csv' },
} satisfies Record<string, ComparisonExport>;

export type ComparisonExportFormat = keyof typeof COMPARISON_EXPORTS;

export function comparisonExportFilename(comparisonId: string, format: ComparisonExportFormat): string {
  return `comparison_${comparisonId.slice(0, 8)}_${COMPARISON_EXPORTS[format].fileSuffix}`;
}

export const comparisonsApi = {
  async compare(baselineScanId: string, currentScanId: string): Promise<ScanComparison> {
    const { data } = await apiClient.post<ScanComparison>('/api/comparisons/compare', null, {
      params: {
        baseline_scan_id: baselineScanId,
        current_scan_id: currentScanId,
      },
    });
    return data;
  },

  async get(comparisonId: string): Promise<ScanComparison> {
    const { data } = await apiClient.get<ScanComparison>(`/api/comparisons/${comparisonId}`);
    return data;
  },

  async listForScan(scanId: string): Promise<Array<Partial<ScanComparison>>> {
    const { data } = await apiClient.get(`/api/comparisons/scan/${scanId}`);
    return data;
  },

  // Goes through apiClient so the request uses the configured base URL and auth token
  async downloadReport(comparisonId: string, format: ComparisonExportFormat): Promise<Blob> {
    const { path, params }: ComparisonExport = COMPARISON_EXPORTS[format];
    const { data } = await apiClient.get<Blob>(`/api/reports/comparison/${comparisonId}/${path}`, {
      params,
      responseType: 'blob',
    });
    return data;
  },
};
