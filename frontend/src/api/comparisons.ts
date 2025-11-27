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
  old_version?: string;
  new_version?: string;
  template_id?: string;
  name?: string;
  vuln_severity?: string;
  matched_at?: string;
  old_vuln_count?: number;
  new_vuln_count?: number;
  description: string;
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
};
