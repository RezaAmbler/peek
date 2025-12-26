import { apiClient } from './client';

export interface ScanStatusCount {
  status: string;
  count: number;
}

export interface VulnerabilitySeverityCount {
  severity: string;
  count: number;
}

export interface RecentScan {
  id: string;
  config_name?: string;
  run_number: number;
  status: string;
  created_at: string;
  total_open_ports: number;
  total_vulnerabilities: number;
}

export interface DashboardStats {
  total_scans: number;
  scans_by_status: ScanStatusCount[];
  total_vulnerabilities: number;
  vulnerabilities_by_severity: VulnerabilitySeverityCount[];
  total_configs: number;
  recent_scans: RecentScan[];
}

export const statsApi = {
  async getDashboard(): Promise<DashboardStats> {
    const { data } = await apiClient.get<DashboardStats>('/api/stats');
    return data;
  },
};
