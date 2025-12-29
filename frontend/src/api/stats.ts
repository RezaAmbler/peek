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

export interface TopVulnerableHost {
  ip_address: string;
  device_name?: string;
  vulnerability_count: number;
  critical_count: number;
}

export interface ServiceCount {
  service_name: string;
  count: number;
}

export interface DailyScanCount {
  date: string;
  count: number;
}

export interface DashboardStats {
  total_scans: number;
  scans_by_status: ScanStatusCount[];
  total_vulnerabilities: number;
  vulnerabilities_by_severity: VulnerabilitySeverityCount[];
  total_configs: number;
  recent_scans: RecentScan[];
  // New fields
  total_ports: number;
  active_schedules: number;
  next_scheduled_run?: string;
  top_vulnerable_hosts: TopVulnerableHost[];
  services_breakdown: ServiceCount[];
  scans_by_day: DailyScanCount[];
}

export const statsApi = {
  async getDashboard(): Promise<DashboardStats> {
    const { data } = await apiClient.get<DashboardStats>('/api/stats');
    return data;
  },
};
