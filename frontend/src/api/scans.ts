import { apiClient } from './client';

export interface ScanTarget {
  id: string;
  device_name?: string;
  ip_address: string;
  status: string;
  error_message?: string;
  started_at?: string;
  finished_at?: string;
  duration_seconds?: number;
  sequence: number;
}

export interface Scan {
  id: string;
  user_id: string;
  created_by_id: string;
  config_id: string;
  name: string;
  description?: string;
  status: string;
  current_phase: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  progress_percent: number;
  total_targets: number;
  completed_targets: number;
  failed_targets: number;
  total_open_ports: number;
  total_vulnerabilities: number;
  baseline_scan_id?: string;
}

export interface ScanDetail extends Scan {
  targets: ScanTarget[];
  phase_stats?: Record<string, { completed: number; total: number }>;
}

export interface ScanListResponse {
  scans: Scan[];
  total: number;
  page: number;
  pages: number;
}

export interface TargetInput {
  ip_address: string;
  device_name?: string;
}

export interface CreateScanRequest {
  name: string;
  description?: string;
  config_id: string;
  targets: TargetInput[];
  baseline_scan_id?: string;
}

export interface CreateScanFromCSVRequest {
  name: string;
  description?: string;
  config_id: string;
  targets_csv: string;
  baseline_scan_id?: string;
}

export interface UpdateScanRequest {
  name?: string;
  description?: string;
  config_id?: string;
  targets?: TargetInput[];
  baseline_scan_id?: string;
}

export interface Port {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  protocol: string;
  state: string;
  service_name?: string;
  product?: string;
  version?: string;
  discovered_by: string;
}

export interface SSHAudit {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  banner?: string;
  ssh_version?: string;
  key_exchange_algorithms?: string[];
  host_key_algorithms?: string[];
  encryption_algorithms?: string[];
  mac_algorithms?: string[];
  vulnerabilities?: Array<{
    severity: string;
    description: string;
    cve?: string;
  }>;
  recommendations?: Array<{
    action: string;
    item: string;
  }>;
  connection_failed: boolean;
  failure_reason?: string;
}

export interface Vulnerability {
  id: string;
  ip_address: string;
  device_name?: string;
  template_id: string;
  name: string;
  severity: string;
  type?: string;
  matched_at: string;
  host: string;
  port?: number;
  description?: string;
  reference?: string[];
  tags?: string[];
  extracted_results?: any[];
  curl_command?: string;
  timestamp: string;
}

export const scansApi = {
  async list(page = 1, limit = 20, status?: string): Promise<ScanListResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
    });
    if (status) params.append('status', status);

    const { data } = await apiClient.get<ScanListResponse>(`/api/scans?${params}`);
    return data;
  },

  async get(scanId: string): Promise<ScanDetail> {
    const { data } = await apiClient.get<ScanDetail>(`/api/scans/${scanId}`);
    return data;
  },

  async create(scan: CreateScanRequest): Promise<Scan> {
    const { data } = await apiClient.post<Scan>('/api/scans', scan);
    return data;
  },

  async createFromCSV(scan: CreateScanFromCSVRequest): Promise<Scan> {
    const { data } = await apiClient.post<Scan>('/api/scans/from-csv', scan);
    return data;
  },

  async update(scanId: string, scan: UpdateScanRequest): Promise<Scan> {
    const { data } = await apiClient.patch<Scan>(`/api/scans/${scanId}`, scan);
    return data;
  },

  async delete(scanId: string): Promise<void> {
    await apiClient.delete(`/api/scans/${scanId}`);
  },

  async cancel(scanId: string): Promise<Scan> {
    const { data } = await apiClient.post<Scan>(`/api/scans/${scanId}/cancel`);
    return data;
  },

  async start(scanId: string): Promise<Scan> {
    const { data } = await apiClient.post<Scan>(`/api/scans/${scanId}/start`);
    return data;
  },

  async restart(scanId: string): Promise<Scan> {
    const { data } = await apiClient.post<Scan>(`/api/scans/${scanId}/restart`);
    return data;
  },

  async getPorts(scanId: string): Promise<Port[]> {
    const { data } = await apiClient.get<Port[]>(`/api/scans/${scanId}/ports`);
    return data;
  },

  async getSSHAudits(scanId: string): Promise<SSHAudit[]> {
    const { data } = await apiClient.get<SSHAudit[]>(`/api/scans/${scanId}/ssh-audits`);
    return data;
  },

  async getVulnerabilities(scanId: string, severity?: string): Promise<Vulnerability[]> {
    const params = severity ? `?severity=${severity}` : '';
    const { data } = await apiClient.get<Vulnerability[]>(`/api/scans/${scanId}/vulnerabilities${params}`);
    return data;
  },
};
