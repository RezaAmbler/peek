import { apiClient } from './client';

export interface ScanConfig {
  id: string;
  user_id: string;
  organization_id?: string | null;
  name: string;
  description?: string;
  // Targets — list of IPs or hostnames to scan
  targets: string[];
  // Scheduling
  schedule?: string | null;  // Cron expression
  schedule_enabled: boolean;
  last_scheduled_run?: string | null;
  run_count?: number;
  // Scan mode
  scan_mode: 'fast' | 'deep';
  // Tool toggles
  enable_ssh_audit: boolean;
  enable_nuclei: boolean;
  enable_nse: boolean;
  enable_sslscan: boolean;
  enable_nikto: boolean;
  enable_zap: boolean;
  // Nuclei settings
  nuclei_severity: string;
  nuclei_templates?: string;
  nuclei_timeout: number;
  // Web scanning settings
  zap_scan_type: string;
  zap_timeout: number;
  nikto_timeout: number;
  target_urls?: string[];
  // Nmap settings
  nmap_args: string[];
  ssh_ports: number[];
  // Concurrency & timeouts
  max_concurrent_hosts: number;
  max_concurrent_scans: number;
  host_timeout_seconds: number;
  nmap_timeout_percent: number;
  // Port discovery
  discovery_top_ports: number;
  additional_ports?: string;
  // Advanced
  global_tool_timeout_seconds?: number;
  parallelism_limit?: number;
  highlight_ports: number[];
  email_on_completion: boolean;
  email_on_changes_only: boolean;
  // Metadata
  created_at: string;
  updated_at: string;
  is_default: boolean;
  is_preset: boolean;
  // Legacy fields (kept for compatibility but not used in UI)
  masscan_rate?: number;
  masscan_interface?: string;
  masscan_timeout_percent?: number;
}

export interface ConfigListResponse {
  configs: ScanConfig[];
  total: number;
}

export interface CreateConfigRequest {
  name: string;
  description?: string;
  // Targets — list of IPs or hostnames to scan
  targets?: string[];
  // Scheduling
  schedule?: string | null;
  schedule_enabled?: boolean;
  // Scan mode
  scan_mode?: 'fast' | 'deep';
  // Tool toggles
  enable_ssh_audit?: boolean;
  enable_nuclei?: boolean;
  enable_nse?: boolean;
  enable_sslscan?: boolean;
  enable_nikto?: boolean;
  enable_zap?: boolean;
  // Nuclei settings
  nuclei_severity?: string;
  nuclei_templates?: string;
  nuclei_timeout?: number;
  // Web scanning settings
  zap_scan_type?: string;
  zap_timeout?: number;
  nikto_timeout?: number;
  target_urls?: string[];
  // Nmap settings
  nmap_args?: string[];
  ssh_ports?: number[];
  // Concurrency & timeouts
  max_concurrent_hosts?: number;
  max_concurrent_scans?: number;
  host_timeout_seconds?: number;
  nmap_timeout_percent?: number;
  // Port discovery
  discovery_top_ports?: number;
  additional_ports?: string;
  // Advanced
  global_tool_timeout_seconds?: number;
  parallelism_limit?: number;
  highlight_ports?: number[];
  email_on_completion?: boolean;
  email_on_changes_only?: boolean;
}

export type UpdateConfigRequest = Partial<CreateConfigRequest>;

export const configsApi = {
  async list(userId?: string): Promise<ConfigListResponse> {
    const params = userId ? `?user_id=${userId}` : '';
    const { data } = await apiClient.get<ConfigListResponse>(`/api/configs${params}`);
    return data;
  },

  async get(configId: string): Promise<ScanConfig> {
    const { data } = await apiClient.get<ScanConfig>(`/api/configs/${configId}`);
    return data;
  },

  async create(config: CreateConfigRequest): Promise<ScanConfig> {
    const { data } = await apiClient.post<ScanConfig>('/api/configs', config);
    return data;
  },

  async update(configId: string, updates: UpdateConfigRequest): Promise<ScanConfig> {
    const { data } = await apiClient.patch<ScanConfig>(`/api/configs/${configId}`, updates);
    return data;
  },

  async delete(configId: string): Promise<void> {
    await apiClient.delete(`/api/configs/${configId}`);
  },

  async setDefault(configId: string): Promise<ScanConfig> {
    const { data } = await apiClient.post<ScanConfig>(`/api/configs/${configId}/set-default`);
    return data;
  },
};
